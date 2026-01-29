# Copyright (C) 2025-2026 OVH SAS
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

import json
from collections import Counter
from math import ceil
from time import sleep, time

from oio.api.object_storage import ObjectStorageApi
from oio.common.constants import (
    OBJECT_REPLICATION_COMPLETED,
    OBJECT_REPLICATION_FAILED,
    OBJECT_REPLICATION_PENDING,
    REPLICATION_STATUS_KEY,
)
from oio.common.easy_value import float_value, int_value
from oio.common.exceptions import (
    ConfigurationException,
    NoSuchContainer,
    NoSuchObject,
    OioNetworkException,
    OioUnhealthyKafkaClusterError,
    ReplicationNotFinished,
    ServiceBusy,
    ServiceUnavailable,
    XcuteRetryTaskLater,
)
from oio.common.kafka import (
    DEFAULT_REPLICATION_DELAYED_TOPIC,
    DEFAULT_REPLICATION_TOPIC,
    KafkaSender,
)
from oio.common.kafka_http import KafkaClusterHealth
from oio.common.utils import depaginate
from oio.event.evob import Event, get_account_from_event, get_root_container_from_event
from oio.xcute.common.job import XcuteJob, XcuteTask


class KafkaError(Exception):
    pass


class ManifestNotCurrentlyAvailable(Exception):
    pass


class BatchReplicatorTask(XcuteTask):
    def __init__(self, conf, job_params, logger=None, watchdog=None):
        super().__init__(conf, job_params, logger=logger, watchdog=watchdog)

        self.api = ObjectStorageApi(conf["namespace"], watchdog=watchdog, logger=logger)
        self.namespace = conf["namespace"]
        self.technical_account = job_params["technical_account"]
        self.technical_bucket = job_params["technical_bucket"]
        self.replication_topic = job_params["replication_topic"]
        self.delay_retry_later = job_params["delay_retry_later"]
        self.kafka_conf = {
            **self.conf,
            "delayed_topic": job_params["replication_delayed_topic"],
        }
        self.kafka_endpoint = self.conf.get("broker_endpoint")
        if not self.kafka_endpoint:
            self.logger.error("Missing kafka broker_endpoint in conf")
            raise ConfigurationException("Missing kafka broker_endpoint in conf")
        self.kafka_producer = None

    def _is_delete_marker(self, event: Event) -> bool:
        for metadata in event.env["data"]:
            if metadata.get("type") == "aliases":
                return metadata.get("deleted", False)

    def _set_status_to_pending(self, event: Event, reqid) -> Event:
        obj = event.url.get("path")
        version = event.url.get("version")

        # Set the metadata on the object
        self.api.object_set_properties(
            account=get_account_from_event(event),
            container=get_root_container_from_event(event),
            obj=obj,
            properties={REPLICATION_STATUS_KEY: OBJECT_REPLICATION_PENDING},
            version=version,
            reqid=reqid,
        )

        # Patch the event with the pending metadata
        found = False
        for metadata in event.env["data"]:
            if (
                metadata.get("type") == "properties"
                and metadata.get("key") == REPLICATION_STATUS_KEY
            ):
                # Enforce the value
                metadata["value"] = "PENDING"
                found = True
        if not found:
            # Craft the metadata
            event.env["data"].append(
                {
                    "type": "properties",
                    "alias": obj,
                    "version": version,
                    "key": REPLICATION_STATUS_KEY,
                    "value": "PENDING",
                }
            )

        return event

    def _send_event(self, event: Event) -> None:
        if self.kafka_producer is None:
            self.kafka_producer = KafkaSender(
                self.kafka_endpoint, self.logger, self.kafka_conf
            )

        # Overwrite the when. The field is populated by default during the listing,
        # but the delay filters rely on it.
        event.when = int(time() * 1000000)  # use time in micro seconds

        try:
            res = self.kafka_producer.send(
                self.replication_topic, event.env, flush=True
            )
            if res > 0:
                # If the event is not acknowledged, we will retry later.
                # We want to be sure that the replication event is sent before
                # committing the task.
                raise XcuteRetryTaskLater(delay=self.delay_retry_later)
        except XcuteRetryTaskLater:
            self.logger.error("Replication event not flushed, send to retry later")
            raise
        except Exception as exc:
            self.logger.error("Fail to send replication event %s: %s", event, exc)
            raise KafkaError from exc

    def _is_object_replicated(self, event: Event, reqid: str) -> str:
        """
        Wait for the object to be in "COMPLETED" / "FAILED" status.
        Returns the status if replication finished, None otherwise.
        """
        props = self.api.object_get_properties(
            account=get_account_from_event(event),
            container=get_root_container_from_event(event),
            obj=event.url.get("path"),
            version=event.url.get("version"),
            reqid=reqid,
        )
        replication_status = props.get("properties", {}).get(REPLICATION_STATUS_KEY)
        if replication_status in (
            OBJECT_REPLICATION_FAILED,
            OBJECT_REPLICATION_COMPLETED,
        ):
            return replication_status

        self.logger.debug(
            "Replication of obj=%s still in progress",
            event.url.get("path"),
        )
        return None

    def process(self, task_id, task_payload, reqid=None, job_id=None):
        """
        Note that a delete marker has no replication status, the event is sent et voilà.
        With OBSTO-3344, delete marker will have a status, then we will be able to
        track their status.
        """
        resp = Counter()
        event = Event(task_payload)
        is_delete_marker = self._is_delete_marker(event)
        replication_event_already_sent = (
            task_payload.get("extra") == "replication_event_already_sent"
        )
        status = None
        try:
            if is_delete_marker:
                # Delete marker cannot (yet) have as replication status
                self._send_event(event)
                # Consider status as COMPLETED
                status = "COMPLETED"
            else:
                if not replication_event_already_sent:
                    event = self._set_status_to_pending(event, reqid)

                    # Can raise KafkaError
                    self._send_event(event)

                    # In ideal world, replication is done fast, it is not necessary
                    # to wait the full delay. If object is big or slow to replicate,
                    # the impact is negligible (an additional event in the delayed
                    # topic).
                    raise ReplicationNotFinished(
                        delay=int(self.delay_retry_later / 2),
                        extra="replication_event_already_sent",
                    )
                else:
                    status = self._is_object_replicated(event, reqid)
        except NoSuchContainer:
            self.logger.info("Container does not exist anymore")
            resp["object_skipped_container_deleted"] += 1
            return resp
        except NoSuchObject:
            self.logger.info("Source object does not exist anymore")
            resp["object_skipped_deleted"] += 1
            return resp
        except (ServiceUnavailable, OioNetworkException, ServiceBusy):
            # Something went wrong, retry later
            raise XcuteRetryTaskLater(delay=self.delay_retry_later)

        if not status:
            raise ReplicationNotFinished(delay=self.delay_retry_later)
        self.logger.debug(
            "Replication of obj=%s finished with status %s",
            event.url.get("path"),
            status,
        )
        resp[f"object_replication_{status}"] += 1
        return resp

    def close(self):
        if self.kafka_producer is not None:
            self.kafka_producer.close()
            self.kafka_producer = None


def iter_lines_from_stream(stream, marker=0):
    buffer = b""
    index = 0
    for chunk in stream:
        buffer += chunk
        while b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            if not line.strip():
                continue
            if index >= marker:
                yield index, line.decode("utf-8")
            index += 1
    # Deal with remaining data in buffer
    if buffer.strip():
        if index >= marker:
            yield index, buffer.decode("utf-8")


class ManifestIterator:
    """
    Handler to easily iterate on a manifest.
    On temporary error, the manifest is reopened automatically.
    """

    def __init__(
        self, api, job_params, manifest_name, start_line, reqid, job_id, logger=None
    ):
        self.api = api
        self.job_params = job_params
        self.name = manifest_name
        self.reqid = reqid
        self.logger = logger
        self.job_id = job_id
        # Initialize to start_line - 1 so that if we need to reopen before any
        # successful yield, we start from start_line
        self.current_line = start_line - 1 if start_line > 0 else 0
        self.MAX_RETRIES = 3  # arbitrary value, we only want to stop if error persists
        self.iterator = self._create_iterator(start_line)

    def _create_iterator(self, start_line):
        """Fetch the manifest and create an iterator starting from start_line."""
        _, stream = self.api.object_fetch(
            self.job_params["technical_account"],
            self.job_params["technical_bucket"],
            self.name,
            reqid=self.reqid,
        )
        return iter_lines_from_stream(stream, start_line)

    def _reopen(self, from_line):
        """Reopen the manifest from a specific line."""
        self.iterator = self._create_iterator(from_line)

    def __iter__(self):
        return self

    def __next__(self):
        # Retry counter will be reset at each call.
        # For a huge bucket with MPU, we might have several timeouts on
        # manifest but we don't want the job to fail.
        retries = 0
        while True:
            try:
                if self.iterator is None:
                    # Reopen the iterator from the last successful line + 1
                    self.iterator = self._create_iterator(self.current_line + 1)
                index, event = next(self.iterator)
                self.current_line = index
                return index, event
            except (ServiceUnavailable, OioNetworkException, ServiceBusy) as err:
                self.iterator = None
                if self.logger:
                    self.logger.error(
                        "[job_id=%s] Error while reading manifest %s: %s (retries=%d)",
                        self.job_id,
                        self.name,
                        err,
                        retries,
                    )
                retries += 1
                if retries > self.MAX_RETRIES:
                    # Manifest is not available right now, we should wait before
                    # retrying. Fatal errors are not caught.
                    retries = 0
                    raise ManifestNotCurrentlyAvailable from err

                # On very first retry, we want to retry immediately
                if retries > 1:
                    sleep(self.job_params["delay_retry_later"])


class BatchReplicatorJob(XcuteJob):
    JOB_TYPE = "batch-replicator"
    TASK_CLASS = BatchReplicatorTask

    DEFAULT_TASKS_PER_SECOND = 200  # aka nb of tasks per shard
    DEFAULT_MAX_TASKS_PER_SECOND = 1000  # aka nb of tasks per bucket if enough shards
    DEFAULT_TASKS_STEP = 10

    DEFAULT_KAFKA_MAX_LAGS = 1000000
    DEFAULT_KAFKA_MIN_AVAILABLE_SPACE = 40  # in percent
    DEFAULT_DELAY_RETRY_LATER = 60  # in seconds
    DEFAULT_BATCH_MANIFESTS_SIZE = 10  # read x manifests at the same time

    @classmethod
    def sanitize_params(cls, job_params):
        sanitized_job_params, _ = super().sanitize_params(job_params)
        sanitized_job_params["technical_manifest_prefix"] = job_params[
            "technical_manifest_prefix"
        ]
        sanitized_job_params["technical_account"] = job_params["technical_account"]
        sanitized_job_params["technical_bucket"] = job_params["technical_bucket"]

        # Kafka
        sanitized_job_params["replication_topic"] = job_params.get(
            "replication_topic", DEFAULT_REPLICATION_TOPIC
        )
        sanitized_job_params["replication_delayed_topic"] = job_params.get(
            "replication_delayed_topic", DEFAULT_REPLICATION_DELAYED_TOPIC
        )
        # Maximum lag allowed for kafka topics (<0 to disable)
        sanitized_job_params["kafka_max_lags"] = int_value(
            job_params.get("kafka_max_lags"), cls.DEFAULT_KAFKA_MAX_LAGS
        )
        # Minimal available space allowed for kafka cluster (in percent) (<0 to disable)
        sanitized_job_params["kafka_min_available_space"] = float_value(
            job_params.get("kafka_min_available_space"),
            cls.DEFAULT_KAFKA_MIN_AVAILABLE_SPACE,
        )
        sanitized_job_params["delay_retry_later"] = int_value(
            job_params.get("delay_retry_later"), cls.DEFAULT_DELAY_RETRY_LATER
        )
        sanitized_job_params["batch_manifest_size"] = int_value(
            job_params.get("batch_manifest_size"), cls.DEFAULT_BATCH_MANIFESTS_SIZE
        )
        # prefix looks like listing/account/bucket/xxx
        _, account, bucket, *_ = job_params["technical_manifest_prefix"].split("/")
        return sanitized_job_params, f"{account}/{bucket}"

    def __init__(self, conf, logger=None, **kwargs):
        super().__init__(conf, logger=logger, **kwargs)
        self.api = ObjectStorageApi(conf["namespace"], logger=logger)
        self.kafka_cluster_health = KafkaClusterHealth(
            {
                "namespace": conf["namespace"],
            },
            pool_manager=self.api.container.pool_manager,
        )

    def get_tasks(self, job_params, marker=None, reqid=None):
        manifest_marker = None
        line_marker = 0
        batch_offset_marker = 0

        new_marker_format = True
        if marker:
            parts = marker.split(";")
            if len(parts) == 3:
                # Format is batch_offset_marker;manifest_name;line_number
                batch_offset_marker = int(parts[0])
                manifest_marker = parts[1]
                line_marker = int(parts[2])
            else:
                # Old format: manifest_name;line_number
                manifest_marker = parts[0]
                line_marker = int(parts[1])
                new_marker_format = False

        # Get all manifests first
        all_manifests = list(self.get_manifests(job_params=job_params, reqid=reqid))
        nb_manifests = len(all_manifests)

        if nb_manifests == 0:
            return

        # stride_size is the spacing between manifests in a batch
        if new_marker_format:
            # Using ceil to ensure max <BATCH_MANIFESTS_SIZE> manifests per batch
            batch_manifest_size = job_params.get(
                "batch_manifest_size", self.DEFAULT_BATCH_MANIFESTS_SIZE
            )
            stride_size = max(1, ceil(nb_manifests / batch_manifest_size))
        else:
            stride_size = 1

        for batch_offset in range(batch_offset_marker, stride_size):
            # Select manifests for this batch
            batch_indexes = list(range(batch_offset, nb_manifests, stride_size))

            # Prepare iterators only for manifests in this batch
            manifest_iters = []

            for batch_index in batch_indexes:
                manifest = all_manifests[batch_index]
                manifest_iters.append(
                    ManifestIterator(
                        api=self.api,
                        job_params=job_params,
                        manifest_name=manifest["name"],
                        start_line=line_marker,
                        reqid=reqid,
                        job_id=self.job_id,
                        logger=self.logger,
                    )
                )

            if line_marker:
                # Line marker is only required for the first batch of manifest
                line_marker = 0

            while manifest_iters:
                manifest_name_finished = []

                for manifest_iter in manifest_iters:
                    # Retry loop for this specific manifest until we yield something
                    while True:
                        try:
                            index, event = next(manifest_iter)
                            if manifest_marker:
                                if manifest_iter.name != manifest_marker:
                                    # Manifest marker not reached, continue
                                    break
                                manifest_marker = None
                                # Marker reached, next manifest will be the good one
                                break

                            task_id = f"{manifest_iter.name};{index}"
                            if new_marker_format:
                                task_id = f"{batch_offset};{task_id}"
                            yield (task_id, json.loads(event))
                            break  # Successfully yielded, move to next manifest
                        except StopIteration:
                            manifest_name_finished.append(manifest_iter)
                            break  # This manifest is done, move to next one
                        except ManifestNotCurrentlyAvailable:
                            # We have to answer something to the orchestrator in order
                            # to give him the possibility to do something else.
                            # Otherwise, from the orchestrator point of view, we are
                            # stuck in a while loop.
                            yield None, None
                            sleep(job_params["delay_retry_later"])
                            # Continue the while True loop to retry this manifest

                for finished_iter in manifest_name_finished:
                    manifest_iters.remove(finished_iter)

    def get_total_tasks(self, job_params, marker=None, reqid=None):
        manifests = self.get_manifests(
            job_params=job_params, marker=marker, reqid=reqid
        )
        for manifest in manifests:
            yield (manifest["name"], int(manifest["properties"]["nb_objects"]))

    def get_manifests(self, job_params, marker=None, reqid=None):
        manifests = depaginate(
            self.api.object_list,
            account=job_params["technical_account"],
            container=job_params["technical_bucket"],
            listing_key=lambda x: x["objects"],
            marker_key=lambda x: x["next_marker"],
            truncated_key=lambda x: x["truncated"],
            prefix=job_params["technical_manifest_prefix"],
            marker=marker,
            properties=True,
            reqid=reqid,
        )
        for manifest in manifests:
            yield manifest

    def can_process_tasks(self, job_params):
        try:
            topics = [
                job_params["replication_topic"],
                job_params["replication_delayed_topic"],
            ]
            self.kafka_cluster_health.check(
                topics=topics,
                min_available_space=job_params["kafka_min_available_space"],
                max_lag=job_params["kafka_max_lags"],
            )
        except OioUnhealthyKafkaClusterError:
            self.logger.debug("Unhealthy kafka cluster, waiting..")
            return False
        return True

    def get_target_task_per_second(self, job_info) -> int:
        """
        The goal here is to have a dynamic target.
        At the beginning, consider that the bucket has no shards: we don't want more
        than DEFAULT_TASKS_PER_SECOND tasks per second.
        With time, we will reach enough objects in the bucket to trigger some sharding.
        Then, the target can be increased to dispatch DEFAULT_TASKS_PER_SECOND across
        shards (with a maximum DEFAULT_MAX_TASKS_PER_SECOND).

        The number of objects per shard is purely arbitrary, most of the time, sharding
        will be triggered before. But this is a safety value, we don't want to increase
        the target if there is still no shards.

        Plus, the destination bucket may be on another region, we don't want to make
        calls to the bucket DB to know how many containers the bucket has (and we don't
        know if containers are shards or +segments).
        """
        NB_OBJECTS_PER_SHARD = 600000  # arbitrary "worst case" scenario
        nb_objects_replicated = job_info["tasks"]["processed"]

        tasks_per_shard = job_info["config"]["tasks_per_second"]
        tasks_per_bucket = job_info["config"]["max_tasks_per_second"]

        computed_nb_shards = 1 + nb_objects_replicated // NB_OBJECTS_PER_SHARD
        target = min(computed_nb_shards * tasks_per_shard, tasks_per_bucket)
        self.logger.debug(
            "New computed target: %d (with %d processed tasks)",
            target,
            nb_objects_replicated,
        )
        return target
