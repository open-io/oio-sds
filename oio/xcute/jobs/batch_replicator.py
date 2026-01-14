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

                    raise ReplicationNotFinished(
                        delay=self.delay_retry_later,
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


class BatchReplicatorJob(XcuteJob):
    JOB_TYPE = "batch-replicator"
    TASK_CLASS = BatchReplicatorTask

    DEFAULT_TASKS_PER_SECOND = 200  # aka nb of tasks per shard
    DEFAULT_MAX_TASKS_PER_SECOND = 1000  # aka nb of tasks per bucket if enough shards

    DEFAULT_KAFKA_MAX_LAGS = 1000000
    DEFAULT_KAFKA_MIN_AVAILABLE_SPACE = 40  # in percent
    DEFAULT_DELAY_RETRY_LATER = 60  # in seconds

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

    def _unsafe_get_tasks(self, job_params, marker=None, reqid=None):
        """
        _unsafe_get_tasks is not safe because timeouts can happens easily on manifests.
        """
        manifest_marker = None
        line_marker = 0
        if marker:
            manifest_marker, line_marker = marker.split(";")
            line_marker = int(line_marker)

        # Prepare iterators for each manifests
        manifest_iters = []
        for manifest in self.get_manifests(job_params=job_params, reqid=reqid):
            _, stream = self.api.object_fetch(
                job_params["technical_account"],
                job_params["technical_bucket"],
                manifest["name"],
                reqid=reqid,
            )
            manifest_iters.append(
                (manifest["name"], iter_lines_from_stream(stream, line_marker))
            )

        manifest_name_finished = []
        while True:
            for manifest_name, it in manifest_iters:
                try:
                    index, event = next(it)
                    if manifest_marker:
                        if manifest_name != manifest_marker:
                            # Marker not reached, continue
                            continue
                        manifest_marker = None
                        # Marker reached, next manifest will be the good one
                        continue
                    task_id = f"{manifest_name};{index}"
                    yield (task_id, json.loads(event))
                except StopIteration:
                    manifest_name_finished.append(manifest_name)

            for manifest_name in manifest_name_finished:
                manifest_iters = [m for m in manifest_iters if m[0] != manifest_name]
            if not manifest_iters:
                break
            manifest_name_finished = []

    def get_tasks(self, job_params, marker=None, reqid=None):
        """Call _unsafe_get_tasks and retry on known errors."""
        max_retries = 3  # arbitrary value, we only want to stop if error persists
        current_marker = marker
        retries = 0

        while True:
            try:
                for task_id, task_payload in self._unsafe_get_tasks(
                    job_params=job_params,
                    marker=current_marker,
                    reqid=reqid,
                ):
                    current_marker = task_id
                    # Reset retry counter if there is something to yield.
                    # For a huge bucket with MPU, we might have several timeouts on
                    # manifest but we don't want the job to fail.
                    retries = 0
                    yield task_id, task_payload

                return

            except (ServiceUnavailable, OioNetworkException, ServiceBusy) as err:
                self.logger.error(
                    "[job_id=%s] Error while reading manifests: %s (retries=%d)",
                    self.job_id,
                    err,
                    retries,
                )
                retries += 1
                if retries > max_retries:
                    raise

                # On very first retry, we want to retry immediately. This way, there
                # is no loss of time because of a potential timeout on manifests.
                if retries > 1:
                    sleep(job_params["delay_retry_later"])

                # Resume from last known marker
                continue

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

        computed_nb_shards = min(1, int(nb_objects_replicated / NB_OBJECTS_PER_SHARD))
        target = min(computed_nb_shards * tasks_per_shard, tasks_per_bucket)
        self.logger.debug(
            "New computed target: %d (with %d processed tasks)",
            target,
            nb_objects_replicated,
        )
        return target
