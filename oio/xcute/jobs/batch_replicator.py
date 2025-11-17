# Copyright (C) 2025 OVH SAS
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

import json
from collections import Counter
from time import sleep

from oio.api.object_storage import ObjectStorageApi
from oio.common.constants import (
    OBJECT_REPLICATION_COMPLETED,
    OBJECT_REPLICATION_FAILED,
    OBJECT_REPLICATION_PENDING,
    REPLICATION_STATUS_KEY,
)
from oio.common.exceptions import (
    NoSuchContainer,
    NoSuchObject,
    OioNetworkException,
    OioUnhealthyKafkaClusterError,
    RetryLater,
)
from oio.common.kafka import (
    DEFAULT_REPLICATION_DELAYED_TOPIC,
    DEFAULT_REPLICATION_TOPIC,
    KafkaSender,
)
from oio.common.kafka_http import KafkaClusterHealth
from oio.common.utils import depaginate, monotonic_time
from oio.event.evob import Event, get_account_from_event, get_root_container_from_event
from oio.xcute.common.job import XcuteJob, XcuteTask

DEFAULT_CHECK_REPLICATION_STATUS_TIMEOUT = 60 * 60 * 24 * 2  # 48 hours


class KafkaError(Exception):
    pass


class ReplicationError(Exception):
    pass


class BatchReplicatorTask(XcuteTask):
    def __init__(self, conf, job_params, logger=None, watchdog=None):
        super().__init__(conf, job_params, logger=logger, watchdog=watchdog)

        self.api = ObjectStorageApi(conf["namespace"], watchdog=watchdog, logger=logger)
        self.namespace = conf["namespace"]
        self.technical_account = job_params["technical_account"]
        self.technical_bucket = job_params["technical_bucket"]
        self.replication_topic = job_params["replication_topic"]
        self.check_replication_status_timeout = job_params[
            "check_replication_status_timeout"
        ]
        self.delay_retry_later = job_params["delay_retry_later"]

        self.kafka_cluster_health = KafkaClusterHealth(
            {
                "namespace": self.namespace,
                "topics": ",".join(
                    (
                        self.replication_topic,
                        job_params["replication_delayed_topic"],
                    )
                ),
                "max_lag": job_params["kafka_max_lags"],
                "min_available_space": job_params["kafka_min_available_space"],
            },
            pool_manager=self.api.container.pool_manager,
        )
        self.kafka_sleep_between_health_check = job_params[
            "kafka_sleep_between_health_check"
        ]

        self.kafka_conf = {
            **self.conf,
            "delayed_topic": job_params["replication_delayed_topic"],
        }
        self.kafka_endpoint = self.conf["broker_endpoint"]
        self.kafka_producer = None

    def _set_status_to_pending(self, event: Event, reqid):
        obj = event.url.get("path")
        version = event.url.get("version")

        # Set the metadata on the object
        metadata = {REPLICATION_STATUS_KEY: OBJECT_REPLICATION_PENDING}
        self.api.object_set_properties(
            account=get_account_from_event(event),
            container=get_root_container_from_event(event),
            obj=obj,
            properties=metadata,
            version=version,
            reqid=reqid,
        )

        # Patch the event with the pending metadata
        found = False
        for metadata in event.env["data"]:
            if (
                metadata["type"] == "properties"
                and metadata["key"] == REPLICATION_STATUS_KEY
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

    def _wait_for_healthy_kafka_cluster(self):
        while True:
            try:
                self.kafka_cluster_health.check()
                break
            except OioUnhealthyKafkaClusterError:
                self.logger.debug("Unhealthy kafka cluster, waiting..")
                sleep(self.kafka_sleep_between_health_check)

    def _send_event(self, event: Event):
        # Check and wait for a healthy kafka cluster before send the event
        self._wait_for_healthy_kafka_cluster()

        if self.kafka_producer is None:
            self.kafka_producer = KafkaSender(
                self.kafka_endpoint, self.logger, self.kafka_conf
            )

        try:
            self.kafka_producer.send(self.replication_topic, event.env, flush=True)
        except Exception as exc:
            self.logger.error("Fail to send replication event %s: %s", event, exc)
            raise KafkaError from exc

    def _wait_for_replication(self, event: Event, reqid: str):
        """
        Wait for the object to be in "COMPLETED" / "FAILED" status
        """
        min_wait = 10  # Minimum value of the exponential backoff
        max_wait = 600  # Maximal value of the exponential backoff

        start_time = monotonic_time()
        wait_time = min_wait
        while True:
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
                break

            # Check if timeout reached
            elapsed = monotonic_time() - start_time
            if elapsed >= self.check_replication_status_timeout:
                msg = "Timeout reached, consider replication failed"
                self.logger.error(msg)
                raise ReplicationError(msg)

            self.logger.debug(
                "Replication of obj=%s still in progress, waiting %ds ...",
                event.url.get("path"),
                wait_time,
            )
            sleep(wait_time)

            # Exponential backoff with max
            wait_time = min(wait_time * 2, max_wait)

    def process(self, task_id, task_payload, reqid=None, job_id=None):
        resp = Counter()
        event = Event(task_payload)

        try:
            event = self._set_status_to_pending(event, reqid)

            # Can raise KafkaError
            self._send_event(event)

            # Can raise ReplicationError
            self._wait_for_replication(event, reqid)
        except NoSuchContainer:
            self.logger.info("Container does not exist anymore")
            resp["object_skipped_container_deleted"] += 1
            return resp
        except NoSuchObject:
            self.logger.info("Source object does not exist anymore")
            resp["object_skipped_deleted"] += 1
            return resp
        except OioNetworkException:
            # Something went wrong, retry later
            raise RetryLater(delay=self.delay_retry_later)

        self.logger.info("Replication of obj=%s finished", event.url.get("path"))
        resp["object_replicated"] += 1
        return resp


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

    DEFAULT_TASKS_PER_SECOND = 200
    MAX_TASKS_BATCH_SIZE = 1

    DEFAULT_KAFKA_MAX_LAGS = 1000000
    DEFAULT_KAFKA_MIN_AVAILABLE_SPACE = 40  # in percent
    DEFAULT_KAFKA_CHECK_BETWEEN_HEALTH_CHECK = 60  # in seconds
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
        sanitized_job_params["kafka_max_lags"] = int(
            job_params.get("kafka_max_lags", cls.DEFAULT_KAFKA_MAX_LAGS)
        )
        # Minimal available space allowed for kafka cluster (in percent) (<0 to disable)
        sanitized_job_params["kafka_min_available_space"] = int(
            job_params.get(
                "kafka_min_available_space", cls.DEFAULT_KAFKA_MIN_AVAILABLE_SPACE
            )
        )
        sanitized_job_params["kafka_sleep_between_health_check"] = int(
            job_params.get(
                "kafka_sleep_between_health_check",
                cls.DEFAULT_KAFKA_CHECK_BETWEEN_HEALTH_CHECK,
            )
        )
        sanitized_job_params["check_replication_status_timeout"] = float(
            job_params.get(
                "check_replication_status_timeout",
                DEFAULT_CHECK_REPLICATION_STATUS_TIMEOUT,
            )
        )
        sanitized_job_params["delay_retry_later"] = int(
            job_params.get("delay_retry_later", cls.DEFAULT_DELAY_RETRY_LATER)
        )
        return sanitized_job_params, job_params["technical_manifest_prefix"]

    def __init__(self, conf, logger=None, **kwargs):
        super().__init__(conf, logger=logger, **kwargs)
        self.api = ObjectStorageApi(conf["namespace"], logger=logger)

    def get_tasks(self, job_params, marker=None, reqid=None):
        manifest_marker = None
        line_marker = 0
        if marker:
            manifest_marker, line_marker = marker.split(";")
            line_marker = int(line_marker)

        manifests = self.get_manifests(
            job_params=job_params, marker=manifest_marker, reqid=reqid
        )
        for manifest in manifests:
            _, stream = self.api.object_fetch(
                job_params["technical_account"],
                job_params["technical_bucket"],
                manifest["name"],
            )
            lines = iter_lines_from_stream(stream, line_marker)
            for index, event in lines:
                task_id = f"{manifest['name']};{index}"
                yield (task_id, json.loads(event))
            line_marker = 0

    def get_total_tasks(self, job_params, marker=None, reqid=None):
        nb_objects = 0
        manifests = self.get_manifests(
            job_params=job_params, marker=marker, reqid=reqid
        )

        for manifest in manifests:
            nb_objects += int(manifest["properties"]["nb_objects"])
        yield (manifest["name"], nb_objects)

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
