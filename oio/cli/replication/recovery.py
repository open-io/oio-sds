#!/usr/bin/env python
# Copyright (C) 2024-2025 OVH SAS
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import json
import os
import signal
import time
from datetime import datetime, timedelta
from functools import partial
from pathlib import Path
from typing import Any, Dict, Generator, List, Tuple

from oio.cli import Command
from oio.common.constants import (
    OBJECT_REPLICATION_COMPLETED,
    OBJECT_REPLICATION_PENDING,
)
from oio.common.easy_value import boolean_value
from oio.common.encryption import TRANSIENT_SYSMETA_PREFIX
from oio.common.exceptions import NoSuchObject
from oio.common.kafka import (
    DEFAULT_REPLICATION_DELAYED_TOPIC,
    DEFAULT_REPLICATION_TOPIC,
    KafkaSender,
)
from oio.common.kafka_http import KafkaClusterHealth, OioUnhealthyKafkaClusterError
from oio.common.replication import get_destination_for_object, object_to_event
from oio.common.utils import depaginate
from oio.event.evob import EventTypes


class ReplicationRecovery(Command):
    """Send new events to replicate objects not yet replicated."""

    log = None
    kafka_producer = None
    marker_file = None
    nb_objects_recovered = 0
    nb_delete_markers_recovered = 0

    def _load_replication_configuration(self, account, bucket) -> None:
        info = self.app.client_manager.storage.container_get_properties(account, bucket)
        replication_conf = info.get("properties", {}).get(
            "X-Container-Sysmeta-S3Api-Replication"
        )
        return replication_conf

    def _get_replication_status_on_previous_version(
        self, account: str, bucket: str, key: str, version: str
    ) -> str:
        """
        Get the replication status of the previous version which is not a delete marker.
        If it is a delete marker, get the previous version etc...
        """
        try:
            older_version = str(int(version) - 1)
            props = self.app.client_manager.storage.object_get_properties(
                account=account, container=bucket, obj=key, version=older_version
            )
            if boolean_value(props.get("deleted", False)):
                return self._get_replication_status_on_previous_version(
                    account, bucket, key, version - 1
                )
            else:
                return props.get("properties", {}).get(
                    "x-object-sysmeta-s3api-replication-status"
                )
        except NoSuchObject:
            return None

    def get_objects_to_replicate(
        self,
        account,
        bucket,
        pending,
        until,
        only_metadata,
        replication_conf,
        marker=None,
    ) -> Generator[Tuple[Dict[str, Any], List[str], str], None, None]:
        objects_gen = depaginate(
            self.app.client_manager.storage.object_list,
            listing_key=lambda x: x["objects"],
            marker_key=lambda x: x.get("next_marker"),
            version_marker_key=lambda x: x.get("next_version_marker"),
            truncated_key=lambda x: x["truncated"],
            account=account,
            container=bucket,
            properties=True,
            versions=True,
            marker=marker,
        )
        for obj in objects_gen:
            key = obj["name"]
            metadata = obj.get("properties") or {}
            is_delete_marker = obj.get("deleted", False)

            # Unable to tell if the deletion marker has already been replicated
            # or if it's a replica
            if not is_delete_marker:
                replication_status = metadata.get(
                    "x-object-sysmeta-s3api-replication-status"
                )
                if pending:
                    if replication_status != OBJECT_REPLICATION_PENDING:
                        continue
                elif only_metadata:  # Update only metadata
                    if replication_status != OBJECT_REPLICATION_COMPLETED:
                        continue
                    has_client_metadata = False
                    for key_metadata in metadata:
                        if key_metadata.startswith(TRANSIENT_SYSMETA_PREFIX):
                            has_client_metadata = True
                            break
                    if not has_client_metadata:
                        # List only object with client metadata
                        continue
                elif replication_status is not None:
                    # PENDING: replication in progress
                    # COMPLETED: replication is already done
                    # REPLICA: it's replicated object (cannot replicate)
                    continue
            else:
                # For delete markers, only recreate events if the previous valid version
                # is replicated.
                # This is to avoid creating events for versions older than the
                # replication conf if this tool is run on a big old bucket.
                if not self._get_replication_status_on_previous_version(
                    account, bucket, key, obj["version"]
                ):
                    continue

            if until and obj["version"] > until:
                continue

            destinations, role = get_destination_for_object(
                replication_conf,
                key,
                metadata=metadata,
                is_deletion=is_delete_marker,
            )
            if not destinations:
                if pending:
                    self.log.error(
                        "No destination for the pending %s %s (%d)",
                        "delete marker" if obj["deleted"] else "object",
                        key,
                        obj["version"],
                    )
                    self.success = False
                continue
            if not is_delete_marker:
                self.nb_objects_recovered += 1
            else:
                self.nb_delete_markers_recovered += 1
            yield obj, destinations, role, is_delete_marker

    def send_event(
        self,
        conf: Dict[str, Any],
        obj: Dict[str, Any],
        dest_buckets: List[str],
        event: Dict[str, Any],
        dry_run: bool,
        is_delete_marker: bool,
    ):
        log = self.log.info if dry_run else self.log.debug
        log(
            "Sending event to replicate object %s (%d) to %s %s",
            obj["name"],
            obj["version"],
            dest_buckets,
            "(delete marker)" if is_delete_marker else "(object)",
        )
        if not dry_run:
            while True:
                try:
                    # Ensure cluster can absorb generated events
                    self.kafka_cluster_health.check()
                    break
                except OioUnhealthyKafkaClusterError as exc:
                    self.log.warning(
                        "Unhealthy kafka cluster, send event on hold: %s", exc
                    )
                    time.sleep(
                        self.kafka_cluster_health.kafka_metrics_client._cache_duration
                    )

            if self.kafka_producer is None:
                self.kafka_producer = KafkaSender(
                    conf.get("broker_endpoint"),
                    self.log,
                    app_conf=conf,
                )
            try:
                self.kafka_producer.send(DEFAULT_REPLICATION_TOPIC, event, flush=True)
            except Exception as exc:
                self.log.warning("Fail to send replication event %s: %s", event, exc)
                self.success = False

    def get_parser(self, prog_name):
        parser = super(ReplicationRecovery, self).get_parser(prog_name)
        parser.add_argument("bucket", help="Name of bucket to scan")
        group = parser.add_mutually_exclusive_group()
        group.add_argument(
            "--pending",
            action="store_true",
            help="Resend only events from objects pending to be replicated (default).",
        )
        group.add_argument(
            "--only-metadata",
            action="store_true",
            help="""Resend only events from objects with metadatata to be replicated
            (only on objects with COMPLETED status).
            """,
        )
        group.add_argument(
            "--all",
            action="store_true",
            help="Resend events from all objects no matter their statuses.",
        )
        parser.add_argument(
            "--until",
            help="Date (timestamp) until which the objects must be checked. "
            "If pending is set to True and until is not specified, until will "
            "default to a timestamp representing the current date (timestamp) "
            "minus 48 hours.",
        )
        parser.add_argument(
            "--kafka-max-lags",
            type=int,
            default=1000000,
            help=(
                "Maximum lag allowed by kafka topics "
                f"{DEFAULT_REPLICATION_TOPIC} and "
                f"{DEFAULT_REPLICATION_DELAYED_TOPIC} (<0 to disable). "
                "(default=1000000)"
            ),
        )
        parser.add_argument(
            "--kafka-min-available-space",
            type=int,
            default=40,
            help=(
                "Minimal available space allowed for kafka cluster in percent "
                "(<0 to disable). (default=40)"
            ),
        )
        parser.add_argument(
            "--do-not-use-marker",
            action="store_true",
            help="Use this option to disable the marker usage.",
        )
        parser.add_argument(
            "--marker-update-after",
            type=int,
            default=1000,
            help="Number of messages sent before marker update. (default=1000)",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Display actions but do nothing",
        )
        parser.add_argument(
            "--max-messages",
            type=int,
            default=-1,
            help="Stop when the number of messages reaches this limit."
            "(default=-1) all events",
        )
        return parser

    def _clean_exit(self, account, bucket, *args):
        """Exit the tool"""
        if self.kafka_producer is not None:
            nb_msg = self.kafka_producer.flush(1.0)
            if nb_msg > 0:
                self.log.warning(
                    "All events are not flushed. %d are still in queue", nb_msg
                )
            # Close the producer
            self.kafka_producer.close()
        self.log.info("Replication recovery exiting.")
        self.log.info(
            "account=%s bucket=%s nb_objects_recovered=%d "
            "nb_delete_markers_recovered=%d",
            account,
            bucket,
            self.nb_objects_recovered,
            self.nb_delete_markers_recovered,
        )

    def _get_marker_file_path(self, operation, account, bucket):
        """Return the path to the appropriate marker file"""
        cache_dirs = (str(Path.home()) + "/.oio/sds", "/var/cache")
        marker_file_name = (
            f"replication_recovery_marker_{operation}_{account}_{bucket}.json"
        )
        parent_dir = None
        for dir_path in cache_dirs:
            if os.path.exists(dir_path):
                try:
                    os.makedirs(f"{dir_path}/replicationrecovery", exist_ok=True)
                    parent_dir = dir_path
                    break
                except OSError as err:
                    self.log.error(
                        "Failed to create marker directory in %s: %s",
                        dir_path,
                        err,
                    )
        else:
            self.log.error("Failed to build marker file path")
            return None
        return f"{parent_dir}/replicationrecovery/{marker_file_name}"

    def flush_and_update_marker(self, account, bucket, obj):
        """
        Flush the events pending in the producer, then update the marker file.
        """
        nb_msg = 0
        if self.kafka_producer:
            nb_msg = self.kafka_producer.flush(1.0)
            attempt = 0
            while nb_msg > 0 and attempt < 3:
                self.log.warning(
                    "All events are not flushed. %d are still in queue", nb_msg
                )
                nb_msg = self.kafka_producer.flush(1.0)
                # Wait little bit
                time.sleep(0.1)
                attempt += 1
        if nb_msg <= 0:
            # Update the marker only if we were able to send the events
            self.update_marker_file(obj["name"], bucket, account)

    def update_marker_file(self, obj_name, bucket, account):
        """Update the marker file with the latest listed object in the bucket."""
        try:
            # Load existing data if the marker file exists
            if os.path.exists(self.marker_file):
                with open(self.marker_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
            else:
                data = {}

            # Update the marker file
            data[str((account, bucket))] = obj_name
            with open(self.marker_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
            self.log.debug(f"Marker file updated: ({account}, {bucket}) -> {obj_name}")
        except Exception as err:
            self.log.warning(
                f"Error while updating marker file {self.marker_file}: {err}"
            )

    def take_action(self, parsed_args):
        bucket = parsed_args.bucket
        pending = parsed_args.pending
        only_metadata = parsed_args.only_metadata
        # invert the condition for readability
        use_marker = not parsed_args.do_not_use_marker
        marker_update_after = parsed_args.marker_update_after
        if not (pending or only_metadata or parsed_args.all):
            # When no option is defined, use pending by default
            pending = True
        until = int(parsed_args.until) * 1000000 if parsed_args.until else None
        if pending and not until:
            # List only objects having PENDING status and created more than 48 hours ago
            until = (
                int(datetime.timestamp(datetime.now() - timedelta(hours=48))) * 1000000
            )
        dry_run = parsed_args.dry_run
        broker_endpoints = self.app.client_manager.sds_conf.get("event-agent", "")
        namespace = self.app.options.ns
        conf = {
            "namespace": namespace,
            "broker_endpoint": broker_endpoints,
        }
        max_messages = parsed_args.max_messages
        self.success = True
        self.log = self.app.client_manager.logger
        self.kafka_cluster_health = KafkaClusterHealth(
            {
                "namespace": namespace,
                "topics": ",".join(
                    (DEFAULT_REPLICATION_TOPIC, DEFAULT_REPLICATION_DELAYED_TOPIC)
                ),
                "max_lag": parsed_args.kafka_max_lags,
                "min_available_space": parsed_args.kafka_min_available_space,
            },
            pool_manager=self.app.client_manager.storage.container.pool_manager,
        )
        account = self.app.client_manager.storage.bucket.bucket_get_owner(bucket)
        signal.signal(signal.SIGTERM, partial(self._clean_exit, account, bucket))
        if pending:
            operation = "pending"
        elif only_metadata:
            operation = "metadata"
        else:
            operation = "all"
        self.marker_file = self._get_marker_file_path(operation, account, bucket)
        marker = None
        use_marker = use_marker and self.marker_file
        if use_marker:
            if os.path.exists(self.marker_file):
                with open(self.marker_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    marker = data.get(str((account, bucket)))

        replication_conf = self._load_replication_configuration(account, bucket)
        self.log.info("Scan bucket %s in account %s", bucket, account)
        objects_to_replicate = self.get_objects_to_replicate(
            account,
            bucket,
            pending,
            until,
            only_metadata,
            replication_conf,
            marker=marker,
        )
        event_type = (
            EventTypes.CONTENT_UPDATE if only_metadata else EventTypes.CONTENT_NEW
        )
        obj = None
        counter = 0
        total_messages = 0
        try:
            for obj, destinations, role, is_delete_marker in objects_to_replicate:
                object_event = object_to_event(
                    obj,
                    destinations,
                    role,
                    namespace,
                    account,
                    bucket,
                    event_type,
                    "s3-replication-recovery",
                )
                self.send_event(
                    conf,
                    obj,
                    destinations,
                    object_event,
                    dry_run,
                    is_delete_marker,
                )
                counter += 1
                total_messages += 1
                if max_messages > 0 and total_messages >= max_messages:
                    if use_marker and self.success:
                        self.flush_and_update_marker(account, bucket, obj)
                    break
                if use_marker and counter >= marker_update_after and self.success:
                    self.flush_and_update_marker(account, bucket, obj)
                    # Reinitialize the counter
                    counter = 0
        except KeyboardInterrupt:  # Catches CTRL+C or SIGINT
            if use_marker and obj and self.success:
                # If the latest listed object is defined
                # and we were always able to send event
                self.update_marker_file(obj["name"], bucket, account)
        else:
            if use_marker:
                try:  # Remove the marker file
                    if os.path.exists(self.marker_file):
                        os.remove(self.marker_file)
                        self.log.debug(f"Marker file {self.marker_file} removed")
                except Exception as err:
                    self.log.error(
                        f"Failed to remove marker file: {self.marker_file}: {err}"
                    )
        self._clean_exit(account, bucket)
