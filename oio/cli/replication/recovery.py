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
import re
import signal
import time
from collections import OrderedDict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Generator, List, Tuple

import xmltodict

from oio.cli import Command
from oio.common.constants import (
    OBJECT_REPLICATION_COMPLETED,
    OBJECT_REPLICATION_PENDING,
    OBJECT_REPLICATION_REPLICA,
)
from oio.common.kafka import DEFAULT_REPLICATION_TOPIC, KafkaSender
from oio.common.utils import cid_from_name, depaginate, request_id
from oio.event.evob import EventTypes

OBJECT_TRANSIENT_SYSMETA_PREFIX = "x-object-transient-sysmeta-"
REPLICATION_ROLE_RE = re.compile(r"arn:aws:iam::([a-zA-Z0-9]+):role/([a-zA-Z0-9\_-]+)")


def _tagging_obj_to_dict(tag_obj: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Transform a Tagging object structure (parsed from an XML document)
    to a dictionary of lists (there may be multiple values for the same tag
    key).
    """
    tagset = tag_obj["Tagging"]["TagSet"]
    if not isinstance(tagset["Tag"], list):
        tagset["Tag"] = [tagset["Tag"]]
    tags: Dict[str, List[str]] = {}
    for tag in tagset["Tag"]:
        tags.setdefault(tag["Key"], []).append(tag["Value"])
    return tags


def _match_prefix_criteria(rule: Dict[str, Any], key: str) -> Tuple[bool, bool]:
    if "Prefix" in rule:
        # For backward compatibility
        prefix = rule.get("Prefix", "")
        return key.startswith(prefix), False

    filter = rule.get("Filter", {})
    if not filter:
        return True, False
    prefix = filter.get("Prefix")
    if prefix is not None:
        return key.startswith(prefix), False
    and_filter = filter.get("And", {})
    prefix = and_filter.get("Prefix", "")
    return key.startswith(prefix), True


def _get_tags_criteria(rule: Dict[str, Any]) -> List[Dict[str, str]]:
    filter = rule.get("Filter", {})
    tag = filter.get("Tag")
    if tag is not None:
        return [tag]
    and_filter = filter.get("And", {})
    return and_filter.get("Tags", [])


def _replicate_deletion_marker_enabled(rule: Dict[str, Any]) -> bool:
    config = rule.get("DeleteMarkerReplication", {})
    status = config.get("Status", "Disabled")
    return status == "Enabled"


def _object_matches(
    rule: Dict[str, Any],
    key: str,
    obj_tags: Dict[str, List[str]] = {},
    is_delete: bool = False,
):
    """
    Check if an object matches the filters of the specified replication rule.
    :return : Tuple(match, continue)
    """
    match, check_tags = _match_prefix_criteria(rule, key)
    if not match:
        return False, True

    if check_tags:
        exp_tags = _get_tags_criteria(rule)
        for tag in exp_tags:
            exp_key = tag.get("Key")
            exp_val = tag.get("Value")
            obj_tag_value = obj_tags.get(exp_key, [])
            if exp_val not in obj_tag_value:
                return False, True
    # Rule match, deal with deletion marker
    if is_delete and not _replicate_deletion_marker_enabled(rule):
        return False, False

    return True, False


def get_replication_destinations(
    configuration: str,
    key: str,
    metadata: Dict[str, str] = {},
    xml_tags: str = None,
    is_deletion: bool = False,
    ensure_replicated: bool = False,
) -> Tuple[List[str], str]:
    """
    Compute the replication destinations for an object according to its
    metadata
    :param configuration: async replication configuration
    :param key: object key
    :param metadata: object metadata
    :param xml_tags: object tags if any
    :param is_deletion: indicate if the object is being delete
    :param ensure_replicated: indicated the object must have been
    replicated. (Used for metadata updates)
    :returns: List of destination buckets the object must be replicated to
                and role
    """
    if not configuration:
        return [], None

    # Ensure we are not dealing with a replica
    replication_status = metadata.get("s3api-replication-status", "")
    if replication_status == OBJECT_REPLICATION_REPLICA:
        return [], None

    # Ensure we are dealing with an already replicated object if required
    if ensure_replicated and not replication_status:
        return [], None

    conf = json.loads(configuration)
    category = "deletions" if is_deletion else "replications"
    rules_per_destination = conf.get(category, {})

    # Retrieve object tags if required
    tags = {}
    if conf.get("use_tags", False):
        if not xml_tags:
            xml_tags = metadata.get("s3api-tagging")

        tags = _tagging_obj_to_dict(xmltodict.parse(xml_tags)) if xml_tags else {}

    dest_buckets = []
    ruleset = conf.get("rules", {})
    for destination, rules in rules_per_destination.items():
        for rule_name in rules:
            rule = ruleset.get(rule_name)
            if not rule:
                continue
            r_match, r_continue = _object_matches(rule, key, tags, is_deletion)
            if r_match:
                dest_buckets.append(destination)
            if not r_continue:
                break
    role = conf.get("role")
    return dest_buckets, role


class ReplicationRecovery(Command):
    """Send new events to replicate objects not yet replicated."""

    log = None
    kafka_producer = None
    marker_file = None

    def _load_replication_configuration(self, account, bucket) -> None:
        info = self.app.client_manager.storage.container_get_properties(account, bucket)
        replication_conf = info.get("properties", {}).get(
            "X-Container-Sysmeta-S3Api-Replication"
        )
        return replication_conf

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
            is_delete_marker = obj["deleted"]

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
                        if key_metadata.startswith(OBJECT_TRANSIENT_SYSMETA_PREFIX):
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
            if until and obj["version"] > until:
                continue

            dest_buckets, role = get_replication_destinations(
                replication_conf,
                key,
                metadata=metadata,
                is_deletion=is_delete_marker,
            )
            dest_buckets = [
                dest[13:] if dest.startswith("arn:aws:s3:::") else dest
                for dest in dest_buckets
            ]
            if not dest_buckets:
                if pending:
                    self.log.error(
                        "No destination for the pending %s %s (%d)",
                        "delete marker" if obj["deleted"] else "object",
                        key,
                        obj["version"],
                    )
                    self.success = False
                continue
            yield obj, dest_buckets, role

    def object_to_event(
        self,
        obj: Dict[str, Any],
        dest_buckets: List[str],
        role: str,
        namespace: str,
        account: str,
        bucket: str,
        event_type: str,
    ) -> Dict[str, Any]:
        match = REPLICATION_ROLE_RE.fullmatch(role)
        src_project_id = match.group(1)
        replicator_id = match.group(2)
        event: Dict[str, Any] = {}
        event["event"] = event_type
        event["when"] = int(time.time() * 1000000)  # use time in micro seconds
        event["url"] = {}
        event["url"]["ns"] = namespace
        event["url"]["account"] = account
        event["url"]["user"] = bucket
        event["url"]["id"] = cid_from_name(account, bucket)
        event["url"]["path"] = obj["name"]
        event["url"]["content"] = obj["content"]
        event["url"]["version"] = obj["version"]
        event["request_id"] = request_id()
        event["origin"] = "s3-replication-recovery"
        event["part"] = 0
        event["parts"] = 1
        event["data"] = []
        event["data"].append(
            {
                "type": "aliases",
                "name": obj["name"],
                "version": obj["version"],
                "ctime": obj["ctime"],
                "mtime": obj["mtime"],
                "deleted": obj["deleted"],
                "header": obj["content"],
            }
        )
        if not obj["deleted"]:  # Not a delete marker
            event["data"].append(
                {
                    "type": "contents_headers",
                    "id": obj["id"],
                    "hash": obj["hash"],
                    "size": obj["size"],
                    "policy": obj["policy"],
                    "chunk-method": obj["chunk_method"],
                    "mime-type": obj["mime_type"],
                }
            )
            properties = OrderedDict(obj["properties"].items())
            for prop in properties:
                if not prop.startswith(OBJECT_TRANSIENT_SYSMETA_PREFIX):
                    value = obj["properties"].get(prop)
                    event["data"].append(
                        {
                            "type": "properties",
                            "alias": obj["name"],
                            "version": obj["version"],
                            "key": prop,
                            "value": value,
                        }
                    )
        event["repli"] = {}
        event["repli"]["destinations"] = ";".join(dest_buckets)
        event["repli"]["replicator_id"] = replicator_id
        event["repli"]["src_project_id"] = src_project_id
        if (
            not obj["deleted"]
            and "x-object-sysmeta-s3api-acl" in obj["properties"]
            and event["event"] == EventTypes.CONTENT_UPDATE
        ):
            event["repli"]["x-object-sysmeta-s3api-acl"] = obj["properties"].get(
                "x-object-sysmeta-s3api-acl"
            )
        return event

    def send_event(
        self,
        conf: Dict[str, Any],
        obj: Dict[str, Any],
        dest_buckets: List[str],
        event: Dict[str, Any],
        dry_run: bool,
        kafka_conf: Dict[str, Any],
    ):
        log = self.log.info if dry_run else self.log.debug
        log(
            "Sending event to replicate object %s (%d) to %s",
            obj["name"],
            obj["version"],
            dest_buckets,
        )
        if not dry_run:
            if self.kafka_producer is None:
                self.kafka_producer = KafkaSender(
                    conf.get("broker_endpoint"),
                    self.log,
                    app_conf=conf,
                    kafka_conf=kafka_conf,
                )
            try:
                self.kafka_producer.send(DEFAULT_REPLICATION_TOPIC, event)
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
            help="Resend only events from objects pending to be replicated.",
        )
        group.add_argument(
            "--only-metadata",
            action="store_true",
            help="Resend only events from objects with metadatata to be replicated",
        )
        group.add_argument(
            "--all",
            action="store_true",
            help="Resend events from all objects",
        )
        parser.add_argument(
            "--until",
            help="Date (timestamp) until which the objects must be checked. "
            "If pending is set to True and until is not specified, until will "
            "default to a timestamp representing the current date (timestamp) "
            "minus 48 hours.",
        )
        parser.add_argument(
            "--batch-num-messages",
            type=int,
            default=1000,
            help="Maximum number of messages in a single batch. (default=1000)",
        )
        parser.add_argument(
            "--linger-ms",
            type=int,
            default=1000,
            help="Artificial delay in ms to wait before sending each batch of events. "
            "(default=1000)",
        )
        parser.add_argument(
            "--use-marker",
            choices=["0", "1", "2"],
            default="0",
            help="""
            Indicate whether or not maker is to be considered:
            0: Execute the command but stop the process if marker found.
               If marker exists, only option 1 or 2 are accepted.
            1: enable use of maker
            2: bypass marker
            (default=0)
            """,
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
        return parser

    def _clean_exit(self, *args):
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
                    self.log.warning(
                        "Failed to create marker directory in %s: %s",
                        dir_path,
                        err,
                    )
        else:
            self.log.warning("Failed to build marker file path")
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
        signal.signal(signal.SIGTERM, self._clean_exit)
        bucket = parsed_args.bucket
        pending = parsed_args.pending
        only_metadata = parsed_args.only_metadata
        use_marker = parsed_args.use_marker
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
        # Maximum number of message in a single batch
        batch_num_messages = parsed_args.batch_num_messages
        # Time to wait before sending events in a batch
        linger_ms = parsed_args.linger_ms
        kafka_conf = {
            "batch.num.messages": batch_num_messages,
            "linger.ms": linger_ms,
        }
        self.success = True
        self.log = self.app.client_manager.logger
        account = self.app.client_manager.storage.bucket.bucket_get_owner(bucket)
        if pending:
            operation = "pending"
        elif only_metadata:
            operation = "metadata"
        else:
            operation = "all"
        self.marker_file = self._get_marker_file_path(operation, account, bucket)
        marker = None
        if self.marker_file:
            if os.path.exists(self.marker_file):
                with open(self.marker_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    marker = data.get(str((account, bucket)))
        if marker:
            if use_marker == "0":
                raise ValueError(
                    f"Use-maker option must be set to 1 or 2 "
                    f"if a marker is found: marker={marker}"
                )
            elif use_marker == "2":
                # Start from the beginning
                marker = None

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
        try:
            for obj, dest_buckets, role in objects_to_replicate:
                object_event = self.object_to_event(
                    obj, dest_buckets, role, namespace, account, bucket, event_type
                )
                self.send_event(
                    conf, obj, dest_buckets, object_event, dry_run, kafka_conf
                )
                counter += 1
                if counter == marker_update_after and self.success:
                    self.flush_and_update_marker(account, bucket, obj)
                    # Reinitialize the counter
                    counter = 0
        except KeyboardInterrupt:  # Catches CTRL+C or SIGINT
            if obj and self.success:
                # If the latest listed object is defined
                # and we were always able to send event
                self.update_marker_file(obj["name"], bucket, account)
        else:
            if marker:
                try:  # Remove the marker file
                    os.remove(self.marker_file)
                    self.log.info(f"Marker file {self.marker_file} removed")
                except Exception as err:
                    self.log.error(
                        f"Failed to remove marker file: {self.marker_file}: {err}"
                    )
        self._clean_exit()
