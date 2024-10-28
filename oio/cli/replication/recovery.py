#!/usr/bin/env python
# Copyright (C) 2024 OVH SAS
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

from collections import OrderedDict
import json
import re
import time
from typing import Any, Dict, Generator, List, Tuple
import xmltodict

from oio.cli import Command
from oio.common.kafka import DEFAULT_REPLICATION_TOPIC, KafkaSender
from oio.common.utils import cid_from_name, depaginate, request_id
from oio.event.evob import EventTypes


OBJECT_REPLICATION_PENDING = "PENDING"
OBJECT_REPLICATION_REPLICA = "REPLICA"
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
    configuration: Dict[str, Any],
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

    configuration = json.loads(configuration)
    category = "deletions" if is_deletion else "replications"
    rules_per_destination = configuration.get(category, {})

    # Retrieve object tags if required
    tags = {}
    if configuration.get("use_tags", False):
        if not xml_tags:
            xml_tags = metadata.get("s3api-tagging")

        tags = _tagging_obj_to_dict(xmltodict.parse(xml_tags)) if xml_tags else {}

    dest_buckets = []
    ruleset = configuration.get("rules", {})
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
    role = configuration.get("role")
    return dest_buckets, role


class ReplicationRecovery(Command):
    """Send new events to replicate objects not yet replicated."""

    log = None
    kafka_producer = None

    def _load_replication_configuration(self, account, bucket) -> None:
        info = self.app.client_manager.storage.container_get_properties(account, bucket)
        replication_conf = info.get("properties", {}).get(
            "X-Container-Sysmeta-S3Api-Replication"
        )
        return replication_conf

    def get_objects_to_replicate(
        self, account, bucket, pending, until, replication_conf
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
            dest_buckets = [dest.lstrip("arn:aws:s3:::") for dest in dest_buckets]
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
    ) -> Dict[str, Any]:
        match = REPLICATION_ROLE_RE.fullmatch(role)
        src_project_id = match.group(1)
        replicator_id = match.group(2)
        event = {}
        event["event"] = EventTypes.CONTENT_NEW
        event["when"] = time.time()
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
        return json.dumps(event)

    def send_event(
        self,
        conf: Dict[str, Any],
        obj: Dict[str, Any],
        dest_buckets: List[str],
        event: Dict[str, Any],
        dry_run: bool,
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
                )
            try:
                self.kafka_producer.send(DEFAULT_REPLICATION_TOPIC, event, flush=True)
            except Exception as exc:
                self.log.warning("Fail to send replication event %s: %s", event, exc)
                self.success = False

    def get_parser(self, prog_name):
        parser = super(ReplicationRecovery, self).get_parser(prog_name)
        parser.add_argument("bucket", help="Name of bucket to scan")
        parser.add_argument(
            "--pending",
            action="store_true",
            help="Resend only events from objects pending to be replicated.",
        )
        parser.add_argument(
            "--until",
            help="Date (timestamp) until which the objects must be checked",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Display actions but do nothing.",
        )
        return parser

    def take_action(self, parsed_args):
        bucket = parsed_args.bucket
        pending = parsed_args.pending
        until = int(parsed_args.until) * 1000000 if parsed_args.until else None
        dry_run = parsed_args.dry_run
        broker_endpoints = self.app.client_manager.sds_conf.get("event-agent", "")
        namespace = self.app.options.ns
        conf = {
            "namespace": namespace,
            "broker_endpoint": broker_endpoints,
        }
        self.success = True
        self.log = self.app.client_manager.logger
        account = self.app.client_manager.storage.bucket.bucket_get_owner(bucket)

        replication_conf = self._load_replication_configuration(account, bucket)
        self.log.info("Scan bucket %s in account %s", bucket, account)
        objects_to_replicate = self.get_objects_to_replicate(
            account, bucket, pending, until, replication_conf
        )
        for obj, dest_buckets, role in objects_to_replicate:
            object_event = self.object_to_event(
                obj, dest_buckets, role, namespace, account, bucket
            )
            self.send_event(conf, obj, dest_buckets, object_event, dry_run)
        if self.kafka_producer is not None:
            # Close the producer
            self.kafka_producer.close()
