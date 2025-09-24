# Copyright (C) 2025 OVH SAS
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
import re
import time
from collections import OrderedDict
from typing import Any, Dict, List, Tuple

import xmltodict

from oio.common.constants import OBJECT_REPLICATION_REPLICA
from oio.common.encryption import TRANSIENT_SYSMETA_PREFIX
from oio.common.utils import cid_from_name, request_id
from oio.event.evob import EventTypes

ARN_AWS_PREFIX = "arn:aws:"
DEST_BUCKET_PREFIX = ARN_AWS_PREFIX + "s3:::"

DEFAULT_USE_STORAGE_CLASS = False
DEFAULT_DELETE_MARKER_REPLICATION_VALUE = "Disabled"

REPLICATION_ROLE_RE = re.compile(r"arn:aws:iam::([a-zA-Z0-9]+):role/([a-zA-Z0-9\_-]+)")


def optimize_replication_conf(configuration):
    if isinstance(configuration, str):
        configuration = json.loads(configuration)

    rules = {}
    replications = {}
    deletions = {}
    use_tags_all_rules = False
    dest_priorities = {}

    for rule in configuration["Rules"]:
        rule_id = rule["ID"]
        rules[rule_id] = rule
        if rule["Status"] != "Enabled":
            continue

        destination = rule["Destination"]
        bucket = destination["Bucket"]
        priority = rule.get("Priority", -1)
        dest_rules = replications.setdefault(bucket, [])
        status_delete_marker = rule.get("DeleteMarkerReplication", {}).get(
            "Status", DEFAULT_DELETE_MARKER_REPLICATION_VALUE
        )
        deletion_marker = status_delete_marker == "Enabled"
        dest_rules.append((rule_id, priority, deletion_marker))

        rule_filter = rule.get("Filter", {})
        and_filter = rule_filter.get("And", {})
        use_tags = "Tag" in rule_filter or "Tags" in and_filter
        use_tags_all_rules |= use_tags

        if deletion_marker and use_tags:
            raise ValueError(
                "Delete marker replication is not supported "
                "if any Tag filter is specified. Please refer to S3 Developer "
                "Guide for more information."
            )

        # Ensure all priorities are unique
        priorities = dest_priorities.setdefault(bucket, set())
        if priority >= 0:
            if priority in priorities:
                raise ValueError(f"Found duplicate priority {priority}.")
            priorities.add(priority)

    for dest, dest_rules in replications.items():
        # sort rules per priority
        dest_rules.sort(key=lambda rule: rule[1], reverse=True)

        # Get all rules until the last one enabling delete marker replication
        for idx, rule in reversed(list(enumerate(dest_rules))):
            if rule[2]:
                deletions[dest] = [r[0] for r in dest_rules[: idx + 1]]
                break

        replications[dest] = [r[0] for r in dest_rules]

    optimized = {
        "role": configuration["Role"],
        "rules": rules,
        "replications": replications,
        "deletions": deletions,
        "use_tags": use_tags_all_rules,
        "use_storage_class": configuration.get(
            "UseStorageClass", DEFAULT_USE_STORAGE_CLASS
        ),
    }

    return optimized


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


def get_destination_for_object(
    configuration: str,
    key: str,
    metadata: Dict[str, str] = {},
    xml_tags: str = None,
    is_deletion: bool = False,
    ensure_replicated: bool = False,
) -> Tuple[str, str]:
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
    :returns: String representing the list of destination buckets
              the object must be replicated (";" separated) to and the role
    """
    if not configuration:
        return None, None

    # Ensure we are not dealing with a replica
    replication_status = metadata.get("s3api-replication-status", "")
    if replication_status == OBJECT_REPLICATION_REPLICA:
        return None, None

    # Ensure we are dealing with an already replicated object if required
    if ensure_replicated and not replication_status:
        return None, None

    if isinstance(configuration, str):
        configuration = json.loads(configuration)
    category = "deletions" if is_deletion else "replications"
    rules_per_destination = configuration.get(category, {})

    # Retrieve object tags if required
    tags = {}
    if configuration.get("use_tags", False):
        if not xml_tags:
            xml_tags = metadata.get("s3api-tagging")

        tags = _tagging_obj_to_dict(xmltodict.parse(xml_tags)) if xml_tags else {}

    destinations = None
    ruleset = configuration.get("rules", {})
    for destination, rules in rules_per_destination.items():
        for rule_name in rules:
            rule = ruleset.get(rule_name)
            if not rule:
                continue
            r_match, r_continue = _object_matches(rule, key, tags, is_deletion)
            if r_match:
                # Remove 'arn:aws:s3:::' prefix from bucket name
                if destination.startswith(DEST_BUCKET_PREFIX):
                    destination = destination[len(DEST_BUCKET_PREFIX) :]
                # Add storage class to the destination
                storage_class = rule["Destination"].get("StorageClass")
                if storage_class:
                    destination = f"{destination}:{storage_class}"

                if not destinations:
                    destinations = destination  # first element of the list
                else:
                    destinations = f"{destinations};{destination}"
            if not r_continue:
                break
    return destinations, configuration.get("role")


def object_to_event(
    obj: Dict[str, Any],
    destinations: str,
    role: str,
    namespace: str,
    account: str,
    bucket: str,
    event_type: str,
    origin: str,
    reqid: str | None = None,
) -> Dict[str, Any]:
    """
    Create an event as a dict from an object to replicate it through s3-replicator.

    :param obj: as a dict coming from an get_properties or a listing
    :param destinations: str representing the list of destinations (";" separated)
    :param role: the role coming from the customer replication configuration
    :param namespace: src namespace
    :param account: src account
    :param bucket: src bucket
    :param event_type: either a new or update content event
    :return: a dict representing the event for replication.
    """
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
    event["url"]["content"] = obj["id"]
    event["url"]["version"] = obj["version"]
    event["request_id"] = reqid if reqid else request_id("repli-")
    event["origin"] = origin
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
            "header": obj["id"],
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
        properties = OrderedDict(obj.get("properties", {}).items())
        for prop in properties:
            if not prop.startswith(TRANSIENT_SYSMETA_PREFIX):
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
    event["repli"]["destinations"] = destinations
    event["repli"]["replicator_id"] = replicator_id
    event["repli"]["src_project_id"] = src_project_id
    if (
        not obj["deleted"]
        and "x-object-sysmeta-s3api-acl" in obj.get("properties", {})
        and event["event"] == EventTypes.CONTENT_UPDATE
    ):
        event["repli"]["x-object-sysmeta-s3api-acl"] = obj.get("properties", {}).get(
            "x-object-sysmeta-s3api-acl"
        )
    return event
