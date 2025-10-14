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

import xmltodict

from oio.common.constants import OBJECT_REPLICATION_REPLICA

ARN_AWS_PREFIX = "arn:aws:"
DEST_BUCKET_PREFIX = ARN_AWS_PREFIX + "s3:::"


def optimize_replication_conf(configuration):
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
        deletion_marker = rule["DeleteMarkerReplication"]["Status"] == "Enabled"
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
        "use_storage_class": configuration["UseStorageClass"],
    }

    return optimized


def _tagging_obj_to_dict(tag_obj: dict) -> dict:
    """
    Transform a Tagging object structure (parsed from an XML document)
    to a dictionary of lists (there may be multiple values for the same tag
    key).
    """
    tagset = tag_obj["Tagging"]["TagSet"]
    if not isinstance(tagset["Tag"], list):
        tagset["Tag"] = [tagset["Tag"]]
    tags: dict = {}
    for tag in tagset["Tag"]:
        tags.setdefault(tag["Key"], []).append(tag["Value"])
    return tags


def _match_prefix_criteria(rule, key):
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


def _get_tags_criteria(rule):
    filter = rule.get("Filter", {})
    tag = filter.get("Tag")
    if tag is not None:
        return [tag]
    and_filter = filter.get("And", {})
    return and_filter.get("Tags", [])


def _replicate_deletion_marker_enabled(rule):
    config = rule.get("DeleteMarkerReplication", {})
    status = config.get("Status", "Disabled")
    return status == "Enabled"


def _object_matches(rule, key, obj_tags={}, is_delete=False):
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
    configuration,
    key,
    metadata={},
    xml_tags=None,
    is_deletion=False,
    ensure_replicated=False,
):
    """
    Compute the replication destinations for an object according to its
    metadata.
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
