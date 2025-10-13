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
