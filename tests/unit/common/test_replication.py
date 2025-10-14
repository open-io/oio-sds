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

import unittest

from oio.common.constants import OBJECT_REPLICATION_REPLICA
from oio.common.replication import get_destination_for_object, optimize_replication_conf


class ReplicationTest(unittest.TestCase):
    TAGGING_BODY = """
        <Tagging>
          <TagSet>
            <Tag>
              <Key>key1</Key>
              <Value>value1</Value>
            </Tag>
            <Tag>
              <Key>key2</Key>
              <Value>value2</Value>
            </Tag>
          </TagSet>
        </Tagging>
    """
    TAGGING_BODY_ONE_TAG = """
        <Tagging>
          <TagSet>
            <Tag>
              <Key>key1</Key>
              <Value>value1</Value>
            </Tag>
          </TagSet>
        </Tagging>
    """

    def test_optimize_configuration(self):
        conf = {
            "Role": "arn:aws:iam::012345678942:role/s3-replication",
            "Rules": [
                {
                    "ID": "rule1",
                    "Status": "Enabled",
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                    "Filter": {
                        "And": {
                            "Prefix": "string",
                            "Tags": [
                                {"Key": "string", "Value": "string"},
                                {"Key": "string", "Value": "string"},
                            ],
                        },
                    },
                    "Destination": {"Bucket": "arn:aws:s3:::bucket1"},
                },
                {
                    "ID": "rule2",
                    "Priority": 4,
                    "Status": "Enabled",
                    "DeleteMarkerReplication": {"Status": "Enabled"},
                    "Filter": {
                        "Prefix": "string",
                    },
                    "Destination": {"Bucket": "arn:aws:s3:::bucket1"},
                },
                {
                    "ID": "rule3",
                    "Status": "Disabled",
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                    "Filter": {
                        "Tag": {"Key": "key", "Value": "value"},
                    },
                    "Destination": {"Bucket": "arn:aws:s3:::bucket2"},
                },
                {
                    "ID": "rule4",
                    "Status": "Enabled",
                    "Priority": 42,
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                    "Filter": {
                        "And": {
                            "Prefix": "string",
                            "Tags": [
                                {"Key": "string", "Value": "string"},
                                {"Key": "string", "Value": "string"},
                            ],
                        },
                    },
                    "Destination": {"Bucket": "arn:aws:s3:::bucket1"},
                },
            ],
            "UseStorageClass": False,
        }
        optimized = optimize_replication_conf(conf)
        self.assertIn("role", optimized)
        self.assertEqual(
            optimized["role"], "arn:aws:iam::012345678942:role/s3-replication"
        )
        self.assertIn("replications", optimized)
        self.assertEqual(
            optimized["replications"],
            {"arn:aws:s3:::bucket1": ["rule4", "rule2", "rule1"]},
        )
        self.assertIn("deletions", optimized)
        self.assertEqual(
            optimized["deletions"], {"arn:aws:s3:::bucket1": ["rule4", "rule2"]}
        )
        self.assertIn("use_tags", optimized)
        self.assertEqual(optimized["use_tags"], True)
        self.assertEqual(optimized["use_storage_class"], False)

    def test_get_destination_for_object_no_conf(self):
        dests = get_destination_for_object({}, "test_key", {})
        self.assertCountEqual(dests, (None, None))

    def test_get_destination_for_object_replications(self):
        rules = """
        {
            "role": "role1",
            "rules": {
                "rule1": {
                    "ID": "rule1",
                    "Status": "Enabled",
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                    "Filter": {
                        "Prefix": "/test/"
                    },
                    "Destination": {"Bucket": "arn:aws:s3:::bucket2"}
                },
                "rule2": {
                    "ID": "rule2",
                    "Priority": 10,
                    "Status": "Enabled",
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                    "Filter": {
                        "Prefix": "/test"
                    },
                    "Destination": {"Bucket": "arn:aws:s3:::bucket1"}
                },
                "rule3": {
                    "ID": "rule3",
                    "Status": "Enabled",
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                    "Filter": {
                        "Tag": {"Key": "key1", "Value": "value1"}
                    },
                    "Destination": {"Bucket": "arn:aws:s3:::bucket2"}
                },
                "rule4": {
                    "ID": "rule4",
                    "Status": "Enabled",
                    "DeleteMarkerReplication": {"Status": "Enabled"},
                    "Filter": {
                        "And": {
                            "Prefix": "/test1/",
                            "Tags": [
                                {"Key": "key1", "Value": "value1"},
                                {"Key": "key2", "Value": "value2"}
                            ]
                        }
                    },
                    "Destination": {"Bucket": "arn:aws:s3:::bucket1"}
                },
                "rule5": {
                    "ID": "rule5",
                    "Status": "Enabled",
                    "DeleteMarkerReplication": {"Status": "Enabled"},
                    "Filter": {
                        "And": {
                            "Prefix": "/test3/",
                            "Tags": [
                                {"Key": "key1", "Value": "value1"},
                                {"Key": "key2", "Value": "value2"}
                            ]
                        }
                    },
                    "Destination": {"Bucket": "arn:aws:s3:::bucket3"}
                }
            },
            "replications": {
                "bucket1": ["rule2", "rule4"],
                "bucket2": ["rule1", "rule3"],
                "bucket3": ["rule5"]
            },
            "deletions": {
                "bucket1": ["rule2", "rule4"],
                "bucket3": ["rule5"]
            },
            "use_tags": true
        }
        """
        # Match prefix "/test/"
        dests = get_destination_for_object(rules, "/test/key")
        self.assertEqual(dests, ("bucket1;bucket2", "role1"))

        # Match no rules
        dests = get_destination_for_object(rules, "/tes/key")
        self.assertEqual(dests, (None, "role1"))

        # Match no rule for deletion
        dests = get_destination_for_object(rules, "/test/key", is_deletion=True)
        self.assertEqual(dests, (None, "role1"))

        # Match rule with tags
        dests = get_destination_for_object(
            rules, "key", metadata={"s3api-tagging": self.TAGGING_BODY}
        )
        self.assertEqual(dests, ("bucket2", "role1"))

        # Match rule with tags for deletion but higher priority rule has
        # deletion marker replication disabled
        dests = get_destination_for_object(
            rules,
            "/test1/key",
            metadata={"s3api-tagging": self.TAGGING_BODY},
            is_deletion=True,
        )
        self.assertEqual(dests, (None, "role1"))

        # Match rule with tags for deletion
        dests = get_destination_for_object(
            rules,
            "/test3/key",
            metadata={"s3api-tagging": self.TAGGING_BODY},
            is_deletion=True,
        )
        self.assertEqual(dests, ("bucket3", "role1"))

        # Match prefix "/test/" but is a replica
        dests = get_destination_for_object(
            rules,
            "/test/key",
            metadata={"s3api-replication-status": OBJECT_REPLICATION_REPLICA},
        )
        self.assertEqual(dests, (None, None))

    def test_get_destination_for_object_deletemarker_one_tag_only(self):
        rules = """
        {
            "role": "role1",
            "rules": {
                "rule5": {
                    "ID": "rule5",
                    "Status": "Enabled",
                    "DeleteMarkerReplication": {"Status": "Enabled"},
                    "Filter": {
                        "And": {
                            "Prefix": "/test3/",
                            "Tags": [
                                {"Key": "key1", "Value": "value1"},
                                {"Key": "key2", "Value": "value2"}
                            ]
                        }
                    },
                    "Destination": {"Bucket": "arn:aws:s3:::bucket3"}
                }
            },
            "replications": {
                "bucket3": ["rule5"]
            },
            "deletions": {
                "bucket3": ["rule5"]
            },
            "use_tags": true
        }
        """
        # This test is the same as in the method above, except that the
        # tagging document lack one expected tag.
        dests = get_destination_for_object(
            rules,
            "/test3/key",
            metadata={"s3api-tagging": self.TAGGING_BODY_ONE_TAG},
            is_deletion=True,
        )
        self.assertEqual(dests, (None, "role1"))
