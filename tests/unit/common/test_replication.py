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

from oio.common.replication import optimize_replication_conf


class ReplicationTest(unittest.TestCase):
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
