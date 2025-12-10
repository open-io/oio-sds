# Copyright (C) 2025 OVH SAS
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
import unittest
from unittest.mock import MagicMock as Mock
from unittest.mock import patch

from oio.xcute.jobs import BatchReplicatorJob


class TestBatchReplicator(unittest.TestCase):
    def _prepare_batch_repli_job(self, lines_per_manifest):
        with patch(
            "oio.xcute.jobs.batch_replicator.ObjectStorageApi", new_callable=Mock()
        ), patch(
            "oio.xcute.jobs.batch_replicator.KafkaClusterHealth", new_callable=Mock()
        ):
            batch_repli_job = BatchReplicatorJob({"namespace": "fake"})
            batch_repli_job.api = Mock()

            batch_repli_job.get_manifests = Mock(
                return_value=[{"name": name} for name in lines_per_manifest]
            )

            def object_fetch(account, bucket, manifest_name, reqid=None):
                data_lines = [
                    f"{json.dumps(d)}\n".encode("utf-8")
                    for d in lines_per_manifest[manifest_name]
                ]
                return None, data_lines

            batch_repli_job.api.object_fetch = Mock(side_effect=object_fetch)
            return batch_repli_job

    def test_single_manifest(self):
        lines = [{"a": 1}, {"b": 2}]
        batch_repli_job = self._prepare_batch_repli_job({"manifest_1": lines})

        results = list(
            batch_repli_job.get_tasks(
                {"technical_account": "demo", "technical_bucket": "bucket"},
            )
        )

        expected = [
            ("manifest_1;0", {"a": 1}),
            ("manifest_1;1", {"b": 2}),
        ]
        self.assertEqual(results, expected)

    def test_multiple_manifests(self):
        lines = {
            "manifest_1": [{"a": 1}, {"b": 2}, {"c": 3}],
            "manifest_2": [{"x": 10}, {"y": 20}, {"z": 30}],
        }
        batch_repli_job = self._prepare_batch_repli_job(lines)

        results = list(
            batch_repli_job.get_tasks(
                {"technical_account": "demo", "technical_bucket": "bucket"},
            )
        )

        expected = [
            ("manifest_1;0", {"a": 1}),
            ("manifest_2;0", {"x": 10}),
            ("manifest_1;1", {"b": 2}),
            ("manifest_2;1", {"y": 20}),
            ("manifest_1;2", {"c": 3}),
            ("manifest_2;2", {"z": 30}),
        ]
        self.assertEqual(results, expected)

    def test_multiple_manifest_with_line_marker(self):
        lines = {
            "manifest_1": [{"a": 1}, {"b": 2}, {"c": 3}],
            "manifest_2": [{"x": 10}, {"y": 20}, {"z": 30}],
        }
        batch_repli_job = self._prepare_batch_repli_job(lines)

        # Start at line index 1
        results = list(
            batch_repli_job.get_tasks(
                {"technical_account": "demo", "technical_bucket": "bucket"},
                marker=";1",
            )
        )

        # Only lines with index >= 1
        expected = [
            ("manifest_1;1", {"b": 2}),
            ("manifest_2;1", {"y": 20}),
            ("manifest_1;2", {"c": 3}),
            ("manifest_2;2", {"z": 30}),
        ]
        self.assertEqual(results, expected)

    def test_multiple_manifests_with_markers(self):
        lines = {
            "manifest_1": [{"a": 1}, {"b": 2}, {"c": 3}],
            "manifest_2": [{"x": 10}, {"y": 20}, {"z": 30}],
            "manifest_3": [{"xx": 100}, {"yy": 200}, {"zz": 300}],
        }
        batch_repli_job = self._prepare_batch_repli_job(lines)

        results = list(
            batch_repli_job.get_tasks(
                {"technical_account": "demo", "technical_bucket": "bucket"},
                marker="manifest_2;1",
            )
        )

        expected = [
            ("manifest_3;1", {"yy": 200}),
            ("manifest_1;2", {"c": 3}),
            ("manifest_2;2", {"z": 30}),
            ("manifest_3;2", {"zz": 300}),
        ]
        self.assertEqual(results, expected)

    def test_multiple_manifest_with_different_number_of_objects(self):
        lines = {
            "manifest_1": [{"a": 1}],
            "manifest_2": [{"x": 10}, {"y": 20}, {"z": 30}, {"za": 40}],
            "manifest_3": [{"aa": 100}, {"bb": 200}, {"cc": 300}],
            "manifest_4": [
                {"xx": 1000},
                {"yy": 2000},
                {"zz": 3000},
                {"zza": 4000},
                {"zzb": 5000},
            ],
        }
        batch_repli_job = self._prepare_batch_repli_job(lines)

        results = list(
            batch_repli_job.get_tasks(
                {"technical_account": "demo", "technical_bucket": "bucket"},
            )
        )

        expected = [
            ("manifest_1;0", {"a": 1}),
            ("manifest_2;0", {"x": 10}),
            ("manifest_3;0", {"aa": 100}),
            ("manifest_4;0", {"xx": 1000}),
            ("manifest_2;1", {"y": 20}),
            ("manifest_3;1", {"bb": 200}),
            ("manifest_4;1", {"yy": 2000}),
            ("manifest_2;2", {"z": 30}),
            ("manifest_3;2", {"cc": 300}),
            ("manifest_4;2", {"zz": 3000}),
            ("manifest_2;3", {"za": 40}),
            ("manifest_4;3", {"zza": 4000}),
            ("manifest_4;4", {"zzb": 5000}),
        ]
        self.assertEqual(results, expected)

    def test_multiple_manifest_with_different_number_of_objects_with_line_marker(self):
        lines = {
            "manifest_1": [{"a": 1}, {"b": 2}],
            "manifest_2": [{"x": 10}, {"y": 20}, {"z": 30}, {"za": 40}],
            "manifest_3": [{"aa": 100}, {"bb": 200}, {"cc": 300}],
            "manifest_4": [
                {"xx": 1000},
                {"yy": 2000},
                {"zz": 3000},
                {"zza": 4000},
                {"zzb": 5000},
            ],
        }
        batch_repli_job = self._prepare_batch_repli_job(lines)

        # Start at line index 3
        results = list(
            batch_repli_job.get_tasks(
                {"technical_account": "demo", "technical_bucket": "bucket"}, marker=";3"
            )
        )

        # Only lines with index >= 3
        expected = [
            ("manifest_2;3", {"za": 40}),
            ("manifest_4;3", {"zza": 4000}),
            ("manifest_4;4", {"zzb": 5000}),
        ]
        self.assertEqual(results, expected)
