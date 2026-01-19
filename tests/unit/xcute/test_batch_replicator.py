# Copyright (C) 2025-2026 OVH SAS
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
from collections import Counter
from unittest.mock import MagicMock as Mock
from unittest.mock import patch

from oio.common.exceptions import ServiceUnavailable
from oio.xcute.jobs import BatchReplicatorJob


class TestBatchReplicator(unittest.TestCase):
    JOB_PARAMS = {
        "technical_account": "demo",
        "technical_bucket": "bucket",
        "delay_retry_later": 0,
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.simulate_errors = 2  # simulate 2 errors on manifest_2

    def _prepare_batch_repli_job(self, lines_per_manifest) -> BatchReplicatorJob:
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

            # Track how many times each manifest is fetched
            batch_repli_job.fetch_counts = Counter()
            batch_repli_job.error_raised = False

            def object_fetch(account, bucket, manifest_name, reqid=None):
                batch_repli_job.fetch_counts[manifest_name] += 1

                # Simulate ServiceUnavailable on first fetch of manifest_1
                # after the second line has been read
                if (
                    manifest_name == "manifest_2"
                    and batch_repli_job.fetch_counts[manifest_name]
                    <= self.simulate_errors
                ):
                    # First fetch returns an iterator that will fail on 2nd line
                    class FailingIterator:
                        def __init__(self):
                            self.lines = [
                                f"{json.dumps(d)}\n".encode("utf-8")
                                for d in lines_per_manifest[manifest_name]
                            ]
                            self.index = 0

                        def __iter__(self):
                            return self

                        def __next__(self):
                            if self.index == 1:
                                batch_repli_job.error_raised = True
                                raise ServiceUnavailable("Simulated error")
                            result = self.lines[self.index]
                            self.index += 1
                            return result

                    return None, FailingIterator()
                else:
                    # Normal fetch for manifest_2 or any other manifest
                    data_lines = [
                        f"{json.dumps(d)}\n".encode("utf-8")
                        for d in lines_per_manifest[manifest_name]
                    ]
                    return None, iter(data_lines)

            batch_repli_job.api.object_fetch = Mock(side_effect=object_fetch)
            return batch_repli_job

    def _get_tasks(
        self, batch_repli_job: BatchReplicatorJob, marker: str = None, job_params=None
    ):
        if not job_params:
            job_params = self.JOB_PARAMS
        tasks = list(batch_repli_job.get_tasks(job_params, marker=marker))

        # Filter any (None, None) in tasks.
        # Those values are returned when there is too many temporary errors while
        # reading a manifest.
        return [item for item in tasks if item != (None, None)]

    def test_1_manifest(self):
        lines = [{"a": 1}, {"b": 2}]
        batch_repli_job = self._prepare_batch_repli_job({"manifest_1": lines})

        results = self._get_tasks(batch_repli_job)

        expected = [
            ("0;manifest_1;0", {"a": 1}),
            ("0;manifest_1;1", {"b": 2}),
        ]
        self.assertEqual(results, expected)

        # Verify manifest_1 was only fetched once (no error simulated)
        self.assertEqual(batch_repli_job.fetch_counts["manifest_1"], 1)
        self.assertFalse(batch_repli_job.error_raised)

    def test_2_manifests(self):
        lines = {
            "manifest_1": [{"a": 1}, {"b": 2}, {"c": 3}],
            "manifest_2": [{"x": 10}, {"y": 20}, {"z": 30}],
        }
        batch_repli_job = self._prepare_batch_repli_job(lines)

        results = self._get_tasks(batch_repli_job)

        expected = [
            ("0;manifest_1;0", {"a": 1}),
            ("0;manifest_2;0", {"x": 10}),
            ("0;manifest_1;1", {"b": 2}),
            ("0;manifest_2;1", {"y": 20}),
            ("0;manifest_1;2", {"c": 3}),
            ("0;manifest_2;2", {"z": 30}),
        ]
        self.assertEqual(results, expected)

        # Verify manifest_1 was only fetched once (no error simulated)
        self.assertEqual(batch_repli_job.fetch_counts["manifest_1"], 1)
        # Verify manifest_2 was fetched twice (initial + retry)
        self.assertEqual(
            batch_repli_job.fetch_counts["manifest_2"], self.simulate_errors + 1
        )
        self.assertTrue(batch_repli_job.error_raised)

    def test_2_manifests_with_line_marker(self):
        lines = {
            "manifest_1": [{"a": 1}, {"b": 2}, {"c": 3}],
            "manifest_2": [{"x": 10}, {"y": 20}, {"z": 30}],
        }
        batch_repli_job = self._prepare_batch_repli_job(lines)

        # Start at line at batch 0, manifest 0, index 1
        results = self._get_tasks(batch_repli_job, marker="0;;1")

        # Only lines with index >= 1
        expected = [
            ("0;manifest_1;1", {"b": 2}),
            ("0;manifest_2;1", {"y": 20}),
            ("0;manifest_1;2", {"c": 3}),
            ("0;manifest_2;2", {"z": 30}),
        ]
        self.assertEqual(results, expected)

    def test_2_manifests_with_markers(self):
        """
        Same test than test_2_manifests_with_line_marker but also using a manifest
        marker.
        """
        lines = {
            "manifest_1": [{"a": 1}, {"b": 2}, {"c": 3}],
            "manifest_2": [{"x": 10}, {"y": 20}, {"z": 30}],
        }
        batch_repli_job = self._prepare_batch_repli_job(lines)

        # Start at line at batch 0, manifest 1, index 1
        results = self._get_tasks(batch_repli_job, marker="0;manifest_1;1")

        expected = [
            ("0;manifest_2;1", {"y": 20}),
            ("0;manifest_1;2", {"c": 3}),
            ("0;manifest_2;2", {"z": 30}),
        ]
        self.assertEqual(results, expected)

    def test_2_manifests_with_markers_backward_compatibility(self):
        """Same than test_2_manifests_with_markers but with old marker format."""
        lines = {
            "manifest_1": [{"a": 1}, {"b": 2}, {"c": 3}],
            "manifest_2": [{"x": 10}, {"y": 20}, {"z": 30}],
        }
        batch_repli_job = self._prepare_batch_repli_job(lines)

        # Old format: manifest_name;line_number (no batch offset)
        results = self._get_tasks(batch_repli_job, marker="manifest_1;1")

        expected = [
            ("manifest_2;1", {"y": 20}),
            ("manifest_1;2", {"c": 3}),
            ("manifest_2;2", {"z": 30}),
        ]
        self.assertEqual(results, expected)

    def test_3_manifests_with_markers(self):
        lines = {
            "manifest_1": [{"a": 1}, {"b": 2}, {"c": 3}],
            "manifest_2": [{"x": 10}, {"y": 20}, {"z": 30}],
            "manifest_3": [{"xx": 100}, {"yy": 200}, {"zz": 300}],
        }
        batch_repli_job = self._prepare_batch_repli_job(lines)

        results = self._get_tasks(batch_repli_job, marker="0;manifest_2;1")

        expected = [
            ("0;manifest_3;1", {"yy": 200}),
            ("0;manifest_1;2", {"c": 3}),
            ("0;manifest_2;2", {"z": 30}),
            ("0;manifest_3;2", {"zz": 300}),
        ]
        self.assertEqual(results, expected)

    def test_4_manifests_with_different_number_of_objects(self):
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

        results = self._get_tasks(batch_repli_job)

        expected = [
            ("0;manifest_1;0", {"a": 1}),
            ("0;manifest_2;0", {"x": 10}),
            ("0;manifest_3;0", {"aa": 100}),
            ("0;manifest_4;0", {"xx": 1000}),
            ("0;manifest_2;1", {"y": 20}),
            ("0;manifest_3;1", {"bb": 200}),
            ("0;manifest_4;1", {"yy": 2000}),
            ("0;manifest_2;2", {"z": 30}),
            ("0;manifest_3;2", {"cc": 300}),
            ("0;manifest_4;2", {"zz": 3000}),
            ("0;manifest_2;3", {"za": 40}),
            ("0;manifest_4;3", {"zza": 4000}),
            ("0;manifest_4;4", {"zzb": 5000}),
        ]
        self.assertEqual(results, expected)

    def test_4_manifests_with_different_number_of_objects_with_line_marker(self):
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
        results = self._get_tasks(batch_repli_job, marker="0;;3")

        # Only lines with index >= 3
        expected = [
            ("0;manifest_2;3", {"za": 40}),
            ("0;manifest_4;3", {"zza": 4000}),
            ("0;manifest_4;4", {"zzb": 5000}),
        ]
        self.assertEqual(results, expected)

    def test_batching_with_10_manifests(self):
        """
        Test with 10 manifests (all manifests are read at the same time)
        (batch step = 10/10 = 1).
        """
        MULTIPLICATOR = 10  # make each value unique across all manifests
        NB_OBJS_PER_MANIFEST = 2
        NB_MANIFESTS = 10

        lines = {
            f"manifest_{i}": [
                {"val": i * MULTIPLICATOR + j} for j in range(NB_OBJS_PER_MANIFEST)
            ]
            for i in range(NB_MANIFESTS)
        }
        batch_repli_job = self._prepare_batch_repli_job(lines)

        results = self._get_tasks(batch_repli_job)

        # BATCH_SIZE = ceil(10/10) = 1
        # All manifests in batch 0
        BATCH_INDEX = 0
        expected = []
        for obj_index in range(NB_OBJS_PER_MANIFEST):
            for manifest_index in range(NB_MANIFESTS):
                expected.append(
                    (
                        f"{BATCH_INDEX};manifest_{manifest_index};{obj_index}",
                        {"val": manifest_index * MULTIPLICATOR + obj_index},
                    )
                )
        self.assertEqual(results, expected)

    def test_batching_with_100_manifests(self):
        """Test with 100 manifests (batch size = 10) (all batch has the same size)."""
        MULTIPLICATOR = 10  # make each value unique across all manifests
        NB_OBJS_PER_MANIFEST = 2
        NB_MANIFESTS = 100

        lines = {
            f"manifest_{i}": [
                {"val": i * MULTIPLICATOR + j} for j in range(NB_OBJS_PER_MANIFEST)
            ]
            for i in range(NB_MANIFESTS)
        }

        batch_repli_job = self._prepare_batch_repli_job(lines)

        results = self._get_tasks(batch_repli_job)

        # Batch size = max(1, int(100 * 0.1)) = 10
        # Batch 0: manifests 0, 10, 20, 30, 40, 50, 60, 70, 80, 90
        # Batch 1: manifests 1, 11, 21, 31, 41, 51, 61, 71, 81, 91
        # ...
        # Batch 9: manifests 9, 19, 29, 39, 49, 59, 69, 79, 89, 99
        NB_BATCHES_EXPECTED = 10
        expected = []
        for batch_index in range(0, NB_BATCHES_EXPECTED):
            for obj_index in range(NB_OBJS_PER_MANIFEST):
                # batch_index is also the first manifest of the batch
                for manifest_index in range(
                    batch_index, NB_MANIFESTS, NB_BATCHES_EXPECTED
                ):
                    expected.append(
                        (
                            f"{batch_index};manifest_{manifest_index};{obj_index}",
                            {"val": manifest_index * MULTIPLICATOR + obj_index},
                        )
                    )
        self.assertEqual(results, expected)

    def test_batching_with_12_manifests_batch_size_12(self):
        """
        Test with 12 manifests with batch_manifest_size=12 (all in round robin).
        STRIDE_SIZE = max(1, ceil(12/12)) = 1, so all manifests in batch 0.
        """
        MULTIPLICATOR = 10  # make each value unique across all manifests
        NB_OBJS_PER_MANIFEST = 4
        NB_MANIFESTS = 12

        lines = {
            f"manifest_{i}": [
                {"val": i * MULTIPLICATOR + j} for j in range(NB_OBJS_PER_MANIFEST)
            ]
            for i in range(NB_MANIFESTS)
        }
        batch_repli_job = self._prepare_batch_repli_job(lines)

        job_params = {**self.JOB_PARAMS, "batch_manifest_size": 12}
        results = self._get_tasks(batch_repli_job, job_params=job_params)

        # All manifests in batch 0, processed in round robin
        BATCH_INDEX = 0
        expected = []
        for obj_index in range(NB_OBJS_PER_MANIFEST):
            for manifest_index in range(NB_MANIFESTS):
                expected.append(
                    (
                        f"{BATCH_INDEX};manifest_{manifest_index};{obj_index}",
                        {"val": manifest_index * MULTIPLICATOR + obj_index},
                    )
                )
        self.assertEqual(results, expected)

    def test_batching_with_23_manifests(self):
        """Test with 23 manifests (batch step = ceil(23/10) = 3)."""
        MULTIPLICATOR = 10  # make each value unique across all manifests
        NB_OBJS_PER_MANIFEST = 2
        NB_MANIFESTS = 23

        lines = {
            f"manifest_{i}": [
                {"val": i * MULTIPLICATOR + j} for j in range(NB_OBJS_PER_MANIFEST)
            ]
            for i in range(NB_MANIFESTS)
        }
        batch_repli_job = self._prepare_batch_repli_job(lines)

        results = self._get_tasks(batch_repli_job)

        # BATCH_STEP = ceil(23/10) = 3
        # Batch 0: manifests 0, 3, 6, 9, 12, 15, 18, 21 (8 manifests)
        # Batch 1: manifests 1, 4, 7, 10, 13, 16, 19, 22 (8 manifests)
        # Batch 2: manifests 2, 5, 8, 11, 14, 17, 20 (7 manifests)
        NB_BATCHES_EXPECTED = 3
        expected = []
        for batch_index in range(0, NB_BATCHES_EXPECTED):
            for obj_index in range(NB_OBJS_PER_MANIFEST):
                # batch_index is also the first manifest of the batch
                for manifest_index in range(
                    batch_index, NB_MANIFESTS, NB_BATCHES_EXPECTED
                ):
                    expected.append(
                        (
                            f"{batch_index};manifest_{manifest_index};{obj_index}",
                            {"val": manifest_index * MULTIPLICATOR + obj_index},
                        )
                    )
        self.assertEqual(results, expected)

    def test_batching_with_23_manifests_incremental(self):
        """
        Test with 23 manifests by calling get_tasks incrementally with markers.
        This verifies that resuming from any marker returns the exact same sequence.
        """
        MULTIPLICATOR = 10  # make each value unique across all manifests
        NB_OBJS_PER_MANIFEST = 2
        NB_MANIFESTS = 23

        lines = {
            f"manifest_{i}": [
                {"val": i * MULTIPLICATOR + j} for j in range(NB_OBJS_PER_MANIFEST)
            ]
            for i in range(NB_MANIFESTS)
        }

        batch_repli_job = self._prepare_batch_repli_job(lines)
        collected = []
        marker = None

        while True:
            task_generator = batch_repli_job.get_tasks(self.JOB_PARAMS, marker=marker)
            try:
                # Get first result from generator and save the marker
                task_id, task_payload = next(task_generator)
                # Note that if None, None is returned, we call get_tasks with the same
                # marker until it returned something.
                if task_id and task_payload:
                    collected.append((task_id, task_payload))
                if task_id:
                    marker = task_id
            except StopIteration:
                # No more tasks
                break

        # Build expected results (same as test_batching_with_23_manifests)
        NB_BATCHES_EXPECTED = 3
        expected = []
        for batch_index in range(0, NB_BATCHES_EXPECTED):
            for obj_index in range(NB_OBJS_PER_MANIFEST):
                for manifest_index in range(
                    batch_index, NB_MANIFESTS, NB_BATCHES_EXPECTED
                ):
                    expected.append(
                        (
                            f"{batch_index};manifest_{manifest_index};{obj_index}",
                            {"val": manifest_index * MULTIPLICATOR + obj_index},
                        )
                    )

        self.assertEqual(collected, expected)

    def test_batching_with_23_manifests_resume_from_manifest_marker(self):
        """Test resuming from a manifest marker with 23 manifests on batch 0."""
        MULTIPLICATOR = 10  # make each value unique across all manifests
        NB_OBJS_PER_MANIFEST = 2
        NB_MANIFESTS = 23

        lines = {
            f"manifest_{i}": [
                {"val": i * MULTIPLICATOR + j} for j in range(NB_OBJS_PER_MANIFEST)
            ]
            for i in range(NB_MANIFESTS)
        }
        batch_repli_job = self._prepare_batch_repli_job(lines)

        # Resume from batch 0, manifest_4, line 1
        results = self._get_tasks(batch_repli_job, marker="0;manifest_3;1")

        NB_BATCHES_EXPECTED = 3
        expected = []
        # First batch is not complete after resuming
        BATCH_INDEX = 0
        obj_index = 1
        for manifest_index in range(
            6, NB_MANIFESTS, NB_BATCHES_EXPECTED
        ):  # manifests 6, 9, 12, 15, 18, 21
            expected.append(
                (
                    f"{BATCH_INDEX};manifest_{manifest_index};{obj_index}",
                    {"val": manifest_index * MULTIPLICATOR + obj_index},
                )
            )
        # All other batches are complete
        for batch_index in range(1, NB_BATCHES_EXPECTED):
            for obj_index in range(NB_OBJS_PER_MANIFEST):
                # batch_index is also the first manifest of the batch
                for manifest_index in range(
                    batch_index, NB_MANIFESTS, NB_BATCHES_EXPECTED
                ):
                    expected.append(
                        (
                            f"{batch_index};manifest_{manifest_index};{obj_index}",
                            {"val": manifest_index * MULTIPLICATOR + obj_index},
                        )
                    )
        self.assertEqual(results, expected)

    def test_batching_with_23_manifests_resume_from_all_markers(self):
        """Test resuming with 23 manifests."""
        MULTIPLICATOR = 10  # make each value unique across all manifests
        NB_OBJS_PER_MANIFEST = 3
        NB_MANIFESTS = 23

        lines = {
            f"manifest_{i}": [
                {"val": i * MULTIPLICATOR + j} for j in range(NB_OBJS_PER_MANIFEST)
            ]
            for i in range(NB_MANIFESTS)
        }
        # Add a lot of errors randomly in this test (it should not have any impact)
        batch_repli_job = self._prepare_batch_repli_job(lines)

        # Resume from batch 1, manifest_4, line 1
        results = self._get_tasks(batch_repli_job, marker="1;manifest_4;1")

        NB_BATCHES_EXPECTED = 3
        expected = []
        # Finish line 1 for remaining manifests in batch 1 (after manifest_4)
        BATCH_INDEX = 1
        obj_index = 1
        for i in range(
            7, NB_MANIFESTS, NB_BATCHES_EXPECTED
        ):  # manifests 7, 10, 13, 16, 19, 22
            expected.append(
                (
                    f"{BATCH_INDEX};manifest_{i};{obj_index}",
                    {"val": i * MULTIPLICATOR + obj_index},
                )
            )
        # Now line 2 for all manifests in batch 1
        obj_index = 2
        for manifest_index in range(
            BATCH_INDEX, NB_MANIFESTS, NB_BATCHES_EXPECTED
        ):  # all manifests of batch 1
            expected.append(
                (
                    f"{BATCH_INDEX};manifest_{manifest_index};{obj_index}",
                    {"val": manifest_index * MULTIPLICATOR + obj_index},
                )
            )
        # Then batch 2: manifests 2, 5, 8, 11, 14, 17, 20
        BATCH_INDEX = 2
        for obj_index in range(NB_OBJS_PER_MANIFEST):  # all lines line-by-line
            for manifest_index in range(BATCH_INDEX, NB_MANIFESTS, NB_BATCHES_EXPECTED):
                expected.append(
                    (
                        f"{BATCH_INDEX};manifest_{manifest_index};{obj_index}",
                        {"val": manifest_index * MULTIPLICATOR + obj_index},
                    )
                )
        self.assertEqual(results, expected)

    def test_batching_with_23_manifests_resume_from_last_manifest_in_batch(self):
        """Test resuming from the last manifest in a batch with 23 manifests."""
        MULTIPLICATOR = 10  # make each value unique across all manifests
        NB_OBJS_PER_MANIFEST = 3
        NB_MANIFESTS = 23

        lines = {
            f"manifest_{i}": [
                {"val": i * MULTIPLICATOR + j} for j in range(NB_OBJS_PER_MANIFEST)
            ]
            for i in range(NB_MANIFESTS)
        }
        batch_repli_job = self._prepare_batch_repli_job(lines)

        # Resume from batch 1, manifest_22 (last manifest in batch 1), line 1
        results = self._get_tasks(batch_repli_job, marker="1;manifest_22;1")

        NB_BATCHES_EXPECTED = 3
        expected = []
        # Line 2 for all manifests in batch 1
        BATCH_INDEX = 1
        obj_index = 2
        for manifest_index in range(
            BATCH_INDEX, NB_MANIFESTS, NB_BATCHES_EXPECTED
        ):  # all manifests in batch 1
            expected.append(
                (
                    f"{BATCH_INDEX};manifest_{manifest_index};{obj_index}",
                    {"val": manifest_index * MULTIPLICATOR + obj_index},
                )
            )
        # Then batch 2: manifests 2, 5, 8, 11, 14, 17, 20
        BATCH_INDEX = 2
        for obj_index in range(NB_OBJS_PER_MANIFEST):  # all lines line-by-line
            for manifest_index in range(BATCH_INDEX, NB_MANIFESTS, NB_BATCHES_EXPECTED):
                expected.append(
                    (
                        f"{BATCH_INDEX};manifest_{manifest_index};{obj_index}",
                        {"val": manifest_index * MULTIPLICATOR + obj_index},
                    )
                )
        self.assertEqual(results, expected)

    def test_batching_with_23_manifests_different_sizes(self):
        """
        Test with 23 manifests having different numbers of objects (batch step = 3).
        """
        NB_MANIFESTS = 23

        # Create manifests with varying sizes: 1 to 5 objects each
        lines = {}
        for i in range(NB_MANIFESTS):
            num_objects = (i % 5) + 1  # 1, 2, 3, 4, 5, 1, 2, ...
            lines[f"manifest_{i}"] = [{"val": i * 100 + j} for j in range(num_objects)]

        batch_repli_job = self._prepare_batch_repli_job(lines)

        results = self._get_tasks(batch_repli_job)

        # BATCH_STEP = ceil(23/10) = 3
        # Batch 0: manifests 0, 3, 6, 9, 12, 15, 18, 21 (sizes: 1, 4, 2, 5, 3, 1, 4, 2)
        # Batch 1: manifests 1, 4, 7, 10, 13, 16, 19, 22 (sizes: 2, 5, 3, 1, 4, 2, 5, 3)
        # Batch 2: manifests 2, 5, 8, 11, 14, 17, 20 (sizes: 3, 1, 4, 2, 5, 3, 1)
        NB_BATCHES_EXPECTED = 3
        expected = []

        # Build expected results line-by-line within each batch
        for batch_index in range(NB_BATCHES_EXPECTED):
            # Find max objects in this batch
            manifest_indices = list(
                range(batch_index, NB_MANIFESTS, NB_BATCHES_EXPECTED)
            )
            max_objects = max((len(lines[f"manifest_{i}"]) for i in manifest_indices))

            # Process line-by-line
            for obj_index in range(max_objects):
                for manifest_index in manifest_indices:
                    manifest_name = f"manifest_{manifest_index}"
                    if obj_index < len(lines[manifest_name]):
                        expected.append(
                            (
                                f"{batch_index};{manifest_name};{obj_index}",
                                {"val": manifest_index * 100 + obj_index},
                            )
                        )

        self.assertEqual(results, expected)
        # Verify we got all objects from all manifests
        total_objects = sum(len(objs) for objs in lines.values())
        self.assertEqual(len(results), total_objects)

    def test_batching_with_23_manifests_different_sizes_resume_from_marker(self):
        """Test resuming with 23 manifests of different sizes (batch > 0)."""
        NB_MANIFESTS = 23

        # Create manifests with varying sizes: 1 to 5 objects each
        lines = {}
        for i in range(NB_MANIFESTS):
            num_objects = (i % 5) + 1  # 1, 2, 3, 4, 5, 1, 2, ...
            lines[f"manifest_{i}"] = [{"val": i * 100 + j} for j in range(num_objects)]

        batch_repli_job = self._prepare_batch_repli_job(lines)

        # Resume from batch 1, manifest_10, line 4
        # Batch 1: manifests 1, 4, 7, 10, 13, 16, 19, 22 (sizes: 2, 5, 3, 1, 4, 2, 5, 3)
        # manifest_10 only has 1 line (line 0), so line 4 is past its end
        results = self._get_tasks(batch_repli_job, marker="1;manifest_19;2")

        NB_BATCHES_EXPECTED = 3
        expected = []

        # Batch 1: manifests 1, 4, 7, 10, 13, 16, 19, 22 (sizes: 2, 5, 3, 1, 4, 2, 5, 3)
        # Marker: 1;manifest_19;2
        # manifest_19 has 5 lines (0-4), so line 2 exists
        # After manifest_19 on line 2, we have manifest_22
        BATCH_INDEX = 1
        obj_index = 2
        # Only manifest_22 remains on line 2 after manifest_19
        for manifest_index in range(
            22, NB_MANIFESTS, NB_BATCHES_EXPECTED
        ):  # just manifest_22
            manifest_name = f"manifest_{manifest_index}"
            if obj_index < len(lines[manifest_name]):
                expected.append(
                    (
                        f"{BATCH_INDEX};{manifest_name};{obj_index}",
                        {"val": manifest_index * 100 + obj_index},
                    )
                )

        # Continue with remaining lines for all manifests in batch 1
        manifest_indices_batch1 = list(
            range(BATCH_INDEX, NB_MANIFESTS, NB_BATCHES_EXPECTED)
        )
        max_objects_batch1 = max(
            (len(lines[f"manifest_{i}"]) for i in manifest_indices_batch1)
        )

        for obj_index in range(3, max_objects_batch1):  # Start from line 3
            for manifest_index in manifest_indices_batch1:
                manifest_name = f"manifest_{manifest_index}"
                if obj_index < len(lines[manifest_name]):
                    expected.append(
                        (
                            f"{BATCH_INDEX};{manifest_name};{obj_index}",
                            {"val": manifest_index * 100 + obj_index},
                        )
                    )

        # Then batch 2: manifests 2, 5, 8, 11, 14, 17, 20 (sizes: 3, 1, 4, 2, 5, 3, 1)
        BATCH_INDEX = 2
        manifest_indices_batch2 = list(
            range(BATCH_INDEX, NB_MANIFESTS, NB_BATCHES_EXPECTED)
        )
        max_objects_batch2 = max(
            (len(lines[f"manifest_{i}"]) for i in manifest_indices_batch2)
        )

        for obj_index in range(max_objects_batch2):
            for manifest_index in manifest_indices_batch2:
                manifest_name = f"manifest_{manifest_index}"
                if obj_index < len(lines[manifest_name]):
                    expected.append(
                        (
                            f"{BATCH_INDEX};{manifest_name};{obj_index}",
                            {"val": manifest_index * 100 + obj_index},
                        )
                    )

        self.assertEqual(results, expected)

    def test_batching_with_23_manifests_different_sizes_resume_from_marker_bis(self):
        """
        Same than test_batching_with_23_manifests_different_sizes_resume_from_marker.
        But resume from a manifest that have more lines than every other manifest in
        its batch (and other manifests are all already full read).
        """
        NB_MANIFESTS = 23

        # Create manifests with varying sizes: 1 to 5 objects each
        lines = {}
        for i in range(NB_MANIFESTS):
            num_objects = (i % 5) + 1  # 1, 2, 3, 4, 5, 1, 2, ...
            lines[f"manifest_{i}"] = [{"val": i * 100 + j} for j in range(num_objects)]

        batch_repli_job = self._prepare_batch_repli_job(lines)

        # Resume from batch 1, manifest_4, line 4
        # Batch 1: manifests 1, 4, 7, 10, 13, 16, 19, 22 (sizes: 2, 5, 3, 1, 4, 2, 5, 3)
        # manifest_4 has 5 lines (0-4), so line 4 is the last line
        results = self._get_tasks(batch_repli_job, marker="1;manifest_4;4")

        NB_BATCHES_EXPECTED = 3
        expected = []

        # Batch 1: manifests 1, 4, 7, 10, 13, 16, 19, 22 (sizes: 2, 5, 3, 1, 4, 2, 5, 3)
        # Marker: 1;manifest_4;4
        # manifest_4 has 5 lines (0-4), so line 4 exists and is the last line
        # After manifest_4 on line 4, we continue with remaining manifests on line 4
        BATCH_INDEX = 1
        obj_index = 4
        # Manifests after manifest_4 in batch 1: 7, 10, 13, 16, 19, 22
        # Only manifest_19 has line 4 (has 5 lines 0-4)
        for manifest_index in range(
            7, NB_MANIFESTS, NB_BATCHES_EXPECTED
        ):  # manifests 7, 10, 13, 16, 19, 22
            manifest_name = f"manifest_{manifest_index}"
            if obj_index < len(lines[manifest_name]):
                expected.append(
                    (
                        f"{BATCH_INDEX};{manifest_name};{obj_index}",
                        {"val": manifest_index * 100 + obj_index},
                    )
                )

        # Then batch 2: manifests 2, 5, 8, 11, 14, 17, 20 (sizes: 3, 1, 4, 2, 5, 3, 1)
        BATCH_INDEX = 2
        manifest_indices_batch2 = list(
            range(BATCH_INDEX, NB_MANIFESTS, NB_BATCHES_EXPECTED)
        )
        max_objects_batch2 = max(
            (len(lines[f"manifest_{i}"]) for i in manifest_indices_batch2)
        )

        for obj_index in range(max_objects_batch2):
            for manifest_index in manifest_indices_batch2:
                manifest_name = f"manifest_{manifest_index}"
                if obj_index < len(lines[manifest_name]):
                    expected.append(
                        (
                            f"{BATCH_INDEX};{manifest_name};{obj_index}",
                            {"val": manifest_index * 100 + obj_index},
                        )
                    )

        self.assertEqual(results, expected)


class TestBatchReplicatorServiceUnavailable(TestBatchReplicator):
    """All same tests but with more ServiceUnavailable."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # simulate 42 errors on manifest_2 (so lot of None, None)
        self.simulate_errors = 42
