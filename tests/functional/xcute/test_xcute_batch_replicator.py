# -*- coding: utf-8 -*-

# Copyright (C) 2025-2026 OVH SAS
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

# pylint: disable=no-member


from oio.common.utils import request_id
from oio.xcute.jobs.batch_replicator import BatchReplicatorJob
from tests.functional.xcute.test_xcute_bucket_lister import BucketListerHelper


class TestBatchReplicator(BucketListerHelper):
    """
    Override BucketListerHelper to benefit from all methods to run a "bucket-lister" job
    (which is a prerequisite of the "batch-replicator" job).
    We could craft the listing but doing both jobs is equivalent of what the
    bucket crawler does.
    """

    def test_xcute_batch_replicator(self):
        bucket = "xcute-batch-replicator"
        obj_prefix = "xcute-batch-replicator"
        nb_obj = 5
        reqid = request_id("test_xcute_batch_replicator-")
        self._create_objects(bucket, obj_prefix, reqid=reqid, nb_obj=nb_obj)

        bucket_lister_job = self._test_xcute_bucket_lister(
            bucket=bucket,
            obj_prefix=obj_prefix,
            nb_obj=nb_obj,  # 5 simple object + 1 MPU
        )

        job_id = bucket_lister_job["job"]["id"]
        job_params = {
            "technical_manifest_prefix": f"listing/{self.account}/{bucket}/{job_id}/",
            "technical_account": self.account,
            "technical_bucket": self.internal_bucket,
            "delay_retry_later": 1,
        }
        job = self.xcute_client.job_create(
            BatchReplicatorJob.JOB_TYPE,
            job_config={"params": job_params},
        )
        job_show = self._wait_for_job_status(job["job"]["id"], "FINISHED")

        # No replicator is running (nor Swift to perform S3 requests)
        # All objects should be marked as not replicated.
        self.assertEqual(nb_obj, job_show["tasks"]["processed"])
        self.assertEqual(nb_obj, job_show["errors"]["total"])
        self.assertEqual(nb_obj, job_show["errors"]["ReplicationNotFinished"])

        # Check all objects have the PENDING status
        objects = self.storage.object_list(self.account, bucket, properties=True)
        for obj in objects["objects"]:
            self.assertEqual(
                "PENDING",
                obj["properties"]["x-object-sysmeta-s3api-replication-status"],
            )
