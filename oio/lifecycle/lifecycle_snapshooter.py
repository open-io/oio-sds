# Copyright (C) 2018-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2022 OVH SAS
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


from functools import partial
from multiprocessing.pool import ThreadPool
from oio.common.exceptions import ClientException, NotFound
from oio.common.logger import get_logger
from oio.common.utils import depaginate
from oio.api.object_storage import ObjectStorageApi

CONCURRENCY_DEFAULT = 10
SNAPSHOTS_ALLOWED_RETRY = 5


class LifecycleSnapshooter:
    def __init__(self, namespace, conf, logger=None):
        self.namespace = namespace
        self.conf = conf
        self.logger = logger or get_logger(conf)

        self.api = ObjectStorageApi(namespace, logger=logger)
        self._checkpoint_file = conf["progress_file"]
        self._bucket_checkpoint = None
        self._container_checkpoint = None

        self._progress_fd = open(self._checkpoint_file, "w+", encoding="utf-8")

        concurrency = conf.get("concurrency", CONCURRENCY_DEFAULT)
        self._threadpool = ThreadPool(concurrency)

        self._processed_errors = 0
        self._processed_containers = 0

    @property
    def bucket_checkpoint(self):
        return self._bucket_checkpoint

    @bucket_checkpoint.setter
    def bucket_checkpoint(self, bucket):
        self._bucket_checkpoint = bucket
        self._write_progress_file()

    @property
    def container_checkpoint(self):
        return self._container_checkpoint

    @container_checkpoint.setter
    def container_checkpoint(self, container):
        self._container_checkpoint = container
        self._write_progress_file()

    def _write_progress_file(self):
        if not self._progress_fd:
            self._progress_fd = open(self._checkpoint_file, "w+", encoding="utf-8")
        self._progress_fd.seek(0)
        self._progress_fd.write(f"{self.bucket_checkpoint}|{self.container_checkpoint}")
        self._progress_fd.truncate()
        self._progress_fd.flush()

    def _load_restart_points(self):
        self._progress_fd.seek()
        line = self._progress_fd.readline()
        bucket, container = line.split("|")
        self._bucket_checkpoint = bucket if bucket else None
        self.container_checkpoint = container if container else None

    def _process_container(self, owner, container):
        self.logger.debug("Request snapshot for container '%s'", container)
        self.container_checkpoint = container
        status = False
        for _ in range(SNAPSHOTS_ALLOWED_RETRY):
            try:
                if not self.api.lifecycle.container_snapshot(owner, container):
                    status = True
                    break
            except ClientException:
                ...
        return (status, container)

    def _process_bucket(self, bucket_name):
        self.logger.debug("Processing bucket '%s'", bucket_name)
        try:
            owner = self.api.bucket.bucket_get_owner(bucket_name)
        except NotFound:
            self.logger.error("No owner found for bucket '%s'", bucket_name)
            return
        self.logger.debug("Bucket owner: '%s'", owner)

        containers = depaginate(
            self.api.account.container_list,
            listing_key=lambda x: x["listing"],
            item_key=lambda x: x[0],
            marker_key=lambda x: x["next_marker"],
            truncated_key=lambda x: x["truncated"],
            account=owner,
            bucket=bucket_name,
            marker=self._container_checkpoint,
        )

        snapshot_status = self._threadpool.map(
            partial(LifecycleSnapshooter._process_container, self, owner), containers
        )

        errors = 0
        for (status, container) in snapshot_status:
            if not status:
                self.logger.error(
                    "Failed to create snapshot for container: '%s'", container
                )
                errors += 1

        self._processed_errors += errors
        self._processed_containers += len(snapshot_status)

    def _reset_metrics(self):
        self.logger.info("Reset lifecycle metrics")

    def run(self, force_reset=False):
        self.logger.info("Running preprocessor")
        self.logger.info(
            f"Retrieve previous checkpoints: bucket:{self.bucket_checkpoint}, "
            f"container: {self.container_checkpoint}"
        )

        if (
            not self._container_checkpoint and not self._bucket_checkpoint
        ) or force_reset:
            self._reset_metrics()

        marker = self._container_checkpoint
        while True:
            data = self.api.bucket.list_lifecycle_buckets(limit=1, marker=marker)
            buckets = data.get("listing", [])
            truncated = data.get("truncated", False)
            marker = data.get("next_marker")

            for bucket in buckets:
                self.bucket_checkpoint = bucket
                self._process_bucket(bucket)
            if not truncated:
                break

        # Reset progression file
        self.bucket_checkpoint = ""
        self.container_checkpoint = ""

        self.logger.info("Processed containers: %d", self._processed_containers)
        self.logger.info("Processed errors: %d", self._processed_errors)
