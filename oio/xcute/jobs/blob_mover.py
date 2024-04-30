# Copyright (C) 2019-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2024 OVH SAS
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

import json
import math

from oio.blob.client import BlobClient
from oio.common.easy_value import float_value, int_value, boolean_value
from oio.common.exceptions import (
    ContentDrained,
    ContentNotFound,
    CorruptedChunk,
    NotFound,
    OrphanChunk,
)
from oio.common.green import time
from oio.common.kafka import DEFAULT_REBUILD_TOPIC
from oio.conscience.client import ConscienceClient
from oio.content.factory import ContentFactory
from oio.event.evob import EventTypes
from oio.rdir.client import RdirClient
from oio.xcute.common.job import XcuteTask
from oio.xcute.jobs.common import XcuteRdirJob


class RawxDecommissionTask(XcuteTask):
    def __init__(self, conf, job_params, logger=None, watchdog=None):
        super(RawxDecommissionTask, self).__init__(
            conf, job_params, logger=logger, watchdog=watchdog
        )

        self.service_id = job_params["service_id"]
        self.rawx_timeout = job_params["rawx_timeout"]
        self.min_chunk_size = job_params["min_chunk_size"]
        self.max_chunk_size = job_params["max_chunk_size"]
        self.excluded_rawx = job_params["excluded_rawx"]

        self.blob_client = BlobClient(
            self.conf, logger=self.logger, watchdog=self.watchdog
        )
        self.content_factory = ContentFactory(
            self.conf, blob_client=self.blob_client, watchdog=self.watchdog
        )
        self.conscience_client = self.blob_client.conscience_client

        self.fake_excluded_chunks = self._generate_fake_excluded_chunks(
            self.excluded_rawx
        )

    def _generate_fake_excluded_chunks(self, excluded_rawx):
        fake_excluded_chunks = []
        fake_chunk_id = "0" * 64
        for service_id in excluded_rawx.keys():
            service_addr = self.conscience_client.resolve_service_id("rawx", service_id)
            chunk = {}
            chunk["hash"] = "0000000000000000000000000000000000"
            chunk["pos"] = "0"
            chunk["size"] = 1
            chunk["score"] = 1
            chunk["url"] = f"http://{service_id}/{fake_chunk_id}"
            chunk["real_url"] = f"http://{service_addr}/{fake_chunk_id}"
            fake_excluded_chunks.append(chunk)
        return fake_excluded_chunks

    def process(self, task_id, task_payload, reqid=None):
        container_id = task_payload["container_id"]
        content_id = task_payload["content_id"]
        path = task_payload["path"]
        version = task_payload["version"]
        chunk_id = task_payload["chunk_id"]
        buf_size = task_payload["buf_size"]
        rebuild_on_read_failure = task_payload["rebuild_on_read_failure"]

        chunk_url = "http://{}/{}".format(self.service_id, chunk_id)
        try:
            meta = self.blob_client.chunk_head(
                chunk_url, timeout=self.rawx_timeout, reqid=reqid
            )
        except NotFound:
            # The chunk is still present in the rdir,
            # but the chunk no longer exists in the rawx.
            # We ignore it because there is nothing to move.
            return {"skipped_chunks_no_longer_exist": 1}
        if container_id != meta["container_id"]:
            raise ValueError(
                "Mismatch container ID: %s != %s", container_id, meta["container_id"]
            )
        if content_id != meta["content_id"]:
            raise ValueError(
                "Mismatch content ID: %s != %s", content_id, meta["content_id"]
            )
        chunk_size = int(meta["chunk_size"])

        # Maybe skip the chunk because it doesn't match the size constraint
        if chunk_size < self.min_chunk_size:
            self.logger.debug("[reqid=%s] SKIP %s too small", reqid, chunk_url)
            return {"skipped_chunks_too_small": 1}
        if self.max_chunk_size > 0 and chunk_size > self.max_chunk_size:
            self.logger.debug("[reqid=%s] SKIP %s too big", reqid, chunk_url)
            return {"skipped_chunks_too_big": 1}

        # Start moving the chunk
        try:
            content = self.content_factory.get_by_path_and_version(
                container_id=container_id,
                content_id=content_id,
                path=path,
                version=version,
                reqid=reqid,
            )
            content.move_chunk(
                chunk_id,
                fake_excluded_chunks=self.fake_excluded_chunks,
                service_id=self.service_id,
                reqid=reqid,
                copy_from_duplica=False,
                buf_size=buf_size,
            )
        except (ContentDrained, ContentNotFound, OrphanChunk):
            return {"orphan_chunks": 1}
        except (CorruptedChunk, IOError):
            if rebuild_on_read_failure:
                data = json.dumps(
                    {
                        "when": time.time(),
                        "event": EventTypes.CONTENT_BROKEN,
                        "url": {
                            "ns": self.conf["namespace"],
                            "id": container_id,
                            "content": content_id,
                            "path": path,
                            "version": version,
                        },
                        "data": {"missing_chunks": [chunk_id]},
                    }
                )
                # emit rebuild event
                is_sent = self.blob_client.send(topic=DEFAULT_REBUILD_TOPIC, data=data)
                if is_sent:
                    return {"rebuilt_chunks": 1}
                return {"read_chunk_errors": 1}

        return {"moved_chunks": 1, "moved_bytes": chunk_size}


class RawxDecommissionJob(XcuteRdirJob):
    JOB_TYPE = "rawx-decommission"
    TASK_CLASS = RawxDecommissionTask

    DEFAULT_RAWX_TIMEOUT = 60.0
    DEFAULT_MIN_CHUNK_SIZE = 0
    DEFAULT_MAX_CHUNK_SIZE = 0
    DEFAULT_USAGE_CHECK_INTERVAL = 60.0
    DEFAULT_BUFFER_SIZE = 262144
    ENABLE_HOST_TOPIC = True
    REBUILD_ON_READ_FAILURE = True

    @classmethod
    def sanitize_params(cls, job_params):
        sanitized_job_params, _ = super(RawxDecommissionJob, cls).sanitize_params(
            job_params
        )

        # specific configuration
        service_id = job_params.get("service_id")
        if not service_id:
            raise ValueError("Missing service ID")
        sanitized_job_params["service_id"] = service_id

        sanitized_job_params["rawx_timeout"] = float_value(
            job_params.get("rawx_timeout"), cls.DEFAULT_RAWX_TIMEOUT
        )

        sanitized_job_params["min_chunk_size"] = int_value(
            job_params.get("min_chunk_size"), cls.DEFAULT_MIN_CHUNK_SIZE
        )

        sanitized_job_params["max_chunk_size"] = int_value(
            job_params.get("max_chunk_size"), cls.DEFAULT_MAX_CHUNK_SIZE
        )

        sanitized_job_params["buffer_size"] = int_value(
            job_params.get("buffer_size"), cls.DEFAULT_BUFFER_SIZE
        )

        # Transform the list into a dictionary: when the value is True,
        # the service has been explicitly excluded.
        excluded_rawx = job_params.get("excluded_rawx")
        if excluded_rawx:
            excluded_rawx = {s: True for s in excluded_rawx.split(",")}
        else:
            excluded_rawx = {}
        sanitized_job_params["excluded_rawx"] = excluded_rawx

        # usage_target is parsed by parent class
        sanitized_job_params["usage_check_interval"] = float_value(
            job_params.get("usage_check_interval"), cls.DEFAULT_USAGE_CHECK_INTERVAL
        )
        sanitized_job_params["enable_host_topic"] = boolean_value(
            job_params.get("enable_host_topic"), cls.ENABLE_HOST_TOPIC
        )
        sanitized_job_params["rebuild_on_read_failure"] = boolean_value(
            job_params.get("rebuild_on_read_failure"), cls.REBUILD_ON_READ_FAILURE
        )

        return sanitized_job_params, f"rawx/{service_id}"

    def __init__(self, conf, logger=None, **kwargs):
        super(RawxDecommissionJob, self).__init__(conf, logger=logger, **kwargs)
        self.rdir_client = RdirClient(self.conf, logger=self.logger)
        self.conscience_client = ConscienceClient(self.conf, logger=self.logger)
        self.must_auto_exclude_rawx = False

    def auto_exclude_rawx(self, job_params, services):
        to_keep = {s: keep for s, keep in job_params["excluded_rawx"].items() if keep}
        new_excluded = {
            svc["tags"].get("tag.service_id", svc["addr"]): False
            for svc in services
            if svc["tags"].get("stat.space", 0) < (100 - job_params["usage_target"])
        }
        # We must do operations in this order, or we may lose some "to_keep"
        job_params["excluded_rawx"].clear()
        job_params["excluded_rawx"].update(new_excluded)
        job_params["excluded_rawx"].update(to_keep)
        self.logger.info(
            "[job_id=%s] excluded_rawx=%s",
            self.job_id,
            ",".join(job_params["excluded_rawx"].keys()),
        )

    def get_usage(self, service_id, services=None):
        if services is None:
            services = self.conscience_client.all_services("rawx", full=True)
        for service in services:
            if service_id == service["tags"].get("tag.service_id", service["addr"]):
                return 100 - service["tags"]["stat.space"]
        raise ValueError(f"No rawx service this ID ({service_id})")

    def check_usage_and_excludes(self, job_params):
        """
        Check the current space usage and update the list of excluded services.

        :returns: True if the decommission should continue, False if the target
                  usage is reached.
        """
        all_rawx = self.conscience_client.all_services("rawx", full=True)
        current_usage = self.get_usage(job_params["service_id"], all_rawx)
        if current_usage <= job_params["usage_target"]:
            self.logger.info(
                "current usage %.2f%%: target reached (%.2f%%)",
                current_usage,
                job_params["usage_target"],
            )
            return False

        if self.must_auto_exclude_rawx:
            self.auto_exclude_rawx(job_params, all_rawx)

        return True

    def get_tasks(self, job_params, marker=None):
        last_usage_check = 0.0
        usage_target = job_params["usage_target"]
        usage_check_interval = job_params["usage_check_interval"]
        # Set the boolean now, and the "auto" will be removed from the list
        if "auto" in job_params["excluded_rawx"]:
            self.must_auto_exclude_rawx = True
            job_params["excluded_rawx"].pop("auto")
            self.logger.info(
                "[job_id=%s] Will auto exclude rawx with usage > %.2f%%",
                self.job_id,
                usage_target,
            )

        now = time.time()
        if not self.check_usage_and_excludes(job_params):
            return
        last_usage_check = now

        chunk_info = self.get_chunk_info(job_params, marker=marker)
        for container_id, chunk_id, descr in chunk_info:
            task_id = "|".join((container_id, chunk_id))
            yield task_id, {
                "container_id": container_id,
                "content_id": descr["content_id"],
                "path": descr["path"],
                "version": descr["version"],
                "chunk_id": chunk_id,
                "buf_size": job_params["buffer_size"],
                "rebuild_on_read_failure": job_params["rebuild_on_read_failure"],
            }

            now = time.time()
            if now - last_usage_check < usage_check_interval:
                continue
            if not self.check_usage_and_excludes(job_params):
                return
            last_usage_check = now

    def get_total_tasks(self, job_params, marker=None):
        service_id = job_params["service_id"]
        usage_target = job_params["usage_target"]

        current_usage = self.get_usage(service_id)
        if current_usage <= usage_target:
            return

        kept_chunks_ratio = 1 - (usage_target / float(current_usage))
        chunk_info = self.get_chunk_info(job_params, marker=marker)
        i = 0
        for i, (container_id, chunk_id, _) in enumerate(chunk_info, 1):
            if i % 1000 == 0:
                yield (
                    "|".join((container_id, chunk_id)),
                    int(math.ceil(1000 * kept_chunks_ratio)),
                )

        remaining = int(math.ceil(i % 1000 * kept_chunks_ratio))
        if remaining > 0:
            yield ("|".join((container_id, chunk_id)), remaining)

    def get_chunk_info(self, job_params, marker=None):
        service_id = job_params["service_id"]
        rdir_fetch_limit = job_params["rdir_fetch_limit"]
        rdir_timeout = job_params["rdir_timeout"]

        chunk_info = self.rdir_client.chunk_fetch(
            service_id, timeout=rdir_timeout, limit=rdir_fetch_limit, start_after=marker
        )

        return chunk_info

    def set_topic_suffix(self, job_params):
        """
        Defines the suffix that will be used to set
        a dedicated topic to a particular host. The suffix is
        the host IP address. If this suffix is defined
        all the job tasks related to a service on the host
        will be sent to the dedicated topic.

        :return: topic suffix
        :rtype: str
        """
        self.topic_suffix = self.conscience_client.resolve_service_id(
            "rawx", job_params["service_id"]
        ).split(":")[0]
