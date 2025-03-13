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

import json
import os
from datetime import datetime
from uuid import uuid4

from oio.common.kafka import get_retry_delay
from oio.event.evob import Event, EventTypes, RetryableEventError
from oio.event.filters.base import Filter


class LifecycleDeleteBackupFilter(Filter):
    DEFAULT_PREFIX = "/lifecycle/recycle_bin/"

    def __init__(self, app, conf):
        self._fds = {}
        self._backup_account = None
        self._backup_bucket = None
        self._prefix = None
        self._directory = None
        self._retry_delay = None
        self._api = None

        super().__init__(app, conf)

    def init(self):
        self._api = self.app_env["api"]
        self._backup_account = self.conf.get("backup_account")
        if not self._backup_account:
            raise ValueError("'backup_account' is missing")
        self._backup_bucket = self.conf.get("backup_bucket")
        if not self._backup_bucket:
            raise ValueError("'backup_bucket' is missing")
        # Validate temp directory
        self._directory = self.conf.get("cache_directory")
        if not self._directory:
            raise ValueError("'cache_directory' is missing")
        if not os.path.exists(self._directory):
            raise ValueError(f"'{self._directory}' does not exist")
        if not os.path.isdir(self._directory):
            raise ValueError(f"'{self._directory}' is not a directory")
        if not os.access(self._directory, os.W_OK):
            raise ValueError(f"'{self._directory}' is not writable")

        self._directory = os.path.join(self._directory, self.app_env["worker_id"])
        os.makedirs(self._directory, exist_ok=True)

        self._prefix = self.conf.get("prefix", self.DEFAULT_PREFIX)
        self._retry_delay = get_retry_delay(self.conf)

    def skip_end_batch_event(self):
        return False

    def _send_to_bucket(self, event):
        # Close all file descriptors
        for fd in self._fds.values():
            fd.close()
        self._fds.clear()

        for entry in os.listdir(self._directory):
            file_path = f"{self._directory}/{entry}"
            if not os.path.isfile(file_path):
                continue

            try:
                self._api.object_create_ext(
                    self._backup_account,
                    self._backup_bucket,
                    file_path,
                    obj_name=f"{self._prefix}/{entry}",
                    reqid=event.reqid,
                )
                os.remove(file_path)
            except Exception as exc:
                self.logger.error(
                    "Failed to upload object '%s', reason: %s", entry, exc
                )
                pass

    def _get_file_descriptor(self, bucket, when):
        fd = self._fds.get(bucket)
        if not fd:
            dt = datetime.utcfromtimestamp(when // 1000000)
            date = dt.strftime("%Y-%m-%d")
            filename = f"{bucket}_{date}_{uuid4().hex}.json.part"
            file_path = os.path.join(self._directory, filename)
            self._fds[bucket] = open(file_path, "a", encoding="utf-8")
            fd = self._fds[bucket]
        return fd

    def _store_event(self, event):
        bucket = event.url.get("bucket")
        if not bucket:
            raise ValueError("'bucket' is missing in url")
        fd = self._get_file_descriptor(bucket, event.when)
        fd.write(json.dumps(event.env, indent=None, separators=(",", ":")))
        fd.write("\n")

    def process(self, env, cb):
        event = Event(env)

        if event.event_type == EventTypes.INTERNAL_BATCH_END:
            self._send_to_bucket(event)
        else:
            try:
                self._store_event(event)
            except Exception as exc:
                self.logger.error("Unable to store event: %s", exc)
                resp = RetryableEventError(
                    event=event,
                    body=f"Failed to backup event. Reason: {exc}",
                    delay=self._retry_delay,
                )
                return resp(env, cb)

        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def make_filter(app):
        return LifecycleDeleteBackupFilter(app, conf)

    return make_filter
