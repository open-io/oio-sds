# Copyright (C) 2024 OVH SAS
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

import os

from oio.common.constants import STRLEN_REFERENCEID
from oio.crawler.common.crawler import Crawler, PipelineWorker
from oio.crawler.meta2.meta2db import Meta2DB


class LifecycleWorker(PipelineWorker):
    """Lifecycle Worker.

    Responsible for processing symbolic links in WORKING_DIR.
    """

    SERVICE_TYPE = "meta2"

    WORKING_DIR = None
    DEFAULT_WORKING_DIR = "local_lifecycle"
    EXCLUDED_DIRS = None

    def __init__(self, conf, volume_path=None, logger=None, api=None, **kwargs):
        super(LifecycleWorker, self).__init__(
            conf, volume_path, logger=logger, api=api, **kwargs
        )
        self.WORKING_DIR = conf.get(
            "working_dir",
            self.DEFAULT_WORKING_DIR,
        )

    def cb(self, status, msg):
        if 500 <= status <= 599:
            self.logger.warning(
                "Meta2worker volume %s handling failure %s", self.volume_id, msg
            )

    def process_entry(self, full_path, reqid=None):
        self.logger.info("processing path: %s", full_path)
        if os.path.islink(full_path):
            if not os.path.exists(full_path):
                # At the end of processing we remove local copy and link
                # becomes broken
                self.logger.info("Path is broken symbolic link: %s", full_path)
                os.unlink(full_path)
                return False
        else:
            self.logger.warning("Path is not a symbolic link: %s", full_path)
            self.invalid_paths += 1
            return False

        db_id = full_path.rsplit("/")[-1].rsplit(".")
        # Expected suffix after .meta2
        if len(db_id) != 6:
            self.logger.warning("Malformed db file name: %s", full_path)
            self.invalid_paths += 1
            return False
        if db_id[0] != "lifecycle":
            self.logger.warning("Bad prefix filename: %s", full_path)
            self.invalid_paths += 1
            return False

        if db_id[3] != "meta2":
            self.logger.warning("Bad extension filename: %s", full_path)
            self.invalid_paths += 1
            return False
        cid_seq = ".".join([db_id[1], db_id[2]])
        if len(cid_seq) < STRLEN_REFERENCEID:
            self.logger.warning("Not a valid CID: %s", cid_seq)
            return False

        real_path = os.path.realpath(full_path)
        meta2db = Meta2DB(self.app_env, dict())
        meta2db.real_path = real_path
        meta2db.volume_id = self.volume_id
        meta2db.cid = db_id[1]
        try:
            meta2db.seq = int(db_id[2])
        except ValueError:
            self.logger.warning("Bad sequence number: %s", db_id[2])
            return False

        try:
            self.pipeline(meta2db.env, self.cb)
            self.successes += 1
        except Exception:
            self.errors += 1
            self.logger.exception("Failed to apply lifeycle on %s", full_path)
        self.scanned_since_last_report += 1
        return True


class LifeycleCrawler(Crawler):
    SERVICE_TYPE = "lifecycle"

    def __init__(self, conf, conf_file=None, worker_class=LifecycleWorker, **kwargs):
        super(LifeycleCrawler, self).__init__(
            conf, conf_file=conf_file, worker_class=worker_class
        )