# Copyright (C) 2021-2025 OVH SAS
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


import re

from oio.common.constants import STRLEN_REFERENCEID
from oio.crawler.common.crawler import Crawler, PipelineWorker
from oio.crawler.meta2.meta2db import Meta2DB


class Meta2Worker(PipelineWorker):
    """
    Meta2 Worker responsible for a single volume.
    """

    SERVICE_TYPE = "meta2"

    def __init__(self, conf, volume_path, logger=None, api=None, **kwargs):
        super(Meta2Worker, self).__init__(
            conf, volume_path, logger=logger, api=api, **kwargs
        )
        self.sharding_suffix_regex = re.compile(r"sharding-([\d]+)-([\d])")

    def cb(self, status, msg):
        if 500 <= status <= 599:
            self.logger.warning(
                "Meta2worker volume %s handling failure %s", self.volume_path, msg
            )

    def process_entry(self, path, reqid=None):
        if path.endswith(("-journal", "-shm", "-wal")):
            self.logger.debug("Ignoring sqlite journal file: %s", path)
            self.ignored_paths += 1
            return False
        db_id = path.rsplit("/")[-1].split(".", 4)

        if len(db_id) < 3:
            self.logger.debug("Malformed db file name: %s", path)
            self.invalid_paths += 1
            return False

        db_cid, db_seq, db_type, *db_suffix = db_id

        if db_suffix:
            db_suffix = db_suffix[0]

            if self.sharding_suffix_regex.match(db_suffix):
                self.ignored_paths += 1
                return False
        else:
            db_suffix = None

        if db_type != "meta2":
            self.logger.debug("Bad extension filename: %s", path)
            self.invalid_paths += 1
            return False

        cid_seq = ".".join([db_cid, db_seq])
        if len(cid_seq) < STRLEN_REFERENCEID:
            self.logger.warning("Not a valid CID: %s", cid_seq)
            self.invalid_paths += 1
            return False

        meta2db = Meta2DB(self.app_env, {})
        meta2db.real_path = path
        meta2db.volume_id = self.volume_id
        meta2db.cid = db_cid
        meta2db.suffix = db_suffix
        try:
            meta2db.seq = int(db_seq)
        except ValueError:
            self.logger.warning("Bad sequence number: %s", db_seq)
            self.invalid_paths += 1
            return False

        try:
            self.pipeline(meta2db.env, self.cb)
            self.successes += 1
        except Exception as c_exc:
            self.errors += 1
            self.logger.exception(
                "Failed to apply pipeline on path='%s': %s", path, c_exc
            )
        self.scanned_since_last_report += 1
        return True


class Meta2Crawler(Crawler):
    CRAWLER_TYPE = "meta2"
    SERVICE_TYPE = "meta2"

    def __init__(self, conf, conf_file=None, worker_class=Meta2Worker, **kwargs):
        super(Meta2Crawler, self).__init__(
            conf, conf_file=conf_file, worker_class=worker_class, **kwargs
        )
