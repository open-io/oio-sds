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


import re
import time
from oio.common.constants import STRLEN_REFERENCEID
from oio.crawler.common.crawler import Crawler, CrawlerWorker
from oio.crawler.meta2.meta2db import Meta2DB, delete_meta2_db
from oio.directory.admin import AdminClient


class Meta2Worker(CrawlerWorker):
    """
    Meta2 Worker responsible for a single volume.
    """

    SERVICE_TYPE = "meta2"

    def __init__(self, conf, volume_path, logger=None, api=None, **kwargs):
        super(Meta2Worker, self).__init__(
            conf, volume_path, logger=logger, api=api, **kwargs
        )
        self.sharding_suffix_regex = re.compile(r"sharding-([\d]+)-([\d])")
        self.admin_client = None

    def cb(self, status, msg):
        if 500 <= status <= 599:
            self.logger.warning(
                "Meta2worker volume %s handling failure %s", self.volume, msg
            )

    def process_path(self, path):
        if path.endswith("-journal") or path.endswith("-wal"):
            self.logger.debug("Ignoring sqlite journal file: %s", path)
            self.ignored_paths += 1
            return False
        db_id = path.rsplit("/")[-1].rsplit(".")
        if len(db_id) != 3:
            if "VerifyChunkPlacement-" in db_id[-1]:
                # This is a meta2 db copy left over after
                # placement-checker-crawler execution, we need to delete it.

                # We will delete copies older than two days
                # to avoid to delete meta2 db currently being
                # used by placement-checker-crawler
                timestamp = int(db_id[-1].split("-")[-1])
                if time.time() > (timestamp + 172800):
                    if not self.admin_client:
                        self.admin_client = AdminClient(
                            self.conf,
                            logger=self.logger,
                            pool_manager=self.app_env["api"].container.pool_manager,
                        )
                    delete_meta2_db(
                        cid=db_id[0],
                        path=path,
                        suffix=db_id[-1],
                        volume_id=self.volume_id,
                        admin_client=self.admin_client,
                        logger=self.logger,
                    )
                    self.logger.warning(
                        "Delete meta2 db copy coming from previous "
                        "placement-checker-crawler execution: %s",
                        path,
                    )
                self.invalid_paths += 1
                return False

            if (len(db_id)) == 4 and self.sharding_suffix_regex.match(db_id[3]):
                self.ignored_paths += 1
                return False
            self.logger.warning("Malformed db file name: %s", path)
            self.invalid_paths += 1
            return False
        if db_id[2] != "meta2":
            self.logger.warning("Bad extension filename: %s", path)
            self.invalid_paths += 1
            return False

        cid_seq = ".".join([db_id[0], db_id[1]])
        if len(cid_seq) < STRLEN_REFERENCEID:
            self.logger.warning("Not a valid CID: %s", cid_seq)
            return False

        meta2db = Meta2DB(self.app_env, {})
        meta2db.real_path = path
        meta2db.volume_id = self.volume_id
        meta2db.cid = db_id[0]
        try:
            meta2db.seq = int(db_id[1])
        except ValueError:
            self.logger.warning("Bad sequence number: %s", db_id[1])
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
    SERVICE_TYPE = "meta2"

    def __init__(self, conf, conf_file=None, worker_class=Meta2Worker, **kwargs):
        super(Meta2Crawler, self).__init__(
            conf, conf_file=conf_file, worker_class=worker_class, **kwargs
        )
