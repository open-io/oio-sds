# Copyright (C) 2021 OVH SAS
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

from oio.common import exceptions as exc
from oio.common.daemon import Daemon
from oio.common.logger import get_logger
from oio.meta2_checker.loader import loadhandlers
from oio.common.green import time
from oio.common.easy_value import int_value
from oio.common.utils import paths_gen
from oio.blob.utils import check_volume_for_service_type
from oio.common.green import ContextPool


class Crawler(Daemon):
    """
    Daemon to crawl volumes and apply filters
    """
    def __init__(self, conf):
        super(Crawler, self).__init__(conf=conf)
        self.success_nb = 0
        self.failed_nb = 0
        self.full_scan_nb = 0
        self._stop = False
        self.logger = get_logger(conf)
        self.app_env = dict()
        self.scans_interval = int_value(self.conf.get('interval'), 1800)
        if not conf.get("volume_list"):
            raise exc.OioException("No meta2 volumes provided to index !")
        self.volumes = [x.strip() for x in conf.get('volume_list').split(',')]
        self.handlers = loadhandlers(self.conf.get('handlers_conf'),
                                     global_conf=self.conf,
                                     app=self)
        self.pool = ContextPool(len(self.volumes))
        self.volume_workers = [self._run_worker(x) for x in
                               self.volumes]

    def run(self, *args, **kwargs):
        """ Main loop to scan volumes and apply filters """
        for worker in self.volume_workers:
            self.pool.spawn(worker)
            self.pool.waitall()

    def _run_worker(self, volume):
        while not self._stop:
            self.crawl_volume(volume)
            time.sleep(self.scans_interval)

    def _apply_filters(self, env):
        for key, obj_list in self.handlers.items():
            for el in obj_list:
                el(env)

    def crawl_volume(self, volume):
        """
        Crawl volume, and check every database.
        """
        env = {}
        namespace, volume_id = check_volume_for_service_type(volume, "meta2")
        paths = paths_gen(volume)
        self.full_scan_nb += 1
        self.success_nb = 0
        self.failed_nb = 0

        self.logger.debug("crawl volume %s", paths)
        # self.report("starting")

        for db_path in paths:
            if self._stop:
                self.logger.info("stop asked for loop paths")
                break

            db_id = db_path.rsplit("/")[-1].rsplit(".")
            if len(db_id) != 3:
                self._warn("Malformed db file name !", db_path)
                continue
            db_id = ".".join(db_id[:2])
            env['db_id'] = db_id
            env['volume_id'] = volume_id
            self._apply_filters(env)
        # self.report("ended")

    def stop(self):
        self.logger.info("asked stop")
        self._stop = True
