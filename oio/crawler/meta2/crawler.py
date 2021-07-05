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

from oio import ObjectStorageApi
from oio.blob.utils import check_volume_for_service_type
from oio.common.constants import STRLEN_REFERENCEID
from oio.common.daemon import Daemon
from oio.common.easy_value import int_value
from oio.common.exceptions import OioException
from oio.common.green import ratelimit, time, ContextPool
from oio.common.logger import get_logger
from oio.common.utils import paths_gen
from oio.crawler.meta2.loader import loadpipeline
from oio.crawler.meta2.meta2db import Meta2DB


class Meta2Worker(object):
    """
    Meta2 Worker responsible for a single volume.
    """

    def __init__(self, conf, volume_path, logger=None, api=None):
        """
        - interval: (int) in sec time between two full scans. Default: half an
                    hour.
        - report_interval: (int) in sec, time between two reports: Default: 300
        - scanned_per_second: (int) maximum number of indexed databases /s.
        """
        self.conf = conf
        self.volume = volume_path
        self.logger = logger or get_logger(self.conf)
        self.running = True

        self.scans_interval = int_value(self.conf.get('interval'), 1800)
        self.report_interval = int_value(self.conf.get('report_interval'), 300)
        self.max_scanned_per_second = int_value(
            self.conf.get('scanned_per_second'), 32)
        self.namespace, self.volume_id = check_volume_for_service_type(
            self.volume, 'meta2')

        self.passes = 0
        self.successes = 0
        self.errors = 0
        self.start_time = 0
        self.last_report_time = 0
        self.scanned_since_last_report = 0

        self.app_env = dict()
        self.app_env['api'] = api or ObjectStorageApi(
            self.namespace, logger=self.logger)

        self.pipeline = loadpipeline(conf.get('conf_file'),
                                     global_conf=self.conf, app=self)

    def cb(self, status, msg):
        if 500 <= status <= 599:
            self.logger.warning('Meta2worker volume %s handling failure %s',
                                self.volume, msg)

    def report(self, tag, force=False):
        """
        Log the status of crawler
        :param tag: One of three: starting, running, ended.
        """
        now = time.time()
        if not force and now - self.last_report_time < self.report_interval:
            return

        elapsed = (now - self.start_time) or 0.00001
        total = self.successes + self.errors
        since_last_rprt = (now - self.last_report_time) or 0.00001
        self.logger.info(
            '%(tag)s '
            'volume_id=%(volume_id)s '
            'elapsed=%(elapsed).02f '
            'pass=%(pass)d '
            'errors=%(errors)d '
            'meta2db_scanned=%(total_scanned)d %(scan_rate).2f/s',
            {
                'tag': tag,
                'volume_id': self.volume_id,
                'elapsed': elapsed,
                'pass': self.passes,
                'errors': self.errors,
                'total_scanned': total,
                'scan_rate': self.scanned_since_last_report / since_last_rprt,
            })

        for filter_name, stats in self.pipeline.get_stats().items():
            self.logger.info(
                '%(tag)s '
                'volume_id=%(volume_id)s '
                'filter=%(filter)s '
                '%(stats)s',
                {
                    'tag': tag,
                    'volume_id': self.volume_id,
                    'filter': filter_name,
                    'stats': ' '.join(('%s=%s' % (key, str(value))
                                       for key, value in stats.items()))
                }
            )

        self.last_report_time = now
        self.scanned_since_last_report = 0

    def process_meta2db(self, db_path):
        db_id = db_path.rsplit("/")[-1].rsplit(".")
        if len(db_id) != 3:
            self.logger.warning("Malformed db file name: %s", db_path)
            return False
        if db_id[2] != 'meta2':
            self.logger.warning("Bad extention filename: %s", db_path)
            return False

        cid_seq = ".".join([db_id[0], db_id[1]])
        if len(cid_seq) < STRLEN_REFERENCEID:
            self.logger.warning('Not a valid CID: %s', cid_seq)
            return False

        meta2db = Meta2DB(dict())
        meta2db.path = db_path
        meta2db.volume_id = self.volume_id
        meta2db.cid = db_id[0]
        meta2db.seq = db_id[1]

        try:
            self.pipeline(meta2db.env, self.cb)
            self.successes += 1
        except Exception:
            self.errors += 1
            self.logger.exception('Failed to apply pipeline')
        self.scanned_since_last_report += 1
        return True

    def crawl_volume(self):
        """
        Crawl volume, and apply filters on every database.
        """
        self.passes += 1
        paths = paths_gen(self.volume)

        self.report('starting', force=True)
        last_scan_time = 0
        for db_path in paths:
            self.logger.debug("crawl_volume current db path: %s", db_path)
            if not self.running:
                self.logger.info("stop asked for loop paths")
                break

            if not self.process_meta2db(db_path):
                continue

            last_scan_time = ratelimit(
                last_scan_time, self.max_scanned_per_second)

            self.report('running')

        self.report('ended', force=True)
        # reset stats for each filter
        self.pipeline.reset_stats()
        # reset crawler stats
        self.errors = 0
        self.successes = 0

    def run(self):
        while self.running:
            try:
                start_crawl = time.time()
                self.crawl_volume()
                crawling_duration = time.time() - start_crawl
                self.logger.debug("start_crawl %d crawling_duration %d",
                                  start_crawl, crawling_duration)
                if(crawling_duration < self.scans_interval):
                    time.sleep(self.scans_interval - crawling_duration)
                else:
                    self.logger.warning("crawler duration %d for volume %s is \
                                        higher", self.volume,
                                        crawling_duration)
            except Exception:
                self.logger.exception('Failed to crawl volume')

    def stop(self):
        """
        Needed for gracefully stopping.
        """
        self.running = False


class Meta2Crawler(Daemon):
    """
    Daemon to crawl volumes
    """
    def __init__(self, conf, conf_file=None, **kwargs):
        super(Meta2Crawler, self).__init__(conf)

        if not conf_file:
            raise OioException('Missing configuration path')
        conf['conf_file'] = conf_file
        self.api = ObjectStorageApi(conf['namespace'], logger=self.logger)

        self.volumes = list()
        for volume in conf.get('volume_list', '').split(','):
            volume = volume.strip()
            if volume:
                self.volumes.append(volume)
        if not self.volumes:
            raise OioException("No meta2 volumes provided to crawl !")

        self.pool = ContextPool(len(self.volumes))
        self.volume_workers = [
            Meta2Worker(conf, volume, logger=self.logger, api=self.api)
            for volume in self.volumes]

    def run(self, *args, **kwargs):
        """ Main loop to scan volumes and apply filters """
        self.logger.info("started meta2 crawler service")
        for worker in self.volume_workers:
            self.pool.spawn(worker.run)
        self.pool.waitall()

    def stop(self):
        self.logger.info("stop meta2 crawler asked")
        for worker in self.volume_workers:
            worker.stop()
