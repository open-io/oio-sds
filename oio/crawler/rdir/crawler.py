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


from collections import namedtuple
from os.path import isfile
from random import randint

from oio.blob.operator import ChunkOperator
from oio.blob.utils import check_volume
from oio.common import exceptions as exc
from oio.common.daemon import Daemon
from oio.common.green import get_watchdog, ratelimit, time, ContextPool
from oio.common.easy_value import boolean_value, int_value
from oio.common.http_urllib3 import get_pool_manager
from oio.common.logger import get_logger
from oio.conscience.client import ConscienceClient
from oio.rdir.client import RdirClient

RawxService = namedtuple('RawxService', ('status', 'last_time'))


class RdirWorker(object):
    """
    Blob indexer worker responsible for a single volume.
    """

    def __init__(self, conf, volume_path, logger=None, pool_manager=None,
                 watchdog=None):
        """
        Initializes an RdirWorker.

        :param volume_path: The volume path to be indexed
        :param conf: The configuration to be passed to the needed services
        :param pool_manager: A connection pool manager. If none is given, a
                new one with a default size of 10 will be created.
        """
        self.conf = conf
        self.logger = logger or get_logger(self.conf)
        if volume_path:
            _, volume_id = check_volume(volume_path)
            self.volume_path = volume_path
            self.volume_id = volume_id
        if not self.volume_path:
            raise exc.ConfigurationException('No volume specified for crawler')
        self.running = True

        self.wait_random_time_before_starting = boolean_value(
            self.conf.get('wait_random_time_before_starting'), False)
        self.scans_interval = int_value(self.conf.get('interval'), 1800)
        self.report_interval = int_value(self.conf.get('report_interval'), 300)
        self.max_chunks_per_second = int_value(
            conf.get('chunks_per_second'), 30)
        self.conscience_cache = int_value(self.conf.get('conscience_cache'),
                                          30)
        self.hash_width = self.conf.get('hash_width')
        if not self.hash_width:
            raise exc.ConfigurationException('No hash_width specified')
        self.hash_depth = self.conf.get('hash_depth')
        if not self.hash_depth:
            raise exc.ConfigurationException('No hash_depth specified')

        self.passes = 0
        self.errors = 0
        self.orphans = 0
        self.repaired = 0
        self.unrecoverable_content = 0
        self.last_report_time = 0
        self.scanned_since_last_report = 0
        self._rawx_service = RawxService(status=False, last_time=0)

        if not pool_manager:
            pool_manager = get_pool_manager(pool_connections=10)
        self.index_client = RdirClient(conf, logger=self.logger,
                                       pool_manager=pool_manager)
        self.conscience_client = ConscienceClient(self.conf,
                                                  logger=self.logger,
                                                  pool_manager=pool_manager)
        self.chunk_operator = ChunkOperator(self.conf, logger=self.logger,
                                            watchdog=watchdog)

    def _check_rawx_up(self):
        now = time.time()
        status, last_time = self._rawx_service
        # If the conscience has been requested in the last X seconds, return
        if now < last_time + self.conscience_cache:
            return status

        status = True
        try:
            data = self.conscience_client.all_services('rawx')
            # Check that all rawx are UP
            # If one is down, the chunk may be still rebuildable in the future
            for srv in data:
                tags = srv['tags']
                addr = srv['addr']
                up = tags.pop('tag.up', 'n/a')
                if not up:
                    self.logger.debug('service %s is down, rebuild may not'
                                      'be possible', addr)
                    status = False
                    break
        except exc.OioException:
            status = False

        self._rawx_service = RawxService(status, now)
        return status

    def report(self, tag, force=False):
        """
        Log the status of the crawler
        :param tag: One of three: starting, running, ended.
        """
        now = time.time()
        if not force and now - self.last_report_time < self.report_interval:
            return
        since_last_rprt = (now - self.last_report_time) or 0.00001

        self.logger.info('%s volume_id=%s pass=%d repaired=%d errors=%d '
                         'unrecoverable=%d orphans=%d chunks=%d '
                         'rate_since_last_report=%.2f/s',
                         tag, self.volume_id,
                         self.passes, self.repaired, self.errors,
                         self.unrecoverable_content,
                         self.orphans,
                         self.scanned_since_last_report,
                         self.scanned_since_last_report / since_last_rprt)
        self.last_report_time = now
        self.scanned_since_last_report = 0

    def error(self, container_id, chunk_id, msg):
        self.logger.error('volume_id=%s container_id=%s chunk_id=%s %s',
                          self.volume_id, container_id, chunk_id, msg)

    def _build_chunk_path(self, chunk_id):
        chunk_path = self.volume_path

        for i in range(int(self.hash_depth)):
            start = chunk_id[i * int(self.hash_width):]
            chunk_path = '{}/{}'.format(chunk_path,
                                        start[:int(self.hash_width)])

        chunk_path = '{}/{}'.format(chunk_path, chunk_id)

        return chunk_path

    def _rebuild_chunk(self, container_id, chunk_id, value):
        try:
            self.chunk_operator.rebuild(
                container_id, value['content_id'], chunk_id,
                rawx_id=self.volume_id)
            self.repaired += 1
        except exc.OioException as err:
            self.errors += 1
            if isinstance(err, exc.UnrecoverableContent):
                self.unrecoverable_content += 1
                if self._check_rawx_up():
                    error = '%(err)s, action required' % {'err': str(err)}
                    self.error(container_id, chunk_id, error)
            elif isinstance(err, exc.OrphanChunk):
                # Note for later: if it an orphan chunk, we should tag it and
                # increment a counter for stats. Another tool could be
                # responsible for those tagged chunks.
                self.orphans += 1
            else:
                error = '%(err)s, not possible to get list of rawx' \
                    % {'err': str(err)}
                self.error(container_id, chunk_id, error)

    def process_entry(self, container_id, chunk_id, value):
        self.logger.debug("current chunk_id=%s volume_id=%s",
                          chunk_id, self.volume_id)

        chunk_path = self._build_chunk_path(chunk_id)

        if not isfile(chunk_path):
            self._rebuild_chunk(container_id, chunk_id, value)

        self.scanned_since_last_report += 1

    def crawl_volume(self):
        self.passes += 1
        self.report('starting', force=True)
        # reset crawler stats
        self.errors = 0
        self.orphans = 0
        self.repaired = 0
        self.unrecoverable_content = 0
        last_scan_time = 0

        try:
            entries = self.index_client.chunk_fetch(self.volume_id)

            for container_id, chunk_id, value in entries:
                if not self.running:
                    self.logger.info("stop asked for loop paths")
                    break

                try:
                    self.process_entry(container_id, chunk_id, value)
                except exc.OioException as err:
                    self.error(container_id, chunk_id,
                               'failed to process, err={}'.format(err))

                last_scan_time = ratelimit(
                    last_scan_time, self.max_chunks_per_second)

                self.report('running')
        except (exc.ServiceBusy, exc.VolumeException, exc.NotFound) as err:
            self.logger.debug('Service busy or not available: %s', err)
        except exc.OioException as err:
            self.logger.exception('Failed to crawl volume_id=%s, err=%s',
                                  self.volume_id, err)

        self.report('ended', force=True)

    def _wait_next_iteration(self, start_crawl):
        crawling_duration = time.time() - start_crawl
        waiting_time_to_start = self.scans_interval - crawling_duration
        if waiting_time_to_start > 0:
            for _ in range(int(waiting_time_to_start)):
                if not self.running:
                    return
                time.sleep(1)
        else:
            self.logger.warning('crawler duration=%.2f for volume_id=%s is '
                                'higher', crawling_duration, self.volume_id)

    def run(self, *args, **kwargs):
        """
        Main worker loop
        """
        if self.wait_random_time_before_starting:
            waiting_time_to_start = randint(0, self.scans_interval)
            self.logger.info('Wait %d secondes before starting',
                             waiting_time_to_start)
            for _ in range(waiting_time_to_start):
                if not self.running:
                    return
                time.sleep(1)
        while self.running:
            start_crawl = time.time()
            self.crawl_volume()
            self._wait_next_iteration(start_crawl)

    def stop(self):
        """
        Could be needed for eventually gracefully stopping.
        """
        self.running = False


class RdirCrawler(Daemon):
    """
    A daemon that spawns a greenlet running a RdirWorker
    for each volume.
    """

    def __init__(self, conf, **kwargs):
        super(RdirCrawler, self).__init__(conf=conf)
        self.logger = get_logger(conf)
        if not conf.get("volume_list"):
            raise exc.OioException("No rawx volumes provided to index!")
        self.volumes = [x.strip() for x in conf.get('volume_list').split(',')]
        self.watchdog = get_watchdog(called_from_main_application=True)
        self.pool = ContextPool(len(self.volumes))
        self.volume_workers = [RdirWorker(conf, x, watchdog=self.watchdog)
                               for x in self.volumes]

    def run(self, *args, **kwargs):
        self.logger.info("started rdir crawler service")
        for worker in self.volume_workers:
            self.pool.spawn(worker.run)
        self.pool.waitall()

    def stop(self):
        self.logger.info("stop rdir crawler asked")
        for worker in self.volume_workers:
            worker.stop()
