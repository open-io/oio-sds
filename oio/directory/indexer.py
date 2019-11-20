# Copyright (C) 2018-2019 OpenIO SAS, as part of OpenIO SDS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from datetime import datetime
from oio.blob.utils import check_volume_for_service_type
from oio.common import exceptions as exc
from oio.common.constants import STRLEN_REFERENCEID
from oio.common.daemon import Daemon
from oio.common.easy_value import int_value, boolean_value
from oio.common.green import ratelimit, ContextPool
from oio.common.http_urllib3 import get_pool_manager
from oio.common.logger import get_logger
from oio.common.utils import paths_gen
from oio.directory.client import DirectoryClient
from oio.rdir.client import RdirClient
from oio.common.green import time


class Meta2IndexingWorker(object):
    """
    Indexing worker responsible for a single volume.
    """

    def __init__(self, volume_path, conf, pool_manager=None):
        """
        Initializes an Indexing worker for indexing meta2 databases.

        Possible values of conf relating to this worker are:
        - interval: (int) in sec time between two full scans. Default: half an
                    hour.
        - report_interval: (int) in sec, time between two reports: Default: 300
        - scanned_per_second: (int) maximum number of indexed databases /s.
        - try_removing_faulty_indexes : In the event where we encounter a
            database that's not supposed to be handled by this volume, attempt
            to remove it from this volume rdir index if it exists
            WARNING: The decision is based off of a proxy response, that could
            be affected by cache inconsistencies for example, use at your own
            risk. Default: False

        :param volume_path: The volume path to be indexed
        :param conf: The configuration to be passed to the needed services
        :param pool_manager: A connection pool manager. If none is given, a
                new one with a default size of 10 will be created.
        """
        self.logger = get_logger(conf)
        self._stop = False
        self.volume = volume_path
        self.success_nb = 0
        self.failed_nb = 0
        self.full_scan_nb = 0
        self.last_report_time = 0
        self.last_scan_time = 0
        self.last_index_time = 0
        self.start_time = 0
        self.indexed_since_last_report = 0
        self.scans_interval = int_value(
            conf.get('interval'), 1800)
        self.report_interval = int_value(
            conf.get('report_interval'), 300)
        self.max_indexed_per_second = int_value(
            conf.get('scanned_per_second'), 3000)
        self.namespace, self.volume_id = check_volume_for_service_type(
            self.volume, "meta2")
        self.attempt_bad_index_removal = boolean_value(
            conf.get('try_removing_faulty_indexes'), False)

        if not pool_manager:
            pool_manager = get_pool_manager(pool_connections=10)
        self.index_client = RdirClient(conf, logger=self.logger,
                                       pool_manager=pool_manager)
        self.dir_client = DirectoryClient(conf, logger=self.logger,
                                          pool_manager=pool_manager)

    def report(self, tag):
        """
        Log the status of indexer

        :param tag: One of three: starting, running, ended.
        """
        total = self.success_nb + self.failed_nb
        now = time.time()
        elapsed = (now - self.start_time) or 0.00001
        since_last_rprt = (now - self.last_report_time) or 0.00001
        self.logger.info(
            'volume_id=%(volume_id)s %(tag)s=%(current_time)s '
            'elapsed=%(elapsed).02f '
            'pass=%(pass)d '
            'errors=%(errors)d '
            'containers_indexed=%(total_indexed)d %(index_rate).2f/s',
            {
                'volume_id': self.volume_id,
                'tag': tag,
                'current_time': datetime.fromtimestamp(
                    int(now)).isoformat(),
                'pass': self.full_scan_nb,
                'errors': self.failed_nb,
                'total_indexed': total,
                'index_rate': self.indexed_since_last_report / since_last_rprt,
                'elapsed': elapsed
            }
        )
        self.last_report_time = now
        self.indexed_since_last_report = 0

    def warn(self, msg, container_id):
        self.logger.warn(
            'volume_id=%(volume_id)s container_id=%(container_id)s %(error)s',
            {
                'volume_id': self.volume_id,
                'container_id': container_id,
                'error': msg
            }
        )

    def _attempt_index_removal(self, db_path, cid):
        """
        Fail safe removal attempt.
        """
        try:
            self.index_client.meta2_index_delete(self.volume_id, db_path, cid)
        except exc.OioException as exception:
            self.warn(
                container_id=cid,
                msg="Unable to remove database from the volume "
                    "index : {0}".format(str(exception))
            )

    def index_meta2_database(self, db_id):
        """
        Add a meta2 database to the rdir index. Fails if the database isn't
        handled by the current volume.

        :param db_id: The ContentID representing the reference to the database.
        """
        if len(db_id) < STRLEN_REFERENCEID:
            self.warn('Not a valid container ID', db_id)
            return
        try:
            srvcs = self.dir_client.list(cid=db_id)
            account, container = srvcs['account'], srvcs['name']
            is_peer = self.volume_id in [x['host'] for x in srvcs['srv'] if
                                         x['type'] == 'meta2']

            container_id = db_id.rsplit(".")[0]

            if isinstance(account, unicode):
                account = account.encode('utf-8')
            if isinstance(container, unicode):
                container = container.encode('utf-8')
            cont_url = "{0}/{1}/{2}".format(self.namespace, account, container)

            if not is_peer:
                self.warn("Trying to index a container that isn't handled by"
                          "this volume", db_id)
                if self.attempt_bad_index_removal:
                    self._attempt_index_removal(cont_url, container_id)
                return

            self.index_client.meta2_index_push(volume_id=self.volume_id,
                                               container_url=cont_url,
                                               mtime=time.time(),
                                               container_id=container_id)

            self.success_nb += 1
        except exc.OioException as exception:
            self.failed_nb += 1
            self.warn("Unable to to index container: %s" % str(exception),
                      db_id)

        self.indexed_since_last_report += 1

    def crawl_volume(self):
        """
        Crawl the volume assigned to this worker, and index every database.
        """
        paths = paths_gen(self.volume)
        self.full_scan_nb += 1
        self.success_nb = 0
        self.failed_nb = 0
        now = time.time()
        self.last_report_time = now

        self.report("starting")

        for db_path in paths:

            # Graceful exit, hopefully
            if self._stop:
                break

            db_id = db_path.rsplit("/")[-1].rsplit(".")

            if len(db_id) != 3:
                self.warn("Malformed db file name !", db_path)
                continue

            db_id = ".".join(db_id[:2])
            self.index_meta2_database(db_id)

            self.last_index_time = ratelimit(
                self.last_index_time,
                self.max_indexed_per_second
            )

            now = time.time()
            if now - self.last_report_time >= self.report_interval:
                self.report("running")

        self.report("ended")

    def run(self):
        """
        Main worker loop
        """
        self.start_time = time.time()
        while not self._stop:
            try:
                self.crawl_volume()
                self.last_scan_time = time.time()
                time.sleep(self.scans_interval)
            except exc.OioException as exception:
                self.logger.exception("ERROR during indexing meta2: %s",
                                      exception)

    def stop(self):
        """
        Could be needed for eventually gracefully stopping.
        """
        self._stop = True


class Meta2Indexer(Daemon):
    """
    A daemon that spawns a greenlet running a Meta2IndexingWorker
    for each volume.
    """

    def __init__(self, conf):
        super(Meta2Indexer, self).__init__(conf=conf)
        self.logger = get_logger(conf)
        if not conf.get("volume_list"):
            raise exc.OioException("No meta2 volumes provided to index !")
        self.volumes = [x.strip() for x in conf.get('volume_list').split(',')]
        self.pool = ContextPool(len(self.volumes))
        self.volume_workers = [Meta2IndexingWorker(x, conf) for x in
                               self.volumes]

    def run(self, *args, **kwargs):
        for worker in self.volume_workers:
            self.pool.spawn(worker.run)
        self.pool.waitall()

    def stop(self):
        for worker in self.volume_workers:
            worker.stop()
