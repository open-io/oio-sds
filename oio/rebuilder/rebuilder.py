# Copyright (C) 2018 OpenIO SAS, as part of OpenIO SDS
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


import time

from oio.common.easy_value import int_value
from oio.common.green import ratelimit, eventlet, threading, ContextPool
from oio.common.logger import get_logger


class Rebuilder(object):
    """
    Base class for rebuilders.
    Subclass and implement
      `_create_worker()`
      `_fill_queue()`
      `_item_to_string()`
      `_get_report()`.
    """

    def __init__(self, conf, logger, volume, input_file=None, **kwargs):
        eventlet.monkey_patch(os=False)

        self.conf = conf
        self.logger = logger or get_logger(conf)
        self.namespace = conf['namespace']
        self.volume = volume
        self.input_file = input_file
        self.nworkers = int_value(conf.get('workers'), 1)
        # counters
        self.lock_counters = threading.Lock()
        self.items_processed = 0
        self.errors = 0
        self.total_items_processed = 0
        self.total_errors = 0
        # report
        self.lock_report = threading.Lock()
        self.start_time = 0
        self.last_report = 0
        self.report_interval = int_value(conf.get('report_interval'), 3600)

    def rebuilder_pass(self, **kwargs):
        self.start_time = self.last_report = time.time()
        self.log_report('START', force=True)

        workers = list()
        with ContextPool(self.nworkers) as pool:
            queue = eventlet.Queue(self.nworkers*10)
            # spawn workers to rebuild
            for i in range(self.nworkers):
                worker = self._create_worker(**kwargs)
                workers.append(worker)
                pool.spawn(worker.rebuilder_pass, i, queue)
            # fill the queue
            self._fill_queue(queue, **kwargs)
            # block until all items are rebuilt
            queue.join()

        self.log_report('DONE', force=True)
        return self.total_errors == 0

    def _create_worker(self, **kwargs):
        raise NotImplementedError()

    def _fill_queue(self, queue, **kwargs):
        """
        Fill `queue` with items that will be passed to
        `RebuilderWorker#_rebuild_one()`.
        """
        raise NotImplementedError()

    def _item_to_string(self, item, **kwargs):
        raise NotImplementedError()

    def _update_processed_without_lock(self, info, error=None, **kwargs):
        self.items_processed += 1
        if error is not None:
            self.errors += 1

    def update_processed(self, item, info, error=None, **kwargs):
        if error is not None:
            self.logger.error('ERROR while rebuilding %s: %s',
                              self._item_to_string(item, **kwargs), error)
        with self.lock_counters:
            self._update_processed_without_lock(info, error=error, **kwargs)

    def _update_totals_without_lock(self, **kwargs):
        items_processed = self.items_processed
        self.items_processed = 0
        self.total_items_processed += items_processed
        errors = self.errors
        self.errors = 0
        self.total_errors += errors
        return items_processed, errors, self.total_items_processed, \
            self.total_errors

    def update_totals(self, **kwargs):
        with self.lock_counters:
            return self._update_totals_without_lock(**kwargs)

    def _get_report(self, status, end_time, counters, **kwargs):
        raise NotImplementedError()

    def log_report(self, status, force=False, **kwargs):
        end_time = time.time()
        if (force and self.lock_report.acquire()) \
            or (end_time - self.last_report >= self.report_interval
                and self.lock_report.acquire(False)):
            try:
                counters = self.update_totals()
                self.logger.info(
                    self._get_report(status, end_time, counters, **kwargs))
                self.last_report = end_time
            finally:
                self.lock_report.release()


class RebuilderWorker(object):
    """
    Base class for rebuilder workers.
    Subclass and implement `_rebuild_one()`.
    """

    def __init__(self, rebuilder, **kwargs):
        self.rebuilder = rebuilder
        self.conf = rebuilder.conf
        self.logger = rebuilder.logger
        self.namespace = rebuilder.namespace
        self.volume = rebuilder.volume
        self.items_run_time = 0
        self.max_items_per_second = int_value(
            rebuilder.conf.get('items_per_second'), 30)

    def update_processed(self, item, info, error=None, **kwargs):
        return self.rebuilder.update_processed(item, info, error=error,
                                               **kwargs)

    def log_report(self, **kwargs):
        return self.rebuilder.log_report('RUN', **kwargs)

    def rebuilder_pass(self, num, queue, **kwargs):
        while True:
            info = None
            err = None
            item = queue.get()
            try:
                info = self._rebuild_one(item, **kwargs)
            except Exception as exc:
                err = str(exc)
            queue.task_done()

            self.update_processed(item, info, error=err, **kwargs)
            self.log_report(**kwargs)

            self.items_run_time = ratelimit(self.items_run_time,
                                            self.max_items_per_second)

    def _rebuild_one(self, item, **kwargs):
        """
        Rebuild one item from the queue previously filled
        by `Rebuilder#_fill_queue()`.
        """
        raise NotImplementedError()
