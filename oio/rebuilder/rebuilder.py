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

from oio.common.utils import get_logger, int_value
from oio.common.green import ratelimit, eventlet, ContextPool


class Rebuilder(object):
    """
    Base class for rebuilders.
    Subclass and implement
      `_create_worker()`
      `_fill_queue()`
      `_init_info()`
      `_compute_info()`
      `_get_report()`.
    """

    def __init__(self, conf, logger, input_file=None, **kwargs):
        self.conf = conf
        self.logger = logger or get_logger(conf)
        self.input_file = input_file
        self.nworkers = int_value(conf.get('workers'), 1)

    def rebuilder_pass(self, **kwargs):
        start_time = time.time()

        workers = list()
        with ContextPool(self.nworkers) as pool:
            queue = eventlet.Queue(self.nworkers*2)

            # spawn workers to rebuild
            for i in range(self.nworkers):
                worker = self._create_worker(**kwargs)
                workers.append(worker)
                pool.spawn(worker.rebuilder_pass, i, queue)

            # fill the queue
            self._fill_queue(queue, **kwargs)

            # block until all items are rebuilt
            queue.join()

        passes = 0
        errors = 0
        total_items_processed = 0
        rebuilder_time = 0
        info = self._init_info(**kwargs)
        for worker in workers:
            passes += worker.passes
            errors += worker.errors
            total_items_processed += worker.total_items_processed
            rebuilder_time += worker.rebuilder_time
            info = self._compute_info(worker, info, **kwargs)

        end_time = time.time()
        elapsed = (end_time - start_time) or 0.000001
        self.logger.info(
            self._get_report(
                start_time, passes, errors, total_items_processed,
                rebuilder_time, end_time, elapsed, info, **kwargs))

    def _create_worker(self, **kwargs):
        raise NotImplementedError()

    def _fill_queue(self, queue, **kwargs):
        """
        Fill `queue` with items that will be passed to
        `RebuilderWorker#_rebuild_one()`.
        """
        raise NotImplementedError()

    def _init_info(self, **kwargs):
        raise NotImplementedError()

    def _compute_info(self, worker, info, **kwargs):
        raise NotImplementedError()

    def _get_report(self, start_time, passes, errors, total_items_processed,
                    rebuilder_time, end_time, elapsed, info, **kwargs):
        raise NotImplementedError()


class RebuilderWorker(object):
    """
    Base class for rebuilder workers.
    Subclass and implement `_rebuild_one()` and `_get_report()`.
    """

    def __init__(self, conf, logger, **kwargs):
        self.conf = conf
        self.logger = logger or get_logger(conf)
        self.passes = 0
        self.errors = 0
        self.last_reported = 0
        self.items_run_time = 0
        self.total_items_processed = 0
        self.rebuilder_time = 0
        self.report_interval = int_value(
            conf.get('report_interval'), 3600)
        self.max_items_per_second = int_value(
            conf.get('items_per_second'), 30)

    def rebuilder_pass(self, num, queue, **kwargs):
        start_time = report_time = time.time()

        while True:
            item = queue.get()
            loop_time = time.time()

            self._rebuild_one(item, **kwargs)

            self.items_run_time = ratelimit(self.items_run_time,
                                            self.max_items_per_second)
            self.total_items_processed += 1

            now = time.time()
            if now - self.last_reported >= self.report_interval:
                self.logger.info(
                    self._get_report(num, start_time, report_time, now,
                                     **kwargs))
                report_time = now
                self.last_reported = now

            self.rebuilder_time += (now - loop_time)
            queue.task_done()

    def _rebuild_one(self, item, **kwargs):
        """
        Rebuild one item from the queue previously filled
        by `Rebuilder#_fill_queue()`.
        """
        raise NotImplementedError()

    def _get_report(self, num, start_time, report_time, now, **kwargs):
        raise NotImplementedError()
