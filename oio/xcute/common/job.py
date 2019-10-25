# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
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

import pickle
import random
from datetime import datetime

from oio.common.easy_value import int_value
from oio.common.exceptions import ExplicitBury, OioException, OioTimeout
from oio.common.green import ratelimit, sleep, threading, time
from oio.common.json import json
from oio.common.logger import get_logger
from oio.conscience.client import ConscienceClient
from oio.event.beanstalk import Beanstalk, BeanstalkdListener, \
    BeanstalkdSender
from oio.xcute.common.backend import XcuteBackend


def uuid():
    return datetime.utcnow().strftime('%Y%m%d%H%M%S%f') \
        + '-%011x' % random.randrange(16**10)


class XcuteJob(object):
    """
    Dispatch tasks on the platform.
    """

    JOB_TYPE = None
    DEFAULT_WORKER_TUBE = 'oio-xcute'
    DEFAULT_ITEM_PER_SECOND = 30
    DEFAULT_DISPATCHER_TIMEOUT = 300

    def __init__(self, conf, job_info=None, lock=None, logger=None):
        self.conf = conf
        self.logger = logger or get_logger(self.conf)
        self.running = True
        self.success = True
        self.sending = None

        # Prepare backend
        self.backend = XcuteBackend(self.conf)

        # Job info / config
        self.job_id = None
        self.last_item_sent = None
        self.processed_items = 0
        self.errors = 0
        self.expected_items = None
        if job_info is None:
            self.job_id = uuid()
            self.job_conf = dict()
            for key, value in self.conf.items():
                if not key.startswith('job_'):
                    continue
                self.job_conf[key[4:]] = value
        else:
            self._load_job_info(job_info)
            self.job_conf = self.backend.get_job_config(self.job_id)

        # Speed
        self.max_items_per_second = int_value(
            self.job_conf.get('items_per_second', None),
            self.DEFAULT_ITEM_PER_SECOND)

        # Beanstalkd
        conscience_client = ConscienceClient(self.conf)
        all_available_beanstalkd = self._get_all_available_beanstalkd(
            conscience_client)
        # Beanstalkd workers
        beanstalkd_worker_tube = self.job_conf.get('beanstalkd_worker_tube') \
            or self.DEFAULT_WORKER_TUBE
        self.job_conf['beanstalkd_worker_tube'] = beanstalkd_worker_tube
        try:
            self.beanstalkd_workers = self._get_beanstalkd_workers(
                conscience_client, all_available_beanstalkd,
                beanstalkd_worker_tube)
        except Exception as exc:
            self.logger.error(
                'ERROR when searching for beanstalkd workers: %s', exc)
            raise
        # Beanstalkd reply
        beanstalkd_reply_tube = self.job_conf.get('beanstalkd_reply_tube') \
            or beanstalkd_worker_tube + '.job.reply.' + self.job_id
        self.job_conf['beanstalkd_reply_tube'] = beanstalkd_reply_tube
        beanstalkd_reply_addr = self.job_conf.get('beanstalkd_reply_addr')
        if not beanstalkd_reply_addr:
            try:
                beanstalkd_reply_addr = self._get_beanstalkd_reply_addr(
                    conscience_client, all_available_beanstalkd)
            except Exception as exc:
                self.logger.error(
                    'ERROR when searching for beanstalkd reply: %s', exc)
                raise
        self.job_conf['beanstalkd_reply_addr'] = beanstalkd_reply_addr
        if job_info is None:
            # If the tube exists, another service must have
            # already used this tube
            tubes = Beanstalk.from_url(
                'beanstalk://' + beanstalkd_reply_addr).tubes()
            if beanstalkd_reply_tube in tubes:
                raise OioException(
                    'Beanstalkd %s using tube %s doesn\'t exist'
                    % (beanstalkd_reply_addr, beanstalkd_reply_tube))
        self.beanstalkd_reply = BeanstalkdListener(
            beanstalkd_reply_addr, beanstalkd_reply_tube, self.logger)
        self.logger.info(
            'Beanstalkd %s using tube %s is selected for the replies',
            self.beanstalkd_reply.addr, self.beanstalkd_reply.tube)

        # Register the job
        mtime = time.time()
        if job_info is None:
            self.backend.start_job(
                self.job_id, conf=self.job_conf, job_type=self.JOB_TYPE,
                mtime=mtime, lock=lock)
        else:
            self.backend.resume_job(self.job_id, mtime=mtime)
        self.sending_job_info = True

    def _load_job_info(self, job_info):
        if job_info['job_type'] != self.JOB_TYPE:
            raise ValueError('Wrong job type')
        self.job_id = job_info['job_id']
        self.last_item_sent = job_info['last_item_sent']
        self.processed_items = int(job_info['processed_items'])
        self.errors = int(job_info['errors'])
        self.expected_items = job_info.get('expected_items')

    def _get_all_available_beanstalkd(self, conscience_client):
        """
        Get all available beanstalkd.
        """
        all_beanstalkd = conscience_client.all_services('beanstalkd')
        all_available_beanstalkd = dict()
        for beanstalkd in all_beanstalkd:
            if beanstalkd['score'] <= 0:
                continue
            all_available_beanstalkd[beanstalkd['addr']] = beanstalkd
        if not all_available_beanstalkd:
            raise OioException('No beanstalkd available')
        return all_available_beanstalkd

    def _locate_tube(self, services, tube):
        """
        Get a list of beanstalkd services hosting the specified tube.

        :param services: known beanstalkd services.
        :type services: iterable of dictionaries
        :param tube: the tube to locate.
        :returns: a list of beanstalkd services hosting the the specified tube.
        :rtype: `list` of `dict`
        """
        available = list()
        for bsd in services:
            tubes = Beanstalk.from_url(
                'beanstalk://' + bsd['addr']).tubes()
            if tube in tubes:
                available.append(bsd)
        return available

    def _get_beanstalkd_workers(self, conscience_client,
                                all_available_beanstalkd,
                                beanstalkd_worker_tube):
        beanstalkd_workers = dict()
        for beanstalkd in self._locate_tube(all_available_beanstalkd.values(),
                                            beanstalkd_worker_tube):
            beanstalkd_worker = BeanstalkdSender(
                beanstalkd['addr'], beanstalkd_worker_tube, self.logger)
            beanstalkd_workers[beanstalkd['addr']] = beanstalkd_worker
            self.logger.info(
                'Beanstalkd %s using tube %s is selected as a worker',
                beanstalkd_worker.addr, beanstalkd_worker.tube)
        if not beanstalkd_workers:
            raise OioException('No beanstalkd worker available')
        nb_workers = len(beanstalkd_workers)
        if self.max_items_per_second > 0:
            # Max 2 seconds in advance
            queue_size_per_worker = self.max_items_per_second * 2 / nb_workers
        else:
            queue_size_per_worker = 64
        for _, beanstalkd_worker in beanstalkd_workers.iteritems():
            beanstalkd_worker.low_limit = queue_size_per_worker / 2
            beanstalkd_worker.high_limit = queue_size_per_worker
        return beanstalkd_workers

    def _get_beanstalkd_reply_addr(self, conscience_client,
                                   all_available_beanstalkd):
        local_services = conscience_client.local_services()
        for local_service in local_services:
            if local_service['type'] != 'beanstalkd':
                continue
            local_beanstalkd = all_available_beanstalkd.get(
                local_service['addr'])
            if local_beanstalkd is None:
                continue
            return local_beanstalkd['addr']
        self.logger.warn('No beanstalkd available locally')
        beanstalkd = conscience_client.next_instance('beanstalkd')
        return beanstalkd['addr']

    def exit_gracefully(self):
        self.logger.info('Stop sending and wait for all tasks already sent')
        self.success = False
        self.running = False

    def _get_tasks_with_args(self):
        raise NotImplementedError()

    def _beanstlkd_job_data_from_task(self, task_class, item, kwargs):
        beanstlkd_job = dict()
        beanstlkd_job['job_id'] = self.job_id
        beanstlkd_job['task'] = pickle.dumps(task_class)
        beanstlkd_job['item'] = pickle.dumps(item)
        beanstlkd_job['kwargs'] = kwargs or dict()
        beanstlkd_job['beanstalkd_reply'] = {
            'addr': self.beanstalkd_reply.addr,
            'tube': self.beanstalkd_reply.tube}
        return json.dumps(beanstlkd_job)

    def _send_task(self, task_with_args, next_worker):
        """
        Send the task through a non-full sender.
        """
        _, item, _ = task_with_args
        beanstlkd_job_data = self._beanstlkd_job_data_from_task(
            *task_with_args)
        workers = self.beanstalkd_workers.values()
        nb_workers = len(workers)
        while True:
            for _ in range(nb_workers):
                success = workers[next_worker].send_job(beanstlkd_job_data)
                next_worker = (next_worker + 1) % nb_workers
                if success:
                    self.last_item_sent = item
                    return next_worker
            self.logger.warn("All beanstalkd workers are full")
            sleep(5)

    def _distribute_tasks(self):
        next_worker = 0
        items_run_time = 0

        try:
            tasks_with_args = self._get_tasks_with_args()
            items_run_time = ratelimit(
                items_run_time, self.max_items_per_second)
            next_worker = self._send_task(
                next(tasks_with_args), next_worker)
            self.sending = True
            for task_with_args in tasks_with_args:
                items_run_time = ratelimit(items_run_time,
                                           self.max_items_per_second)
                next_worker = self._send_task(task_with_args, next_worker)

                if not self.running:
                    break
        except Exception as exc:
            if not isinstance(exc, StopIteration) and self.running:
                self.logger.error("Failed to distribute tasks: %s", exc)
                self.success = False
        finally:
            self.sending = False

    def _prepare_job_info(self):
        info = dict()
        info['mtime'] = time.time()
        info['last_item_sent'] = self.last_item_sent
        info['processed_items'] = self.processed_items
        info['errors'] = self.errors
        return info

    def _send_job_info_periodically(self):
        while self.sending_job_info:
            sleep(1)
            info = self._prepare_job_info()
            self.backend.update_job(self.job_id, **info)

    def _all_tasks_are_processed(self):
        """
        Tell if all workers have finished to process their tasks.
        """
        if self.sending:
            return False

        total_tasks = 0
        for _, worker in self.beanstalkd_workers.iteritems():
            total_tasks += worker.nb_jobs
        return total_tasks <= 0

    def _decode_reply(self, beanstlkd_job_id, beanstlkd_job_data, **kwargs):
        reply_info = json.loads(beanstlkd_job_data)
        if reply_info['job_id'] != self.job_id:
            raise ExplicitBury('Wrong job ID (%d ; expected=%d)'
                               % (reply_info['job_id'], self.job_id))
        yield reply_info

    def _update_job_info(self, reply_info):
        self.processed_items += 1

        exc = pickle.loads(reply_info['exc'])
        if exc:
            self.logger.error(exc)
            self.errors += 1

    def _process_reply(self, reply_info):
        self._update_job_info(reply_info)

        beanstalkd_worker_addr = reply_info['beanstalkd_worker']['addr']
        self.beanstalkd_workers[beanstalkd_worker_addr].job_done()

    def run(self):
        thread_distribute_tasks = threading.Thread(
            target=self._distribute_tasks)
        thread_distribute_tasks.start()

        # Wait until the thread is started sending events
        while self.sending is None:
            sleep(0.1)

        self.sending_job_info = True
        thread_send_job_info_periodically = threading.Thread(
            target=self._send_job_info_periodically)
        thread_send_job_info_periodically.start()

        # Retrieve replies until all events are processed
        try:
            while not self._all_tasks_are_processed():
                replies = self.beanstalkd_reply.fetch_job(
                    self._decode_reply,
                    timeout=self.DEFAULT_DISPATCHER_TIMEOUT)
                for reply in replies:
                    self._process_reply(reply)
        except OioTimeout:
            self.logger.error('No reply for %d seconds',
                              self.DEFAULT_DISPATCHER_TIMEOUT)
            self.success = False
        except Exception:
            self.logger.exception('ERROR in distributed dispatcher')
            self.success = False

        # Send the last information
        self.sending_job_info = False
        info = self._prepare_job_info()
        self.success = self.errors > 0
        thread_send_job_info_periodically.join()
        if self.running:
            self.backend.finish_job(self.job_id, **info)
        else:
            self.backend.pause_job(self.job_id, **info)
