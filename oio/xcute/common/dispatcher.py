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
from uuid import uuid1

from oio.common.easy_value import int_value
from oio.common.exceptions import ExplicitBury, OioException, OioTimeout
from oio.common.green import ratelimit, sleep, threading
from oio.common.json import json
from oio.common.logger import get_logger
from oio.conscience.client import ConscienceClient
from oio.event.beanstalk import Beanstalk, BeanstalkdListener, \
    BeanstalkdSender


def uuid(prev=None):
    if prev is not None:
        return prev
    return uuid1().hex


class XcuteDispatcher(object):
    """
    Dispatch actions on the platform.
    """

    DEFAULT_WORKER_TUBE = 'oio-xcute'
    DEFAULT_ITEM_PER_SECOND = 30
    DEFAULT_DISPATCHER_TIMEOUT = 300

    def __init__(self, conf, logger=None):
        self.conf = conf
        self.logger = logger or get_logger(self.conf)
        self.running = True
        self.success = True
        self.sending = None
        self.task_id = uuid()

        self.max_items_per_second = int_value(
            self.conf.get('items_per_second', None),
            self.DEFAULT_ITEM_PER_SECOND)

        # All available beanstalkd
        conscience_client = ConscienceClient(self.conf)
        all_beanstalkd = conscience_client.all_services('beanstalkd')
        all_available_beanstalkd = dict()
        for beanstalkd in all_beanstalkd:
            if beanstalkd['score'] <= 0:
                continue
            all_available_beanstalkd[beanstalkd['addr']] = beanstalkd
        if not all_available_beanstalkd:
            raise OioException('No beanstalkd available')

        # Beanstalkd workers
        self.workers_tube = self.conf.get('worker_tube') \
            or self.DEFAULT_WORKER_TUBE
        self.beanstalkd_workers = dict()
        for beanstalkd in self._locate_tube(all_available_beanstalkd.values(),
                                            self.workers_tube):
            beanstalkd_worker = BeanstalkdSender(
                beanstalkd['addr'], self.workers_tube, self.logger)
            self.beanstalkd_workers[beanstalkd['addr']] = beanstalkd_worker
            self.logger.info(
                'Beanstalkd %s using tube %s is selected as a worker',
                beanstalkd_worker.addr, beanstalkd_worker.tube)
        if not self.beanstalkd_workers:
            raise OioException('No beanstalkd worker available')
        nb_workers = len(self.beanstalkd_workers)
        if self.max_items_per_second > 0:
            # Max 2 seconds in advance
            queue_size_per_worker = self.max_items_per_second * 2 / nb_workers
        else:
            queue_size_per_worker = 64
        for _, beanstalkd_worker in self.beanstalkd_workers.iteritems():
            beanstalkd_worker.low_limit = queue_size_per_worker / 2
            beanstalkd_worker.high_limit = queue_size_per_worker

        # Beanstalkd reply
        beanstalkd_reply = dict()
        try:
            local_services = conscience_client.local_services()
            for local_service in local_services:
                if local_service['type'] != 'beanstalkd':
                    continue
                beanstalkd = all_available_beanstalkd.get(
                    local_service['addr'])
                if beanstalkd is None:
                    continue
                if beanstalkd_reply \
                        and beanstalkd_reply['score'] >= beanstalkd['score']:
                    continue
                beanstalkd_reply = beanstalkd
        except Exception as exc:
            self.logger.warning(
                'ERROR when searching for beanstalkd locally: %s', exc)
        if not beanstalkd_reply:
            self.logger.warn('No beanstalkd available locally')
            try:
                beanstalkd = conscience_client.next_instance('beanstalkd')
                beanstalkd_reply = all_available_beanstalkd[beanstalkd['addr']]
            except Exception as exc:
                self.logger.warning(
                    'ERROR when searching for beanstalkd: %s', exc)
        beanstalkd_reply_addr = beanstalkd_reply['addr']
        # If the tube exists, another service must have already used this tube
        beanstalkd_reply_tube = self.workers_tube + '.reply.' + self.task_id
        tubes = Beanstalk.from_url(
            'beanstalk://' + beanstalkd_reply_addr).tubes()
        if beanstalkd_reply_tube in tubes:
            raise OioException('Beanstalkd %s using tube %s is already used')
        self.beanstalkd_reply = BeanstalkdListener(
            beanstalkd_reply_addr, beanstalkd_reply_tube, self.logger)
        self.logger.info(
            'Beanstalkd %s using tube %s is selected for the replies',
            self.beanstalkd_reply.addr, self.beanstalkd_reply.tube)

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

    def _get_actions_with_args(self):
        raise NotImplementedError()

    def _job_data_from_action(self, action, args, kwargs):
        job = dict()
        job['task_id'] = self.task_id
        job['action'] = pickle.dumps(action)
        job['args'] = args or list()
        job['kwargs'] = kwargs or dict()
        job['beanstalkd_reply'] = {'addr': self.beanstalkd_reply.addr,
                                   'tube': self.beanstalkd_reply.tube}
        return json.dumps(job)

    def _send_action(self, action_with_args, next_worker):
        """
        Send the action through a non-full sender.
        """
        job_data = self._job_data_from_action(*action_with_args)
        workers = self.beanstalkd_workers.values()
        nb_workers = len(workers)
        while True:
            for _ in range(nb_workers):
                success = workers[next_worker].send_job(job_data)
                next_worker = (next_worker + 1) % nb_workers
                if success:
                    return next_worker
            self.logger.warn("All beanstalkd workers are full")
            sleep(5)

    def _distribute_actions(self):
        next_worker = 0
        items_run_time = 0

        try:
            actions_with_args = self._get_actions_with_args()
            items_run_time = ratelimit(
                items_run_time, self.max_items_per_second)
            next_worker = self._send_action(
                next(actions_with_args), next_worker)
            self.sending = True
            for action_with_args in actions_with_args:
                items_run_time = ratelimit(items_run_time,
                                           self.max_items_per_second)
                next_worker = self._send_action(action_with_args, next_worker)

                if not self.running:
                    break
        except Exception as exc:
            if not isinstance(exc, StopIteration) and self.running:
                self.logger.error("Failed to distribute actions: %s", exc)
                self.success = False
        finally:
            self.sending = False

    def _update_status(self):
        self.redis_conn
        sleep(1)

    def _all_actions_are_processed(self):
        """
        Tell if all workers have finished to process their actions.
        """
        if self.sending:
            return False

        total_actions = 0
        for _, worker in self.beanstalkd_workers.iteritems():
            total_actions += worker.nb_jobs
        return total_actions <= 0

    def _decode_reply(self, job_id, job_data, **kwargs):
        reply_info = json.loads(job_data)
        if reply_info['task_id'] != self.task_id:
            raise ExplicitBury('Wrong task ID (%d ; expected=%d)'
                               % (reply_info['task_id'], self.task_id))
        yield reply_info

    def _process_reply(self, reply_info):
        exc = pickle.loads(reply_info['exc'])
        if exc:
            self.logger.error(exc)

        beanstalkd_worker_addr = reply_info['beanstalkd_worker']['addr']
        self.beanstalkd_workers[beanstalkd_worker_addr].job_done()

    def run(self):
        thread_distribute_actions = threading.Thread(
            target=self._distribute_actions)
        thread_distribute_actions.start()

        # Wait until the thread is started sending events
        while self.sending is None:
            sleep(0.1)

        # Retrieve replies until all events are processed
        try:
            while not self._all_actions_are_processed():
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
