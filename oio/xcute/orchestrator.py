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

from collections import OrderedDict
import itertools
import pickle
import os
import socket

from oio.common.exceptions import OioTimeout
from oio.common.logger import get_logger
from oio.common.green import sleep, thread, threading
from oio.common.json import json
from oio.conscience.client import ConscienceClient
from oio.event.beanstalk import Beanstalk, BeanstalkdListener, BeanstalkdSender, ConnectionError
from oio.xcute.common.manager import XcuteManager
from oio.xcute.jobs import JOB_TYPES


class XcuteOrchestrator(object):

    DEFAULT_DISPATCHER_TIMEOUT = 2
    DEFAULT_TASKS_BATCH_SIZE = 8

    def __init__(self, conf, verbose):
        self.conf = conf
        self.logger = get_logger(self.conf, verbose=verbose)
        self.manager = XcuteManager(self.conf, self.logger)
        self.conscience_client = ConscienceClient(self.conf)

        self.orchestrator_id = self.conf.get('orchestrator_id')
        if not self.orchestrator_id:
            raise ValueError('Missing orchestrator ID')
        self.logger.info('Using orchestrator ID: %s', self.orchestrator_id)

        self.beanstalkd_workers_tube = self.conf.get('beanstalkd_workers_tube')
        if not self.beanstalkd_workers_tube:
            raise ValueError('Missing beanstalkd workers tube')
        self.logger.info('Using beanstalkd workers tube: %s',
                         self.beanstalkd_workers_tube)

        self.beanstalkd_reply_addr = self.conf.get('beanstalkd_reply_addr')
        if not self.beanstalkd_reply_addr:
            raise ValueError('Missing beanstalkd reply address')
        self.beanstalkd_reply_tube = self.conf.get(
            'beanstalkd_reply_tube', self.beanstalkd_workers_tube + '.reply')
        self.logger.info('Using beanstalkd reply : %s %s',
                         self.beanstalkd_reply_addr,
                         self.beanstalkd_reply_tube)

        self.running = True
        self.threads = {}

    def run_forever(self):
        """
            Take jobs from the queue and spawn threads to dispatch them
        """

        # gather beanstalkd info
        self.all_beanstalkd = OrderedDict()
        self.beanstalkd_senders = {}
        beanstalkd_thread = threading.Thread(target=self.refresh_all_beanstalkd)
        beanstalkd_thread.start()

        self.logger.info('Wait until beanstalkd are found')
        while len(self.all_beanstalkd) == 0:
            if not self.running:
                return

            sleep(5)

        self.threads[beanstalkd_thread.ident] = beanstalkd_thread

        # restart running jobs
        self.logger.debug('Look for unfinished jobs')
        running_jobs = \
            self.manager.backend.get_running_jobs(self.orchestrator_id)
        for running_job in running_jobs:
            self.run_job(*running_job)

        # start processing replies
        listen_thread = threading.Thread(target=self.listen)
        listen_thread.start()

        self.threads[listen_thread.ident] = listen_thread

        # run new jobs
        while self.running:
            # remove dead dispatching threads
            for thread_id, thread_ in self.threads.items():
                if not thread_.is_alive():
                    del self.threads[thread_id]

            new_jobs = iter(
                lambda: self.manager.backend.run_next(self.orchestrator_id), None)
            for new_job in new_jobs:
                self.run_job(*new_job)

            sleep(2)

        for thread_ in self.threads.values():
            thread_.join()

    def run_job(self, job_id, job_type, last_sent, job_config):
        """
            Get the beanstalkd available for this job
            and start the dispatching thread
        """
        self.logger.info('Run job %s', job_id)

        try:
            thread_args = (job_id, JOB_TYPES[job_type], last_sent, job_config)
            dispatch_thread = threading.Thread(
                target=self.dispatch_job,
                args=thread_args)
            dispatch_thread.start()

            self.threads[dispatch_thread.ident] = dispatch_thread
        except Exception:
            self.logger.exception('Failed to run job %s', job_id)
            self.manager.fail_job(self.orchestrator_id, job_id)

    def dispatch_job(self, job_id, job_class, last_sent, job_config):
        """
            Dispatch all of a job's tasks
        """

        self.logger.info('Start dispatching job (job_id=%s)', job_id)

        # TODO(adu)
        beanstalkd_workers = self.get_loadbalanced_workers(
            self.beanstalkd_workers_tube)

        try:
            job_tasks = job_class.get_tasks(
                self.conf, self.logger,
                job_config['params'], marker=last_sent)

            all_tasks_sent = False
            tasks_batch = list()
            for task in job_tasks:
                if not self.running:
                    break

                tasks_batch.append(task)

                if len(tasks_batch) < self.DEFAULT_TASKS_BATCH_SIZE:
                    continue

                sent = self.dispatch_tasks(
                    beanstalkd_workers, job_id, tasks_batch)
                if sent:
                    paused = self.manager.backend.update_tasks_sent(
                        job_id, self.orchestrator_id,
                        [task_id for _, task_id, _ in tasks_batch])
                    if paused:
                        return
                    tasks_batch = list()
            else:
                self.logger.info('All tasks sent (job_id=%s)' % job_id)
                all_tasks_sent = True

            sent = self.dispatch_tasks(
                beanstalkd_workers, job_id, tasks_batch)
            if sent:
                self.manager.backend.update_tasks_sent(
                    job_id, self.orchestrator_id,
                    [task_id for _, task_id, _ in tasks_batch],
                    all_tasks_sent=True)

            if not self.running:
                self.manager.pause_job(job_id)

            self.logger.info('Finished dispatching job (job_id=%s)', job_id)
        except Exception:
            self.logger.exception('Failed generating task list (job_id=%s', job_id)

            self.manager.fail_job(self.orchestrator_id, job_id)

    def dispatch_tasks(self, beanstalkd_workers, job_id, tasks_batch):
        """
            Try sending a task until it's ok
        """
        if len(tasks_batch) == 0:
            return True

        beanstalkd_payload = self.make_beanstalkd_payload(job_id, tasks_batch)
        if len(beanstalkd_payload) > 2**16:
            raise ValueError('Task payload is too big (length=%s)' % len(beanstalkd_payload))

        while self.running:
            workers_tried = set()
            for worker in beanstalkd_workers:
                if worker is None:
                    self.logger.info('No beanstalkd available (job_id=%s)' % job_id)
                    break

                if worker.addr in workers_tried:
                    self.logger.debug('Tried all beanstalkd (job_id=%s)' % job_id)
                    break

                sent = worker.send_job(beanstalkd_payload)

                if not sent:
                    workers_tried.add(worker.addr)
                    continue

                return True

            workers_tried.clear()
            sleep(5)

    def make_beanstalkd_payload(self, job_id, tasks_batch):
        tasks_payload = list()
        for task_class, task_id, task_payload in tasks_batch:
            tasks_payload.append({
                'task_class': pickle.dumps(task_class),
                'task_id': task_id,
                'task_payload': task_payload
            })
        beanstalkd_payload = {
            'event': 'xcute.task',
            'data': {
                'job_id': job_id,
                'tasks': tasks_payload,
                'beanstalkd_reply': {
                    'addr': self.beanstalkd_reply_addr,
                    'tube': self.beanstalkd_reply_tube,
                },
            }
        }
        return json.dumps(beanstalkd_payload)

    def listen(self):
        """
            Process this orchestrator's job replies
        """

        self.logger.info('Connecting to the reply beanstalkd')

        while self.running:
            try:
                listener = BeanstalkdListener(
                    addr=self.beanstalkd_reply_addr,
                    tube=self.beanstalkd_reply_tube,
                    logger=self.logger)

                break
            except ConnectionError:
                self.logger.error('Failed to connect to the reply beanstalkd')

            sleep(5)

        self.logger.info('Listening to replies on %s (tube=%s)',
                         self.beanstalkd_reply_addr, self.beanstalkd_reply_tube)

        # keep the job results in memory
        self.job_results = {}
        while self.running:
            connection_error = self.listen_loop(listener)

            # in case of a beanstalkd connection error
            # sleep to avoid spamming
            if connection_error:
                sleep(2)

        self.logger.info('Exited listening thread')

    def listen_loop(self, listener):
        """
            One iteration of the listening loop
        """

        connection_error = False
        try:
            replies = listener.fetch_job(
                self.process_reply, timeout=self.DEFAULT_DISPATCHER_TIMEOUT)

            # to force the execution of process_reply
            # if there were no replies, consider it as a connection error
            connection_error = len(list(replies)) == 0

        except OioTimeout:
            pass

        return connection_error

    def process_reply(self, beanstalkd_job_id, beanstalkd_job_data):
        job_results = self.job_results
        reply = json.loads(beanstalkd_job_data)

        job_id = reply['job_id']
        task_replies = reply['task_replies']
        task_ids = list()
        task_errors = 0
        task_results = 0
        for task_reply in task_replies:
            task_ids.append(task_reply['task_id'])
            task_results += task_reply['task_result']
            if not task_reply['task_ok']:
                task_errors += 1

        try:
            self.manager.backend.update_tasks_processed(
                job_id, task_ids, task_errors, task_results)
        except Exception:
            self.logger.exception('Error processing reply')

        yield None

    def refresh_all_beanstalkd(self):
        """
            Get all the beanstalkd and their tubes
        """

        while self.running:
            all_beanstalkd = self.conscience_client.all_services('beanstalkd')

            all_beanstalkd_with_tubes = {}
            for beanstalkd in all_beanstalkd:
                beanstalkd_addr = beanstalkd['addr']

                try:
                    beanstalkd_tubes = self.get_beanstalkd_tubes(beanstalkd_addr)
                except ConnectionError:
                    continue

                all_beanstalkd_with_tubes[beanstalkd_addr] = (beanstalkd, beanstalkd_tubes)

            for beanstalkd_addr in self.all_beanstalkd:
                if beanstalkd_addr in all_beanstalkd_with_tubes:
                    continue

                self.logger.info('Removed beanstalkd %s' % beanstalkd_addr)
                del self.all_beanstalkd[beanstalkd_addr]

            for beanstalkd_addr, beanstalkd in all_beanstalkd_with_tubes.iteritems():
                if beanstalkd_addr not in self.all_beanstalkd:
                    self.logger.info('Found beanstalkd %s' % beanstalkd_addr)

                self.all_beanstalkd[beanstalkd_addr] = beanstalkd + ({},)

            sleep(5)

        self.logger.info('Exited beanstalkd thread')

    @staticmethod
    def get_beanstalkd_tubes(beanstalkd_addr):
        return Beanstalk.from_url('beanstalkd://' + beanstalkd_addr).tubes()

    def get_loadbalanced_workers(self, worker_tube):
        """
            Yield senders following a loadbalancing strategy
        """

        while True:
            yielded = False
            for beanstalkd, beanstalkd_tubes, beanstalkd_senders in self.all_beanstalkd.itervalues():
                if beanstalkd['score'] == 0:
                    continue

                if worker_tube not in beanstalkd_tubes:
                    continue

                if worker_tube not in beanstalkd_senders:
                    sender = BeanstalkdSender(
                        addr=beanstalkd['addr'],
                        tube=worker_tube,
                        logger=self.logger)

                    beanstalkd_senders[worker_tube] = sender

                yield beanstalkd_senders[worker_tube]
                yielded = True

            if not yielded:
                yield None

    def exit(self, *args, **kwargs):
        if self.running:
            self.logger.info('Exiting gracefully')

            self.running = False

            return

        self.logger.info('Exiting')
        os._exit(1)
