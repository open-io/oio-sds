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

    DEFAULT_WORKER_TUBE = 'oio-xcute'
    DEFAULT_REPLY_TUBE = DEFAULT_WORKER_TUBE + '.reply'
    DEFAULT_DISPATCHER_TIMEOUT = 2

    def __init__(self, conf, verbose):
        self.conf = conf
        self.logger = get_logger(self.conf, verbose=verbose)
        self.manager = XcuteManager(self.conf, self.logger)
        self.conscience_client = ConscienceClient(self.conf)

        self.running = True
        self.threads = {}

    def run_forever(self):
        """
            Take jobs from the queue and spawn threads to dispatch them
        """

        self.orchestrator_id = \
            self.conf.get('orchestrator_id', socket.gethostname())
        self.logger.info('Using orchestrator id %s' % self.orchestrator_id)

        # gather beanstalkd info
        self.all_beanstalkd = OrderedDict()
        self.beanstalkd_senders = {}
        beanstalkd_thread = threading.Thread(target=self.refresh_all_beanstalkd)
        beanstalkd_thread.start()

        self.logger.info('Wait until beanstalkd are found')
        while len(self.all_beanstalkd) == 0:
            sleep(5)

        self.reply_beanstalkd_addr = self.get_reply_beanstalkd_addr()
        self.reply_tube = self.conf.get('beanstalkd_reply_tube', self.DEFAULT_REPLY_TUBE)

        self.threads[beanstalkd_thread.ident] = beanstalkd_thread

        # restart running jobs
        self.logger.debug('Look for unfinished jobs')
        orchestrator_jobs = \
            self.manager.get_orchestrator_jobs(self.orchestrator_id)

        for job_id, job_conf, job_info in orchestrator_jobs:
            self.logger.info('Found running job (job_id=%s, job_conf=%s)' %
                             (job_id, job_conf))
            self.handle_running_job(job_id, job_conf, job_info)

        # start processing replies
        listen_thread = threading.Thread(target=self.listen)
        listen_thread.start()

        self.threads[listen_thread.ident] = listen_thread

        while self.running:
            self.orchestrate_loop()

            sleep(2)

        for thread_ in self.threads.values():
            thread_.join()

    def orchestrate_loop(self):
        """
            One iteration of the main loop
        """

        new_jobs = self.manager.get_new_jobs(self.orchestrator_id)
        for job_id, job_conf, job_info in new_jobs:
            self.logger.info('Found new job (job_id=%s, job_conf=%s)' %
                             (job_id, job_conf))
            try:
                job_type = job_info['job_type']

                self.handle_new_job(job_id, job_type, job_conf, job_info)
            except Exception:
                self.logger.exception((
                    'Failed to instantiate job'
                    ' (job_id=%s, job_conf=%s)') %
                    (job_type, job_conf))

                self.manager.fail_job(job_id)

    def handle_new_job(self, job_id, job_type, job_conf, job_info):
        """
            Set a new job's configuration
            and get its tasks before dispatching it
        """

        job_tasks = JOB_TYPES[job_type].get_tasks(
            self.conf, self.logger,
            job_conf['params'])

        job_conf.setdefault('beanstalkd_worker_tube',
            self.conf.get('beanstalkd_workers_tube', self.DEFAULT_WORKER_TUBE))
        job_conf['beanstalkd_reply_addr'] = self.reply_beanstalkd_addr
        job_conf['beanstalkd_reply_tube'] = self.reply_tube

        self.handle_job(job_id, job_conf, job_info, job_tasks)

    def handle_running_job(self, job_id, job_conf, job_info):
        """
            Read the job's configuration
            and get its tasks before dispatching it
        """

        if job_info['all_sent']:
            return

        job_type = job_info['job_type']
        last_task_id = None
        if len(job_info['last_sent']) > 0:
            last_task_id = job_info['last_sent']
        job_tasks = JOB_TYPES[job_type].get_tasks(
            self.conf, self.logger,
            job_conf['params'], marker=last_task_id)

        self.handle_job(job_id, job_conf, job_info, job_tasks)

    def handle_job(self, job_id, job_conf, job_info, job_tasks):
        """
            Get the beanstalkd available for this job
            and start the dispatching thread
        """

        worker_tube = job_conf['beanstalkd_worker_tube']

        beanstalkd_workers = \
            self.get_loadbalanced_workers(worker_tube)

        self.manager.start_job(job_id, job_conf)

        thread_args = (job_id, job_conf,
                       job_tasks, beanstalkd_workers)
        dispatch_thread = threading.Thread(
            target=self.dispatch_job,
            args=thread_args)
        dispatch_thread.start()

        self.threads[dispatch_thread.ident] = dispatch_thread

    def dispatch_job(self, job_id, job_conf, job_tasks, beanstalkd_workers):
        """
            Dispatch all of a job's tasks
        """

        try:
            for task in job_tasks:
                (task_class, task_id, task_payload, total_tasks) = task

                sent = self.dispatch_task(beanstalkd_workers, job_id,
                                        task_id, task_class, task_payload)

                if sent:
                    self.manager.task_sent(job_id, task_id, total_tasks)

                if not self.running:
                    break
            else:
                self.logger.info('All tasks sent (job_id=%s)' % job_id)
                self.manager.all_tasks_sent(job_id)

                # threading.current_thread returns the wrong id
                del self.threads[thread.get_ident()]

                return

            self.manager.pause_job(job_id)
        except Exception:
            self.manager.fail_job(job_id)

    def dispatch_task(self, beanstalkd_workers, job_id,
                      task_id, task_class, task_payload):
        """
            Try sending a task until it's ok
        """

        beanstalkd_payload = \
            self.make_beanstalkd_payload(job_id, task_id,
                                         task_class, task_payload)

        if len(beanstalkd_payload) > 2**16:
            raise ValueError('Task payload is too big (length=%s)' % len(beanstalkd_payload))

        while self.running:
            workers_tried = set()
            for worker in beanstalkd_workers:
                if worker is None:
                    self.logger.info('No beanstalkd available (job_id=%s)' % job_id)
                    sleep(5)
                    workers_tried.clear()
                    continue

                if worker.addr in workers_tried:
                    self.logger.debug('Tried all beanstalkd (job_id=%s)' % job_id)
                    sleep(5)
                    workers_tried.clear()
                    continue

                sent = worker.send_job(beanstalkd_payload)

                if not sent:
                    workers_tried.add(worker.addr)

                    continue

                self.logger.debug('Task (job_id=%s, task_id=%s) sent to %s' %
                                  (job_id, task_id, worker.addr))
                return True

            sleep(5)

    def make_beanstalkd_payload(self, job_id,
                                task_id, task_class, task_payload):
        return json.dumps({
            'event': 'xcute.task',
            'data': {
                'job_id': job_id,
                'task_class': pickle.dumps(task_class),
                'task_id': task_id,
                'task_payload': task_payload,
                'beanstalkd_reply': {
                    'addr': self.reply_beanstalkd_addr,
                    'tube': self.reply_tube,
                },
            }
        })

    def listen(self):
        """
            Process this orchestrator's job replies
        """

        self.logger.info('Connecting to the reply beanstalkd')

        while self.running:
            try:
                listener = BeanstalkdListener(
                    addr=self.reply_beanstalkd_addr,
                    tube=self.reply_tube,
                    logger=self.logger)

                break
            except ConnectionError:
                self.logger.error('Failed to connect to the reply beanstalkd')

            sleep(5)

        self.logger.info('Listening to replies on %s (tube=%s)' %
                         (self.reply_beanstalkd_addr, self.reply_tube))

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

    def process_reply(self, beanstalkd_job_id, encoded_reply):
        job_results = self.job_results
        reply = json.loads(encoded_reply)

        job_id = reply['job_id']
        task_id = reply['task_id']
        task_ok = reply['task_ok']
        task_result = reply['task_result']

        self.logger.debug((
            'Task processed'
            ' (job_id=%s, task_id=%s)') %
            (job_id, task_id))

        try:
            if job_id not in job_results:
                job_results[job_id] = self.manager.get_job_result(job_id)

            job_type, job_result = job_results[job_id]

            new_job_result = job_result
            if task_ok:
                new_job_result = JOB_TYPES[job_type].reduce_result(job_result, task_result)

            job_results[job_id] = (job_type, new_job_result)

            job_done = \
                self.manager.task_processed(self.orchestrator_id,
                                            job_id,
                                            task_id, task_ok,
                                            new_job_result)

            if job_done:
                del job_results[job_id]

                self.logger.info('Job done (job_id=%s)' % job_id)
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

    def get_reply_beanstalkd_addr(self):
        """
            Get the beanstalkd used for the reply
        """

        if 'beanstalkd_reply_addr' in self.conf:
            return self.conf['beanstalkd_reply_addr']

        # prefer a local beanstalkd if it's not in the configuration
        for service in self.conscience_client.local_services():
            if service['type'] == 'beanstalkd':
                return service['addr']

        return self.conscience_client.next_instance('beanstalkd')['addr']

    @staticmethod
    def get_beanstalkd_tubes(beanstalkd_addr):
        return Beanstalk.from_url('beanstalkd://' + beanstalkd_addr).tubes()

    def get_loadbalanced_workers(self, worker_tube):
        """
            Yield senders following a loadbalancing strategy
        """

        while True:
            if len(self.all_beanstalkd) == 0:
                yield None

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

    def exit(self, *args, **kwargs):
        if self.running:
            self.logger.info('Exiting gracefully')

            self.running = False

            return

        self.logger.info('Exiting')
        os._exit(1)
