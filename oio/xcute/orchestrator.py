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

from oio.common.logger import get_logger
from oio.common.green import ratelimit, sleep, threading
from oio.common.json import json
from oio.conscience.client import ConscienceClient
from oio.event.beanstalk import Beanstalk, \
    BeanstalkdSender, ConnectionError
from oio.xcute.common.backend import XcuteBackend
from oio.xcute.jobs import JOB_TYPES


class XcuteOrchestrator(object):

    DEFAULT_DISPATCHER_TIMEOUT = 2

    def __init__(self, conf, logger=None):
        self.conf = conf
        self.logger = logger or get_logger(self.conf)
        self.backend = XcuteBackend(self.conf, logger=self.logger)
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

        self.running = True
        self.threads = {}

    def run_forever(self):
        """
            Take jobs from the queue and spawn threads to dispatch them
        """

        # gather beanstalkd info
        self.all_beanstalkd = OrderedDict()
        self.beanstalkd_senders = {}
        beanstalkd_thread = threading.Thread(
            target=self.refresh_all_beanstalkd)
        beanstalkd_thread.start()

        self.logger.info('Wait until beanstalkd are found')
        while len(self.all_beanstalkd) == 0:
            if not self.running:
                return

            sleep(5)

        self.threads[beanstalkd_thread.ident] = beanstalkd_thread

        # restart running jobs
        self.logger.debug('Look for unfinished jobs')
        orchestrator_jobs = \
            self.backend.list_orchestrator_jobs(self.orchestrator_id)

        for job_info in orchestrator_jobs:
            job_id = job_info['job']['id']
            self.logger.info('Found running job %s', job_id)
            self.handle_running_job(job_info)

        while self.running:
            # remove dead dispatching threads
            for thread_id, thread_ in self.threads.items():
                if not thread_.is_alive():
                    del self.threads[thread_id]

            self.orchestrate_loop()

            sleep(2)

        for thread_ in self.threads.values():
            thread_.join()

        self.logger.info('Exited running thread')

    def orchestrate_loop(self):
        """
            One iteration of the main loop
        """

        new_jobs = iter(
            lambda: self.backend.run_next(self.orchestrator_id), None)
        for job_info in new_jobs:
            job_id = job_info['job']['id']
            self.logger.info('Found new job %s', job_id)
            try:
                self.handle_running_job(job_info)
            except Exception:
                self.logger.exception(
                    'Failed to instantiate job %s', job_id)
                self.backend.fail(job_id)

    def handle_running_job(self, job_info):
        """
            Read the job's configuration
            and get its tasks before dispatching it
        """
        if job_info['tasks']['all_sent']:
            return

        job_id = job_info['job']['id']
        job_type = job_info['job']['type']
        last_task_id = job_info['tasks']['last_sent']
        total_marker = job_info['tasks']['total_marker']
        job_config = job_info['config']
        job_params = job_config['params']
        job_class = JOB_TYPES[job_type]
        job = job_class(self.conf, logger=self.logger)
        job_tasks = job.get_tasks(job_params, marker=last_task_id)

        tasks_counter = None
        if job_info['tasks']['is_total_temp']:
            tasks_counter = job.get_total_tasks(
                job_params, marker=total_marker)

        beanstalkd_workers = self.get_loadbalanced_workers()

        thread_args = (job_id, job_type, job_config, job_tasks,
                       beanstalkd_workers)
        dispatch_thread = threading.Thread(
            target=self.dispatch_job,
            args=thread_args)
        dispatch_thread.start()

        self.threads[dispatch_thread.ident] = dispatch_thread

        if tasks_counter is None:
            return

        total_tasks_thread = threading.Thread(
            target=self.get_job_total_tasks,
            args=(job_id, tasks_counter))
        total_tasks_thread.start()

    def dispatch_job(self, job_id, job_type, job_config, job_tasks,
                     beanstalkd_workers):
        """
            Dispatch all of a job's tasks
        """

        self.logger.info('Start dispatching job (job_id=%s)', job_id)

        try:
            tasks_per_second = job_config['tasks_per_second']
            tasks_batch_size = job_config['tasks_batch_size']

            tasks_run_time = 0
            batch_per_second = tasks_per_second / float(
                tasks_batch_size)
            tasks = dict()
            for task_id, task_payload in job_tasks:
                if not self.running:
                    break

                tasks[task_id] = task_payload
                if len(tasks) < tasks_batch_size:
                    continue

                tasks_run_time = ratelimit(
                    tasks_run_time, batch_per_second)

                sent = self.dispatch_tasks(
                    beanstalkd_workers,
                    job_id, job_type, job_config, tasks)
                if sent:
                    job_status = self.backend.update_tasks_sent(
                        job_id, tasks.keys())
                    tasks = dict()
                    if job_status == 'PAUSED':
                        self.logger.info('Job %s is paused', job_id)
                        return
            else:
                self.logger.info('All tasks sent (job_id=%s)' % job_id)

                sent = self.dispatch_tasks(
                    beanstalkd_workers,
                    job_id, job_type, job_config, tasks)
                if sent:
                    job_status = self.backend.update_tasks_sent(
                        job_id, tasks.keys(), all_tasks_sent=True)
                    if job_status == 'FINISHED':
                        self.logger.info('Job %s is finished', job_id)

                    self.logger.info('Finished dispatching job (job_id=%s)',
                                     job_id)
                    return

            self.backend.free(job_id)
        except Exception:
            self.logger.exception('Failed generating task list (job_id=%s)',
                                  job_id)

            self.backend.fail(job_id)

    def dispatch_tasks(self, beanstalkd_workers,
                       job_id, job_type, job_config, tasks):
        """
            Try sending a task until it's ok
        """

        beanstalkd_payload = self.make_beanstalkd_payload(
            job_id, job_type, job_config, tasks)

        if len(beanstalkd_payload) > 2**16:
            raise ValueError('Task payload is too big (length=%s)' %
                             len(beanstalkd_payload))

        while self.running:
            workers_tried = set()
            for worker in beanstalkd_workers:
                if worker is None:
                    self.logger.info('No beanstalkd available (job_id=%s)',
                                     job_id)
                    break

                if worker.addr in workers_tried:
                    self.logger.debug('Tried all beanstalkd (job_id=%s)',
                                      job_id)
                    break

                sent = worker.send_job(beanstalkd_payload)

                if not sent:
                    workers_tried.add(worker.addr)

                    continue

                self.logger.debug('Tasks (job_id=%s) sent to %s: %s',
                                  job_id, worker.addr, tasks)
                return True

            workers_tried.clear()
            sleep(5)

    def make_beanstalkd_payload(self, job_id, job_type, job_config,
                                tasks):
        return json.dumps(
            {
                'event': 'xcute.tasks',
                'data': {
                    'job_id': job_id,
                    'job_type': job_type,
                    'job_config': job_config,
                    'tasks': tasks
                }
            })

    def get_job_total_tasks(self, job_id, tasks_counter):
        for total_marker, tasks_incr in tasks_counter:
            stop = self.backend.incr_total_tasks(
                job_id, total_marker, tasks_incr)

            if stop or not self.running:
                return

        total_tasks = self.backend.total_tasks_done(job_id)

        self.logger.info('Job %s has %s tasks', job_id, total_tasks)

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
                    beanstalkd_tubes = self.get_beanstalkd_tubes(
                        beanstalkd_addr)
                except ConnectionError:
                    continue

                all_beanstalkd_with_tubes[beanstalkd_addr] = (
                    beanstalkd, beanstalkd_tubes)

            for beanstalkd_addr in self.all_beanstalkd:
                if beanstalkd_addr in all_beanstalkd_with_tubes:
                    continue

                self.logger.info('Removed beanstalkd %s' % beanstalkd_addr)
                del self.all_beanstalkd[beanstalkd_addr]

            for beanstalkd_addr, beanstalkd \
                    in all_beanstalkd_with_tubes.iteritems():
                if beanstalkd_addr not in self.all_beanstalkd:
                    self.logger.info('Found beanstalkd %s' % beanstalkd_addr)

                self.all_beanstalkd[beanstalkd_addr] = beanstalkd + ({},)

            sleep(5)

        self.logger.info('Exited beanstalkd thread')

    @staticmethod
    def get_beanstalkd_tubes(beanstalkd_addr):
        return Beanstalk.from_url('beanstalkd://' + beanstalkd_addr).tubes()

    def get_loadbalanced_workers(self):
        """
            Yield senders following a loadbalancing strategy
        """

        while True:
            yielded = False
            for beanstalkd, beanstalkd_tubes, beanstalkd_senders \
                    in self.all_beanstalkd.itervalues():
                if beanstalkd['score'] == 0:
                    continue

                if self.beanstalkd_workers_tube not in beanstalkd_tubes:
                    continue

                if self.beanstalkd_workers_tube not in beanstalkd_senders:
                    sender = BeanstalkdSender(
                        addr=beanstalkd['addr'],
                        tube=self.beanstalkd_workers_tube,
                        logger=self.logger)

                    beanstalkd_senders[self.beanstalkd_workers_tube] = sender

                yield beanstalkd_senders[self.beanstalkd_workers_tube]
                yielded = True

            if not yielded:
                yield None

    def exit_gracefully(self, *args, **kwargs):
        if self.running:
            self.logger.info('Exiting gracefully')
            self.running = False
        else:
            self.logger.info('Already exiting gracefully')
