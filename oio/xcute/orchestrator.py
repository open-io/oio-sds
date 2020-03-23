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

import math
import random
from collections import OrderedDict
from redis import ConnectionError as RedisConnectionError, \
    TimeoutError as RedisTimeoutError

from oio.common.easy_value import int_value
from oio.common.exceptions import OioTimeout
from oio.common.logger import get_logger
from oio.common.green import ratelimit, sleep, threading
from oio.common.json import json
from oio.conscience.client import ConscienceClient
from oio.event.beanstalk import Beanstalk, BeanstalkdListener, \
    ConnectionError, DEFAULT_TTR
from oio.event.evob import EventTypes
from oio.xcute.common.backend import XcuteBackend
from oio.xcute.jobs import JOB_TYPES


class XcuteOrchestrator(object):

    DEFAULT_DISPATCHER_TIMEOUT = 2
    DEFAULT_REFRESH_TIME_BEANSTALKD_WORKERS = 30
    DEFAULT_MAX_JOBS_PER_BEANSTALKD = 1024

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

        self.beanstalkd_reply_addr = self.conf.get('beanstalkd_reply_addr')
        if not self.beanstalkd_reply_addr:
            raise ValueError('Missing beanstalkd reply address')
        self.beanstalkd_reply_tube = self.conf.get(
            'beanstalkd_reply_tube', self.beanstalkd_workers_tube + '.reply')
        self.logger.info('Using beanstalkd reply : %s %s',
                         self.beanstalkd_reply_addr,
                         self.beanstalkd_reply_tube)

        self.refresh_time_beanstalkd_workers = int_value(
            self.conf.get('refresh_time_beanstalkd_workers'),
            self.DEFAULT_REFRESH_TIME_BEANSTALKD_WORKERS)

        self.max_jobs_per_beanstalkd = int_value(
            self.conf.get('max_jobs_per_beanstalkd'),
            self.DEFAULT_MAX_JOBS_PER_BEANSTALKD)

        self.running = True
        self.beanstalkd_workers = dict()

        self.refresh_beanstalkd_workers_thread = None
        self.listen_beanstalkd_reply_thread = None
        self.dispatch_tasks_threads = dict()
        self.compute_total_tasks_threads = dict()

    def handle_backend_errors(self, func, *args, **kwargs):
        while True:
            try:
                return func(*args, **kwargs), None
            except (RedisConnectionError, RedisTimeoutError) as exc:
                self.logger.warn(
                    'Fail to communicate with redis: %s', exc)
                if not self.running:
                    return None, exc
                sleep(1)

    def safe_run_forever(self):
        try:
            self.run_forever()
        except Exception as exc:
            self.logger.exception('Fail to run forever: %s', exc)
            self.exit_gracefully()

        if self.refresh_beanstalkd_workers_thread:
            self.refresh_beanstalkd_workers_thread.join()
        if self.listen_beanstalkd_reply_thread:
            self.listen_beanstalkd_reply_thread.join()
        for dispatch_tasks_thread in self.dispatch_tasks_threads.values():
            dispatch_tasks_thread.join()
        for compute_total_tasks_thread \
                in self.compute_total_tasks_threads.values():
            compute_total_tasks_thread.join()
        self.logger.info('Exited running thread')

    def run_forever(self):
        """
            Take jobs from the queue and spawn threads to dispatch them
        """

        # gather beanstalkd info
        self.refresh_beanstalkd_workers_thread = threading.Thread(
            target=self.refresh_beanstalkd_workers_forever)
        self.refresh_beanstalkd_workers_thread.start()

        # start processing replies
        self.listen_beanstalkd_reply_thread = threading.Thread(
            target=self.listen_beanstalkd_reply_forever)
        self.listen_beanstalkd_reply_thread.start()

        if not self.running:
            return

        # restart running jobs
        self.logger.debug('Look for unfinished jobs')
        orchestrator_jobs, exc = self.handle_backend_errors(
            self.backend.list_orchestrator_jobs, self.orchestrator_id)
        if exc is not None:
            self.logger.warn(
                'Unable to list running jobs for this orchestrator: %s', exc)
            return
        for job_info in orchestrator_jobs:
            if not self.running:
                return
            self.safe_handle_running_job(job_info)

        # run next jobs
        while self.running:
            sleep(1)
            job_info, exc = self.handle_backend_errors(
                self.backend.run_next, self.orchestrator_id)
            if exc is not None:
                self.logger.warn('Unable to run next job: %s', exc)
                return
            if not job_info:
                continue
            self.safe_handle_running_job(job_info)

    def safe_handle_running_job(self, job_info):
        try:
            job_id = job_info['job']['id']
            job_type = job_info['job']['type']
            self.logger.info('Run job %s: %s', job_id, job_type)
            self.handle_running_job(job_id, job_type, job_info)
        except Exception as exc:
            self.logger.exception('Failed to run job %s: %s', job_id, exc)
            _, exc = self.handle_backend_errors(
                self.backend.fail, job_id)
            if exc is not None:
                self.logger.warn(
                    '[job_id=%s] Job has not been updated '
                    'with the failure: %s', job_id, exc)

    def handle_running_job(self, job_id, job_type, job_info):
        """
        First launch the computation of total number of tasks,
        then launch the dispatchnig of all tasks across the platform.
        """
        if job_info['tasks']['all_sent']:
            self.logger.info(
                '[job_id=%s] All tasks are already sent', job_id)
            return

        job_class = JOB_TYPES[job_type]
        job = job_class(self.conf, logger=self.logger)

        if job_info['tasks']['total'] == 0 \
                and job_info['tasks']['is_total_temp'] \
                and job_info['tasks']['sent'] == 0 \
                and not job_info['tasks']['all_sent']:
            job.prepare(job_info['config']['params'])

        if job_id in self.compute_total_tasks_threads:
            self.logger.info(
                '[job_id=%s] Already computing the total number of tasks',
                job_id)
        elif job_info['tasks']['is_total_temp']:
            compute_total_tasks_thread = threading.Thread(
                target=self.safe_compute_total_tasks,
                args=(job_id, job_type, job_info, job))
            compute_total_tasks_thread.start()
            self.compute_total_tasks_threads[job_id] = \
                compute_total_tasks_thread
        else:
            self.logger.info(
                '[job_id=%s] The total number of tasks is already computed',
                job_id)

        if job_id in self.dispatch_tasks_threads:
            self.logger.warning(
                '[job_id=%s] Already dispatching the tasks', job_id)
        else:
            dispatch_tasks_thread = threading.Thread(
                target=self.safe_dispatch_tasks,
                args=(job_id, job_type, job_info, job))
            dispatch_tasks_thread.start()
            self.dispatch_tasks_threads[job_id] = dispatch_tasks_thread

    def safe_dispatch_tasks(self, job_id, job_type, job_info, job):
        """
        Dispatch all tasks across the platform
        and update the backend.
        """
        try:
            self.logger.info(
                '[job_id=%s] Start to dispatch tasks', job_id)
            self.dispatch_tasks(job_id, job_type, job_info, job)
            self.logger.info(
                '[job_id=%s] Finish to dispatch tasks', job_id)
        except Exception as exc:
            self.logger.exception(
                '[job_id=%s] Fail to dispatch tasks: %s', job_id, exc)
            _, exc = self.handle_backend_errors(
                self.backend.fail, job_id)
            if exc is not None:
                self.logger.warn(
                    '[job_id=%s] Job has not been updated '
                    'with the failure: %s', job_id, exc)
        finally:
            del self.dispatch_tasks_threads[job_id]

    def dispatch_tasks(self, job_id, job_type, job_info, job):
        job_config = job_info['config']
        job_params = job_config['params']
        tasks_per_second = job_config['tasks_per_second']
        tasks_batch_size = job_config['tasks_batch_size']
        last_task_id = job_info['tasks']['last_sent']

        job_tasks = job.get_tasks(job_params, marker=last_task_id)
        beanstalkd_workers = self.get_beanstalkd_workers()

        tasks_run_time = 0
        batch_per_second = tasks_per_second / float(
            tasks_batch_size)
        # The backend must have the tasks in order
        # to know the last task sent
        tasks = OrderedDict()
        for task_id, task_payload in job_tasks:
            if not self.running:
                break

            tasks[task_id] = task_payload
            if len(tasks) < tasks_batch_size:
                continue

            tasks_run_time = ratelimit(
                tasks_run_time, batch_per_second)

            sent = self.dispatch_tasks_batch(
                beanstalkd_workers,
                job_id, job_type, job_config, tasks)
            if sent:
                job_status, exc = self.handle_backend_errors(
                    self.backend.update_tasks_sent, job_id, tasks.keys())
                tasks.clear()
                if exc is not None:
                    self.logger.warn(
                        '[job_id=%s] Job has not been updated '
                        'with the sent tasks: %s', job_id, exc)
                    break
                if job_status == 'PAUSED':
                    self.logger.info('Job %s is paused', job_id)
                    return

            if not self.running:
                break
        else:
            sent = True
            if tasks:
                sent = self.dispatch_tasks_batch(
                    beanstalkd_workers,
                    job_id, job_type, job_config, tasks)
            if sent:
                job_status, exc = self.handle_backend_errors(
                    self.backend.update_tasks_sent, job_id, tasks.keys(),
                    all_tasks_sent=True)
                if exc is None:
                    if job_status == 'FINISHED':
                        self.logger.info('Job %s is finished', job_id)

                    self.logger.info(
                        'Finished dispatching job (job_id=%s)', job_id)
                    return
                else:
                    self.logger.warn(
                        '[job_id=%s] Job has not been updated '
                        'with the last sent tasks: %s', job_id, exc)

        _, exc = self.handle_backend_errors(self.backend.free, job_id)
        if exc is not None:
            self.logger.warn(
                '[job_id=%s] Job has not been freed: %s', job_id, exc)

    def dispatch_tasks_batch(self, beanstalkd_workers,
                             job_id, job_type, job_config, tasks):
        """
            Try sending a task until it's ok
        """

        beanstalkd_payload = self.make_beanstalkd_payload(
            job_id, job_type, job_config, tasks)

        if len(beanstalkd_payload) > 2**16:
            raise ValueError('Task payload is too big (length=%s)' %
                             len(beanstalkd_payload))

        # max 2 minutes per task
        ttr = len(tasks) * DEFAULT_TTR

        while self.running:
            for beanstalkd_worker in beanstalkd_workers:
                if not self.running:
                    return False
                if beanstalkd_worker is not None:
                    break

            try:
                beanstalkd_worker.put(beanstalkd_payload, ttr=ttr)
                self.logger.debug(
                    '[job_id=%s] Tasks sent to %s: %s', job_id,
                    beanstalkd_worker.addr, str(tasks))
                return True
            except Exception as exc:
                self.logger.warn(
                    '[job_id=%s] Fail to send beanstalkd job: %s',
                    job_id, exc)
                # TODO(adu): We could be more lenient
                # and wait for a few errors in a row
                # to happen before marking it as broken.
                beanstalkd_worker.is_broken = True
        return False

    def make_beanstalkd_payload(self, job_id, job_type, job_config,
                                tasks):
        return json.dumps(
            {
                'event': EventTypes.XCUTE_TASKS,
                'data': {
                    'job_id': job_id,
                    'job_type': job_type,
                    'job_config': job_config,
                    'tasks': tasks,
                    'beanstalkd_reply': {
                        'addr': self.beanstalkd_reply_addr,
                        'tube': self.beanstalkd_reply_tube,
                    },
                }
            })

    def safe_compute_total_tasks(self, job_id, job_type, job_info, job):
        """
        Compute the total number of tasks
        and update the backend.
        """
        try:
            self.logger.info(
                '[job_id=%s] Start to compute the total number of tasks',
                job_id)
            self.compute_total_tasks(job_id, job_type, job_info, job)
            self.logger.info(
                '[job_id=%s] Finish to compute the total number of tasks',
                job_id)
        except Exception as exc:
            self.logger.exception(
                '[job_id=%s] Fail to compute the total number of tasks: %s',
                job_id, exc)
        finally:
            del self.compute_total_tasks_threads[job_id]

    def compute_total_tasks(self, job_id, job_type, job_info, job):
        job_params = job_info['config']['params']
        total_marker = job_info['tasks']['total_marker']

        tasks_counter = job.get_total_tasks(
                job_params, marker=total_marker)
        for total_marker, tasks_incr in tasks_counter:
            stop, exc = self.handle_backend_errors(
                self.backend.incr_total_tasks, job_id,
                total_marker, tasks_incr)
            if exc is not None:
                self.logger.warn(
                    '[job_id=%s] Job has not been updated '
                    'with total tasks: %s', job_id, exc)
                return
            if stop or not self.running:
                return

        total_tasks, exc = self.handle_backend_errors(
            self.backend.total_tasks_done, job_id)
        if exc is not None:
            self.logger.warn(
                '[job_id=%s] Job has not been updated '
                'with last total tasks: %s', job_id, exc)
            return
        self.logger.info(
            '[job_id=%s] %s estimated tasks', job_id, total_tasks)

    def listen_beanstalkd_reply_forever(self):
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
                         self.beanstalkd_reply_addr,
                         self.beanstalkd_reply_tube)

        # keep the job results in memory
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
        reply = json.loads(encoded_reply)

        job_id = reply['job_id']
        task_ids = reply['task_ids']
        task_results = reply['task_results']
        task_errors = reply['task_errors']

        self.logger.debug('Tasks processed (job_id=%s): %s', job_id, task_ids)

        try:
            finished, exc = self.handle_backend_errors(
                self.backend.update_tasks_processed,
                job_id, task_ids, task_errors, task_results)
            if exc is None:
                if finished:
                    self.logger.info('Job %s is finished', job_id)
            else:
                self.logger.warn(
                    '[job_id=%s] Job has not been updated '
                    'with the processed tasks: %s', job_id, exc)
        except Exception:
            self.logger.exception('Error processing reply')

        yield None

    def refresh_beanstalkd_workers_forever(self):
        """
        Refresh beanstalkd workers by looking at the score,
        existing tubes and tube statistics.
        """
        while self.running:
            try:
                beanstalkd_workers = self._find_beanstalkd_workers()
            except Exception as exc:
                self.logger.error(
                    'Fail to find beanstalkd workers: %s', exc)
                # TODO(adu): We could keep trying to send jobs
                # to the beanstalkd we already found.
                # But we need the score to know how to dispatch the tasks...
                beanstalkd_workers = dict()

            old_beanstalkd_workers_addr = set(self.beanstalkd_workers.keys())
            new_beanstalkd_workers_addr = set(beanstalkd_workers.keys())

            added_beanstalkds = new_beanstalkd_workers_addr \
                - old_beanstalkd_workers_addr
            for beanstalkd_addr in added_beanstalkds:
                self.logger.info('Add beanstalkd %s' % beanstalkd_addr)
                beanstalkd = beanstalkd_workers[beanstalkd_addr]
                beanstalkd.use(self.beanstalkd_workers_tube)

            removed_beanstalkds = old_beanstalkd_workers_addr \
                - new_beanstalkd_workers_addr
            for beanstalkd_addr in removed_beanstalkds:
                self.logger.info('Remove beanstalkd %s' % beanstalkd_addr)

            self.logger.info('Refresh beanstalkd workers')
            self.beanstalkd_workers = beanstalkd_workers

            for _ in range(self.refresh_time_beanstalkd_workers):
                if not self.running:
                    break
                sleep(1)

        self.logger.info('Exited beanstalkd workers thread')

    def _find_beanstalkd_workers(self):
        """
        Find beanstalkd workers by looking at the score,
        existing tubes and tube statistics.
        """
        all_beanstalkd = self.conscience_client.all_services(
            'beanstalkd')

        beanstalkd_workers = dict()
        for beanstalkd_info in all_beanstalkd:
            try:
                beanstalkd = self._check_beanstalkd_worker(beanstalkd_info)
                if not beanstalkd:
                    continue
                beanstalkd_workers[beanstalkd.addr] = beanstalkd
            except Exception as exc:
                self.logger.error('Fail to check beanstalkd: %s', exc)
        return beanstalkd_workers

    def _check_beanstalkd_worker(self, beanstalkd_info):
        """
        Check beanstalkd worker by looking at the score,
        existing tubes and tube statistics.
        """
        beanstalkd_addr = 'beanstalk://' + beanstalkd_info['addr']
        beanstalkd_score = beanstalkd_info['score']
        if beanstalkd_score == 0:
            self.logger.debug(
                'Ignore beanstalkd %s: score=0', beanstalkd_addr)
            return None

        beanstalkd = self.beanstalkd_workers.get(beanstalkd_addr)
        if not beanstalkd:
            beanstalkd = Beanstalk.from_url(beanstalkd_addr)
            beanstalkd.addr = beanstalkd_addr

        beanstalkd_tubes = beanstalkd.tubes()
        if self.beanstalkd_workers_tube not in beanstalkd_tubes:
            self.logger.debug(
                'Ignore beanstalkd %s: '
                'No worker has ever listened to the tube %s',
                beanstalkd_addr, self.beanstalkd_workers_tube)
            return None

        current_stats = beanstalkd.stats_tube(
            self.beanstalkd_workers_tube)
        beanstalkd_jobs_ready = current_stats['current-jobs-ready']
        if beanstalkd_jobs_ready > 0:
            beanstalkd_jobs_reserved = current_stats['current-jobs-reserved']
            if beanstalkd_jobs_reserved <= 0:
                self.logger.warn(
                    'Ignore beanstalkd %s: The worker doesn\'t process task '
                    '(current-jobs-ready=%d, current-jobs-reserved=%d)',
                    beanstalkd_addr, beanstalkd_jobs_ready,
                    beanstalkd_jobs_reserved)
                return None

            if beanstalkd_jobs_ready >= self.max_jobs_per_beanstalkd:
                self.logger.warn(
                    'Ignore beanstalkd %s: The queue is full '
                    '(current-jobs-ready=%d, current-jobs-reserved=%d)',
                    beanstalkd_addr, beanstalkd_jobs_ready,
                    beanstalkd_jobs_reserved)
                return None

        if hasattr(beanstalkd, 'is_broken') and beanstalkd.is_broken:
            self.logger.info(
                'Beanstalkd %s was broken, and now it\'s coming back',
                beanstalkd_addr)
        beanstalkd.is_broken = False

        # Favor the workers with a good score
        # 50% -> beanstalkd score
        worker_score = beanstalkd_score * 50. / 100.
        # 50% -> beanstalkd tube size
        worker_score += 50 - (beanstalkd_jobs_ready * 50.
                              / self.max_jobs_per_beanstalkd)
        beanstalkd.occurrence = int(math.ceil(worker_score / 10.))

        self.logger.debug(
            'Give the green light to beanstalkd %s (worker_score=%d)',
            beanstalkd_addr, worker_score)
        return beanstalkd

    def get_beanstalkd_workers(self):
        """
            Yield beanstalkd workers following a loadbalancing strategy
        """

        beanstalkd_workers_id = None
        beanstalkd_workers = list()
        while True:
            if not self.beanstalkd_workers:
                self.logger.info('No beanstalkd worker available')
                sleep(1)
                yield None
                continue

            if id(self.beanstalkd_workers) != beanstalkd_workers_id:
                beanstalkd_workers_id = id(self.beanstalkd_workers)
                beanstalkd_workers = list()
                for beanstalkd in self.beanstalkd_workers.values():
                    for _ in range(beanstalkd.occurrence):
                        beanstalkd_workers.append(beanstalkd)

            # Shuffle to not have the same suite for all jobs
            random.shuffle(beanstalkd_workers)

            yielded = False
            for beanstalkd_worker in beanstalkd_workers:
                if id(self.beanstalkd_workers) != beanstalkd_workers_id:
                    break
                if beanstalkd_worker.is_broken:
                    continue
                yield beanstalkd_worker
                yielded = True
            else:
                if not yielded:
                    self.logger.info(
                        'All beanstalkd workers available are broken')
                    sleep(1)
                    yield None

    def exit_gracefully(self, *args, **kwargs):
        if self.running:
            self.logger.info('Exiting gracefully')
            self.running = False
        else:
            self.logger.info('Already exiting gracefully')
