# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
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


import signal

from oio.common.easy_value import int_value
from oio.common.exceptions import OioException, OioTimeout, RetryLater
from oio.common.green import ContextPool, eventlet, ratelimit, sleep, \
    threading, time
from oio.common.json import json
from oio.common.logger import get_logger
from oio.conscience.client import ConscienceClient
from oio.event.beanstalk import Beanstalk, BeanstalkdListener, \
    BeanstalkdSender


DISTRIBUTED_DISPATCHER_TIMEOUT = 300


class Tool(object):
    """
    Process all found items.

    For the task_res variable, the following format must be respected:
    (item, info, error).
    """

    DEFAULT_BEANSTALKD_WORKER_TUBE = 'oio-process'
    DEFAULT_REPORT_INTERVAL = 3600
    DEFAULT_RETRY_DELAY = 3600
    DEFAULT_ITEM_PER_SECOND = 30
    DEFAULT_CONCURRENCY = 1
    DEFAULT_DISTRIBUTED_BEANSTALKD_WORKER_TUBE = 'oio-process'

    def __init__(self, conf, beanstalkd_addr=None, logger=None):
        self.conf = conf
        self.logger = logger or get_logger(self.conf)
        self.namespace = conf['namespace']
        self.success = True

        # exit gracefully
        self.running = True
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

        # counters
        self.items_processed = 0
        self.total_items_processed = 0
        self.errors = 0
        self.total_errors = 0
        self.total_expected_items = None

        # report
        self.start_time = 0
        self.last_report = 0
        self.report_interval = int_value(self.conf.get(
            'report_interval'), self.DEFAULT_REPORT_INTERVAL)

        # dispatcher
        self.dispatcher = None

        # input
        self.beanstalkd = None
        if beanstalkd_addr:
            self.beanstalkd = BeanstalkdListener(
                beanstalkd_addr,
                self.conf.get('beanstalkd_worker_tube')
                or self.DEFAULT_BEANSTALKD_WORKER_TUBE,
                self.logger)

        # retry
        self.retryer = None
        self.retry_queue = None
        if self.beanstalkd:
            self.retryer = BeanstalkdSender(
                self.beanstalkd.addr, self.beanstalkd.tube, self.logger)
            self.retry_queue = eventlet.Queue()
        self.retry_delay = int_value(self.conf.get('retry_delay'),
                                     self.DEFAULT_RETRY_DELAY)

    @staticmethod
    def items_from_task_event(task_event):
        """
        Convert the task event into a list (generator) of items.
        """
        raise NotImplementedError()

    @staticmethod
    def task_event_from_item(item):
        """
        Convert the item into a task event.
        """
        raise NotImplementedError()

    @staticmethod
    def tasks_res_from_res_event(res_event):
        """
        Convert the result event into a list (generator) of tasks result.
        """
        raise NotImplementedError()

    @staticmethod
    def res_event_from_task_res(task_res):
        """
        Convert the task result into a result event.
        """
        raise NotImplementedError()

    @staticmethod
    def string_from_item(item):
        """
        Convert the item into a string.
        """
        raise NotImplementedError()

    def exit_gracefully(self, signum, frame):
        self.logger.info(
            'Stop sending and wait for all results already sent')
        self.success = False
        self.running = False
        if self.beanstalkd:
            self.beanstalkd.running = False

    def _item_with_beanstalkd_reply_from_task_event(self, job_id, data):
        task_event = json.loads(data)
        beanstalkd_reply = task_event.get('beanstalkd_reply')
        items = self.items_from_task_event(task_event)
        for item in items:
            yield (item, beanstalkd_reply)

    def _fetch_items_with_beanstalkd_reply_from_beanstalkd(self):
        # Do not block more than 2 seconds
        return self.beanstalkd.fetch_jobs(
            self._item_with_beanstalkd_reply_from_task_event,
            reserve_timeout=2)

    def _fetch_items(self):
        """
        Fetch items from inputs (other than the beanstalkd).
        """
        raise NotImplementedError()

    def _fetch_items_with_beanstalkd_reply(self):
        items = self._fetch_items()
        for item in items:
            yield (item, None)

    def fetch_items_with_beanstalkd_reply(self):
        """
        Fetch items with beanstalkd reply (useful if the task is distributed).
        """
        if self.beanstalkd:
            return self._fetch_items_with_beanstalkd_reply_from_beanstalkd()
        return self._fetch_items_with_beanstalkd_reply()

    def update_counters(self, task_res):
        """
        Update all counters of the tool.
        """
        _, _, error = task_res
        self.items_processed += 1
        if error is not None:
            self.errors += 1

    def _update_total_counters(self):
        items_processed = self.items_processed
        self.items_processed = 0
        self.total_items_processed += items_processed
        errors = self.errors
        self.errors = 0
        self.total_errors += errors
        return items_processed, self.total_items_processed, \
            errors, self.total_errors

    def _get_report(self, status, end_time, counters):
        raise NotImplementedError()

    def log_report(self, status, force=False):
        """
        Log a report with a fixed interval.
        """
        end_time = time.time()
        if force or (end_time - self.last_report >= self.report_interval):
            counters = self._update_total_counters()
            self.logger.info(self._get_report(status, end_time, counters))
            self.last_report = end_time

    def create_worker(self, queue_workers, queue_reply):
        """
        Create worker to process the items.
        """
        raise NotImplementedError()

    def prepare_local_dispatcher(self):
        """
        The tool will dispatch the tasks locally.
        """
        self.dispatcher = _LocalDispatcher(self.conf, self)

    def prepare_distributed_dispatcher(self):
        """
        The tool will dispatch the tasks on the platform.
        """
        self.dispatcher = _DistributedDispatcher(
            self.conf, self)

    def _load_total_expected_items(self):
        raise NotImplementedError()

    def _read_retry_queue(self):
        if self.retry_queue is None:
            return
        while True:
            # Reschedule jobs we were not able to handle.
            item = self.retry_queue.get()
            if self.retryer:
                sent = False
                while not sent:
                    sent = self.retryer.send_job(
                        json.dumps(self.task_event_from_item(item)),
                        delay=self.retry_delay)
                    if not sent:
                        sleep(1.0)
                self.retryer.job_done()
            self.retry_queue.task_done()

    def run(self):
        """
        Start processing all found items.
        """
        if self.dispatcher is None:
            raise ValueError('No dispatcher')

        eventlet.spawn_n(self._load_total_expected_items)

        # spawn one worker for the retry queue
        eventlet.spawn_n(self._read_retry_queue)

        for task_res in self.dispatcher.run():
            yield task_res

        # block until the retry queue is empty
        if self.retry_queue:
            self.retry_queue.join()

    def is_success(self):
        """
        Check if there are any errors.
        """
        if not self.success:
            return False
        if self.total_items_processed == 0:
            self.logger.warn('No item to process')
        return self.total_errors == 0


class ToolWorker(object):
    """
    Process all items given by the tool.
    """

    def __init__(self, tool, queue_workers, queue_reply):
        self.tool = tool
        self.conf = self.tool.conf
        self.logger = self.tool.logger
        self.queue_workers = queue_workers
        self.queue_reply = queue_reply

        # reply
        self.beanstalkd_reply = None

    def _process_item(self, item):
        raise NotImplementedError()

    def _reply_task_res(self, beanstalkd_reply, task_res):
        self.queue_reply.put(task_res)

        if beanstalkd_reply is None:
            return

        res_event = self.tool.res_event_from_task_res(task_res)
        if self.tool.beanstalkd is not None:
            res_event['beanstalkd_worker'] = \
                {
                    'addr': self.tool.beanstalkd.addr,
                    'tube': self.tool.beanstalkd.tube
                }

        try:
            if self.beanstalkd_reply is None \
                    or self.beanstalkd_reply.addr != beanstalkd_reply['addr'] \
                    or self.beanstalkd_reply.tube != beanstalkd_reply['tube']:
                if self.beanstalkd_reply is not None:
                    self.beanstalkd_reply.close()
                self.beanstalkd_reply = BeanstalkdSender(
                    beanstalkd_reply['addr'], beanstalkd_reply['tube'],
                    self.logger)

            sent = False
            event_json = json.dumps(res_event)
            # This will loop forever if there is a connection issue with the
            # beanstalkd server. We chose to let it loop until someone fixes
            # the problem (or the problem resolves by magic).
            while not sent:
                sent = self.beanstalkd_reply.send_job(event_json)
                if not sent:
                    sleep(1.0)
            self.beanstalkd_reply.job_done()
        except Exception as exc:  # pylint: disable=broad-except
            item, info, error = task_res
            self.logger.warn(
                'Beanstalkd reply failed %s (info=%s error=%s): %s',
                self.tool.string_from_item(item), str(info), error, exc)

    def run(self):
        """
        Starting processing all items given by the tool.
        """
        while True:
            item_with_beanstalkd_reply = self.queue_workers.get()
            if item_with_beanstalkd_reply is None:  # end signal
                break
            item, beanstalkd_reply = item_with_beanstalkd_reply
            info = None
            error = None
            try:
                info = self._process_item(item)
            except RetryLater as exc:
                # Schedule a retry only if the sender did not set reply address
                # (rebuild CLIs set reply address, meta2 does not).
                if self.tool.retry_queue and not beanstalkd_reply:
                    self.logger.warn(
                        "Putting an item (%s) in the retry queue: %s",
                        self.tool.string_from_item(item), exc.args[0])
                    self.tool.retry_queue.put(item)
                else:
                    error = str(exc.args[0])
            except Exception as exc:  # pylint: disable=broad-except
                error = str(exc)
            task_res = (item, info, error)
            self._reply_task_res(beanstalkd_reply, task_res)
            self.queue_workers.task_done()


class _Dispatcher(object):
    """
    Dispatch tasks.
    """

    def __init__(self, conf, tool):
        self.conf = conf
        self.tool = tool
        self.logger = self.tool.logger

    def run(self):
        """
        Start dispatching tasks.
        :returns: the list (generator) of processed tasks
        """
        raise NotImplementedError()


class _LocalDispatcher(_Dispatcher):
    """
    Dispatch tasks locally.
    """

    def __init__(self, conf, tool):
        super(_LocalDispatcher, self).__init__(conf, tool)

        concurrency = int_value(self.conf.get(
            'concurrency'), self.tool.DEFAULT_CONCURRENCY)
        self.max_items_per_second = int_value(self.conf.get(
            'items_per_second'), self.tool.DEFAULT_ITEM_PER_SECOND)
        if self.max_items_per_second > 0:
            # Max 2 seconds in advance
            queue_size = self.max_items_per_second * 2
        else:
            queue_size = concurrency * 64
        self.queue_workers = eventlet.Queue(queue_size)
        self.queue_reply = eventlet.Queue()

        self.workers = list()
        for _ in range(concurrency):
            worker = self.tool.create_worker(
                self.queue_workers, self.queue_reply)
            self.workers.append(worker)

    def _fill_queue(self):
        """
        Fill the queue.
        """
        items_run_time = 0

        try:
            items_with_beanstalkd_reply = \
                self.tool.fetch_items_with_beanstalkd_reply()
            for item_with_beanstalkd_reply in items_with_beanstalkd_reply:
                items_run_time = ratelimit(items_run_time,
                                           self.max_items_per_second)
                self.queue_workers.put(item_with_beanstalkd_reply)

                if not self.tool.running:
                    break
        except Exception as exc:
            if self.tool.running:
                self.logger.error("Failed to fill queue: %s", exc)
                self.tool.success = False

    def _fill_queue_and_wait_all_items(self):
        """
        Fill the queue and wait for all items to be processed.
        """
        self._fill_queue()
        self.queue_workers.join()
        for _ in self.workers:
            self.queue_workers.put(None)
        self.queue_reply.put(None)

    def run(self):
        self.tool.start_time = self.tool.last_report = time.time()
        self.tool.log_report('START', force=True)

        try:
            with ContextPool(len(self.workers) + 1) as pool:
                # spawn workers
                for worker in self.workers:
                    pool.spawn(worker.run)

                # spawn one worker to fill the queue
                pool.spawn(self._fill_queue_and_wait_all_items)

                # with the main thread
                while True:
                    task_res = self.queue_reply.get()
                    if task_res is None:  # end signal
                        break
                    self.tool.update_counters(task_res)
                    yield task_res
                    self.tool.log_report('RUN')
        except Exception:  # pylint: disable=broad-except
            self.logger.exception('ERROR in local dispatcher')
            self.tool.success = False

        self.tool.log_report('DONE', force=True)


def locate_tube(services, tube):
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


class _DistributedDispatcher(_Dispatcher):
    """
    Dispatch tasks on the platform.
    """

    def __init__(self, conf, tool):
        super(_DistributedDispatcher, self).__init__(conf, tool)
        self.sending = None

        self.max_items_per_second = int_value(self.conf.get(
            'items_per_second'), self.tool.DEFAULT_ITEM_PER_SECOND)

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
        workers_tube = self.conf.get('distributed_beanstalkd_worker_tube') \
            or self.tool.DEFAULT_DISTRIBUTED_BEANSTALKD_WORKER_TUBE
        self.beanstalkd_workers = dict()
        for beanstalkd in locate_tube(all_available_beanstalkd.values(),
                                      workers_tube):
            beanstalkd_worker = BeanstalkdSender(
                beanstalkd['addr'], workers_tube, self.logger)
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
        for _, beanstalkd_worker in self.beanstalkd_workers.items():
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
        except Exception as exc:  # pylint: disable=broad-except
            self.logger.warning(
                'ERROR when searching for beanstalkd locally: %s', exc)
        if not beanstalkd_reply:
            self.logger.warn('No beanstalkd available locally')

            try:
                beanstalkd = conscience_client.next_instance('beanstalkd')
                beanstalkd_reply = all_available_beanstalkd[beanstalkd['addr']]
            except Exception as exc:  # pylint: disable=broad-except
                self.logger.warning(
                    'ERROR when searching for beanstalkd: %s', exc)
        beanstalkd_reply_addr = beanstalkd_reply['addr']

        # If the tube exists, another service must have already used this tube
        tube_reply = workers_tube + '.reply.' + str(time.time())
        tubes = Beanstalk.from_url(
            'beanstalk://' + beanstalkd_reply_addr).tubes()
        if tube_reply in tubes:
            raise OioException('Beanstalkd %s using tube %s is already used')

        self.beanstalkd_reply = BeanstalkdListener(
            beanstalkd_reply_addr, tube_reply, self.logger)
        self.logger.info(
            'Beanstalkd %s using tube %s is selected for the replies',
            self.beanstalkd_reply.addr, self.beanstalkd_reply.tube)

    def _fetch_tasks_events_to_send(self):
        items_with_beanstalkd_reply = \
            self.tool.fetch_items_with_beanstalkd_reply()
        for item, _ in items_with_beanstalkd_reply:
            yield self.tool.task_event_from_item(item)

    def _tasks_res_from_res_event(self, job_id, data, **kwargs):
        res_event = json.loads(data)
        beanstalkd_worker_addr = res_event['beanstalkd_worker']['addr']
        tasks_res = self.tool.tasks_res_from_res_event(res_event)
        self.beanstalkd_workers[beanstalkd_worker_addr].job_done()
        return tasks_res

    def _all_events_are_processed(self):
        """
        Tell if all workers have finished to process their events.
        """
        if self.sending:
            return False

        total_events = 0
        for worker in self.beanstalkd_workers.values():
            total_events += worker.nb_jobs
        return total_events <= 0

    def _send_task_event(self, task_event, reply_loc, next_worker):
        """
        Send the event through a non-full sender.
        """
        task_event['beanstalkd_reply'] = reply_loc
        workers = list(self.beanstalkd_workers.values())
        nb_workers = len(workers)
        while True:
            for _ in range(nb_workers):
                success = workers[next_worker].send_job(
                    json.dumps(task_event))
                next_worker = (next_worker + 1) % nb_workers
                if success:
                    return next_worker
            self.logger.warn("All beanstalkd workers are full")
            sleep(5)

    def _distribute_events(self, reply_loc=None):
        next_worker = 0
        items_run_time = 0

        try:
            tasks_events = self._fetch_tasks_events_to_send()
            items_run_time = ratelimit(
                items_run_time, self.max_items_per_second)
            next_worker = self._send_task_event(
                next(tasks_events), reply_loc, next_worker)
            self.sending = True
            for task_event in tasks_events:
                items_run_time = ratelimit(items_run_time,
                                           self.max_items_per_second)
                next_worker = self._send_task_event(task_event, reply_loc,
                                                    next_worker)

                if not self.tool.running:
                    break
        except Exception as exc:
            if not isinstance(exc, StopIteration) and self.tool.running:
                self.logger.error("Failed to distribute events: %s", exc)
                self.tool.success = False
        finally:
            self.sending = False

    def run(self):
        self.tool.start_time = self.tool.last_report = time.time()
        self.tool.log_report('START', force=True)
        reply_loc = {'addr': self.beanstalkd_reply.addr,
                     'tube': self.beanstalkd_reply.tube}
        # pylint: disable=no-member
        thread = threading.Thread(target=self._distribute_events,
                                  args=[reply_loc])
        thread.start()

        # Wait until the thread is started sending events
        while self.sending is None:
            sleep(0.1)

        # Retrieve responses until all events are processed
        try:
            while not self._all_events_are_processed():
                tasks_res = self.beanstalkd_reply.fetch_job(
                    self._tasks_res_from_res_event,
                    timeout=DISTRIBUTED_DISPATCHER_TIMEOUT)
                for task_res in tasks_res:
                    self.tool.update_counters(task_res)
                    yield task_res
                self.tool.log_report('RUN')
        except OioTimeout:
            self.logger.error('No response for %d seconds',
                              DISTRIBUTED_DISPATCHER_TIMEOUT)
            self.tool.success = False
        except Exception:  # pylint: disable=broad-except
            self.logger.exception('ERROR in distributed dispatcher')
            self.tool.success = False

        self.tool.log_report('DONE', force=True)
