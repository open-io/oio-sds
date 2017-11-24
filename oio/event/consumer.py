# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
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
import signal
import os
import sys

import greenlet
import eventlet
from eventlet import Timeout, greenthread
from oio.common.exceptions import OioNetworkException

from oio.conscience.client import ConscienceClient
from oio.rdir.client import RdirClient
from oio.event.beanstalk import Beanstalk, ConnectionError
from oio.common.utils import drop_privileges
from oio.common.easy_value import true_value, int_value
from oio.common.json import json
from oio.event.evob import is_success, is_error
from oio.event.loader import loadhandlers
from oio.common.exceptions import ExplicitBury


SLEEP_TIME = 1
ACCOUNT_SERVICE_TIMEOUT = 60
ACCOUNT_SERVICE = 'account'
DEFAULT_TUBE = 'oio'

BEANSTALK_RECONNECTION = 2.0
# default release delay (in seconds)
RELEASE_DELAY = 15


def _eventlet_stop(client, server, beanstalk):
    try:
        try:
            client.wait()
        finally:
            beanstalk.close()
    except greenlet.GreenletExit:
        pass
    except Exception:
        greenthread.kill(server, *sys.exc_info())


class StopServe(Exception):
    pass


class Worker(object):

    SIGNALS = [getattr(signal, "SIG%s" % x)
               for x in "HUP QUIT INT TERM CHLD".split()]

    def __init__(self, ppid, conf, logger):
        self.ppid = ppid
        self.conf = conf
        self.started = False
        self.aborted = False
        self.alive = True
        self.logger = logger

    @property
    def pid(self):
        return os.getpid()

    def run(self):
        raise NotImplementedError()

    def init(self):
        drop_privileges(self.conf.get("user", "openio"))

        self.init_signals()

        self.started = True
        # main loop
        self.run()

    def init_signals(self):
        [signal.signal(s, signal.SIG_DFL) for s in self.SIGNALS]
        signal.signal(signal.SIGQUIT, self.handle_quit)
        signal.signal(signal.SIGTERM, self.handle_exit)
        signal.signal(signal.SIGINT, self.handle_quit)
        signal.siginterrupt(signal.SIGTERM, False)

    def handle_exit(self, sig, frame):
        self.alive = False

    def handle_quit(self, sig, frame):
        self.alive = False
        eventlet.sleep(0.1)
        sys.exit(0)

    def parent_alive(self):
        if self.ppid != os.getppid():
            self.logger.warn("parent changed, shutting down")
            return False
        return True


class EventTypes(object):
    CHUNK_NEW = 'storage.chunk.new'
    CHUNK_DELETED = 'storage.chunk.deleted'
    CONTAINER_NEW = 'storage.container.new'
    CONTAINER_DELETED = 'storage.container.deleted'
    CONTAINER_STATE = 'storage.container.state'
    CONTENT_BROKEN = 'storage.content.broken'
    CONTENT_NEW = 'storage.content.new'
    CONTENT_DELETED = 'storage.content.deleted'


def _stop(client, server):
    try:
        client.wait()
    except greenlet.GreenletExit:
        pass
    except Exception:
        greenthread.kill(server, *sys.exc_info())


class EventWorker(Worker):
    def __init__(self, *args, **kwargs):
        super(EventWorker, self).__init__(*args, **kwargs)
        self.app_env = dict()

    def init(self):
        eventlet.monkey_patch(os=False)
        self.tube = self.conf.get("tube", DEFAULT_TUBE)
        self.cs = ConscienceClient(self.conf, logger=self.logger)
        self.rdir = RdirClient(self.conf, logger=self.logger)
        self._acct_addr = None
        self.acct_update = 0
        self.graceful_timeout = 1
        self.acct_refresh_interval = int_value(
            self.conf.get('acct_refresh_interval'), 60
        )
        self.acct_update = true_value(self.conf.get('acct_update', True))
        self.rdir_update = true_value(self.conf.get('rdir_update', True))
        self.app_env['acct_addr'] = self.acct_addr
        if 'handlers_conf' not in self.conf:
            raise ValueError("'handlers_conf' path not defined in conf")
        self.handlers = loadhandlers(self.conf.get('handlers_conf'),
                                     global_conf=self.conf,
                                     app=self)
        super(EventWorker, self).init()

    def notify(self):
        """TODO"""
        pass

    def safe_decode_job(self, job_id, data):
        try:
            env = json.loads(data)
            env['job_id'] = job_id
            return env
        except Exception as exc:
            self.logger.warn('Failed to decode job %s: "%s"',
                             job_id, str(exc.message))
            return None

    def run(self):
        coros = []
        queue_url = self.conf.get('queue_url', '127.0.0.1:11300')
        concurrency = int_value(self.conf.get('concurrency'), 10)

        server_gt = greenthread.getcurrent()

        for i in range(concurrency):
            beanstalk = Beanstalk.from_url(queue_url)
            gt = eventlet.spawn(self.handle, beanstalk)
            gt.link(_eventlet_stop, server_gt, beanstalk)
            coros.append(gt)
            beanstalk, gt = None, None

        while self.alive:
            self.notify()
            try:
                eventlet.sleep(1.0)
            except AssertionError:
                self.alive = False
                break

        self.notify()
        try:
            with Timeout(self.graceful_timeout) as t:
                [c.kill(StopServe()) for c in coros]
                [c.wait() for c in coros]
        except Timeout as te:
            if te != t:
                raise
            [c.kill() for c in coros]

    def handle(self, beanstalk):
        conn_error = False
        try:
            if self.tube:
                beanstalk.use(self.tube)
                beanstalk.watch(self.tube)
            while True:
                try:
                    job_id, data = beanstalk.reserve()
                    if conn_error:
                        self.logger.warn("beanstalk reconnected")
                        conn_error = False
                except ConnectionError:
                    if not conn_error:
                        self.logger.warn("beanstalk connection error")
                        conn_error = True
                    eventlet.sleep(BEANSTALK_RECONNECTION)
                    continue
                event = self.safe_decode_job(job_id, data)
                try:
                    self.process_event(job_id, event, beanstalk)
                except OioNetworkException as exc:
                    self.logger.warn("Burying event %s (%s): %s",
                                     job_id, event.get('event'), exc)
                    beanstalk.bury(job_id)
                except ExplicitBury:
                    self.logger.info("Burying event %s (%s)",
                                     job_id, event.get('event'))
                    beanstalk.bury(job_id)
                except Exception:
                    self.logger.exception("Burying event %s: %s",
                                          job_id, event)
                    beanstalk.bury(job_id)
        except StopServe:
            pass

    def process_event(self, job_id, event, beanstalk):
        handler = self.get_handler(event)
        if not handler:
            self.logger.warn('no handler found for %r' % event)
            beanstalk.delete(job_id)
            return

        def cb(status, msg):
            if is_success(status):
                beanstalk.delete(job_id)
            elif is_error(status):
                self.logger.warn(
                    'event %s handling failure (release with delay): %s',
                    event['job_id'], msg)
                beanstalk.release(job_id, delay=RELEASE_DELAY)

        handler(event, cb)

    def get_handler(self, event):
        return self.handlers.get(event.get('event'), None)

    def acct_addr(self):
        if not self._acct_addr or self.acct_refresh():
            acct_instance = self.cs.next_instance(ACCOUNT_SERVICE)
            self._acct_addr = acct_instance.get('addr')
            self.acct_update = time.time()
        return self._acct_addr

    def acct_refresh(self):
        return (time.time() - self.acct_update) > self.acct_refresh_interval
