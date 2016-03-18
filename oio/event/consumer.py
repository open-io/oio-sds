import time
import signal
import os
import sys

import greenlet
import eventlet
from eventlet import GreenPile, Timeout, greenthread

from oio.conscience.client import ConscienceClient
from oio.rdir.client import RdirClient
from oio.event.beanstalk import Beanstalk
from oio.common.http import requests
from oio.common.utils import true_value, drop_privileges, \
        json, int_value


SLEEP_TIME = 1
PARALLEL_CHUNKS_DELETE = 2
CHUNK_TIMEOUT = 60
ACCOUNT_SERVICE_TIMEOUT = 60


ACCOUNT_SERVICE = 'account'


class StopServe(Exception):
    pass


class Worker(object):

    SIGNALS = [getattr(signal, "SIG%s" % x)
               for x in "HUP QUIT INT TERM CHLD".split()]

    def __init__(self, ppid, conf, logger):
        self.ppid = ppid
        self.conf = conf
        self.booted = False
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

        self.booted = True
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
        time.sleep(0.1)
        sys.exit(0)

    def parent_alive(self):
        if self.ppid != os.getppid():
            self.logger.warn("parent changed, shutting down")
            return False
        return True


class EventType(object):
    REFERENCE_UPDATE = "meta1.account.services"
    CONTAINER_PUT = "meta2.container.create"
    CONTAINER_DESTROY = "meta2.container.destroy"
    CONTAINER_UPDATE = "meta2.container.state"
    OBJECT_PUT = "meta2.content.new"
    OBJECT_DELETE = "meta2.content.deleted"
    CHUNK_PUT = "rawx.chunk.new"
    CHUNK_DELETE = "rawx.chunk.delete"
    PING = "ping"


def _stop(client, server):
    try:
        client.wait()
    except greenlet.GreenletExit:
        pass
    except Exception:
        greenthread.kill(server, *sys.exc_info())


class EventWorker(Worker):
    def init(self):
        eventlet.monkey_patch(os=False)
        self.session = requests.Session()
        self.cs = ConscienceClient(self.conf)
        self.rdir = RdirClient(self.conf)
        self._acct_addr = None
        self.acct_update = 0
        self.graceful_timeout = 1
        self.acct_refresh_interval = int_value(
            self.conf.get('acct_refresh_interval'), 60
        )
        self.concurrency = int_value(self.conf.get('concurrency'), 1000)
        self.acct_update = true_value(self.conf.get('acct_update', True))
        self.rdir_update = true_value(self.conf.get('rdir_update', True))
        super(EventWorker, self).init()

    def notify(self):
        """TODO"""
        pass

    def safe_decode_job(self, job):
        try:
            return json.loads(job)
        except Exception as e:
            self.logger.warn('ERROR decoding job "%s"', str(e.message))
            return None

    def run(self):
        queue_url = self.conf.get('queue_url', 'tcp://127.0.0.1:11300')
        self.beanstalk = Beanstalk.from_url(queue_url)

        gt = eventlet.spawn(
            self.handle)

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
                gt.kill(StopServe())
                gt.wait()
        except Timeout as te:
            if te != t:
                raise
            gt.kill()

    def handle(self):
        try:
            while True:
                job_id, data = self.beanstalk.reserve()
                try:
                    event = self.safe_decode_job(data)
                    if event:
                        self.process_event(event)
                    self.beanstalk.delete(job_id)
                except Exception:
                    self.logger.exception("ERROR handling event %s", job_id)
        except StopServe:
            self.logger.info('Stopping event handler')

    def process_event(self, event):
        handler = self.get_handler(event)
        if not handler:
            self.logger.warn("ERROR no handler found for event")
            # mark as success
            return True
        success = True
        try:
            handler(event)
        except Exception:
            success = False
        finally:
            return success

    def get_handler(self, event):
        event_type = event.get('event')
        if not event_type:
            return None

        if event_type == EventType.CONTAINER_PUT:
            return self.handle_container_put
        elif event_type == EventType.CONTAINER_DESTROY:
            return self.handle_container_destroy
        elif event_type == EventType.CONTAINER_UPDATE:
            return self.handle_container_update
        elif event_type == EventType.OBJECT_PUT:
            return self.handle_object_put
        elif event_type == EventType.OBJECT_DELETE:
            return self.handle_object_delete
        elif event_type == EventType.REFERENCE_UPDATE:
            return self.handle_reference_update
        elif event_type == EventType.CHUNK_PUT:
            return self.handle_chunk_put
        elif event_type == EventType.CHUNK_DELETE:
            return self.handle_chunk_delete
        elif event_type == EventType.PING:
            return self.handle_ping
        else:
            return None

    @property
    def acct_addr(self):
        if not self._acct_addr or self.acct_refresh():
            try:
                acct_instance = self.cs.next_instance(ACCOUNT_SERVICE)
                self._acct_addr = acct_instance.get('addr')
                self.acct_update = time.time()
            except Exception:
                self.logger.warn('Unable to find account instance')
        return self._acct_addr

    def acct_refresh(self):
        return (time.time() - self.acct_update) > self.acct_refresh_interval

    def handle_container_put(self, event):
        """
        Handle container creation.
        :param event:
        """
        self.logger.debug('worker handle container put')
        if not self.acct_update:
            return
        uri = 'http://%s/v1.0/account/container/update' % self.acct_addr
        mtime = event.get('when')
        data = event.get('data')
        name = data.get('url').get('user')
        account = data.get('url').get('account')

        event = {'mtime': mtime, 'name': name}
        self.session.post(uri, params={'id': account}, json=event)

    def handle_container_update(self, event):
        """
        Handle container update.
        :param event:
        """
        self.logger.debug('worker handle container update')
        if not self.acct_update:
            return
        uri = 'http://%s/v1.0/account/container/update' % self.acct_addr
        mtime = event.get('when')
        data = event.get('data')
        name = event.get('url').get('user')
        account = event.get('url').get('account')
        bytes_count = data.get('bytes-count', 0)
        object_count = data.get('object-count', 0)

        event = {
            'mtime': mtime,
            'name': name,
            'bytes': bytes_count,
            'objects': object_count
        }
        self.session.post(uri, params={'id': account}, json=event)

    def handle_container_destroy(self, event):
        """
        Handle container destroy.
        :param event:
        """
        self.logger.debug('worker handle container destroy')
        if not self.acct_update:
            return
        uri = 'http://%s/v1.0/account/container/update' % self.acct_addr
        dtime = event.get('when')
        data = event.get('data')
        name = data.get('url').get('user')
        account = data.get('url').get('account')

        event = {'dtime': dtime, 'name': name}
        self.session.post(uri, params={'id': account}, data=json.dumps(event))

    def handle_object_delete(self, event):
        """
        Handle object deletion.
        Delete the chunks of the object.
        :param event:
        """
        self.logger.debug('worker handle object delete')
        pile = GreenPile(PARALLEL_CHUNKS_DELETE)

        chunks = []

        for item in event.get('data'):
            if item.get('type') == 'chunks':
                chunks.append(item)
        if not len(chunks):
            self.logger.warn('No chunks found in event data')
            return

        def delete_chunk(chunk):
            resp = None
            try:
                with Timeout(CHUNK_TIMEOUT):
                    resp = self.session.delete(chunk['id'])
            except (Exception, Timeout) as e:
                self.logger.warn('error while deleting chunk %s "%s"',
                                 chunk['id'], str(e.message))
            return resp

        for chunk in chunks:
            pile.spawn(delete_chunk, chunk)

        resps = [resp for resp in pile if resp]

        for resp in resps:
            if resp.status_code == 204:
                self.logger.debug('deleted chunk %s' % resp.url)
            else:
                self.logger.warn('failed to delete chunk %s' % resp.url)

    def handle_object_put(self, event):
        """
        Handle object creation.
        TODO
        :param event:
        """
        self.logger.debug('worker handle object put')

    def handle_reference_update(self, event):
        """
        Handle reference update.
        TODO
        :param event
        """
        self.logger.debug('worker handle reference update')

    def handle_chunk_put(self, event):
        """
        Handle chunk creation.
        :param event
        """
        if not self.rdir_update:
            self.logger.debug('worker skip chunk creation')
            return

        self.logger.debug('worker handle chunk creation')

        when = event.get('when')
        data = event.get('data')
        volume_id = data.get('volume_id')
        del data['volume_id']
        container_id = data.get('container_id')
        del data['container_id']
        content_id = data.get('content_id')
        del data['content_id']
        chunk_id = data.get('chunk_id')
        del data['chunk_id']
        data['mtime'] = when
        self.rdir.chunk_push(volume_id, container_id, content_id, chunk_id,
                             **data)

    def handle_chunk_delete(self, event):
        """
        Handle chunk deletion.
        :param event
        """
        if not self.rdir_update:
            self.logger.debug('worker skip chunk deletion')
            return

        self.logger.debug('worker handle chunk deletion')

        data = event.get('data')
        volume_id = data.get('volume_id')
        container_id = data.get('container_id')
        content_id = data.get('content_id')
        chunk_id = data.get('chunk_id')
        self.rdir.chunk_delete(volume_id, container_id, content_id, chunk_id)

    def handle_ping(self, event):
        """
        Handle ping
        :param event
        """
        self.logger.debug('worker handle ping')
