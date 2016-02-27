import sqlite3
import time

from eventlet import GreenPile
from eventlet import GreenPool
from eventlet import Timeout
from eventlet import sleep
from eventlet.green import zmq

from oio.common.daemon import Daemon
from oio.common.http import requests
from oio.common.queue.sqlite import SqliteQueue
from oio.common.utils import get_logger
from oio.common.utils import int_value
from oio.common.utils import json
from oio.common.utils import true_value
from oio.common.utils import validate_service_conf
from oio.conscience.client import ConscienceClient
from oio.rdir.client import RdirClient


PARALLEL_CHUNKS_DELETE = 2
CHUNK_TIMEOUT = 60
ACCOUNT_SERVICE_TIMEOUT = 60

ACCOUNT_SERVICE = 'account'


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


def validate_msg(msg):
    return len(msg) == 4


def decode_msg(msg):
    return json.loads(msg[1])


class EventWorker(object):
    def __init__(self, conf, name, context, **kwargs):
        self.conf = conf
        self.name = name
        verbose = kwargs.pop('verbose', False)
        self.logger = get_logger(self.conf, verbose=verbose)
        self.init_zmq(context)
        self.cs = ConscienceClient(self.conf)
        self.rdir = RdirClient(self.conf)
        self._acct_addr = None
        self.acct_update = 0
        self.acct_refresh_interval = int_value(
            conf.get('acct_refresh_interval'), 60
        )
        self.acct_update = true_value(
            conf.get('acct_update', True))
        self.rdir_update = true_value(
            conf.get('rdir_update', True))
        self.session = requests.Session()
        self.failed = False

    def start(self):
        self.logger.info('worker "%s" starting', self.name)
        self.running = True
        self.run()

    def stop(self):
        self.logger.info('worker "%s" stopping', self.name)
        self.running = False

    def init_zmq(self, context):
        socket = context.socket(zmq.REP)
        socket.set(zmq.LINGER, 1000)
        socket.connect('inproc://event-front')
        self.socket = socket

    def safe_ack(self, msg):
        try:
            self.socket.send_multipart(msg)
        except Exception:
            self.logger.warn('Unable to ack event')

    def run(self):
        try:
            while self.running:
                msg = self.socket.recv_multipart()
                self.logger.debug("msg received: %s" % msg)
                event = None
                try:
                    event = decode_msg(msg)
                except Exception as e:
                    self.logger.warn('ERROR decoding msg "%s"', e)
                success = False
                if event:
                    success = self.process_event(event)
                f = "0" if success else ""
                self.safe_ack([msg[0], f])
        except Exception as e:
            self.logger.warn('ERROR in worker "%s"', e)
            self.failed = True
        finally:
            self.logger.info('worker "%s" stopped', self.name)

    def process_event(self, event):
        handler = self.get_handler(event)
        if not handler:
            self.logger.warn("No handler found")
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
        self.logger.debug('worker "%s" handle container put', self.name)
        if not self.acct_update:
            return
        uri = 'http://%s/v1.0/account/container/update' % self.acct_addr
        mtime = event.get('when')
        data = event.get('data')
        name = data.get('url').get('user')
        account = data.get('url').get('account')

        event = {'mtime': mtime, 'name': name}
        self.session.post(uri, params={'id': account}, data=json.dumps(event))

    def handle_container_update(self, event):
        """
        Handle container update.
        :param event:
        """
        self.logger.debug('worker "%s" handle container update', self.name)
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
        self.session.post(uri, params={'id': account}, data=json.dumps(event))

    def handle_container_destroy(self, event):
        """
        Handle container destroy.
        :param event:
        """
        self.logger.debug('worker "%s" handle container destroy', self.name)
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
        self.logger.debug('worker "%s" handle object delete', self.name)
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
                self.logger.info('deleted chunk %s' % resp.url)
            else:
                self.logger.warn('failed to delete chunk %s' % resp.url)

    def handle_object_put(self, event):
        """
        Handle object creation.
        TODO
        :param event:
        """
        self.logger.debug('worker "%s" handle object put', self.name)

    def handle_reference_update(self, event):
        """
        Handle reference update.
        TODO
        :param event
        """
        self.logger.debug('worker "%s" handle reference update', self.name)

    def handle_chunk_put(self, event):
        """
        Handle chunk creation.
        :param event
        """
        if not self.rdir_update:
            self.logger.debug('worker "%s" skip chunk creation', self.name)
            return

        self.logger.debug('worker "%s" handle chunk creation', self.name)

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
            self.logger.debug('worker "%s" skip chunk deletion', self.name)
            return

        self.logger.debug('worker "%s" handle chunk deletion', self.name)

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
        self.logger.debug('worker "%s" handle ping', self.name)


class EventAgent(Daemon):
    def __init__(self, conf):
        validate_service_conf(conf)
        self.conf = conf
        self.logger = get_logger(conf)
        self.running = False
        self.retry_interval = int_value(conf.get('retry_interval'), 5)
        self.batch_size = int_value(conf.get('batch_size'), 500)
        self.last_retry = 0
        self.init_zmq()
        self.init_queue()
        self.init_workers()

    def run(self, *args, **kwargs):
        try:
            self.logger.info('event agent: starting')

            pool = GreenPool(len(self.workers))

            for worker in self.workers:
                pool.spawn(worker.start)

            def front(server, backend):
                while True:
                    msg = server.recv_multipart()
                    if validate_msg(msg):
                        try:
                            event_id = sqlite3.Binary(msg[2])
                            data = msg[3]
                            self.queue.put(event_id, data)
                            event = ['', msg[2], msg[3]]
                            backend.send_multipart(event)
                        except Exception:
                            pass
                        finally:
                            ack = msg[0:3]
                            server.send_multipart(ack)

            def back(backend):
                while True:
                    msg = backend.recv_multipart()
                    event_id = msg[1]
                    success = msg[2]
                    event_id = sqlite3.Binary(event_id)
                    if not success:
                        self.queue.failed(event_id)
                    else:
                        self.queue.delete(event_id)

            boss_pool = GreenPool(2)
            boss_pool.spawn_n(front, self.server, self.backend)
            boss_pool.spawn_n(back, self.backend)
            while True:
                sleep(1)

                now = time.time()
                if now - self.last_retry > self.retry_interval:
                    self.retry()
                    self.last_retry = now

                for w in self.workers:
                    if w.failed:
                        self.workers.remove(w)
                        self.logger.warn('restart worker "%s"', w.name)
                        new_w = EventWorker(self.conf, w.name, self.context)
                        self.workers.append(new_w)
                        pool.spawn(new_w.start)

        except Exception as e:
            self.logger.error('ERROR in main loop %s', e)
            raise e
        finally:
            self.logger.warn('event agent: stopping')
            self.stop_workers()

            self.logger.warn('ZMQ context being destroyed')
            self.context.destroy(linger=True)
            self.context = None

    def init_zmq(self):
        self.context = zmq.Context()
        self.server = self.context.socket(zmq.ROUTER)
        self.server.set(zmq.LINGER, 1000)
        bind_addr = self.conf.get('bind_addr',
                                  'ipc:///tmp/run/event-agent.sock')
        self.server.bind(bind_addr)
        self.backend = self.context.socket(zmq.DEALER)
        self.backend.set(zmq.LINGER, 1000)
        self.backend.bind('inproc://event-front')

    def init_queue(self):
        queue_location = self.conf.get(
            'queue_location', '/tmp/oio-event-queue.db')
        self.queue = SqliteQueue('oio_event', queue_location)

    def init_workers(self):
        nbworkers = int_value(self.conf.get('workers'), 2)
        workers = []
        for i in xrange(nbworkers):
            workers.append(EventWorker(self.conf, str(i), self.context))
        self.workers = workers

    def stop_workers(self):
        for worker in self.workers:
            worker.stop()

    def retry(self):
        cursor = self.queue.load(self.batch_size)

        for event in cursor:
            event_id, data = event
            msg = ['', event_id, str(data)]
            self.backend.send_multipart(msg)
