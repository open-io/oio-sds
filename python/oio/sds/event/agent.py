import json
import logging

from eventlet.green import zmq
from eventlet import GreenPool
from eventlet import GreenPile
from eventlet import Timeout

from oio.common.daemon import Daemon
from oio.common.http import requests
from oio.common.utils import get_logger
from oio.common.utils import int_value
from oio.common.utils import validate_service_conf
from oio.conscience.client import ConscienceClient


PARALLEL_CHUNKS_DELETE = 5
CHUNK_TIMEOUT = 60
ACCOUNT_SERVICE_TIMEOUT = 60

ACCOUNT_SERVICE = 'account'


class EventType(object):
    CONTAINER_PUT = "meta2.container.create"
    CONTAINER_DESTROY = "meta2.container.destroy"
    CONTAINER_UPDATE = "meta2.container.state"
    OBJECT_PUT = "meta2.content.new"
    OBJECT_DELETE = "meta2.content.deleted"


def decode_msg(msg):
    return json.loads(msg[1])


class EventWorker(object):
    def __init__(self, conf, context, **kwargs):
        self.conf = conf
        verbose = kwargs.pop('verbose', False)
        self.logger = get_logger(self.conf, verbose=verbose)
        self._configure_zmq(context)
        self.cs = ConscienceClient(self.conf)
        self._account_addr = None

    def _configure_zmq(self, context):
        socket = context.socket(zmq.REP)
        socket.connect('inproc://event-front')
        self.socket = socket

    def run(self):
        while True:
            try:
                msg = self.socket.recv_multipart()
                if self.logger.isEnabledFor(logging.DEBUG):
                    self.logger.debug('msg: %s' % msg)
                ack = ['']
                try:
                    ack = [msg[0]]
                    event = decode_msg(msg)
                    self.process_event(event)
                except Exception as e:
                    self.logger.exception('Unable to process event')
                    continue
            except Exception as e:
                self.logger.exception(e)
            finally:
                try:
                    self.socket.send_multipart(ack)
                except Exception as e:
                    self.logger.exception('Unable to ack event')

    def process_event(self, event):
        handler = self.get_handler(event)
        if not handler:
            raise Exception('No handler found')
        handler(event)

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
        else:
            return None

    @property
    def account_addr(self):
        if not self._account_addr:
            try:
                account_instance = self.cs.next_instance(ACCOUNT_SERVICE)
                self._account_addr = account_instance.get('addr')
            except Exception as e:
                self.logger.warn('Unable to find account instance')
                # fallback on conf
                account_addr = self.conf.get('account_addr')
                if not account_addr:
                    self.logger.warn(
                        'Unable to find fallback account instance in config')
                    raise Exception('Unable to find account instance')
                self._account_addr = account_addr
        return self._account_addr

    def handle_container_put(self, event):
        """
        Handle container creation.
        :param event:
        """
        uri = 'http://%s/v1.0/account/container/update' % self.account_addr
        mtime = event.get('when')
        data = event.get('data')
        name = data.get('url').get('user')

        event = {'mtime': mtime, 'name': name}
        requests.post(uri, params={'id': 'test'}, data=json.dumps(event))

    def handle_container_update(self, event):
        """
        Handle container update.
        TODO
        :param event:
        """
        uri = 'http://%s/v1.0/account/container/update' % self.account_addr
        mtime = event.get('when')
        data = event.get('data')
        name = event.get('url').get('user')
        bytes_count = data.get('bytes-count', 0)
        object_count = data.get('object-count', 0)

        event = {
            'mtime': mtime,
            'name': name,
            'bytes': bytes_count,
            'objects': object_count
        }
        requests.post(uri, params={'id': 'test'}, data=json.dumps(event))

    def handle_container_destroy(self, event):
        """
        Handle container destroy.
        :param event:
        """
        uri = 'http://%s/v1.0/account/container/update' % self.account_addr
        dtime = event.get('when')
        data = event.get('data')
        name = data.get('url').get('user')

        event = {'dtime': dtime, 'name': name}
        requests.post(uri, params={'id': 'test'}, data=json.dumps(event))

    def handle_object_delete(self, event):
        """
        Handle object deletion.
        Delete the chunks of the object.
        :param event:
        """
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
                    resp = requests.delete(chunk['id'])
            except (Exception, Timeout) as e:
                self.logger.exception(e)
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
        pass


class EventAgent(Daemon):
    def __init__(self, conf):
        validate_service_conf(conf)
        self.conf = conf
        self.logger = get_logger(conf)

    def run(self, *args, **kwargs):
        context = zmq.Context()
        server = context.socket(zmq.ROUTER)
        bind_addr = self.conf.get('bind_addr',
                                  'ipc:///tmp/run/event-agent.sock')
        server.bind(bind_addr)

        backend = context.socket(zmq.DEALER)
        backend.bind('inproc://event-front')

        nb_workers = int_value(self.conf.get('workers'), 2)
        worker_pool = GreenPool(nb_workers)

        for i in range(0, nb_workers):
            worker = EventWorker(self.conf, context)
            worker_pool.spawn_n(worker.run)

        def proxy(socket_from, socket_to):
            while True:
                m = socket_from.recv_multipart()
                socket_to.send_multipart(m)

        boss_pool = GreenPool(2)
        boss_pool.spawn_n(proxy, server, backend)
        boss_pool.spawn_n(proxy, backend, server)

        worker_pool.waitall()

