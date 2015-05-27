import json
import logging
from oio.common.daemon import Daemon
from oio.common.http import requests
from oio.common.utils import get_logger
from eventlet.green import zmq
from eventlet import GreenPool
from eventlet import GreenPile
from eventlet import Timeout

PARALLEL_CHUNKS_DELETE = 5
CHUNK_TIMEOUT = 60
ACCOUNT_SERVICE_TIMEOUT = 60


class EventType(object):
    CONTAINER_PUT = "meta2.create"
    CONTAINER_DESTROY = "meta2.destroy"
    CONTAINER_UPDATE = "meta2.container.state"
    OBJECT_PUT = "meta2.content.new"
    OBJECT_DELETE = "meta2.content.deleted"


def decode_msg(msg):
    return json.loads(msg[1])


class EventWorker(object):
    def __init__(self, conf, context, **kwargs):
        socket = context.socket(zmq.REP)
        socket.connect('inproc://event-front')
        self.socket = socket
        self.logger = get_logger(conf, verbose=kwargs.pop('verbose', False))

    def run(self):
        while True:
            try:
                msg = self.socket.recv_multipart()
                if self.logger.isEnabledFor(logging.DEBUG):
                    self.logger.debug('msg: %s' % msg)
                ack = [""]
                try:
                    ack = [msg[0]]
                    event = decode_msg(msg)
                    self.process_event(event)
                except Exception as e:
                    self.logger.exception(e)
                    continue
            except Exception as e:
                self.logger.exception(e)
            finally:
                try:
                    self.socket.send_multipart(ack)
                except Exception as e:
                    self.logger.exception(e)

    def process_event(self, event):
        handler = self.get_handler(event)
        if not handler:
            raise Exception("No handler found")
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

    def handle_container_put(self, event):
        """
        Handle container creation.
        TODO
        :param event:
        """
        pass

    def handle_container_update(self, event):
        """
        Handle container update.
        TODO
        :param event:
        """
        pass

    def handle_container_destroy(self, event):
        """
        Handle container destroy.
        TODO
        :param event:
        """
        pass

    def handle_object_delete(self, event):
        """
        Handle object deletion.
        Delete the chunks of the object.
        :param event:
        """
        pile = GreenPile(PARALLEL_CHUNKS_DELETE)

        chunks = []

        for item in event.get('data'):
            if item.get('type') == "chunks":
                chunks.append(item)
        if not len(chunks):
            self.logger.warn("No chunks found in event data")

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
                self.logger.info("deleted chunk %s" % resp.url)
            else:
                self.logger.warn("failed to delete chunk %s" % resp.url)

    def handle_object_put(self, event):
        """
        Handle object creation.
        TODO
        :param event:
        """
        pass


class EventAgent(Daemon):
    def __init__(self, conf):
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

        nb_workers = int(self.conf.get('workers', '2'))
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

        boss_pool.waitall()





