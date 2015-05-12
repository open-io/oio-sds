import logging
from oio.common.daemon import Daemon
from eventlet.green import zmq
from eventlet import GreenPool


class EventAgent(Daemon):
    def __init__(self, conf):
        self.conf = conf
        self.logger = logging.getLogger('event-agent')

    def run(self, *args, **kwargs):
        context = zmq.Context()
        server = context.socket(zmq.ROUTER)
        bind_addr = self.conf.get('bind_addr',
                                  'ipc:///tmp/run/event-agent.sock')
        server.bind(bind_addr)

        backend = context.socket(zmq.DEALER)
        backend.bind('inproc://event-front')

        def worker(id_worker, socket):
            while True:
                try:
                    m = socket.recv_multipart()
                    print('worker id: %s event: %s' % (id_worker, m))
                    socket.send_multipart([m[0]])
                except Exception as e:
                    print e

        nb_workers = int(self.conf.get('workers', '2'))
        worker_pool = GreenPool(nb_workers)

        for i in range(0, nb_workers):
            worker_socket = context.socket(zmq.REP)
            worker_socket.connect('inproc://event-front')
            worker_pool.spawn_n(worker, i, worker_socket)

        def proxy(socket_from, socket_to):
            while True:
                m = socket_from.recv_multipart()
                socket_to.send_multipart(m)

        boss_pool = GreenPool(2)
        boss_pool.spawn_n(proxy, server, backend)
        boss_pool.spawn_n(proxy, backend, server)

        boss_pool.waitall()


