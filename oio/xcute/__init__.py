import logging
import pickle
import urlparse
import json
from eventlet import Queue, Timeout, GreenPile, GreenPool
from uuid import uuid1 as uuid
from oio.event.beanstalk import Beanstalk, BeanstalkdListener, BeanstalkdSender


def _uuid(prev):
    if prev is not None:
        return prev
    return uuid().hex


class Handler(object):
    def __init__(self, source, sink, job_id, uri_out):
        super(Handler, self).__init__()
        self.source = source
        self.sink = sink
        self.job_id = job_id
        self.uri_out = uri_out

    def recurse(self, job):
        """Send a new action to the beanstalkd that emitted
        the current action."""
        self.sink.send(self.source.back_url(),
                       Action(self.uri_out, job, id_ = self.job_id))

    def produce(self, msg):
        """Send an output to the beanstalkd whose URL is configured
        in the action."""
        self.sink.send(self.uri_out, (self.job_id, msg))

    def propagate(self, job):
        """Trigger a new job somewhere on the platform"""
        url = None
        sink.send(url,
                  Action(self.uri_out, msg))


class Action(object):
    """Serialisable wrapper for an action submitted in the xcute hub."""
    def __init__(self, uri_out, job, id_=None):
        super(Action, self).__init__()
        self.uri_out = uri_out
        self.job = job
        self.job_id = _uuid(id_)

    def raw(self):
        return {'out': self.uri_out, 'id': self.job_id, 'job': repr(self.job)}

    def __repr__(self):
        return 'Action' + json.dumps(self.raw())

    def __call__(self, source, sink):
        rc = None
        try:
            rc = self.job(Handler(source, sink, self.job_id, self.uri_out))
        except Exception as ex:
            rc = ex
        if 'uuid' not in self.__dict__:
            self.uuid = None
        if rc is not None:
            sink.send(self.uri_out, (self.uuid, rc))


class Worker(object):
    def __init__(self, url, source_factory, sink):
        super(Worker, self).__init__()
        self.running = True
        self.url = url
        self.source_factory = source_factory
        self.sink = sink

    def step(self, source):
        jobid, action = None, None
        # Decode the input
        try:
            jobid, action = source.reserve()
            logging.warn("Job polled id=%s %s", jobid, repr(action))
        except Exception as ex:
            logging.exception("Action not decoded: %s", ex)
            source.bury(jobid)
            return
        # Execute the action
        try:
            if not isinstance(action, Action):
                raise Exception("Unexpected encoded object")
            else:
                action(source, self.sink)
                source.delete(jobid)
        except Exception as ex:
            logging.exception("Action error: %s", ex)
            source.bury(jobid)

    def worker(self):
        source = self.source_factory(self.url)
        while self.running:
            try:
                self.step(source)
            except StopIteration:
                self.running = False

    def run(self):
        pool = GreenPool()
        for i in range(5):
            pool.spawn_n(self.worker);
        pool.waitall()


class BeanstalkdSource(object):
    def __init__(self, addr, tube):
        super(BeanstalkdSource, self).__init__()
        self.addr = addr
        self.tube = tube
        self.client = Beanstalk.from_url("beanstalk://" + self.addr)
        self.client.watch(self.tube)

    def back(self):
        """Return a BeanstalkdTarget associated with the local
        BeanstalkdSource: same target and same source."""
        return BeanstalkdTarget(self.addr, self.tube)

    def back_url(self):
        """Return a BeanstalkdTarget associated with the local
        BeanstalkdSource: same target and same source."""
        return "https://{0}/{1}".format(self.addr, self.tube)

    def reserve(self):
        jobid, encoded = self.client.reserve()
        return jobid, pickle.loads(encoded)

    def delete(self, jobid):
        return self.client.delete(jobid)

    def bury(self, jobid):
        return self.client.bury(jobid)


class BeanstalkdTarget(object):
    """The BeanstalkdSink does nothing more than submitting the given
    message to the beanstalkd whose URL has been given.
    It acts like a client pool toward beanstalkd services. """
    def __init__(self, addr, tube):
        super(BeanstalkdTarget, self).__init__()
        self.addr = addr
        self.tube = tube
        self.client = Beanstalk.from_url('beanstalk://' + addr)
        self.client.use(tube)

    def send(self, msg):
        logging.warn("-> %s %s", self.tube, repr(msg))
        msg = str(pickle.dumps(msg))
        self.client.put(msg)


class BeanstalkdSink(object):
    """The BeanstalkdSink does nothing more than submitting the given
    message to the beanstalkd whose URL has been given.
    It acts like a client pool toward beanstalkd services. """
    def __init__(self):
        super(BeanstalkdSink, self).__init__()
        self.clients = dict()

    def send(self, to, msg):
        if to not in self.clients:
            parsed = urlparse.urlparse(to)
            tube = parsed.path.strip('/')
            self.clients[to] = BeanstalkdTarget(parsed.netloc, tube)
        client = self.clients[to]
        client.send(msg)


class ClientSync(object):
    def __init__(self, local_addr):
        super(ClientSync, self).__init__()
        self.uuid = _uuid(None)
        self.local = local_addr
        self.source = BeanstalkdSource(self.local, self.uuid)
        self.sink = BeanstalkdSink()

    def execute(self, to, job):
        job = Action('beanstalk://' + self.local + '/' + self.uuid, job)
        self.sink.send(to + '/worker', job)
        jobid, result = self.source.reserve()
        self.source.delete(jobid)
        return result[1]


class ClientAsync(object):
    def __init__(self, local_addr, id_=None):
        super(ClientAsync, self).__init__()
        self.local = local_addr
        self.uuid = _uuid(id_)
        self.source = BeanstalkdSource(self.local, self.uuid)
        self.sink = BeanstalkdSink()
        self.pending = set()
        self.done = dict()

    def start(self, to, job):
        job = Action('beanstalk://' + self.local + '/' + self.uuid, job)
        self.sink.send(to + '/worker', job)
        self.pending.add(job.uuid)
        return job.uuid

    def join(self, job_uuid):
        while True:
            # Maybe the result has already been received
            if job_uuid in self.done:
                rc = self.done[job_uuid]
                del self.done[job_uuid]
                return rc
            # If not, we poll for an other notification until we get hte one we expect
            jobid, result = self.source.reserve()
            ju, rc = result
            self.source.delete(jobid)
            if ju in self.pending:
                self.pending.remove(ju)
            self.done[ju] = rc


class Stream(object):
    def __init__(self, local_addr, id_=None):
        super(Stream, self).__init__()
        self.uuid = id_
        self.local = local_addr
        self.source = BeanstalkdSource(self.local, self.uuid)
        self.sink = BeanstalkdSink()

    def kick(self, to, job):
        assert(self.uuid is None)
        job = Action('beanstalk://' + self.local + '/' + self.uuid, job,
                     id_ = self.uuid)
        self.sink.send(to + '/worker', job)
        self.uuid = job.uuid
        return job.uuid

    def __iter__(self):
        """Creates an iterator on the replies, until a StopIteration
        exception is returned from a worker."""
        return self.generator()

    def generator(self):
        while True:
            jobid, result = self.source.reserve()
            ju, rc = result
            if ju != self.uuid:
                logging.warn("Unexpected message %s %s", ju, repr(rc))
                continue
            self.source.delete(jobid)
            if isinstance(rc, StopIteration):
                raise StopIteration
            yield rc

