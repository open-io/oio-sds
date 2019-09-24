from time import sleep
import logging
import pickle
import urlparse
import json
from eventlet import Queue, Timeout, GreenPile, GreenPool
from uuid import uuid1 as uuid
from oio.event.beanstalk import Beanstalk


def _uuid(prev):
    if prev is not None:
        return prev
    return uuid().hex


class Handler(object):
    def __init__(self, source, sink, ns_name, job_id, uri_out):
        super(Handler, self).__init__()
        self.source = source
        self.sink = sink
        self.job_id = job_id
        self.uri_out = uri_out

    def produce(self, msg):
        """Send an output to the beanstalkd whose URL is configured
        in the action."""
        self.sink.send(self.uri_out, (self.job_id, msg))

    def propagate(self, job):
        """Trigger a new job somewhere on the platform"""
        sink.send(None, Action(self.uri_out, msg))


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
    def __init__(self, ns_name):
        super(BeanstalkdSink, self).__init__()
        self.clients = dict()
        self.ns_name = ns_name

    def send(self, to, msg):
        if not to:
            lb = LbClient({'namespace': self.ns_name})
            to = lb.poll('beanstalkd')
            to = 'beanstalk://' + to[0]['addr']
        if to not in self.clients:
            parsed = urlparse.urlparse(to)
            tube = parsed.path.strip('/')
            self.clients[to] = BeanstalkdTarget(parsed.netloc, tube)
        client = self.clients[to]
        client.send(msg)


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


class ClientSync(object):
    def __init__(self, ns_name, local_addr):
        super(ClientSync, self).__init__()
        self.ns_name = ns_name
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
    def __init__(self, ns_name, local_addr, id_=None):
        super(ClientAsync, self).__init__()
        self.ns_name = ns_name
        self.local = local_addr
        self.uuid = _uuid(id_)
        self.source = BeanstalkdSource(self.local, self.uuid)
        self.sink = BeanstalkdSink(ns_name)
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


class DetachedTask(object):
    def __init__(self, nsname, batch_id, task_id, task):
        super(DetachedTask, self).__init__()
        self.batch_id = batch_id
        self.task_id = task_id
        self.task = task

    def raw(self):
        return {'bid': self.batch_id, 'tid': self.task_id, 't': self.task}

    def __repr__(self):
        return 'DetachedTask' + json.dumps(self.raw())

    def __call__(self, handle):
        try:
            self.task(handle)
        finally:
            # TODO(jfs): remove the task from the repository
            pass


class Batch(object):
    def __init__(self, ns_name, redis_cnx, batch_id=None):
        super(Batch, self).__init__()
        self.ns_name = ns_name
        self.redis = redis_cnx
        self.batch_id = batch_id

    def start(self, handler, generator, cls_executor):
        """
        :param handler:
        :param generator: a callable object that yields items
        :param executor: the class of a callable object that can be
                         instanciated with any element generated by generator.
        """
        assert(self.batch_id is None)
        self.batch_id = _uuid(None)
        sink = BeanstalkdSink(self.ns_name)
        # TODO(jfs): register the batch in the repository
        for item in generator():
            # TODO(jfs): register the task in the repository
            executor = cls_executor(item)
            todo = Action(None, executor)
            todo = DetachedTask(self.batch_id, _uuid(None), todo)
            sink.send(None, todo)

    def _zset_name(self):
        return 'job:' + self.batch_id

    def status(self):
        assert(self.batch_id is not None)
        return self.redis.conn.zcard(self._zset_name())

    def resume(self):
        assert(self.batch_id is not None)
        # TODO(jfs): Poll the ZSET with all the job, get the URL from the
        #            value of each ZSET entry, and send a 'pause-tube'
        #            command with a value of 0.
        raise Exception("Not Yet Implemented")

    def pause(self):
        assert(self.batch_id is not None)
        # TODO(jfs): Poll the ZSET with all the job, get the URL from the
        #            value of each ZSET entry, and send a 'pause-tube'
        #            command with a value of 'many' ;)
        raise Exception("Not Yet Implemented")

    def join(self):
        assert(self.batch_id is not None)
        while True:
         count = self.redis.conn.zcard(self._zset_name())
         if count <= 0:
             return
         sleep(1.0)

