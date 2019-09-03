#!/usr/bin/env python

import logging
import pickle
import urlparse
from eventlet import Queue, Timeout, GreenPile, GreenPool # noqa
from uuid import uuid1 as uuid
from oio.event.beanstalk import Beanstalk, BeanstalkdListener, BeanstalkdSender


class Action(object):
    def __init__(self, uri_out, job):
        super(Action, self).__init__()
        self.uri_out = uri_out
        self.job = job
        self.uuid = uuid().hex

    def __call__(self, out, **kwargs):
        rc = None
        try:
            rc = self.job(**kwargs)
        except Exception as ex:
            rc = ex
        if 'uuid' not in self.__dict__:
            self.uuid = None
        out.send(self.uri_out, (self.uuid, rc))


class Worker(object):
    def __init__(self, source, sink):
        super(Worker, self).__init__()
        self.running = True
        self.source = source
        self.sink = sink
        self.pool = GreenPool()

    def _execute(self, jobid, action, **kwargs):
        try:
            if not isinstance(action, Action):
                raise Exception("Unexpected encoded object")
            else:
                action(self.sink, **kwargs)
        except Exception as ex:
            logging.exception("Action error: %s", ex)
        finally:
            self.source.delete(jobid)

    def step(self, **kwargs):
        jobid, action = None, None
        try:
            jobid, action = self.source.reserve()
        except Exception as ex:
            logging.exception("Action not decoded: %s", ex)
            self.source.bury(jobid)
            return
        self.pool.spawn_n(self._execute, jobid, action, **kwargs)

    def run(self, **kwargs):
        while self.running:
            try:
                self.step(**kwargs)
            except StopIteration:
                self.running = False
        self.pool.waitall()


class BeanstalkdSource(object):
    def __init__(self, addr, tube):
        super(BeanstalkdSource, self).__init__()
        self.addr = addr
        self.tube = tube
        self.client = Beanstalk.from_url("beanstalk://" + self.addr)
        self.client.watch(self.tube)

    def reserve(self):
        jobid, encoded = self.client.reserve()
        return jobid, pickle.loads(encoded)

    def delete(self, jobid):
        return self.client.delete(jobid)

    def bury(self, jobid):
        return self.client.bury(jobid)


class BeanstalkdSink(object):
    def __init__(self):
        super(BeanstalkdSink, self).__init__()
        self.clients = dict()

    def send(self, to, msg):
        msg = str(pickle.dumps(msg))
        parsed = urlparse.urlparse(to)
        url = 'beanstalk://' + parsed.netloc
        tube = parsed.path.strip('/')
        client = Beanstalk.from_url(url)
        client.use(tube)
        client.put(msg)

class ClientSync(object):
    def __init__(self, local_addr):
        super(ClientSync, self).__init__()
        self.uuid = uuid().hex
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
    def __init__(self, local_addr):
        super(ClientAsync, self).__init__()
        self.uuid = uuid().hex
        self.local = local_addr
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

