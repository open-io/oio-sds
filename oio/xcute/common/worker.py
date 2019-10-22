# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

import pickle

from oio.common.green import sleep
from oio.common.json import json
from oio.event.beanstalk import BeanstalkdSender
from oio.xcute.common.task import XcuteTask


class XcuteWorker(object):

    def __init__(self, beanstalkd_worker_addr, beanstalkd_worker_tube, conf,
                 logger):
        self.beanstalkd_worker_addr = beanstalkd_worker_addr
        self.beanstalkd_worker_tube = beanstalkd_worker_tube
        self.beanstalkd_reply = None
        self.conf = conf
        self.logger = logger

    def _reply(self, beanstalkd_job, res, exc):
        reply_dest = beanstalkd_job.get('beanstalkd_reply')
        if not reply_dest:
            return

        beanstalkd_job['beanstalkd_worker'] = {
            'addr': self.beanstalkd_worker_addr,
            'tube': self.beanstalkd_worker_tube}
        beanstalkd_job['res'] = pickle.dumps(res)
        beanstalkd_job['exc'] = pickle.dumps(exc)
        beanstalkd_job_data = json.dumps(beanstalkd_job)

        try:
            if self.beanstalkd_reply is None \
                    or self.beanstalkd_reply.addr != reply_dest['addr'] \
                    or self.beanstalkd_reply.tube != reply_dest['tube']:
                if self.beanstalkd_reply is not None:
                    self.beanstalkd_reply.close()
                self.beanstalkd_reply = BeanstalkdSender(
                    reply_dest['addr'], reply_dest['tube'], self.logger)

            sent = False
            while not sent:
                sent = self.beanstalkd_reply.send_job(beanstalkd_job_data)
                if not sent:
                    sleep(1.0)
            self.beanstalkd_reply.job_done()
        except Exception as exc:
            self.logger.warn('Fail to reply %s: %s', str(beanstalkd_job), exc)

    def process_job(self, beanstalkd_job):
        try:
            # Decode the beanstakd job
            task_class_encoded = beanstalkd_job['task']

            task_class = pickle.loads(task_class_encoded)
            task = task_class(self.conf, self.logger)

            if not isinstance(task, XcuteTask):
                raise ValueError('Unexpected task: %s' % task_class)

            task_item = beanstalkd_job['item']
            task_kwargs = beanstalkd_job.get('kwargs', dict())

            # Execute the task
            res = task.process(task_item, **task_kwargs)
            exc = None
        except Exception as exc:
            res = None

        if exc:
            self.logger.error('Error to process job %s: %s',
                              str(beanstalkd_job), exc)

        # Reply
        self._reply(beanstalkd_job, res, exc)
