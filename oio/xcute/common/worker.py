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
from oio.xcute.common.action import XcuteAction


class XcuteWorker(object):

    def __init__(self, beanstalkd_worker_addr, beanstalkd_worker_tube, conf,
                 logger):
        self.beanstalkd_worker_addr = beanstalkd_worker_addr
        self.beanstalkd_worker_tube = beanstalkd_worker_tube
        self.beanstalkd_reply = None
        self.conf = conf
        self.logger = logger

    def _reply(self, job, res, exc):
        reply_dest = job.get('beanstalkd_reply')
        if not reply_dest:
            return

        job['beanstalkd_worker'] = {'addr': self.beanstalkd_worker_addr,
                                    'tube': self.beanstalkd_worker_tube}
        job['res'] = pickle.dumps(res)
        job['exc'] = pickle.dumps(exc)
        job_data = json.dumps(job)

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
                sent = self.beanstalkd_reply.send_job(job_data)
                if not sent:
                    sleep(1.0)
            self.beanstalkd_reply.job_done()
        except Exception as exc:
            self.logger.warn('Fail to reply %s: %s', job, exc)

    def process_job(self, job):
        try:
            # Decode the job
            action_class_encoded = job['action']

            action_class = pickle.loads(action_class_encoded)
            action = action_class(self.conf, self.logger)

            if not isinstance(action, XcuteAction):
                raise ValueError('Unexpected action: %s' % action_class)

            action_item = pickle.loads(job['item'])
            action_kwargs = job.get('kwargs', dict())

            # Execute the action
            res = action.process(action_item, **action_kwargs)
            exc = None
        except Exception as exc:
            res = None

        if exc:
            self.logger.error('Error to process job %s: %s', str(job), exc)

        # Reply
        self._reply(job, res, exc)
