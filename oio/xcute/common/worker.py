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
import traceback

from oio.common.green import sleep
from oio.common.json import json
from oio.event.beanstalk import BeanstalkdSender
from oio.xcute.common.task import XcuteTask


class XcuteWorker(object):

    def __init__(self, beanstalkd_worker_addr, beanstalkd_worker_tube, conf,
                 logger):
        self.beanstalkd_worker_addr = beanstalkd_worker_addr
        self.beanstalkd_worker_tube = beanstalkd_worker_tube
        self.beanstalkd_senders = {}
        self.conf = conf
        self.logger = logger

    def process_beanstalkd_job(self, beanstalkd_job):
        job_id = beanstalkd_job['job_id']
        task_id = beanstalkd_job['task_id']
        task_class_encoded = beanstalkd_job['task_class']
        task_payload_encoded = beanstalkd_job['task_payload']
        reply_addr = beanstalkd_job['beanstalkd_reply']['addr']
        reply_tube = beanstalkd_job['beanstalkd_reply']['tube']

        try:
            task_class = pickle.loads(task_class_encoded)
            task_payload = pickle.loads(task_payload_encoded)
            task = task_class(self.conf, self.logger)

            if not isinstance(task, XcuteTask):
                raise ValueError('Unexpected task: %s' % task_class)

            task_ok = self._execute_task(task, task_payload)
        except Exception:
            self.logger.error('Error processing job %s: %s',
                              beanstalkd_job, traceback.format_exc())
            task_ok = False

        self._reply(reply_addr, reply_tube, job_id, task_id, task_ok)

    @staticmethod
    def _execute_task(task, task_payload):
        return task.process(task_payload)

    def _reply(self, reply_addr, reply_tube, job_id, task_id, task_ok):
        reply_payload = json.dumps({
            'job_id': job_id,
            'task_id': task_id,
            'task_ok': task_ok,
        })

        sender_key = (reply_addr, reply_tube)
        if sender_key not in self.beanstalkd_senders:
            self.beanstalkd_senders[sender_key] = BeanstalkdSender(
                addr=reply_addr,
                tube=reply_tube,
                logger=self.logger)

        beanstalkd_sender = self.beanstalkd_senders[(reply_addr, reply_tube)]

        while not beanstalkd_sender.send_job(reply_payload):
            sleep(1)

        beanstalkd_sender.job_done()
