# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from oio.event.evob import Event, EventTypes
from oio.event.beanstalk import BeanstalkError
from oio.event.filters.base import Filter
from oio.common.easy_value import int_value
from oio.common.json import json
from oio.xcute.common.worker import XcuteWorker


class XcuteFilter(Filter):

    DEFAULT_RETRY_DELAY_TO_REPLY = 60

    def init(self):
        self.retry_delay_to_reply = int_value(
            self.conf.get('retry_delay_to_reply'),
            self.DEFAULT_RETRY_DELAY_TO_REPLY)

        self.worker = XcuteWorker(self.conf, logger=self.logger)

    def process(self, env, beanstalkd, cb):
        event = Event(env)

        if event.data.get('processed'):
            job_id = event.data['job_id']
            task_ids = event.data['task_ids']
            task_results = event.data['task_results']
            task_errors = event.data['task_errors']
            beanstalkd_reply_info = event.data['beanstalkd_reply']
        else:
            job_id, task_ids, task_results, task_errors, \
                beanstalkd_reply_info = self.worker.process(event.data)

        try:
            self.worker.reply(
                job_id, task_ids, task_results, task_errors,
                beanstalkd_reply_info)
        except BeanstalkError as exc:
            self.logger.warn(
                '[job_id=%s] Fail to reply, retry later (%d): %s',
                job_id, self.retry_delay_to_reply, exc)
            tasks_processed_event = json.dumps({
                'event': EventTypes.XCUTE_TASKS,
                'data': {
                    'job_id': job_id,
                    'task_ids': task_ids,
                    'task_results': task_results,
                    'task_errors': task_errors,
                    'beanstalkd_reply': beanstalkd_reply_info,
                    'processed': True
                }
            })
            beanstalkd.put(
                tasks_processed_event, delay=self.retry_delay_to_reply)

        return self.app(env, beanstalkd, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def account_filter(app):
        return XcuteFilter(app, conf)
    return account_filter
