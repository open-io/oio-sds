# Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
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


from oio.common import exceptions
from oio.common.http_urllib3 import urllib3, get_pool_manager, \
    oio_exception_from_httperror
from oio.common.json import json
from oio.event.evob import Event, EventError, EventTypes
from oio.event.filters.base import Filter
from oio.container.client import ContainerClient


class WebhookFilter(Filter):

    def init(self):
        self.container_client = ContainerClient(self.conf, logger=self.logger)
        self.endpoint = self.conf.get('endpoint')
        # TODO configure pool manager
        self.http = get_pool_manager()

    def _request(self, data):
        try:
            resp = self.http.request(
                "POST",
                self.endpoint,
                headers={'Content-Type': 'application/json'},
                body=data)
            if resp.status >= 400:
                raise exceptions.from_response(resp)
        except urllib3.exceptions.HTTPError as exc:
            oio_exception_from_httperror(exc)

    def process(self, env, beanstalkd, cb):
        event = Event(env)

        url = env['url']
        alias, content_header, properties = extract_data_from_event(env)

        data = {
            'id': url['content'],
            'account': url['account'],
            'container': url['user'],
            'name': url['path'],
        }
        if all((alias, content_header)) \
                and event.event_type == EventTypes.CONTENT_NEW:
            data.update({
                'md5Hash': content_header['hash'],
                'contentType': content_header['mime-type'],
                'policy': content_header['policy'],
                'chunkMethod': content_header['chunk-method'],
                'size': content_header['size'],
                'creationTime': alias['ctime'],
                'modificationTime': alias['mtime'],
                'version': alias['version'],
                'metadata': properties,
            })
        elif event.event_type not in (EventTypes.CONTENT_DELETED,
                                      EventTypes.CONTENT_APPEND):
            all_properties = self.container_client.content_get_properties(
                account=url['account'], reference=url['user'],
                content=url['content'])
            data.update({
                'md5Hash': all_properties['hash'],
                'contentType': all_properties['mime_type'],
                'policy': all_properties['policy'],
                'chunkMethod': all_properties['chunk_method'],
                'size': all_properties['length'],
                'creationTime': all_properties['ctime'],
                'modificationTime': all_properties['mtime'],
                'version': all_properties['version'],
                'metadata': all_properties['properties'],
            })

        body = {
            'eventId': env['job_id'],
            'eventType': env['event'],
            'timestamp': env['when'],
            'data': data
        }

        try:
            data = json.dumps(body)
            self._request(data)
        except exceptions.OioException as exc:
            return EventError(
                event=event,
                body='webhook error: %s' % exc)(env, beanstalkd, cb)
        return self.app(env, beanstalkd, cb)


def extract_data_from_event(env):
    alias = None
    content_header = None
    properties = dict()

    for item in env['data']:
        if alias is None and item.get('type') == 'aliases':
            alias = item
        elif content_header is None and item.get('type') == 'contents_headers':
            content_header = item
        elif item.get('type') == 'properties':
            properties[item['key']] = item['value']
    return alias, content_header, properties


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def webhook(app):
        return WebhookFilter(app, conf)
    return webhook
