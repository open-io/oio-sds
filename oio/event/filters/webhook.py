# Copyright (C) 2015-2018 OpenIO SAS, as part of OpenIO SDS
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
from oio.event.evob import Event, EventError
from oio.event.filters.base import Filter


class WebhookFilter(Filter):
    def init(self):
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
                raise exceptions.from_response(resp, '')
        except urllib3.exceptions.HTTPError as exc:
            oio_exception_from_httperror(exc)

    def process(self, env, cb):
        event = Event(env)

        url = env['url']
        alias = extract_from_event('aliases', env)
        content_header = extract_from_event('contents_headers', env)

        body = {
            'eventId': env['job_id'],
            'eventType': env['event'],
            'timestamp': env['when'],
            'data': {
                'id': url['content'],
                'account': url['account'],
                'container': url['user'],
                'name': url['path'],
                'md5Hash': content_header['hash'],
                'contentType': content_header['mime-type'],
                'policy': content_header['policy'],
                'chunkMethod': content_header['chunk-method'],
                'size': content_header['size'],
                'creationTime': alias['ctime'],
                'modificationTime': alias['mtime'],
                'version': alias['version'],
                'metadata': {},
            },
        }

        try:
            data = json.dumps(body)
            self._request(data)
        except exceptions.OioException as exc:
            return EventError(
                event=event,
                body='webhook error: %s' % exc)(env, cb)
        return self.app(env, cb)


def extract_from_event(data_type, env):
    for item in env['data']:
        if item.get('type') == data_type:
            return item
    return {}


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def webhook(app):
        return WebhookFilter(app, conf)
    return webhook
