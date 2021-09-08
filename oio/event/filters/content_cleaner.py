# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021 OVH SAS
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

from oio.blob.client import BlobClient
from oio.common.constants import REQID_HEADER
from oio.common.easy_value import int_value, float_value
from oio.common.exceptions import OioException
from oio.common.http_urllib3 import URLLIB3_POOLMANAGER_KWARGS, urllib3
from oio.common.storage_method import STORAGE_METHODS, guess_storage_method
from oio.common.utils import request_id
from oio.event.evob import Event, EventTypes
from oio.event.filters.base import Filter


class ContentReaperFilter(Filter):
    """Filter that deletes chunks on content deletion events"""

    def init(self):
        self.handlers = {
            "plain": self._handle_rawx,
            "ec": self._handle_rawx,
        }
        kwargs = {k: v for k, v in self.conf.items()
                  if k in URLLIB3_POOLMANAGER_KWARGS}
        self.blob_client = BlobClient(self.conf, logger=self.logger,
                                      watchdog=self.app_env['watchdog'],
                                      **kwargs)
        self.chunk_concurrency = int_value(self.conf.get('concurrency'), 3)
        self.chunk_timeout = float_value(self.conf.get('timeout'), None)
        if not self.chunk_timeout:
            connection_timeout = float_value(
                self.conf.get('connection_timeout'), 1.0)
            read_timeout = float_value(self.conf.get('read_timeout'), 5.0)
            self.chunk_timeout = urllib3.Timeout(
                    connect=connection_timeout,
                    read=read_timeout)

    def _handle_rawx(self, url, chunks, content_headers,
                     storage_method, reqid):
        cid = url.get('id')
        headers = {REQID_HEADER: reqid,
                   'Connection': 'close'}

        resps = self.blob_client.chunk_delete_many(
            chunks, cid=cid, headers=headers,
            concurrency=self.chunk_concurrency, timeout=self.chunk_timeout)
        for resp in resps:
            if isinstance(resp, Exception):
                self.logger.warn(
                    'failed to delete chunk %s (%s)',
                    resp.chunk.get('real_url', resp.chunk['url']), resp)
            elif resp.status not in (204, 404):
                self.logger.warn(
                    'failed to delete chunk %s (HTTP %s)',
                    resp.chunk.get('real_url', resp.chunk['url']), resp.status)

    def _load_handler(self, chunk_method):
        storage_method = STORAGE_METHODS.load(chunk_method)
        handler = self.handlers.get(storage_method.type)
        if not handler:
            raise OioException("No handler found for chunk method [%s]" %
                               chunk_method)
        return handler, storage_method

    def process(self, env, beanstalkd, cb):
        event = Event(env)
        if event.event_type == EventTypes.CONTENT_DELETED:
            url = event.env.get('url')
            chunks = []
            content_headers = list()

            for item in event.data:
                if item.get('type') == 'chunks':
                    # The event contains "id" whereas the API uses "url".
                    item['url'] = item['id']
                    chunks.append(item)
                if item.get("type") == 'contents_headers':
                    content_headers.append(item)
            if len(chunks):
                reqid = event.reqid or request_id('content-cleaner-')
                if not content_headers:
                    chunk_method = guess_storage_method(chunks[0]['id']) + '/'
                else:
                    chunk_method = content_headers[0]['chunk-method']
                handler, storage_method = self._load_handler(chunk_method)
                handler(url, chunks, content_headers, storage_method, reqid)
                return self.app(env, beanstalkd, cb)

        return self.app(env, beanstalkd, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def reaper_filter(app):
        return ContentReaperFilter(app, conf)
    return reaper_filter
