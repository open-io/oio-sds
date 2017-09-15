# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
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


from urlparse import urlparse
from eventlet import Timeout, GreenPile
from oio.common.http_eventlet import http_connect
from oio.event.evob import Event
from oio.event.consumer import EventTypes
from oio.event.filters.base import Filter
from oio.common.exceptions import OioException
from oio.api.backblaze import BackblazeDeleteHandler
from oio.api.backblaze_http import BackblazeUtils
from oio.common.storage_method import STORAGE_METHODS, guess_storage_method
from oio.common.utils import request_id

CHUNK_TIMEOUT = 60
PARALLEL_CHUNKS_DELETE = 3
NB_TRIES = 3


class ContentReaperFilter(Filter):
    """Filter that deletes chunks on content deletion events"""

    def __init__(self, *args, **kwargs):
        super(ContentReaperFilter, self).__init__(*args, **kwargs)
        self.handlers = {
                "plain": self._handle_rawx,
                "ec": self._handle_rawx,
                "backblaze": self._handle_b2,
        }

    def delete_chunk(self, chunk, cid, reqid):
        resp = None
        parsed = urlparse(chunk['id'])
        headers = {'X-oio-req-id': reqid,
                   'X-oio-chunk-meta-container-id': cid}
        try:
            with Timeout(CHUNK_TIMEOUT):
                conn = http_connect(parsed.netloc, 'DELETE', parsed.path,
                                    headers=headers)
                resp = conn.getresponse()
                resp.chunk = chunk
        except (Exception, Timeout) as exc:
            self.logger.warn(
                'error while deleting chunk %s "%s"',
                chunk['id'], str(exc.message))
        return resp

    def _handle_rawx(self, url, chunks, headers, storage_method, reqid):
        pile = GreenPile(PARALLEL_CHUNKS_DELETE)
        cid = url.get('id')
        for chunk in chunks:
            pile.spawn(self.delete_chunk, chunk, cid, reqid)
        resps = [resp for resp in pile if resp]
        for resp in resps:
            if resp.status != 204:
                self.logger.warn(
                    'failed to delete chunk %s (HTTP %s)',
                    resp.chunk['id'], resp.status)

    def _handle_b2(self, url, chunks, headers, storage_method, reqid):
        meta = {'container_id': url['id']}
        chunk_list = []
        for chunk in chunks:
            chunk['url'] = chunk['id']
            chunk_list.append(chunk)
        key_file = self.conf.get('key_file')
        b2_creds = BackblazeUtils.get_credentials(
            storage_method, key_file)
        try:
            BackblazeDeleteHandler(meta, chunk_list,
                                   b2_creds).delete()
        except OioException as exc:
            self.logger.warn('delete failed: %s' % str(exc))

    def _load_handler(self, chunk_method):
        storage_method = STORAGE_METHODS.load(chunk_method)
        handler = self.handlers.get(storage_method.type)
        if not handler:
            raise OioException("No handler found for chunk method [%s]" %
                               chunk_method)
        return handler, storage_method

    def process(self, env, cb):
        event = Event(env)
        if event.event_type == EventTypes.CONTENT_DELETED:
            url = event.env.get('url')
            chunks = []
            content_headers = list()

            for item in event.data:
                if item.get('type') == 'chunks':
                    chunks.append(item)
                if item.get("type") == 'contents_headers':
                    content_headers.append(item)
            if len(chunks):
                reqid = request_id()
                if not content_headers:
                    chunk_method = guess_storage_method(chunks[0]['id']) + '/'
                else:
                    chunk_method = content_headers[0]['chunk-method']
                handler, storage_method = self._load_handler(chunk_method)
                handler(url, chunks, content_headers, storage_method, reqid)
                return self.app(env, cb)

        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def reaper_filter(app):
        return ContentReaperFilter(app, conf)
    return reaper_filter
