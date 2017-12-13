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


from oio.blob.client import BlobClient
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
        self.blob_client = BlobClient()

    def _handle_rawx(self, url, chunks, content_headers,
                     storage_method, reqid):
        cid = url.get('id')
        headers = {'X-oio-req-id': reqid}
        resps = self.blob_client.chunk_delete_many(
            chunks, cid=cid, headers=headers)
        for resp in resps:
            if isinstance(resp, Exception):
                self.logger.warn(
                    'failed to delete chunk %s (%s)',
                    resp.chunk['url'], resp)
            elif resp.status not in (204, 404):
                self.logger.warn(
                    'failed to delete chunk %s (HTTP %s)',
                    resp.chunk['url'], resp.status)

    def _handle_b2(self, url, chunks, headers, storage_method, reqid):
        meta = {'container_id': url['id']}
        key_file = self.conf.get('key_file')
        b2_creds = BackblazeUtils.get_credentials(
            storage_method, key_file)
        try:
            BackblazeDeleteHandler(meta, chunks, b2_creds).delete()
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
                    # The event contains "id" whereas the API uses "url".
                    item['url'] = item['id']
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
