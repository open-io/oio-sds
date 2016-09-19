from urlparse import urlparse
from eventlet import Timeout, GreenPile
from oio.common.http import http_connect
from oio.event.evob import Event
from oio.event.consumer import EventTypes
from oio.event.filters.base import Filter
from oio.common.exceptions import OioException
from oio.api.backblaze import BackblazeDeleteHandler
from oio.api.backblaze_http import BackblazeUtils
from oio.common.storage_method import STORAGE_METHODS

CHUNK_TIMEOUT = 60
PARALLEL_CHUNKS_DELETE = 3
NB_TRIES = 3


class ContentReaperFilter(Filter):

    def process(self, env, cb):
        event = Event(env)
        if event.event_type == EventTypes.CONTENT_DELETED:
            pile = GreenPile(PARALLEL_CHUNKS_DELETE)
            url = event.env.get('url')
            chunks = []
            content_headers = None
            for item in event.data:
                if item.get('type') == 'chunks':
                    chunks.append(item)
                if item.get("type") == 'contents_headers':
                    content_headers = item
            if len(chunks):
                def delete_chunk(chunk):
                    resp = None
                    p = urlparse(chunk['id'])
                    try:
                        with Timeout(CHUNK_TIMEOUT):
                            conn = http_connect(p.netloc, 'DELETE', p.path)
                            resp = conn.getresponse()
                            resp.chunk = chunk
                    except (Exception, Timeout) as exc:
                        self.logger.warn(
                            'error while deleting chunk %s "%s"',
                            chunk['id'], str(exc.message))
                    return resp

                def delete_chunk_backblaze(chunks, url, storage_method):
                    meta = {}
                    meta['container_id'] = url['id']
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

                chunk_method = content_headers['chunk-method']
                # don't load storage method other than backblaze
                if chunk_method.startswith('backblaze'):
                    storage_method = STORAGE_METHODS.load(chunk_method)
                    delete_chunk_backblaze(chunks, url, storage_method)
                    return self.app(env, cb)
                for chunk in chunks:
                    pile.spawn(delete_chunk, chunk)

                resps = [resp for resp in pile if resp]

                for resp in resps:
                    if resp.status != 204:
                        self.logger.warn(
                            'failed to delete chunk %s (HTTP %s)',
                            resp.chunk['id'], resp.status)
        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def reaper_filter(app):
        return ContentReaperFilter(app, conf)
    return reaper_filter
