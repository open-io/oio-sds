from eventlet import Timeout, GreenPile
from urlparse import urlparse
from oio.common.http import http_connect
from oio.event.evob import Event
from oio.event.consumer import EventTypes
from oio.event.filters.base import Filter

CHUNK_TIMEOUT = 60
PARALLEL_CHUNKS_DELETE = 3


class ContentReaperFilter(Filter):

    def process(self, env, cb):
        event = Event(env)
        if event.event_type == EventTypes.CONTENT_DELETED:
            pile = GreenPile(PARALLEL_CHUNKS_DELETE)

            chunks = []

            for item in event.data:
                if item.get('type') == 'chunks':
                    chunks.append(item)
            if len(chunks):
                def delete_chunk(chunk):
                    resp = None
                    p = urlparse(chunk['id'])
                    try:
                        with Timeout(CHUNK_TIMEOUT):
                            conn = http_connect(
                                p.hostname, p.port, 'DELETE', p.path)
                            resp = conn.getresponse()
                            resp.chunk = chunk
                    except (Exception, Timeout) as e:
                        self.logger.warn(
                            'error while deleting chunk %s "%s"',
                            chunk['id'], str(e.message))
                    return resp

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
