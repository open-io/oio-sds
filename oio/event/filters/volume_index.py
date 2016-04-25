from oio.event.evob import Event
from oio.event.consumer import EventTypes
from oio.event.filters.base import Filter


CHUNK_EVENTS = [EventTypes.CHUNK_DELETED, EventTypes.CHUNK_NEW]


class VolumeIndexFilter(Filter):

    def process(self, env, cb):
        event = Event(env)
        if event.event_type in CHUNK_EVENTS:
            data = event.data
            volume_id = data.get('volume_id')
            container_id = data.get('container_id')
            content_id = data.get('content_id')
            chunk_id = data.get('chunk_id')
            if event.event_type == EventTypes.CHUNK_DELETED:
                self.app.rdir.chunk_delete(
                    volume_id, container_id, content_id, chunk_id)
            else:
                args = {
                    'mtime': event.when,
                    'chunk_hash': data['chunk_hash'],
                    'chunk_position': data['chunk_position'],
                    'content_path': data['content_path'],
                    'content_version': data['content_version'],
                    'content_chunk_method': data['content_chunk_method'],
                    'content_mime_type': data['content_mime_type'],
                    'content_storage_policy': data['content_storage_policy'],
                    'content_nbchunks': data['content_nbchunks']}
                self.app.rdir.chunk_push(
                    volume_id, container_id, content_id, chunk_id, **args)
        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def except_filter(app):
        return VolumeIndexFilter(app, conf)
    return except_filter
