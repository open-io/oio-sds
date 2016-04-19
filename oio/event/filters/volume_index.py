from oio.event.evob import Event
from oio.event.consumer import EventTypes
from oio.event.filters.base import Filter


class VolumeIndexFilter(Filter):

    def process(self, env, cb):
        event = Event(env)
        if event.event_type == EventTypes.CHUNK_DELETED:
            data = event.data
            volume_id = data.get('volume_id')
            container_id = data.get('container_id')
            content_id = data.get('content_id')
            chunk_id = data.get('chunk_id')
            self.app.rdir.chunk_delete(
                volume_id, container_id, content_id, chunk_id)
        elif event.event_type == EventTypes.CHUNK_NEW:
            when = env.get('when')
            data = env.get('data').copy()
            volume_id = data.get('volume_id')
            del data['volume_id']
            container_id = data.get('container_id')
            del data['container_id']
            content_id = data.get('content_id')
            del data['content_id']
            chunk_id = data.get('chunk_id')
            del data['chunk_id']
            data['mtime'] = when
            self.app.rdir.chunk_push(
                volume_id, container_id, content_id, chunk_id, **data)
        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def except_filter(app):
        return VolumeIndexFilter(app, conf)
    return except_filter
