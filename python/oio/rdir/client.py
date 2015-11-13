from oio.common.client import Client
from oio.common.utils import true_value


class RdirClient(Client):
    def __init__(self, conf, **kwargs):
        super(RdirClient, self).__init__(conf, **kwargs)
        self.autocreate = true_value(conf.get('autocreate', True))

    def _make_uri(self, action, volume_id):
        uri = 'v3.0/%s/%s?vol=%s' % (self.ns, action, volume_id)
        return uri

    def chunk_push(self, volume, container, content, chunk, mtime=None):
        uri = self._make_uri('rdir/push', volume)
        body = {'container': container,
                'content': content,
                'chunk': chunk}
        if mtime:
            body['mtime'] = mtime
        headers = {}
        if self.autocreate:
            headers['x-oio-action-mode'] = 'autocreate'

        self._request('POST', uri, json=body, headers=headers)

    def chunk_delete(self, volume, container, content, chunk):
        uri = self._make_uri('rdir/delete', volume)
        body = {'container': container,
                'content': content,
                'chunk': chunk}

        self._request('DELETE', uri, json=body)
