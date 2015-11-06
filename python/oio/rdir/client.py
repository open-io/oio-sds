from oio.common.client import Client
from oio.common.utils import true_value


class RdirClient(Client):
    def __init__(self, conf, **kwargs):
        super(RdirClient, self).__init__(conf, **kwargs)
        self.autocreate = true_value(conf.get('autocreate'))

    def _make_uri(self, action, volume_id):
        uri = 'v3.0/%s/%s?vol=%s' % (self.ns, action, volume_id)
        return uri

    def chunk_push(self, volume_id, chunk_id, content_cid, content_path):
        uri = self._make_uri('rdir/push', volume_id)
        body = {'container': content_cid,
                'content': content_path,
                'chunk': chunk_id}
        headers = {}
        if self.autocreate:
            headers['x-oio-action-mode'] = 'autocreate'

        self._request('POST', uri, json=body, headers=headers)
