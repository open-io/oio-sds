from oio.common.client import Client
from oio.common.exceptions import ClientException
from oio.common.utils import true_value
from oio.directory.client import DirectoryClient


class RdirClient(Client):
    def __init__(self, conf, **kwargs):
        super(RdirClient, self).__init__(conf, **kwargs)
        self.autocreate = true_value(conf.get('autocreate', True))
        self.directory_client = DirectoryClient(conf)

    def _get_rdir_addr(self, volume_id):
        resp = self.directory_client.show(acct="_RDIR", ref=volume_id)
        for srv in resp['srv']:
            if srv['type'] == 'rdir':
                return srv['host']
        raise ClientException("No rdir service found")

    def _make_uri(self, action, volume_id):
        rdir_host = self._get_rdir_addr(volume_id)
        uri = 'http://%s/%s/%s?vol=%s' % (
            rdir_host, self.ns, action, volume_id)
        return uri

    def chunk_push(self, volume, container, content, chunk,
                   mtime=None, rtime=None):
        uri = self._make_uri('rdir/push', volume)
        body = {'container': container,
                'content': content,
                'chunk': chunk}
        if mtime:
            body['mtime'] = mtime
        if rtime:
            body['rtime'] = rtime
        headers = {}
        if self.autocreate:
            headers['x-oio-action-mode'] = 'autocreate'

        self._direct_request('POST', uri, json=body, headers=headers)

    def chunk_delete(self, volume, container, content, chunk):
        uri = self._make_uri('rdir/delete', volume)
        body = {'container': container,
                'content': content,
                'chunk': chunk}

        self._direct_request('DELETE', uri, json=body)

    def chunk_fetch(self, volume, limit=100, rebuild=False):
        uri = self._make_uri('rdir/fetch', volume)
        req_body = {'limit': limit}
        if rebuild:
            req_body['rebuild'] = True

        while True:
            resp, resp_body = self._direct_request('POST', uri, json=req_body)
            resp.raise_for_status()
            if len(resp_body) == 0:
                break
            for key, value in resp_body.iteritems():
                container, content, chunk = key.split('|')
                yield container, content, chunk, value
            req_body['start_after'] = key

    def admin_broken_set(self, volume, date):
        uri = self._make_uri('rdir/admin/broken', volume)
        body = {'date': date}

        self._direct_request('POST', uri, json=body)

    def admin_broken_get(self, volume):
        uri = self._make_uri('rdir/admin/broken', volume)

        resp, resp_body = self._direct_request('GET', uri)
        return resp_body.get('date')

    def admin_lock(self, volume, who):
        uri = self._make_uri('rdir/admin/lock', volume)
        body = {'who': who}

        self._direct_request('POST', uri, json=body)

    def admin_unlock(self, volume):
        uri = self._make_uri('rdir/admin/unlock', volume)

        self._direct_request('POST', uri)

    def admin_show(self, volume):
        uri = self._make_uri('rdir/admin/show', volume)

        resp, resp_body = self._direct_request('GET', uri)
        return resp_body
