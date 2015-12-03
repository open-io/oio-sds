from oio.common.client import Client
from oio.common.exceptions import ClientException, NotFound
from oio.common.utils import true_value
from oio.directory.client import DirectoryClient


class RdirClient(Client):
    def __init__(self, conf, **kwargs):
        super(RdirClient, self).__init__(conf, **kwargs)
        self.autocreate = true_value(conf.get('autocreate', True))
        self.directory_client = DirectoryClient(conf)

    # TODO keep rdir addr in local cache to avoid lookup requests
    def _get_rdir_addr(self, volume_id):
        try:
            resp = self.directory_client.show(acct='_RDIR', ref=volume_id)
        except NotFound as e:
            if self.autocreate:
                self.directory_client.link('_RDIR', volume_id, 'rdir',
                                           autocreate=True)
                resp = self.directory_client.show(acct='_RDIR', ref=volume_id)
            else:
                raise e

        for srv in resp['srv']:
            if srv['type'] == 'rdir':
                return srv['host']
        raise ClientException("No rdir service found")

    def _make_uri(self, action, volume_id):
        rdir_host = self._get_rdir_addr(volume_id)
        uri = 'http://%s/v1/%s/%s?vol=%s' % (
            rdir_host, self.ns, action, volume_id)
        return uri

    def _rdir_request(self, volume, method, action, **kwargs):
        uri = self._make_uri(action, volume)
        resp, body = self._direct_request(method, uri, **kwargs)
        return resp, body

    def chunk_push(self, volume_id, container_id, content_id, chunk_id,
                   **data):
        body = {'container_id': container_id,
                'content_id': content_id,
                'chunk_id': chunk_id}

        for key, value in data.iteritems():
            body[key] = value

        headers = {}

        self._rdir_request(volume_id, 'POST', 'rdir/push',
                           json=body, headers=headers)

    def chunk_delete(self, volume_id, container_id, content_id, chunk_id):
        body = {'container_id': container_id,
                'content_id': content_id,
                'chunk_id': chunk_id}

        self._rdir_request(volume_id, 'DELETE', 'rdir/delete', json=body)

    def chunk_fetch(self, volume, limit=100, rebuild=False):
        req_body = {'limit': limit}
        if rebuild:
            req_body['rebuild'] = True

        while True:
            resp, resp_body = self._rdir_request(volume, 'POST', 'rdir/fetch',
                                                 json=req_body)
            resp.raise_for_status()
            if len(resp_body) == 0:
                break
            for (key, value) in resp_body:
                container, content, chunk = key.split('|')
                yield container, content, chunk, value
            req_body['start_after'] = key

    def admin_incident_set(self, volume, date):
        body = {'date': date}
        self._rdir_request(volume, 'POST', 'rdir/admin/incident', json=body)

    def admin_incident_get(self, volume):
        resp, resp_body = self._rdir_request(volume, 'GET',
                                             'rdir/admin/incident')
        return resp_body.get('date')

    def admin_lock(self, volume, who):
        body = {'who': who}

        self._rdir_request(volume, 'POST', 'rdir/admin/lock', json=body)

    def admin_unlock(self, volume):
        self._rdir_request(volume, 'POST', 'rdir/admin/unlock')

    def admin_show(self, volume):
        resp, resp_body = self._rdir_request(volume, 'GET', 'rdir/admin/show')
        return resp_body
