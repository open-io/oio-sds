from oio.common.client import Client
from oio.common.exceptions import ClientException, NotFound, VolumeException
from oio.api.directory import DirectoryAPI


RDIR_ACCT = '_RDIR'


class RdirClient(Client):
    def __init__(self, conf, **kwargs):
        super(RdirClient, self).__init__(conf, **kwargs)
        self.directory = DirectoryAPI(self.ns, self.endpoint, **kwargs)
        self._addr_cache = dict()

    def _lookup_rdir_host(self, resp):
        host = None
        for srv in resp.get('srv', {}):
            if srv['type'] == 'rdir':
                host = srv['host']
        if not host:
            raise ClientException("No rdir service found")
        return host

    def _link_rdir(self, volume_id):
        self.directory.link(RDIR_ACCT, volume_id, 'rdir',
                            autocreate=True)
        return self.directory.get(RDIR_ACCT, volume_id, service_type='rdir')

    def _get_rdir_addr(self, volume_id, create=False, nocache=False):
        if not nocache and volume_id in self._addr_cache:
            return self._addr_cache[volume_id]
        resp = {}
        try:
            resp = self.directory.get(RDIR_ACCT, volume_id,
                                      service_type='rdir')
        except NotFound:
            if not create:
                raise VolumeException('No such volume %s' % volume_id)

        try:
            host = self._lookup_rdir_host(resp)
        except ClientException:
            # Reference exists but no rdir linked
            if not create:
                raise
            resp = self._link_rdir(volume_id)
            host = self._lookup_rdir_host(resp)
        self._addr_cache[volume_id] = host
        return host

    def _make_uri(self, action, volume_id, create=False, nocache=False):
        rdir_host = self._get_rdir_addr(volume_id, create=create,
                                        nocache=nocache)
        uri = 'http://%s/v1/%s' % (rdir_host, action)
        return uri

    def _rdir_request(self, volume, method, action, create=False, **kwargs):
        params = {'vol': volume}
        if create:
            params['create'] = '1'
        uri = self._make_uri(action, volume, create=create)
        try:
            resp, body = self._direct_request(method, uri, params=params,
                                              **kwargs)
        except NotFound:
            uri = self._make_uri(action, volume, create=create, nocache=True)
            resp, body = self._direct_request(method, uri, params=params,
                                              **kwargs)
        return resp, body

    def chunk_push(self, volume_id, container_id, content_id, chunk_id,
                   **data):
        """Reference a chunk in the reverse directory"""
        body = {'container_id': container_id,
                'content_id': content_id,
                'chunk_id': chunk_id}

        for key, value in data.iteritems():
            body[key] = value

        headers = {}

        self._rdir_request(volume_id, 'POST', 'rdir/push', create=True,
                           json=body, headers=headers)

    def chunk_delete(self, volume_id, container_id, content_id, chunk_id):
        """Unreference a chunk from the reverse directory"""
        body = {'container_id': container_id,
                'content_id': content_id,
                'chunk_id': chunk_id}

        self._rdir_request(volume_id, 'DELETE', 'rdir/delete', json=body)

    def chunk_fetch(self, volume, limit=100, rebuild=False):
        """Fetch the list of chunks belonging to the specified volume"""
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
        body = {'date': int(float(date))}
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

    def admin_clear(self, volume, clear_all=False):
        body = {'all': clear_all}
        resp, resp_body = self._rdir_request(
            volume, 'POST', 'rdir/admin/clear', json=body)
        return resp_body

    def status(self, volume):
        resp, resp_body = self._rdir_request(volume, 'GET', 'rdir/status')
        return resp_body
