from oio.api.base import HttpApi
from oio.common.exceptions import ClientException, NotFound, VolumeException
from oio.common.exceptions import ServiceUnavailable
from oio.conscience.client import ConscienceClient
from oio.directory.client import DirectoryClient


RDIR_ACCT = '_RDIR'


def _make_id(ns, type_, addr):
    return "%s|%s|%s" % (ns, type_, addr)


class RdirClient(HttpApi):
    """
    Client class for rdir services.
    """

    def __init__(self, conf, **kwargs):
        super(RdirClient, self).__init__(None, **kwargs)
        self.conf = conf
        self.ns = self.conf["namespace"]
        self.directory = DirectoryClient(conf, **kwargs)
        self._addr_cache = dict()

    def assign_all_rawx(self):
        """
        Find a rdir service for all rawx that don't have one already.
        """
        cs = ConscienceClient(self.conf)
        all_rawx = cs.all_services('rawx')
        all_rdir = cs.all_services('rdir', True)
        by_id = {_make_id(self.ns, 'rdir', x['addr']): x
                 for x in all_rdir}
        for rawx in all_rawx:
            try:
                # Verify that there is no rdir linked
                resp = self.directory.list(RDIR_ACCT, rawx['addr'],
                                           service_type='rdir')
                rawx['rdir'] = by_id[_make_id(self.ns, 'rdir',
                                              self._lookup_rdir_host(resp))]
            except (NotFound, ClientException):
                if rawx['score'] <= 0:
                    self.logger.warn("rawx %s has score %s, and thus cannot be"
                                     " affected a rdir (load balancer "
                                     "limitation)",
                                     rawx['addr'], rawx['score'])
                    continue
                rdir = self._smart_link_rdir(rawx['addr'], cs, all_rdir)
                n_bases = by_id[rdir]['tags'].get("stat.opened_db_count", 0)
                by_id[rdir]['tags']["stat.opened_db_count"] = n_bases + 1
                rawx['rdir'] = by_id[rdir]
        return all_rawx

    def _smart_link_rdir(self, volume_id, cs=None, all_rdir=None):
        """
        Force the load balancer to avoid services that already host more
        bases than the average while selecting rdir services.
        """
        if not cs:
            cs = ConscienceClient(self.conf)
        if not all_rdir:
            all_rdir = cs.all_services('rdir', True)
        if len(all_rdir) <= 0:
            raise ServiceUnavailable("No rdir service found in %s" % self.ns)

        avail_base_count = [x['tags']['stat.opened_db_count'] for x in all_rdir
                            if x['score'] > 0]
        if len(avail_base_count) <= 0:
            raise ServiceUnavailable(
                    "No valid rdir service found in %s" % self.ns)
        mean = sum(avail_base_count) / float(len(avail_base_count))
        avoids = [_make_id(self.ns, "rdir", x['addr'])
                  for x in all_rdir
                  if x['score'] > 0 and
                  x['tags']['stat.opened_db_count'] > mean]
        known = [_make_id(self.ns, "rawx", volume_id)]
        try:
            polled = cs.poll('rdir', avoid=avoids, known=known)[0]
        except ClientException as exc:
            if exc.status != 481:
                raise
            # Retry without `avoids`, hoping the next iteration will rebalance
            polled = cs.poll('rdir', known=known)[0]
        forced = {'host': polled['addr'], 'type': 'rdir',
                  'seq': 1, 'args': "", 'id': polled['id']}
        self.directory.force(RDIR_ACCT, volume_id, 'rdir',
                             forced, autocreate=True)
        return polled['id']

    def _link_rdir(self, volume_id, smart=True):
        if not smart:
            self.directory.link(RDIR_ACCT, volume_id, 'rdir',
                                autocreate=True)
        else:
            self._smart_link_rdir(volume_id)
        return self.directory.list(RDIR_ACCT, volume_id, service_type='rdir')

    def _lookup_rdir_host(self, resp):
        host = None
        for srv in resp.get('srv', {}):
            if srv['type'] == 'rdir':
                host = srv['host']
        if not host:
            raise ClientException("No rdir service found in %s" % resp)
        return host

    def _get_rdir_addr(self, volume_id, create=False, nocache=False):
        if not nocache and volume_id in self._addr_cache:
            return self._addr_cache[volume_id]
        resp = {}
        try:
            resp = self.directory.list(RDIR_ACCT, volume_id,
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
        uri = 'http://%s/v1/rdir/%s' % (rdir_host, action)
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

        self._rdir_request(volume_id, 'POST', 'push', create=True,
                           json=body, headers=headers)

    def chunk_delete(self, volume_id, container_id, content_id, chunk_id):
        """Unreference a chunk from the reverse directory"""
        body = {'container_id': container_id,
                'content_id': content_id,
                'chunk_id': chunk_id}

        self._rdir_request(volume_id, 'DELETE', 'delete', json=body)

    def chunk_fetch(self, volume, limit=100, rebuild=False,
                    container_id=None):
        """
        Fetch the list of chunks belonging to the specified volume.

        :param volume: the volume to get chunks from
        :type volume: `str`
        :param limit: maximum number of results to return
        :type limit: `int`
        :param rebuild:
        :type rebuild: `bool`
        :keyword container_id: get only chunks belonging to
           the specified container
        :type container_id: `str`
        """
        req_body = {'limit': limit}
        if rebuild:
            req_body['rebuild'] = True
        if container_id:
            req_body['container_id'] = container_id

        while True:
            resp, resp_body = self._rdir_request(volume, 'POST', 'fetch',
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
        self._rdir_request(volume, 'POST', 'admin/incident', json=body)

    def admin_incident_get(self, volume):
        resp, resp_body = self._rdir_request(volume, 'GET',
                                             'admin/incident')
        return resp_body.get('date')

    def admin_lock(self, volume, who):
        body = {'who': who}

        self._rdir_request(volume, 'POST', 'admin/lock', json=body)

    def admin_unlock(self, volume):
        self._rdir_request(volume, 'POST', 'admin/unlock')

    def admin_show(self, volume):
        resp, resp_body = self._rdir_request(volume, 'GET', 'admin/show')
        return resp_body

    def admin_clear(self, volume, clear_all=False):
        body = {'all': clear_all}
        resp, resp_body = self._rdir_request(
            volume, 'POST', 'admin/clear', json=body)
        return resp_body

    def status(self, volume):
        resp, resp_body = self._rdir_request(volume, 'GET', 'status')
        return resp_body
