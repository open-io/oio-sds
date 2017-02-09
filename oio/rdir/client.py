from oio.common.client import Client
from oio.common.exceptions import ClientException, NotFound, \
        VolumeException, ServiceUnavailable
from oio.conscience.client import ConscienceClient
from oio.api.directory import DirectoryAPI


RDIR_ACCT = '_RDIR'


def _make_id(ns, type_, addr):
    return "%s|%s|%s" % (ns, type_, addr)


def _filter_rdir_host(allsrv):
    for srv in allsrv.get('srv', {}):
        if srv['type'] == 'rdir':
            return srv['host']
    raise NotFound("No rdir service found in %s" % (allsrv, ))


class RdirDispatcher(Client):
    def __init__(self, conf, **kwargs):
        super(RdirDispatcher, self).__init__(conf, **kwargs)
        self.directory = DirectoryAPI(self.ns, self.endpoint, **kwargs)
        self.rdir = RdirClient(conf, **kwargs)

    def get_assignation(self):
        cs = ConscienceClient(self.conf)
        all_rawx = cs.all_services('rawx')
        all_rdir = cs.all_services('rdir', True)
        by_id = {_make_id(self.ns, 'rdir', x['addr']): x
                 for x in all_rdir}

        for rawx in all_rawx:
            try:
                # Verify that there is no rdir linked
                resp = self.directory.get(RDIR_ACCT, rawx['addr'],
                                          service_type='rdir')
                rdir_host = _filter_rdir_host(resp)
                try:
                    rawx['rdir'] = by_id[_make_id(self.ns, 'rdir', rdir_host)]
                except KeyError:
                    self.logger.warn("rdir %s linked to rawx %s seems down",
                                     rdir_host, rawx['addr'])
                    rawx['rdir'] = {"addr": rdir_host, "tags": dict()}
                    by_id[_make_id(self.ns, 'rdir', rdir_host)] = rawx['rdir']
            except NotFound:
                self.logger.info("No rdir linked to %s", rawx['addr'])
        return all_rawx

    def assign_all_rawx(self, max_per_rdir=None):
        """
        Find a rdir service for all rawx that don't have one already.

        :param max_per_rdir: maximum number or rawx services that an rdir
                             can be linked to
        :type max_per_rdir: `int`
        """
        cs = ConscienceClient(self.conf)
        all_rawx = cs.all_services('rawx')
        all_rdir = cs.all_services('rdir', True)
        if len(all_rdir) <= 0:
            raise ServiceUnavailable("No rdir service found in %s" % self.ns)

        by_id = {_make_id(self.ns, 'rdir', x['addr']): x
                 for x in all_rdir}

        for rawx in all_rawx:
            try:
                # Verify that there is no rdir linked
                resp = self.directory.get(RDIR_ACCT, rawx['addr'],
                                          service_type='rdir')
                rdir_host = _filter_rdir_host(resp)
                try:
                    rawx['rdir'] = by_id[_make_id(self.ns, 'rdir', rdir_host)]
                except KeyError:
                    self.logger.warn("rdir %s linked to rawx %s seems down",
                                     rdir_host, rawx['addr'])
            except (NotFound, ClientException):
                if rawx['score'] <= 0:
                    self.logger.warn("rawx %s has score %s, and thus cannot be"
                                     " affected a rdir (load balancer "
                                     "limitation)",
                                     rawx['addr'], rawx['score'])
                    continue
                rdir = self._smart_link_rdir(rawx['addr'], cs, all_rdir,
                                             max_per_rdir)
                n_bases = by_id[rdir]['tags'].get("stat.opened_db_count", 0)
                by_id[rdir]['tags']["stat.opened_db_count"] = n_bases + 1
                rawx['rdir'] = by_id[rdir]
        return all_rawx

    def _smart_link_rdir(self, volume_id, cs, all_rdir, max_per_rdir=None):
        """
        Force the load balancer to avoid services that already host more
        bases than the average (or more than `max_per_rdir`)
        while selecting rdir services.
        """
        opened_db = [x['tags']['stat.opened_db_count'] for x in all_rdir
                     if x['score'] > 0]
        if len(opened_db) <= 0:
            raise ServiceUnavailable(
                    "No valid rdir service found in %s" % self.ns)
        if not max_per_rdir:
            upper_limit = sum(opened_db) / float(len(opened_db))
        else:
            upper_limit = max_per_rdir - 1
        avoids = [_make_id(self.ns, "rdir", x['addr'])
                  for x in all_rdir
                  if x['score'] > 0 and
                  x['tags']['stat.opened_db_count'] > upper_limit]
        known = [_make_id(self.ns, "rawx", volume_id)]
        try:
            polled = cs.poll('rdir', avoid=avoids, known=known)[0]
        except ClientException as exc:
            if exc.status != 481 or max_per_rdir:
                raise
            # Retry without `avoids`, hoping the next iteration will rebalance
            polled = cs.poll('rdir', known=known)[0]
        forced = {'host': polled['addr'], 'type': 'rdir',
                  'seq': 1, 'args': "", 'id': polled['id']}
        self.directory.force(RDIR_ACCT, volume_id, 'rdir',
                             forced, autocreate=True)
        try:
            self.rdir.create(volume_id)
        except Exception as exc:
            self.logger.warn("Failed to create database for %s on %s: %s",
                             volume_id, polled['addr'], exc)
        return polled['id']


class RdirClient(Client):
    def __init__(self, conf, **kwargs):
        super(RdirClient, self).__init__(conf, **kwargs)
        self.directory = DirectoryAPI(self.ns, self.endpoint, **kwargs)
        self._addr_cache = dict()

    def _clear_cache(self, volume_id):
        del self._addr_cache[volume_id]

    def _get_rdir_addr(self, volume_id):
        # Initial lookup in the cache
        if volume_id in self._addr_cache:
            return self._addr_cache[volume_id]
        # Not cached, try a direct lookup
        try:
            resp = self.directory.get(RDIR_ACCT, volume_id,
                                      service_type='rdir')
            host = _filter_rdir_host(resp)
            # Add the new service to the cache
            self._addr_cache[volume_id] = host
            return host
        except NotFound:
            raise VolumeException('No rdir assigned to volume %s' % volume_id)

    def _make_uri(self, action, volume_id):
        rdir_host = self._get_rdir_addr(volume_id)
        return 'http://%s/v1/%s' % (rdir_host, action)

    def _rdir_request(self, volume, method, action, create=False, **kwargs):
        params = {'vol': volume}
        if create:
            params['create'] = '1'
        uri = self._make_uri(action, volume)
        resp, body = self._direct_request(method, uri, params=params, **kwargs)
        return resp, body

    def create(self, volume_id):
        """Create the database for `volume_id` on the appropriate rdir"""
        self._rdir_request(volume_id, 'POST', 'rdir/create')

    def chunk_push(self, volume_id, container_id, content_id, chunk_id,
                   **data):
        """Reference a chunk in the reverse directory"""
        body = {'container_id': container_id,
                'content_id': content_id,
                'chunk_id': chunk_id}

        for key, value in data.iteritems():
            body[key] = value

        self._rdir_request(volume_id, 'POST', 'rdir/push', create=True,
                           json=body)

    def chunk_delete(self, volume_id, container_id, content_id, chunk_id):
        """Unreference a chunk from the reverse directory"""
        body = {'container_id': container_id,
                'content_id': content_id,
                'chunk_id': chunk_id}

        self._rdir_request(volume_id, 'DELETE', 'rdir/delete', json=body)

    def chunk_fetch(self, volume, limit=100, rebuild=False,
                    container_id=None):
        """
        Fetch the list of chunks belonging to the specified volume.
        You can set `container_id` to get only chunks belonging to
        the specified container.
        """
        req_body = {'limit': limit}
        if rebuild:
            req_body['rebuild'] = True
        if container_id:
            req_body['container_id'] = container_id

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
