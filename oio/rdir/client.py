# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from six import iteritems
from oio.api.base import HttpApi
from oio.common.exceptions import ClientException, NotFound, VolumeException
from oio.common.exceptions import ServiceUnavailable, ServerException
from oio.common.exceptions import OioNetworkException
from oio.common.utils import request_id
from oio.common.logger import get_logger
from oio.conscience.client import ConscienceClient
from oio.directory.client import DirectoryClient


RDIR_ACCT = '_RDIR'


def _make_id(ns, type_, addr):
    return "%s|%s|%s" % (ns, type_, addr)


def _filter_rdir_host(allsrv):
    for srv in allsrv.get('srv', {}):
        if srv['type'] == 'rdir':
            return srv['host']
    raise NotFound("No rdir service found in %s" % (allsrv, ))


class RdirDispatcher(object):
    def __init__(self, conf, **kwargs):
        self.conf = conf
        self.ns = conf['namespace']
        self.logger = get_logger(conf)
        self.directory = DirectoryClient(conf, logger=self.logger, **kwargs)
        self.rdir = RdirClient(conf, logger=self.logger, **kwargs)
        self._cs = None

    @property
    def cs(self):
        if not self._cs:
            self._cs = ConscienceClient(self.conf, logger=self.logger)
        return self._cs

    def get_assignation(self):
        all_rawx = self.cs.all_services('rawx')
        all_rdir = self.cs.all_services('rdir', True)
        by_id = {_make_id(self.ns, 'rdir', x['addr']): x
                 for x in all_rdir}

        for rawx in all_rawx:
            try:
                # Verify that there is no rdir linked
                resp = self.directory.list(RDIR_ACCT, rawx['addr'],
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
        return all_rawx, all_rdir

    def assign_all_rawx(self, max_per_rdir=None):
        """
        Find a rdir service for all rawx that don't have one already.

        :param max_per_rdir: maximum number or rawx services that an rdir
                             can be linked to
        :type max_per_rdir: `int`
        """
        all_rawx = self.cs.all_services('rawx')
        all_rdir = self.cs.all_services('rdir', True)
        if len(all_rdir) <= 0:
            raise ServiceUnavailable("No rdir service found in %s" % self.ns)

        by_id = {_make_id(self.ns, 'rdir', x['addr']): x
                 for x in all_rdir}

        for rawx in all_rawx:
            try:
                # Verify that there is no rdir linked
                resp = self.directory.list(RDIR_ACCT, rawx['addr'],
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
                rdir = self._smart_link_rdir(rawx['addr'], all_rdir,
                                             max_per_rdir)
                n_bases = by_id[rdir]['tags'].get("stat.opened_db_count", 0)
                by_id[rdir]['tags']["stat.opened_db_count"] = n_bases + 1
                rawx['rdir'] = by_id[rdir]
        return all_rawx

    def _smart_link_rdir(self, volume_id, all_rdir, max_per_rdir=None):
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
            polled = self._poll_rdir(avoid=avoids, known=known)
        except ClientException as exc:
            if exc.status != 481 or max_per_rdir:
                raise
            # Retry without `avoids`, hoping the next iteration will rebalance
            polled = self._poll_rdir(known=known)
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

    def _poll_rdir(self, avoid=None, known=None):
        """Call the special rdir service pool (created if missing)"""
        try:
            svcs = self.cs.poll('__rawx_rdir', avoid=avoid, known=known)
        except ClientException as exc:
            if exc.status != 400:
                raise
            self.cs.lb.create_pool('__rawx_rdir', ((1, 'rawx'), (1, 'rdir')))
            svcs = self.cs.poll('__rawx_rdir', avoid=avoid, known=known)
        for svc in svcs:
            # FIXME: we should include the service type in a dedicated field
            if 'rdir' in svc['id']:
                return svc
        raise ServerException("LB returned incoherent result: %s" % svcs)


class RdirClient(HttpApi):
    """
    Client class for rdir services.
    """

    def __init__(self, conf, **kwargs):
        super(RdirClient, self).__init__(conf, **kwargs)
        self.directory = DirectoryClient(conf, **kwargs)
        self._addr_cache = dict()

    def _clear_cache(self, volume_id):
        self._addr_cache.pop(volume_id, None)

    def _get_rdir_addr(self, volume_id, req_id=None):
        # Initial lookup in the cache
        if volume_id in self._addr_cache:
            return self._addr_cache[volume_id]
        # Not cached, try a direct lookup
        try:
            headers = {'X-oio-req-id': req_id or request_id()}
            resp = self.directory.list(RDIR_ACCT, volume_id,
                                       service_type='rdir',
                                       headers=headers)
            host = _filter_rdir_host(resp)
            # Add the new service to the cache
            self._addr_cache[volume_id] = host
            return host
        except NotFound:
            raise VolumeException('No rdir assigned to volume %s' % volume_id)

    def _make_uri(self, action, volume_id, req_id=None):
        rdir_host = self._get_rdir_addr(volume_id, req_id)
        return 'http://%s/v1/rdir/%s' % (rdir_host, action)

    def _rdir_request(self, volume, method, action, create=False, **kwargs):
        params = {'vol': volume}
        if create:
            params['create'] = '1'
        uri = self._make_uri(action, volume, req_id=kwargs.get('X-oio-req-id'))
        try:
            resp, body = self._direct_request(method, uri, params=params,
                                              **kwargs)
        except OioNetworkException:
            self._clear_cache(volume)
            raise

        return resp, body

    def create(self, volume_id):
        """Create the database for `volume_id` on the appropriate rdir"""
        self._rdir_request(volume_id, 'POST', 'create')

    def chunk_push(self, volume_id, container_id, content_id, chunk_id,
                   **data):
        """Reference a chunk in the reverse directory"""
        body = {'container_id': container_id,
                'content_id': content_id,
                'chunk_id': chunk_id}

        for key, value in iteritems(data):
            body[key] = value

        self._rdir_request(volume_id, 'POST', 'push', create=True,
                           json=body)

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
