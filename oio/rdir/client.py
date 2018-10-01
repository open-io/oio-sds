# Copyright (C) 2015-2018 OpenIO SAS, as part of OpenIO SDS
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

from oio.api.base import HttpApi
from oio.common.exceptions import ClientException, NotFound, VolumeException
from oio.common.exceptions import ServiceUnavailable, ServerException
from oio.common.exceptions import OioNetworkException, OioException, \
    reraise as oio_reraise
from oio.common.utils import group_chunk_errors, request_id
from oio.common.logger import get_logger
from oio.common.decorators import ensure_headers, ensure_request_id
from oio.conscience.client import ConscienceClient
from oio.directory.client import DirectoryClient
from time import sleep

RDIR_ACCT = '_RDIR'

# Special target that will match any service from the "known" service list
JOKER_SVC_TARGET = '__any_slot'


def _make_id(ns, type_, addr):
    return "%s|%s|%s" % (ns, type_, addr)


def _filter_rdir_host(allsrv):
    for srv in allsrv.get('srv', {}):
        if srv['type'] == 'rdir':
            return srv['host']
    raise NotFound("No rdir service found in %s" % (allsrv,))


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

    def get_assignation(self, **kwargs):
        all_rawx = self.cs.all_services('rawx', **kwargs)
        all_rdir = self.cs.all_services('rdir', True, **kwargs)
        by_id = {_make_id(self.ns, 'rdir', x['addr']): x
                 for x in all_rdir}

        for rawx in all_rawx:
            try:
                ref = rawx.get('tags', {}).get('tag.service_id')
                resp = self.directory.list(RDIR_ACCT, ref or rawx['addr'],
                                           service_type='rdir',
                                           **kwargs)
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
            except OioException as exc:
                self.logger.warn('Failed to get rdir linked to %s: %s',
                                 rawx['addr'], exc)
        return all_rawx, all_rdir

    def assign_all_meta2(self, max_per_rdir=None, **kwargs):
        all_meta2 = self.cs.all_services('meta2', **kwargs)
        all_rdir = self.cs.all_services('rdir', True, **kwargs)
        if len(all_rdir) <= 0:
            raise ServiceUnavailable("No rdir service found in %s" % self.ns)

        by_id = {_make_id(self.ns, 'rdir', x['addr']): x
                 for x in all_rdir}

        errors = list()
        for meta2 in all_meta2:
            meta2_address = meta2['tags'].get('tag.service_id', meta2['addr'])

            try:
                resp = self.directory.list(RDIR_ACCT, meta2_address,
                                           service_type='rdir', **kwargs)
                rdir_host = _filter_rdir_host(resp)
                try:
                    meta2['rdir'] = by_id[_make_id(self.ns, 'rdir', rdir_host)]
                except KeyError:
                    self.logger.warn("rdir %s linked to meta2 %s seems down",
                                     rdir_host, meta2_address)
            except NotFound:
                try:
                    rdir = self._smart_link_rdir(meta2_address, all_rdir,
                                                 service_type='meta2',
                                                 max_per_rdir=max_per_rdir,
                                                 **kwargs)
                except OioException as exc:
                    self.logger.warn("Failed to link an rdir to meta2 %s: %s",
                                     meta2_address, exc)
                    errors.append((meta2_address, exc))
                    continue
                n_bases = by_id[rdir]['tags'].get("stat.opened_db_count", 0)
                by_id[rdir]['tags']["stat.opened_db_count"] = n_bases + 1
                meta2['rdir'] = by_id[rdir]
            except OioException as exc:
                self.logger.warn("Failed to check rdir linked to rawx %s "
                                 "(thus won't try to make the link): %s",
                                 meta2_address, exc)
                errors.append((meta2_address, exc))
        if errors:
            # group_chunk_errors is flexible enough to accept service addresses
            errors = group_chunk_errors(errors)
            if len(errors) == 1:
                err, addrs = errors.popitem()
                oio_reraise(type(err), err, str(addrs))
            else:
                raise OioException('Several errors encountered: %s' %
                                   errors)
        return all_meta2

    def assign_all_rawx(self, max_per_rdir=None, **kwargs):
        """
        Find a rdir service for all rawx that don't have one already.

        :param max_per_rdir: maximum number or rawx services that an rdir
                             can be linked to
        :type max_per_rdir: `int`
        """
        all_rawx = self.cs.all_services('rawx', **kwargs)
        all_rdir = self.cs.all_services('rdir', True, **kwargs)
        if len(all_rdir) <= 0:
            raise ServiceUnavailable("No rdir service found in %s" % self.ns)

        by_id = {_make_id(self.ns, 'rdir', x['addr']): x
                 for x in all_rdir}

        errors = list()
        for rawx in all_rawx:
            rawx_id = rawx['tags'].get('tag.service_id', rawx['addr'])
            try:
                # Verify that there is no rdir linked
                resp = self.directory.list(RDIR_ACCT, rawx_id,
                                           service_type='rdir', **kwargs)
                rdir_host = _filter_rdir_host(resp)
                try:
                    rawx['rdir'] = by_id[_make_id(self.ns, 'rdir', rdir_host)]
                except KeyError:
                    self.logger.warn("rdir %s linked to rawx %s seems down",
                                     rdir_host, rawx['addr'])
            except NotFound:
                try:
                    rdir = self._smart_link_rdir(rawx_id, all_rdir,
                                                 max_per_rdir=max_per_rdir,
                                                 **kwargs)
                except OioException as exc:
                    self.logger.warn("Failed to link an rdir to rawx %s: %s",
                                     rawx['addr'], exc)
                    errors.append((rawx['addr'], exc))
                    continue
                n_bases = by_id[rdir]['tags'].get("stat.opened_db_count", 0)
                by_id[rdir]['tags']["stat.opened_db_count"] = n_bases + 1
                rawx['rdir'] = by_id[rdir]
            except OioException as exc:
                self.logger.warn("Failed to check rdir linked to rawx %s "
                                 "(thus won't try to make the link): %s",
                                 rawx['addr'], exc)
                errors.append((rawx['addr'], exc))
        if errors:
            # group_chunk_errors is flexible enough to accept service addresses
            errors = group_chunk_errors(errors)
            if len(errors) == 1:
                err, addrs = errors.popitem()
                oio_reraise(type(err), err, str(addrs))
            else:
                raise OioException('Several errors encountered: %s' %
                                   errors)
        return all_rawx

    def _smart_link_rdir(self, volume_id, all_rdir, max_per_rdir=None,
                         max_attempts=7, service_type='rawx', **kwargs):
        """
        Force the load balancer to avoid services that already host more
        bases than the average (or more than `max_per_rdir`)
        while selecting rdir services.
        """
        opened_db = [x['tags'].get('stat.opened_db_count', 0) for x in all_rdir
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
                  x['tags'].get('stat.opened_db_count', 0) > upper_limit]
        known = [_make_id(self.ns, service_type, volume_id)]
        try:
            polled = self._poll_rdir(avoid=avoids, known=known, **kwargs)
        except ClientException as exc:
            if exc.status != 481 or max_per_rdir:
                raise
            # Retry without `avoids`, hoping the next iteration will rebalance
            polled = self._poll_rdir(known=known, **kwargs)

        # Associate the rdir to the rawx
        forced = {'host': polled['addr'], 'type': 'rdir',
                  'seq': 1, 'args': "", 'id': polled['id']}
        for i in range(max_attempts):
            try:
                self.directory.force(RDIR_ACCT, volume_id, 'rdir',
                                     forced, autocreate=True, **kwargs)
                break
            except ClientException as ex:
                # Already done
                done = (455,)
                if ex.status in done:
                    break
                if ex.message.startswith(
                        'META1 error: (SQLITE_CONSTRAINT) '
                        'UNIQUE constraint failed'):
                    self.logger.info(
                        "Ignored exception (already0): %s", ex)
                    break
                if ex.message.startswith(
                        'META1 error: (SQLITE_CONSTRAINT) '
                        'columns cid, srvtype, seq are not unique'):
                    self.logger.info(
                        "Ignored exception (already1): %s", ex)
                    break
                # Manage several unretriable errors
                retry = (406, 450, 503, 504)
                if ex.status >= 400 and ex.status not in retry:
                    raise
                # Monotonic backoff (retriable and net erorrs)
                if i < max_attempts - 1:
                    sleep(i * 1.0)
                    continue
                # Too many attempts
                raise

        # Do the creation in the rdir itself
        try:
            self.rdir.create(volume_id, **kwargs)
        except Exception as exc:
            self.logger.warn("Failed to create database for %s on %s: %s",
                             volume_id, polled['addr'], exc)
        return polled['id']

    def _poll_rdir(self, avoid=None, known=None, **kwargs):
        """Call the special rdir service pool (created if missing)"""
        try:
            svcs = self.cs.poll('__rawx_rdir', avoid=avoid, known=known,
                                **kwargs)
        except ClientException as exc:
            if exc.status != 400:
                raise
            self.cs.lb.create_pool(
                '__rawx_rdir', ((1, JOKER_SVC_TARGET), (1, 'rdir')),
                **kwargs)
            svcs = self.cs.poll('__rawx_rdir', avoid=avoid, known=known,
                                **kwargs)
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

    @ensure_headers
    @ensure_request_id
    def _rdir_request(self, volume, method, action, create=False, params=None,
                      **kwargs):
        if params is None:
            params = dict()
        params['vol'] = volume
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

    def _rdir_meta2_request(self, meta2_address, method, action,
                            auto_create=True, **kwargs):
        params = {'meta2_address': meta2_address}
        if auto_create:
            params['autocreate'] = 1
        # Assuming we'll use the same facility to fetch assigned rdirs to META2
        # Since technically speaking it's a KV store so it shouldn't matter.
        req_id = kwargs.get('headers')['X-oio-req-id'] \
            if kwargs.get('headers') is not None else None
        uri = self._make_uri('meta2/%s' % action, meta2_address,
                             req_id=req_id)

        try:
            resp, body = self._direct_request(method, uri, params=params,
                                              **kwargs)
        except OioNetworkException:
            self._clear_cache(meta2_address)
            raise

        return resp, body

    def create(self, volume_id, **kwargs):
        """Create the database for `volume_id` on the appropriate rdir"""
        self._rdir_request(volume_id, 'POST', 'create', **kwargs)

    def chunk_push(self, volume_id, container_id, content_id, chunk_id,
                   headers=None, **data):
        """Reference a chunk in the reverse directory"""
        body = {'container_id': container_id,
                'content_id': content_id,
                'chunk_id': chunk_id}

        for key, value in data.iteritems():
            body[key] = value

        self._rdir_request(volume_id, 'POST', 'push', create=True,
                           json=body, headers=headers)

    def chunk_delete(self, volume_id, container_id, content_id, chunk_id,
                     **kwargs):
        """Unreference a chunk from the reverse directory"""
        body = {'container_id': container_id,
                'content_id': content_id,
                'chunk_id': chunk_id}

        self._rdir_request(volume_id, 'DELETE', 'delete',
                           json=body, **kwargs)

    def chunk_fetch(self, volume, limit=100, rebuild=False,
                    container_id=None, max_attempts=3, **kwargs):
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
            for i in range(max_attempts):
                try:
                    _resp, resp_body = self._rdir_request(
                        volume, 'POST', 'fetch', json=req_body, **kwargs)
                    break
                except OioNetworkException:
                    # Monotonic backoff
                    if i < max_attempts - 1:
                        sleep(i * 1.0)
                        continue
                    # Too many attempts
                    raise
            if len(resp_body) == 0:
                break
            key = None
            for (key, value) in resp_body:
                container, content, chunk = key.split('|')
                yield container, content, chunk, value
            if key is not None:
                req_body['start_after'] = key

    def admin_incident_set(self, volume, date, **kwargs):
        body = {'date': int(float(date))}
        self._rdir_request(volume, 'POST', 'admin/incident',
                           json=body, **kwargs)

    def admin_incident_get(self, volume, **kwargs):
        _resp, body = self._rdir_request(volume, 'GET',
                                         'admin/incident', **kwargs)
        return body.get('date')

    def admin_lock(self, volume, who, **kwargs):
        body = {'who': who}

        self._rdir_request(volume, 'POST', 'admin/lock', json=body, **kwargs)

    def admin_unlock(self, volume, **kwargs):
        self._rdir_request(volume, 'POST', 'admin/unlock', **kwargs)

    def admin_show(self, volume, **kwargs):
        _resp, body = self._rdir_request(volume, 'GET', 'admin/show',
                                         **kwargs)
        return body

    def admin_clear(self, volume, clear_all=False, before_incident=False,
                    repair=False, **kwargs):
        params = {'all': clear_all, 'before_incident': before_incident,
                  'repair': repair}
        _resp, resp_body = self._rdir_request(
            volume, 'POST', 'admin/clear', params=params, **kwargs)
        return resp_body

    def status(self, volume, **kwargs):
        _resp, body = self._rdir_request(volume, 'GET', 'status', **kwargs)
        return body

    def meta2_index_create(self, volume_id, **kwargs):
        return self._rdir_meta2_request(volume_id, 'POST', 'create',
                                        **kwargs)

    def meta2_index_push(self, volume_id, content_path, content_id, mtime,
                         headers=None, **kwargs):
        body = {'content_url': content_path,
                'container_id': content_id,
                'mtime': int(mtime)}

        for key, value in kwargs.iteritems():
            body[key] = value

        return self._rdir_meta2_request(volume_id, 'POST', 'push',
                                        create=True,
                                        json=body, headers=headers)

    def meta2_index_delete(self, volume_id, content_path, content_id,
                           **kwargs):
        body = {'content_url': content_path,
                'container_id': content_id}

        for key, value in kwargs.iteritems():
            body[key] = value

        return self._rdir_meta2_request(volume_id, 'POST', 'delete',
                                        create=False,
                                        json=body)

    def meta2_index_fetch(self, volume_id, prefix='', marker=0, limit=4096,
                          **kwargs):
        raise ClientException("Not Yet Implemented.")
