# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2020-2022 OVH SAS
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

import random

from oio.api.base import HttpApi
from oio.common.constants import HEADER_PREFIX, REQID_HEADER
from oio.common.exceptions import ClientException, NotFound, VolumeException
from oio.common.exceptions import ServiceUnavailable, ServerException
from oio.common.exceptions import OioNetworkException, OioException, \
    reraise as oio_reraise
from oio.common.utils import group_chunk_errors, request_id
from oio.common.logger import get_logger
from oio.common.decorators import ensure_headers, ensure_request_id
from oio.conscience.client import ConscienceClient
from oio.directory.client import DirectoryClient
from oio.common.utils import depaginate, cid_from_name, monotonic_time
from oio.common.green import sleep
from oio.common.easy_value import true_value
from oio.common.green import GreenPile

RDIR_ACCT = '_RDIR'

# Special target that will match any service from the "known" service list
JOKER_SVC_TARGET = '__any_slot'

# Default rdir replicas for meta2/rawx services
DEFAULT_RDIR_REPLICAS = 3


def _make_id(ns, type_, addr):
    return "%s|%s|%s" % (ns, type_, addr)


def _build_dict_by_id(ns, all_rdir):
    """
    Build a dictionary of all rdir services indexed by their ID.
    """
    return {
        _make_id(ns, 'rdir', x['tags'].get('tag.service_id', x['addr'])): x
        for x in all_rdir
    }


def _filter_rdir_hosts(allsrv):
    host_list = list()
    for srv in allsrv.get('srv', {}):
        if srv['type'] == 'rdir':
            host_list.append(srv['host'])
    if not host_list:
        raise NotFound("No rdir service found in %s" % (allsrv,))
    return host_list


class RdirDispatcher(object):
    def __init__(self, conf, rdir_client=None, **kwargs):
        self.conf = conf
        self.ns = conf['namespace']
        self.logger = get_logger(conf)
        self.directory = DirectoryClient(conf, logger=self.logger, **kwargs)
        if rdir_client:
            self.rdir = rdir_client
        else:
            self.rdir = RdirClient(conf, directory_client=self.directory,
                                   logger=self.logger, **kwargs)
        self._pool_options = None

    @property
    def cs(self):
        return self.rdir.cs

    def get_assignments(self, service_type, **kwargs):
        """
        Get rdir assignments for all services of the specified type.

        :returns: a tuple with a list all services of the specified type,
            and a list of all rdir services.
        :rtype: `tuple<list<dict>,list<dict>>`
        """
        all_services = self.cs.all_services(service_type, **kwargs)
        all_rdir = self.cs.all_services('rdir', True, **kwargs)
        by_id = _build_dict_by_id(self.ns, all_rdir)

        for service in all_services:
            try:
                ref = service.get('tags', {}).get('tag.service_id')
                resp = self.directory.list(RDIR_ACCT,
                                           ref or service['addr'],
                                           service_type='rdir',
                                           **kwargs)
                rdir_hosts = _filter_rdir_hosts(resp)
                service['rdir'] = []

                for el in rdir_hosts:
                    try:
                        service['rdir'].append(
                            by_id[_make_id(self.ns, 'rdir', el)])
                    except KeyError:
                        self.logger.warning("rdir %s linked to %s %s seems \
                                            down",
                                            el, service_type,
                                            service['addr'])
                        down_svc = {"addr": el, "score": 0, "tags": dict()}
                        service['rdir'].append(down_svc)
                        by_id[_make_id(self.ns, 'rdir', el)] = down_svc

            except NotFound:
                self.logger.info("No rdir linked to %s",
                                 service['addr'])
            except OioException as exc:
                self.logger.warning('Failed to get rdir linked to %s: %s',
                                    service['addr'], exc)
        return all_services, all_rdir

    def assign_services(self, service_type, max_per_rdir=None, min_dist=None,
                        service_id=None, reassign=None, **kwargs):
        """
        Assign an rdir service to all `service_type` servers that aren't
        already assigned one.

        :param max_per_rdir: Maximum number of services an rdir can handle.
        :type max_per_rdir: `int`
        :param min_dist: Minimum required distance between any service and
            its assigned rdir service.
        :type min_dist: `int`
        :param service_id: Assign only this service ID.
        :type service_id: `str`
        :param reassign: ID of an rdir service to be decommissioned.
        :type reassign: `str`
        :param dry_run: Display actions but do nothing.
        :type dry_run: `bool`
        :returns: The list of `service_type` services that were assigned
            rdir services.
        """
        all_services = self.cs.all_services(service_type, **kwargs)
        if service_id:
            for provider in all_services:
                provider_id = provider['tags'].get('tag.service_id',
                                                   provider['addr'])
                if service_id == provider_id:
                    break
            else:
                raise ValueError('%s isn\'t a %s' % (service_id, service_type))
            all_services = [provider]
        all_rdir = self.cs.all_services('rdir', True, **kwargs)
        if len(all_rdir) <= 0:
            raise ServiceUnavailable("No rdir service found in %s" % self.ns)

        by_id = _build_dict_by_id(self.ns, all_rdir)

        errors = list()
        for provider in all_services:
            provider_id = provider['tags'].get('tag.service_id',
                                               provider['addr'])
            provider['rdir'] = []
            rdir_hosts = None
            try:
                resp = self.directory.list(RDIR_ACCT, provider_id,
                                           service_type='rdir', **kwargs)
                rdir_hosts = _filter_rdir_hosts(resp)
                for rdir_host in rdir_hosts:
                    try:
                        rdir = by_id[_make_id(self.ns, 'rdir', rdir_host)]
                        if reassign == rdir_host:
                            rdir['tags']['stat.opened_db_count'] = \
                                rdir['tags'].get('stat.opened_db_count', 0) - 1
                        provider['rdir'].append(rdir)
                    except KeyError:
                        self.logger.warning("rdir %s linked to %s %s seems \
                                            down",
                                            rdir_host, service_type,
                                            provider_id)
                if reassign:
                    raise NotFound('Trick to avoid code duplication')
            except NotFound:
                try:
                    # Check if all known rdir hosts (except the reassign)
                    # are not locked
                    for el in all_rdir:
                        if rdir_hosts and el['addr'] in rdir_hosts and \
                           el['addr'] != reassign and el['score'] == 0:
                            # TODO (LAA) raise exception ?
                            self.logger.warning(
                                "The service %s is supposed "
                                "to be kept but has score to 0", el['addr'])

                    rdirs = self._smart_link_rdir(provider_id, all_rdir,
                                                  service_type=service_type,
                                                  max_per_rdir=max_per_rdir,
                                                  min_dist=min_dist,
                                                  reassign=reassign,
                                                  known_hosts=rdir_hosts,
                                                  **kwargs)
                except (OioException, ValueError) as exc:
                    self.logger.warning("Failed to link an rdir to %s %s: %s",
                                        service_type, provider_id, exc)
                    errors.append((provider_id, exc))
                    continue

                provider['rdir'] = list()
                for rdir in rdirs:
                    n_base = by_id[rdir]['tags'].get("stat.opened_db_count", 0)
                    by_id[rdir]['tags']["stat.opened_db_count"] = n_base + 1
                    provider['rdir'].append(by_id[rdir])
            except OioException as exc:
                self.logger.warning("Failed to check rdir linked to %s %s "
                                    "(thus won't try to make the link): %s",
                                    service_type, provider_id, exc)
                errors.append((provider_id, exc))
        if errors:
            # group_chunk_errors is flexible enough to accept service addresses
            errors = group_chunk_errors(errors)
            if len(errors) == 1:
                err, addrs = errors.popitem()
                oio_reraise(type(err), err, str(addrs))
            else:
                raise OioException('Several errors encountered: %s' %
                                   errors)
        return all_services

    def assign_all_meta2(self, max_per_rdir=None, **kwargs):
        """
        Assign an rdir service to all meta2 servers that aren't already
        assigned one.

        :param max_per_rdir: Maximum number of services an rdir can handle.
        :type max_per_rdir: `int`
        :returns: The list of meta2 that were assigned rdir services.
        """
        return self.assign_services("meta2", max_per_rdir, **kwargs)

    def assign_all_rawx(self, max_per_rdir=None, **kwargs):
        """
        Find an rdir service for all rawx that don't have one already.

        :param max_per_rdir: maximum number or rawx services that an rdir
                             can be linked to
        :type max_per_rdir: `int`
        """
        return self.assign_services("rawx", max_per_rdir, **kwargs)

    def _assign_rdir(self, volume_id, assignments,
                     is_reassign=False, max_attempts=7, **kwargs):
        """
        Save the assignment in the directory (meta1).

        :param is_reassign: tell there may be already some assignments,
            an we want to overwrite them. When False, if there are already
            some assignments, an exception will be raised.
        """
        for i in range(max_attempts):
            try:
                self.directory.force(RDIR_ACCT, volume_id, 'rdir',
                                     assignments, autocreate=True,
                                     replace=is_reassign, **kwargs)
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
                # Monotonic backoff (retriable and net errors)
                if i < max_attempts - 1:
                    sleep(i * 1.0)
                    continue
                # Too many attempts
                raise

    def _smart_link_rdir(self, volume_id, all_rdir, max_per_rdir=None,
                         max_attempts=7, service_type='rawx', min_dist=None,
                         reassign=None, dry_run=False, known_hosts=None,
                         replicas=DEFAULT_RDIR_REPLICAS, **kwargs):
        """
        Force the load balancer to avoid services that already host more
        bases than the average (or more than `max_per_rdir`)
        while selecting rdir services.

        :param reassign: ID of the rdir to get rid of, or None
        :param known_hosts: IDs of rdir services already assigned to volume_id

        :returns: the list of IDs of all rdir services assigned to volume_id.
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
        avoids = [_make_id(self.ns, "rdir", x['tags'].get('tag.service_id',
                                                          x['addr']))
                  for x in all_rdir
                  if x['score'] > 0 and
                  x['tags'].get('stat.opened_db_count', 0) > upper_limit]

        # Build the list of known services. The first one is the meta2 or rawx
        # in need of an rdir (for distance comparison).
        known_ids = [_make_id(self.ns, service_type, volume_id)]
        if known_hosts:
            if reassign:
                try:
                    known_hosts.remove(reassign)
                except ValueError:
                    pass
            for host in known_hosts:
                known_ids.append(_make_id(self.ns, 'rdir', host))
        reassigned_id = None
        if reassign:
            reassigned_id = _make_id(self.ns, 'rdir', reassign)
            avoids.append(reassigned_id)

        # First try with a non-empty 'avoids' list.
        try:
            polled = self._poll_rdir(avoid=avoids, known=known_ids,
                                     min_dist=min_dist, replicas=replicas,
                                     **kwargs)
        except ClientException as exc:
            if exc.status != 481 or max_per_rdir:
                raise
            # Retry with a reduced `avoids`, hoping the next iteration
            # will rebalance.
            avoids = [reassigned_id] if reassign else None
            polled = self._poll_rdir(avoid=avoids, known=known_ids,
                                     min_dist=min_dist,
                                     replicas=replicas, **kwargs)

        # Prepare the output list of IDs
        polled_ids = [p['id'] for p in polled]
        if reassign:
            polled_ids = polled_ids + [_make_id(self.ns, 'rdir', host)
                                       for host in known_hosts]
        if dry_run:
            # No association of the rdir to the rawx
            # No creation in the rdir
            return polled_ids

        # Associate the rdir to the rawx
        all_hosts = [el['addr'] for el in polled]
        if known_hosts:
            all_hosts = known_hosts + all_hosts

        assignments = {
            'host': ','.join(all_hosts),
            'type': 'rdir',
            'seq': 1, 'args': "",
            'id': ','.join(polled_ids)}
        self._assign_rdir(volume_id, assignments, is_reassign=bool(reassign),
                          max_attempts=max_attempts, **kwargs)

        # Do the creation in the rdir itself
        try:
            self.rdir._clear_cache(volume_id)
            self.rdir.create(volume_id, service_type=service_type, **kwargs)
        except Exception as exc:
            self.logger.warning("Failed to create database for %s on %s: %s",
                                volume_id, polled, exc)
        return polled_ids

    def _create_special_pool(self, options=None, force=False,
                             replicas=DEFAULT_RDIR_REPLICAS, **kwargs):
        """
        Create the special pool for rdir services.

        :param options: dictionary of custom options for the pool.
        :param force: overwrite the pool if it exists already.
        :param replicas: number of rdir services which must be selected.
        """
        self.cs.lb.create_pool(
            '__rawx_rdir', ((1, JOKER_SVC_TARGET), (replicas, 'rdir')),
            options=options, force=force, **kwargs)

    def _poll_rdir(self, avoid=None, known=None, min_dist=None,
                   replicas=DEFAULT_RDIR_REPLICAS, **kwargs):
        """
        Call the special rdir service pool (created if missing).

        :param min_dist: minimum distance to ensure between the known
            service and the selected rdir service.
        :param replicas: number of rdir services which must be selected.

        :returns: the list of NEW services assigned to volume_id (when
            reassigning there will be less than 'replicas' services).
        """
        if not known or len(known) > replicas:
            raise ValueError(
                'There should be at most %d "known" services, but known=%s'
                % (replicas, known))

        options = {}
        if min_dist is not None:
            options['min_dist'] = min_dist
        if options != self._pool_options:
            # Options have changed, overwrite the pool.
            self._pool_options = options
            self._create_special_pool(self._pool_options, force=True,
                                      replicas=replicas, **kwargs)

        try:
            svcs = self.cs.poll('__rawx_rdir', avoid=avoid, known=known,
                                **kwargs)
        except ClientException as exc:
            if exc.status != 400:
                raise
            self._create_special_pool(self._pool_options,
                                      replicas=replicas, **kwargs)
            svcs = self.cs.poll('__rawx_rdir', avoid=avoid, known=known,
                                **kwargs)
        expected = (replicas - len(known) + 1)
        rdir_count = 0
        for svc in svcs:
            # FIXME: we should include the service type in a dedicated field
            if 'rdir' in svc['id']:
                rdir_count += 1
        if rdir_count == expected:
            return svcs
        raise ServerException(
            "LB returned incoherent result (expected %d rdir, got %d): %s"
            % (expected, rdir_count, svcs))


class RdirClient(HttpApi):
    """
    Client class for rdir services.
    """

    base_url = {
        'rawx': 'rdir',
        'meta2': 'rdir/meta2',
    }

    def __init__(self, conf, directory_client=None, cache_duration=60.0,
                 **kwargs):
        super(RdirClient, self).__init__(service_type='rdir', **kwargs)
        self.directory = directory_client or DirectoryClient(conf, **kwargs)
        self.ns = conf['namespace']
        self._addr_cache = dict()
        self._cache_duration = cache_duration
        self.conf = conf
        self._cs = None
        self.logger = self.directory.logger

    @property
    def cs(self):
        if not self._cs:
            self._cs = ConscienceClient(
                self.conf,
                logger=self.directory.logger,
                pool_manager=self.directory.pool_manager)
        return self._cs

    def _clear_cache(self, volume_id):
        self._addr_cache.pop(volume_id, None)

    def _get_rdir_addr(self, volume_id, now=None, reqid=None):
        if now is None:
            now = monotonic_time()
        # Initial lookup in the cache
        if volume_id in self._addr_cache:
            addr, deadline = self._addr_cache[volume_id]
            if deadline > now:
                return addr
            else:
                del self._addr_cache[volume_id]
        # Not cached or stale, try a direct lookup
        try:
            headers = {REQID_HEADER: reqid or request_id()}
            resp = self.directory.list(RDIR_ACCT, volume_id,
                                       service_type='rdir',
                                       headers=headers)

            hosts = _filter_rdir_hosts(resp)
            cur_hosts = [self.cs.resolve_service_id('rdir', host)
                         for host in hosts]
            # Add the list of services to the cache
            self._addr_cache[volume_id] = (
                cur_hosts,
                now + self._cache_duration * random.randrange(90, 100) / 100)
            return cur_hosts
        except NotFound:
            raise VolumeException('No rdir assigned to volume %s' % volume_id)

    def _get_resolved_rdir_hosts(self, volume_id, rdir_hosts=None, reqid=None):
        if not rdir_hosts:
            rdir_hosts = self._get_rdir_addr(volume_id, reqid=reqid)
        else:
            rdir_hosts = [self.cs.resolve_service_id('rdir', host)
                          for host in rdir_hosts]
        return rdir_hosts

    def _make_uri(self, action, volume_id, reqid=None, service_type='rawx',
                  rdir_hosts=None):
        rdir_hosts = self._get_resolved_rdir_hosts(
            volume_id, rdir_hosts=rdir_hosts, reqid=reqid)
        all_uri = []
        for rdir_host in rdir_hosts:
            all_uri.append('http://%s/v1/%s/%s' % (
                rdir_host,
                self.__class__.base_url[service_type], action))
        return all_uri

    @ensure_headers
    @ensure_request_id
    def _rdir_request(self, volume, method, action, create=False, params=None,
                      service_type='rawx', rdir_hosts=None, **kwargs):
        if params is None:
            params = dict()
        params['vol'] = volume
        if create:
            params['create'] = '1'
        all_uri = self._make_uri(action, volume,
                                 reqid=kwargs['headers'][REQID_HEADER],
                                 service_type=service_type,
                                 rdir_hosts=rdir_hosts)

        resp = ""
        body = ""
        errors = list()
        if method in ('GET', 'HEAD'):
            for uri in all_uri:
                try:
                    resp, body = self._direct_request(method, uri,
                                                      params=params, **kwargs)

                    # Why: because there are as much of uri requests as
                    # rawx/meta2 services. When we fetch chunk we do it once
                    break

                except Exception as exc:
                    errors.append((uri, exc))
        else:
            pile = GreenPile(len(all_uri))

            def _local_request(method, uri, params, **kwargs):
                try:
                    return self._direct_request(method, uri, params=params,
                                                **kwargs)
                except Exception as exc:
                    return (uri, exc)

            for uri in all_uri:
                pile.spawn(_local_request, method, uri, params=params,
                           **kwargs)

            for el in pile:
                # exception
                if el[0] in all_uri:
                    errors.append(el)
                else:
                    resp = el[0]
                    body = el[1]

        if errors:
            errorsStr = [
                '%s: %s' % (type(err).__name__, err) for (_, err) in errors]
            self.logger.warning(
                'rdir request[%s][%s]: %i/%i subrequests failed:\n%s' % (
                    method,
                    kwargs['reqid'],
                    len(errors),
                    len(all_uri),
                    '\n'.join(errorsStr)))
            # clear cache if at least one error
            self._clear_cache(volume)

            if len(errors) == len(all_uri):  # all requests failed
                class_type = type(errors[0][1])
                same_error = all(
                    isinstance(x, class_type) for (uri, x) in errors)
                errors = group_chunk_errors(errors)
                if same_error:
                    err, addrs = errors.popitem()
                    oio_reraise(
                        type(err), err, str(addrs) + " method:" + method)
                else:
                    raise OioException(
                        'Several errors encountered: %s %s' % errors, method)

        return resp, body

    def create(self, volume_id, service_type='rawx', **kwargs):
        """Create the database for `volume_id` on the appropriate rdir"""
        self._rdir_request(volume_id, 'POST', 'create',
                           service_type=service_type, **kwargs)

    def chunk_push(self, volume_id, container_id, content_id, chunk_id,
                   content_path, content_version,
                   headers=None, **data):
        """Reference a chunk in the reverse directory"""
        body = {
            # Will be stripped and kept only in the key
            'chunk_id': chunk_id,
            'container_id': container_id,
            # Will remain in the value
            'content_id': content_id,
            'path': content_path,
            'version': int(content_version)
        }

        # Mostly mtime
        for key, value in data.items():
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

    def chunk_fetch(self, volume, limit=1000, rebuild=False,
                    container_id=None, max_attempts=3,
                    start_after=None, shuffle=False, full_urls=False,
                    old_format=False, **kwargs):
        """
        Fetch the list of chunks belonging to the specified volume.

        :param volume: the volume to get chunks from
        :type volume: `str`
        :param limit: maximum number of results to return per request
            to the rdir server.
        :type limit: `int`
        :param rebuild: fetch only the chunks that were there
            before the last incident.
        :type rebuild: `bool`
        :keyword container_id: get only chunks belonging to
           the specified container
        :type container_id: `str`
        :keyword start_after: fetch only chunk that appear after
            this container ID
        :type start_after: `str`
        :keyword old_format: yield (container, content, chunk and value)
            instead of just (container, chunk and value).
        """
        req_body = {'limit': limit}
        if rebuild:
            req_body['rebuild'] = True
        if container_id:
            req_body['container_id'] = container_id
        if start_after:
            req_body['start_after'] = start_after

        while True:
            for i in range(max_attempts):
                try:
                    resp, resp_body = self._rdir_request(
                        volume, 'GET', 'fetch', json=req_body, **kwargs)
                    break
                except OioNetworkException:
                    # Monotonic backoff
                    if i < max_attempts - 1:
                        sleep(i * 1.0)
                        continue
                    # Too many attempts
                    raise

            truncated = resp.headers.get(HEADER_PREFIX + 'list-truncated')
            if truncated is None:
                # TODO(adu): Delete when it will no longer be used
                if not resp_body:
                    break
                truncated = True
                req_body['start_after'] = resp_body[-1][0]
            else:
                truncated = true_value(truncated)
                if truncated:
                    req_body['start_after'] = resp.headers[
                        HEADER_PREFIX + 'list-marker']

            if shuffle:
                random.shuffle(resp_body)
            for (key, value) in resp_body:
                container, chunk = key.split('|')
                if full_urls:
                    chunk = 'http://%s/%s' % (volume, chunk)
                if old_format:
                    yield container, value['content_id'], chunk, value
                else:
                    yield container, chunk, value

            if not truncated:
                break

    @ensure_request_id
    def chunk_copy_vol(self, volume_id, sources=None, dests=None,
                       batch_size=1000, create=True, reqid=None, **kwargs):
        """
        Copy all chunks records from volume_id from one rdir to another.

        :param volume_id: ID of a rawx service
        :param sources: optional list of source rdir services
            (will be fetched from the service directory if empty)
        :param dests: optional list of destination rdir services
            (will be fetched from the service directory if empty)
        :param batch_size: size of record batches
        :param create: whether to create the database on the destination
        """
        # Make sure to NOT use a destination as a source
        src_rdir_hosts = self._get_resolved_rdir_hosts(
            volume_id, rdir_hosts=sources, reqid=reqid)
        dests_rdir_hosts = self._get_resolved_rdir_hosts(
            volume_id, rdir_hosts=dests, reqid=reqid)
        src_rdir_hosts = [src_rdir_host for src_rdir_host in src_rdir_hosts
                          if src_rdir_host not in dests_rdir_hosts]
        if not src_rdir_hosts:
            raise OioException('No source available')
        if not dests_rdir_hosts:
            raise OioException('No destination available')

        batch = []
        for cid, chunk, rec in self.chunk_fetch(volume_id,
                                                rdir_hosts=src_rdir_hosts,
                                                reqid=reqid, **kwargs):
            rec['container_id'] = cid
            rec['chunk_id'] = chunk
            batch.append(rec)

            if len(batch) >= batch_size:
                self._rdir_request(volume_id, 'POST', 'push', create=create,
                                   json=batch, rdir_hosts=dests_rdir_hosts,
                                   reqid=reqid, **kwargs)
                batch = []
        if batch:
            self._rdir_request(volume_id, 'POST', 'push', create=create,
                               json=batch, rdir_hosts=dests_rdir_hosts,
                               reqid=reqid, **kwargs)

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

    def status(self, volume, max=1000, prefix=None, marker=None,
               max_attempts=3, **kwargs):
        """
        Get the status of chunks belonging to the specified volume.

        :param volume: the volume to get chunks from
        :type volume: `str`
        :param max: maximum number of results to return per request
            to the rdir server.
        :type max: `int`
        :keyword prefix: get only chunks belonging to
           the specified prefix
        :type prefix: `str`
        :keyword marker: fetch only chunk that appear after
            this marker
        :type marker: `str`
        """
        req_params = {'max': max}
        if prefix:
            req_params['prefix'] = prefix
        if marker:
            req_params['marker'] = marker
        chunks = dict()
        containers = dict()

        while True:
            for i in range(max_attempts):
                try:
                    _resp, resp_body = self._rdir_request(
                        volume, 'GET', 'status', params=req_params, **kwargs)
                    break
                except OioNetworkException:
                    # Monotonic backoff
                    if i < max_attempts - 1:
                        sleep(i * 1.0)
                        continue
                    # Too many attempts
                    raise

            for (key, value) in resp_body.get('chunk', dict()).items():
                chunks[key] = chunks.get(key, 0) + value
            for (cid, info) in resp_body.get('container', dict()).items():
                for (key, value) in info.items():
                    containers[cid][key] = containers.setdefault(
                        cid, dict()).get(key, 0) + value

            if not true_value(_resp.headers.get(
                    HEADER_PREFIX + 'list-truncated')):
                break
            req_params['marker'] = _resp.headers[HEADER_PREFIX + 'list-marker']

        return {'chunk': chunks, 'container': containers}

    def meta2_index_create(self, volume_id, **kwargs):
        """
        Create a new meta2 rdir index.

        :param volume_id: The meta2 volume.
        """
        return self.create(volume_id, service_type='meta2', **kwargs)

    def meta2_index_push(self, volume_id, container_url, container_id, mtime,
                         **kwargs):
        """
        Add a newly created container to the list of containers handled
        by the meta2 server in question.

        :param volume_id: The meta2 volume.
        :param container_url: The container path (NS/account/container)
        :param container_id: The container ID.
        :param mtime: The last time it was spotted on this volume.
        :param headers: Optional headers to pass along to the request.
        """
        body = {'container_url': container_url,
                'container_id': container_id,
                'mtime': int(mtime)}

        for key, value in kwargs.items():
            body[key] = value

        res = self._rdir_request(volume=volume_id, method='POST',
                                 action='push', create=True, json=body,
                                 service_type='meta2',
                                 **kwargs)
        return res, body

    def _resolve_cid_to_path(self, cid):
        """
        Resolves a container ID into a a container path.

        :param cid: The container ID.
        :return: NS/account/container path.
        """
        resp = self.directory.list(cid=cid)
        return '{0}/{1}/{2}'.format(
            self.ns,
            resp['account'],
            resp['name']
        )

    def meta2_index_delete(self, volume_id, container_path=None,
                           container_id=None, **kwargs):
        """
        Remove a meta2 record from the volume's index. Either the container ID
        or the container path have to be given.

        :param volume_id: The meta2 volume.
        :param container_id: The container ID.
        :param container_path: The container path
        """
        if not container_path and container_id:
            container_path = self._resolve_cid_to_path(container_id)
        elif container_path and not container_id:
            _tmp = container_path.rsplit("/")
            container_id = cid_from_name(_tmp[1], _tmp[3])
        elif not container_path and not container_id:
            raise ValueError("At least the container ID or the container path "
                             "should be given.")

        body = {'container_url': container_path,
                'container_id': container_id}

        for key, value in kwargs.items():
            body[key] = value

        return self._rdir_request(volume=volume_id, method='POST',
                                  action='delete', create=False, json=body,
                                  service_type='meta2', **kwargs)

    def meta2_index_fetch(self, volume_id, prefix=None, marker=None,
                          limit=4096, **kwargs):
        """
        Fetch specific meta2 records, or a range of records.

        :param volume_id: The meta2 volume.
        :param prefix: The prefix all meta2 records should have.
        :param marker: The container path from which the API will start the
                        listing. The marker will not be included in the result.
        :param limit: The number of records to be returned. Capped at 4096
        :return: A dictionary containing the following entries:
                  - records: A list containing the actual records.
                  - truncated: A boolean value representing whether there
                  are still records left that fulfill this query.
        """
        params = {}
        if prefix:
            params['prefix'] = prefix
        if marker:
            # FIXME(ABO): Validate this one.
            params['marker'] = marker
        if limit:
            params['limit'] = limit
        _resp, body = self._rdir_request(volume=volume_id, method='GET',
                                         action='fetch', json=params,
                                         service_type='meta2', **kwargs)
        return body

    def meta2_index_fetch_all(self, volume_id, **kwargs):
        """
        A wrapper around meta2_index_fetch that loops until no more records
        are available, returning all the records in a certain volume's index.

        WARNING: For testing purposes only
        """
        return depaginate(
            self.meta2_index_fetch,
            volume_id=volume_id,
            listing_key=lambda x: x['records'],
            truncated_key=lambda x: x['truncated'],
            # The following is only called when the list is truncated
            # So we can assume there are records in the list
            marker_key=lambda x: x['records'][-1]['container_url'],
            **kwargs
        )

    @ensure_request_id
    def meta2_copy_vol(self, volume_id, sources=None, dests=None,
                       batch_size=1000, create=True, reqid=None, **kwargs):
        """
        Copy all meta2 records from volume_id from one rdir to another.

        :param volume_id: ID of a meta2 service
        :param sources: optional list of source rdir services
            (will be fetched from the service directory if empty)
        :param dests: optional list of destination rdir services
            (will be fetched from the service directory if empty)
        :param batch_size: size of record batches
        :param create: whether to create the database on the destination
        """
        # Make sure to NOT use a destination as a source
        src_rdir_hosts = self._get_resolved_rdir_hosts(
            volume_id, rdir_hosts=sources, reqid=reqid)
        dests_rdir_hosts = self._get_resolved_rdir_hosts(
            volume_id, rdir_hosts=dests, reqid=reqid)
        src_rdir_hosts = [src_rdir_host for src_rdir_host in src_rdir_hosts
                          if src_rdir_host not in dests_rdir_hosts]
        if not src_rdir_hosts:
            raise OioException('No source available')
        if not dests_rdir_hosts:
            raise OioException('No destination available')

        batch = []
        for rec in self.meta2_index_fetch_all(volume_id,
                                              rdir_hosts=src_rdir_hosts,
                                              reqid=reqid, **kwargs):
            batch.append(rec)

            if len(batch) >= batch_size:
                self._rdir_request(volume_id, 'POST', 'push', create=create,
                                   json=batch, service_type='meta2',
                                   rdir_hosts=dests_rdir_hosts,
                                   reqid=reqid, **kwargs)
                batch = []
        if batch:
            self._rdir_request(volume_id, 'POST', 'push', create=create,
                               json=batch, service_type='meta2',
                               rdir_hosts=dests_rdir_hosts,
                               reqid=reqid, **kwargs)
