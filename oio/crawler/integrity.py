# Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
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

"""
Recursively check account, container, content and chunk integrity.
"""


from __future__ import print_function
from oio.common.green import Event, GreenPool, LightQueue, sleep, Semaphore,\
    ratelimit_function_build

import os
import csv
import sys
from time import time

from oio.blob.rebuilder import BlobRebuilder
from oio.common import exceptions as exc
from oio.common.fullpath import decode_fullpath
from oio.common.json import json
from oio.common.logger import get_logger
from oio.common.storage_method import STORAGE_METHODS
from oio.common.utils import cid_from_name, CacheDict
from oio.event.beanstalk import BeanstalkdSender
from oio.api.object_storage import ObjectStorageApi
from oio.api.object_storage import _sort_chunks
from oio.rdir.client import RdirClient

DEFAULT_DEPTH = 4


IRREPARABLE_PREFIX = '#IRREPARABLE'


class Target(object):
    """
    Identify the target of a check, hold a log of errors.
    """

    def __init__(self, account, container=None, obj=None,
                 chunk=None, content_id=None, version=None,
                 cid=None):
        self.account = account
        self.container = container
        self.obj = obj
        self.content_id = content_id
        self.version = version
        self.chunk = chunk
        self._cid = cid

        # List of tuples with a timestamp as first element,
        # and an ItemResult as second element.
        self.error_log = list()

    def append_result(self, result):
        self.error_log.append((time(), result))

    @property
    def cid(self):
        if not self._cid and self.account and self.container:
            self._cid = cid_from_name(self.account, self.container)
        return self._cid

    @cid.setter
    def cid(self, cid):
        if cid is not None:
            self._cid = cid
            self.account = None
            self.container = None

    def copy(self):
        return Target(
            self.account,
            self.container,
            self.obj,
            self.chunk,
            self.content_id,
            self.version)

    def copy_object(self):
        return Target(self.account, self.container, self.obj,
                      content_id=self.content_id, version=self.version)

    def copy_container(self):
        return Target(self.account, self.container)

    def copy_account(self):
        return Target(self.account)

    @property
    def has_errors(self):
        """
        Tell if this target still presents errors.
        Will return False if it showed errors in the past but does not show
        them anymore.
        """
        return self.error_log and self.error_log[-1][1].errors

    @property
    def irreparable(self):
        """
        Tell if the target presents irreparable errors.

        Check only the latest result. The "irreparable" situation may have been
        temporary, for example if a rawx went down then up again.
        """
        return self.has_errors and self.latest_error_result().irreparable

    def latest_error_result(self):
        if self.has_errors:
            return self.error_log[-1][1]
        return None

    def time_in_error(self):
        """
        Tell for how long this target has shown errors.

        :rtype: tuple
        :returns: the duration (in seconds) since we detected an error,
            and the number of consecutive error confirmations.
        """
        if not self.has_errors:
            return 0.0, 0
        consecutive = list()
        for res in reversed(self.error_log):
            if not res[1]:
                break
            consecutive.append(res)
        return time() - consecutive[-1][0], len(consecutive) - 1

    def __repr__(self):
        if self.type == 'chunk':
            return 'chunk=' + self.chunk
        out = 'account=%s' % self.account
        if self.container:
            out += ', container=' + self.container
        if self.cid:
            out += ', cid=' + self.cid
        if self.obj:
            out += ', obj=' + self.obj
        if self.content_id:
            out += ', content_id=' + self.content_id
        if self.version:
            out += ', version=' + self.version
        if self.chunk:
            out += ', chunk=' + self.chunk
        return out

    @property
    def type(self):
        """Tell which type of item this object targets."""
        if self.chunk:
            return 'chunk'
        elif self.obj:
            return 'object'
        elif self.container:
            return 'container'
        else:
            return 'account'


class ItemResult(object):
    """
    Hold the result of a check.
    Must be serializable to be used in the Checker's return queue.
    """

    def __init__(self, errors=None, irreparable=False):
        self.errors = errors if errors is not None else list()
        self.irreparable = irreparable

    def errors_to_str(self, separator='\n', err_format='%s'):
        """
        Pretty print errors stored in this result.
        """
        if not self.errors:
            return str(None)
        return separator.join(err_format % x for x in self.errors)


class Checker(object):
    def __init__(self, namespace, concurrency=50,
                 error_file=None, rebuild_file=None, check_xattr=True,
                 limit_listings=0, request_attempts=1,
                 logger=None, verbose=False, check_hash=False,
                 min_time_in_error=0.0, required_confirmations=0,
                 beanstalkd_addr=None,
                 beanstalkd_tube=BlobRebuilder.DEFAULT_BEANSTALKD_WORKER_TUBE,
                 cache_size=2**24, **_kwargs):
        self.pool = GreenPool(concurrency)
        self.error_file = error_file
        self.error_sender = None
        self.check_xattr = bool(check_xattr)
        self.check_hash = bool(check_hash)
        self.logger = logger or get_logger({'namespace': namespace},
                                           name='integrity', verbose=verbose)
        # Optimisation for when we are only checking one object
        # or one container.
        # 0 -> do not limit
        # 1 -> limit account listings (list of containers)
        # 2 -> limit container listings (list of objects)
        self.limit_listings = limit_listings
        if self.error_file:
            outfile = open(self.error_file, 'a')
            self.error_writer = csv.writer(outfile, delimiter=' ')

        self.rebuild_file = rebuild_file
        if self.rebuild_file:
            self.fd = open(self.rebuild_file, 'a')
            self.rebuild_writer = csv.writer(self.fd, delimiter='|')

        if beanstalkd_addr:
            self.error_sender = BeanstalkdSender(
                beanstalkd_addr, beanstalkd_tube, self.logger)

        self.api = ObjectStorageApi(
            namespace,
            logger=self.logger,
            max_retries=request_attempts - 1,
            request_attempts=request_attempts)
        self.rdir_client = RdirClient(
            {"namespace": namespace}, logger=self.logger)

        self.accounts_checked = 0
        self.containers_checked = 0
        self.objects_checked = 0
        self.chunks_checked = 0
        self.account_not_found = 0
        self.container_not_found = 0
        self.object_not_found = 0
        self.chunk_not_found = 0
        self.account_exceptions = 0
        self.container_exceptions = 0
        self.object_exceptions = 0
        self.chunk_exceptions = 0

        self.list_cache = CacheDict(cache_size)
        self.running_tasks = {}
        self.running_lock = Semaphore(1)
        self.result_queue = LightQueue(concurrency)

        self.running = True
        self.run_time = 0

        # Set of targets which must be checked again, to confirm
        # or deny the issues reported by previous passes.
        self.delayed_targets = dict()
        # Minimum time in error and number of confirmations of the error
        # before triggering a reconstruction action.
        self.min_time_in_error = min_time_in_error
        self.required_confirmations = required_confirmations

    def reset_stats(self):
        self.accounts_checked = 0
        self.containers_checked = 0
        self.objects_checked = 0
        self.chunks_checked = 0
        self.account_not_found = 0
        self.container_not_found = 0
        self.object_not_found = 0
        self.chunk_not_found = 0
        self.account_exceptions = 0
        self.container_exceptions = 0
        self.object_exceptions = 0
        self.chunk_exceptions = 0

    def _spawn(self, func, target, *args, **kwargs):
        """
        Spawn a task on the internal GreenPool.
        Discards the task if the pool is no more running.
        """
        if self.running:
            return self.pool.spawn(func, target, *args, **kwargs)
        self.logger.info("Discarding %s", target)
        return None

    def _spawn_n(self, func, target, *args, **kwargs):
        """
        Spawn a task on the internal GreenPool, do not wait for the result.
        Discards the task if the pool is no more running.
        """
        if self.running:
            return self.pool.spawn_n(func, target, *args, **kwargs)
        self.logger.info("Discarding %s", target)
        return None

    def complete_target_from_chunk_metadata(self, target, xattr_meta):
        """
        Complete a Target object from metadata found in chunk's extended
        attributes. In case the "fullpath" is not available, try to read
        legacy metadata, and maybe ask meta1 to resolve the CID into
        account and container names.
        """
        # pylint: disable=unbalanced-tuple-unpacking
        try:
            acct, ct, path, vers, content_id = \
                decode_fullpath(xattr_meta['full_path'])
            target.account = acct
            target.container = ct
            target.obj = path
            target.content_id = content_id
            target.version = vers
        except KeyError:
            # No fullpath header, try legacy headers
            if 'content_path' in xattr_meta:
                target.obj = xattr_meta['content_path']
            if 'content_id' in xattr_meta:
                target.content_id = xattr_meta['content_id']
            if 'content_version' in xattr_meta:
                target.version = xattr_meta['content_version']
            cid = xattr_meta.get('container_id')
            if cid:
                try:
                    md = self.api.directory.show(cid=cid)
                    acct = md.get('account')
                    ct = md.get('name')
                    if acct:
                        target.account = acct
                    if ct:
                        target.container = ct
                except Exception as err:
                    self.logger.warn("Failed to resolve CID %s into account "
                                     "and container names: %s",
                                     cid, err)

    def recover_and_complete_object_meta(self, target, chunk):
        _, rawx_service, chunk_id = chunk.rsplit('/', 2)
        # 1. Fetch chunk list from rdir (could be cached).
        # Unfortunately we cannot seek for a chunk ID.
        entries = [x for x in self.rdir_client.chunk_fetch(
                       rawx_service, limit=-1) if x[2] == chunk_id]
        if not entries:
            self.logger.warn(
                'Chunk %s not found in rdir' % chunk_id)
            return
        elif len(entries) > 1:
            self.logger.info('Chunk %s appears in %d objects',
                             chunk_id, len(entries))
        # 2. Find content and container IDs
        target.cid, target.content_id = entries[0][0:2]
        meta = self.api.object_get_properties(
            None, None, None,
            cid=target.cid, content=target.content_id)
        target.obj = meta['name']
        target.version = meta['version']
        target.account, target.container = self.api.resolve_cid(target.cid)

    def send_result(self, target, errors=None, irreparable=False):
        """
        Put an item in the result queue.
        """
        # TODO(FVE): send to an external queue.
        target.append_result(ItemResult(errors, irreparable))
        self.result_queue.put(target)

    def send_chunk_job(self, target, irreparable=False):
        """
        Send a "content broken" event, to trigger the
        reconstruction of the chunk.
        """
        item = (self.api.namespace, target.cid,
                target.content_id, target.chunk)
        ev_dict = BlobRebuilder.task_event_from_item(item)
        if irreparable:
            ev_dict['data']['irreparable'] = irreparable
        job = json.dumps(ev_dict)
        self.error_sender.send_job(job)
        self.error_sender.job_done()  # Don't expect any response

    def write_error(self, target, irreparable=False):
        if not self.error_file:
            return
        error = list()
        if irreparable:
            error.append(IRREPARABLE_PREFIX)
        error.append(target.account)
        if target.container:
            error.append(target.container)
        if target.obj:
            error.append(target.obj)
        if target.chunk:
            error.append(target.chunk)
        self.error_writer.writerow(error)

    def write_rebuilder_input(self, target, irreparable=False):
        error = list()
        if irreparable:
            error.append(IRREPARABLE_PREFIX)
        error.append(target.cid)
        # FIXME(FVE): ensure we always resolve content_id,
        # or pass object version along with object name.
        error.append(target.content_id or target.obj)
        error.append(target.chunk)
        self.rebuild_writer.writerow(error)

    def write_chunk_error(self, target,
                          chunk=None, irreparable=False):
        if chunk is not None:
            target = target.copy()
            target.chunk = chunk
        self.write_error(target, irreparable=irreparable)
        if self.rebuild_file:
            self.write_rebuilder_input(target,
                                       irreparable=irreparable)
        if self.error_sender:
            self.send_chunk_job(target, irreparable=irreparable)

    def _check_chunk_xattr(self, target, obj_meta, xattr_meta):
        """
        Check coherency of chunk extended attributes with object metadata.

        :returns: a list of errors
        """
        errors = list()
        # Composed position -> erasure coding
        attr_prefix = 'meta' if '.' in obj_meta['pos'] else ''

        attr_key = attr_prefix + 'chunk_size'
        if str(obj_meta['size']) != xattr_meta.get(attr_key):
            errors.append(
                "'%s' xattr (%s) differs from size in meta2 (%s)" %
                (attr_key, xattr_meta.get(attr_key), obj_meta['size']))

        attr_key = attr_prefix + 'chunk_hash'
        if obj_meta['hash'] != xattr_meta.get(attr_key):
            errors.append(
                "'%s' xattr (%s) differs from hash in meta2 (%s)" %
                (attr_key, xattr_meta.get(attr_key), obj_meta['hash']))
        return errors

    def _check_chunk(self, target):
        """
        Execute various checks on a chunk:
        - does it appear in object's chunk list?
        - is it reachable?
        - are its extended attributes coherent?

        :returns: the list of errors encountered,
            and the chunk's owner object metadata.
        """
        chunk = target.chunk
        errors = list()
        obj_meta = None
        xattr_meta = None

        cached = self._get_cached_or_lock(chunk)
        if cached is not None:
            return cached + (True, )

        self.logger.debug('Checking chunk "%s"', target)
        try:
            xattr_meta = self.api.blob_client.chunk_head(
                chunk, xattr=self.check_xattr, check_hash=self.check_hash)
        except exc.NotFound as err:
            self.chunk_not_found += 1
            errors.append('Not found: %s' % (err, ))
        except exc.FaultyChunk as err:
            self.chunk_exceptions += 1
            errors.append('Faulty: %r' % (err, ))
        except Exception as err:
            self.chunk_exceptions += 1
            errors.append('Check failed: %s' % (err, ))

        if not target.obj:
            if xattr_meta:
                self.complete_target_from_chunk_metadata(target, xattr_meta)
            else:
                self.recover_and_complete_object_meta(target, chunk)

        if target.obj:
            obj_listing, obj_meta = self.check_obj(target.copy_object())
            if chunk not in obj_listing:
                errors.append('Missing from object listing')
                db_meta = dict()
            else:
                db_meta = obj_listing[chunk]

            if db_meta and xattr_meta and self.check_xattr:
                errors.extend(
                    self._check_chunk_xattr(target, db_meta, xattr_meta))

        self.list_cache[chunk] = errors, obj_meta
        self._unlock(chunk)

        # Do not send errors directly, let the caller do it.
        # Indeed, it may want to check if the chunks can be repaired or not.
        self.chunks_checked += 1
        return errors, obj_meta, False

    def check_chunk(self, target):
        errors, _obj_meta, from_cache = self._check_chunk(target)
        # If the result comes from the cache, we already reported it.
        if not from_cache:
            self.send_result(target, errors, target.irreparable)
        return errors

    def _check_metachunk(self, target, stg_met, pos, chunks,
                         recurse=0):
        """
        Check that a metachunk has the right number of chunks.

        :returns: the list of errors
        """
        required = stg_met.expected_chunks
        errors = list()
        chunk_results = list()

        if len(chunks) < required:
            missing_chunks = required - len(chunks)
            if stg_met.ec:
                subs = {x['num'] for x in chunks}
                for sub in range(required):
                    if sub not in subs:
                        chkt = target.copy()
                        chkt.chunk = '%d.%d' % (pos, sub)
                        err = "Missing chunk at position %s" % chkt.chunk
                        chunk_results.append((chkt, [err], False))
                        errors.append(err)
            else:
                for _ in range(missing_chunks):
                    chkt = target.copy()
                    chkt.chunk = '%d.%d' % (pos, sub)
                    err = "Missing chunk at position %d" % pos
                    chunk_results.append((chkt, [err], False))
                    errors.append(err)

        if recurse > 0:
            for chunk in chunks:
                tcopy = target.copy()
                tcopy.chunk = chunk['url']
                chunk_errors, _, from_cache = self._check_chunk(tcopy)
                chunk_results.append((tcopy, chunk_errors, from_cache))
                if chunk_errors:
                    errors.append("Unusable chunk %s at position %s" % (
                        chunk['url'], chunk['pos']))

        irreparable = required - len(errors) < stg_met.min_chunks_to_read
        if irreparable:
            errors.append(
                "Unavailable metachunk at position %s "
                "(%d/%d chunks available, %d/%d required)" % (
                    pos, required - len(errors), stg_met.expected_chunks,
                    stg_met.min_chunks_to_read, stg_met.expected_chunks))
        for tgt, errs, from_cache in chunk_results:
            # If the result comes from the cache, we already reported it.
            if not from_cache:
                self.send_result(tgt, errs, irreparable)
        # Since the "metachunk" is not an official item type,
        # this method does not report errors itself. Errors will
        # be reported as object errors.
        return errors

    def _check_obj_policy(self, target, obj_meta, chunks, recurse=0):
        """
        Check that the list of chunks of an object matches
        the object's storage policy.

        :returns: the list of errors encountered
        """
        stg_met = STORAGE_METHODS.load(obj_meta['chunk_method'])
        chunks_by_pos = _sort_chunks(chunks, stg_met.ec)
        tasks = list()
        for pos, pchunks in chunks_by_pos.iteritems():
            tasks.append((pos, self._spawn(
                self._check_metachunk,
                target.copy(), stg_met, pos, pchunks,
                recurse=recurse)))
        errors = list()
        for pos, task in tasks:
            if not task and not self.running:
                errors.append("Pos %d skipped: checker is exiting" % pos)
                continue
            try:
                errors.extend(task.wait())
            except Exception as err:
                errors.append("Check failed: pos %d: %s" % (pos, err))
        return errors

    def check_obj_versions(self, target, versions, recurse=0):
        """
        Run checks of all versions of the targeted object in parallel.
        """
        tasks = list()
        for ov in versions:
            tcopy = target.copy_object()
            tcopy.content_id = ov['id']
            tcopy.version = str(ov['version'])
            tasks.append((tcopy.version,
                          self._spawn(self.check_obj,
                                      tcopy, recurse=recurse)))
        errors = list()
        for version, task in tasks:
            if not task and not self.running:
                errors.append(
                    "Version %s skipped: checker is exiting" % version)
                continue
            try:
                task.wait()
            except Exception as err:
                errors.append("Check failed: version %s: %s" % (version, err))
        if errors:
            # Send a result with the target without version to tell
            # we were not able to check all versions of the object.
            self.send_result(target, errors)

    def _load_obj_meta(self, target, errors):
        """
        Load object metadata and chunks.

        :param target: which object to check.
        :param errors: list of errors that will be appended
            in case any error occurs.
        :returns: a tuple with object metadata and a list of chunks.
        """
        try:
            return self.api.object_locate(
                target.account, target.container, target.obj,
                version=target.version, properties=False)
        except exc.NoSuchObject as err:
            self.object_not_found += 1
            errors.append('Not found: %s' % (err, ))
        except Exception as err:
            self.object_exceptions += 1
            errors.append('Check failed: %s' % (err, ))
        return None, []

    def _get_cached_or_lock(self, lock_key):
        # If something is running, wait for it
        with self.running_lock:
            event = self.running_tasks.get(lock_key)
        if event:
            event.wait()
            event = None

        # Maybe get a cached result
        if lock_key in self.list_cache:
            return self.list_cache[lock_key]

        # No cached result, try to compute the thing ourselves
        while True:
            with self.running_lock:
                # Another check while locked
                if lock_key in self.list_cache:
                    return self.list_cache[lock_key]
                # Still nothing cached
                event = self.running_tasks.get(lock_key)
                if event is None:
                    self.running_tasks[lock_key] = Event()
                    return None
            event.wait()

    def _unlock(self, lock_key):
        with self.running_lock:
            event = self.running_tasks[lock_key]
            del self.running_tasks[lock_key]
            event.send(True)

    def check_obj(self, target, recurse=0):
        """
        Check one object version.
        If no version is specified, all versions of the object will be checked.
        :returns: the result of the check of the most recent version,
            or the one that is explicitly targeted.
        """
        account = target.account
        container = target.container
        obj = target.obj
        vers = target.version  # can be None

        cached = self._get_cached_or_lock((account, container, obj, vers))
        if cached is not None:
            return cached

        self.logger.info('Checking object "%s"', target)
        container_listing, _ = self.check_container(target.copy_container())
        errors = list()
        if obj not in container_listing:
            errors.append('Missing from container listing')
            # checksum = None
        else:
            versions = container_listing[obj]
            if vers is None:
                if target.content_id is None:
                    # No version specified, check all versions
                    self.check_obj_versions(target.copy_object(), versions,
                                            recurse=recurse)
                    # Now return the cached result of the most recent version
                    target.content_id = versions[0]['id']
                    target.version = str(versions[0]['version'])
                    res = self.check_obj(target, recurse=0)
                    self._unlock((account, container, obj, vers))
                    return res
                else:
                    for ov in versions:
                        if ov['id'] == target.content_id:
                            vers = str(ov['version'])
                            target.version = vers
                            break
                    else:
                        errors.append('Missing from container listing')

            # TODO check checksum match
            # checksum = container_listing[obj]['hash']
            pass

        meta, chunks = self._load_obj_meta(target, errors)

        chunk_listing = {c['url']: c for c in chunks}
        if meta:
            if target.content_id is None:
                target.content_id = meta['id']
            if target.version is None:
                target.version = str(meta['version'])
            self.list_cache[(account, container, obj, vers)] = \
                (chunk_listing, meta)
        self.objects_checked += 1
        self._unlock((account, container, obj, vers))

        # Skip the check if we could not locate the object
        if meta:
            errors.extend(
                self._check_obj_policy(target, meta, chunks, recurse=recurse))

        self.send_result(target, errors)
        return chunk_listing, meta

    def check_container(self, target, recurse=0):
        account = target.account
        container = target.container

        cached = self._get_cached_or_lock((account, container))
        if cached is not None:
            return cached

        self.logger.info('Checking container "%s"', target)
        account_listing = self.check_account(target.copy_account())
        errors = list()
        if container not in account_listing:
            errors.append('Missing from account listing')

        marker = None
        results = []
        ct_meta = dict()
        extra_args = dict()
        if self.limit_listings > 1 and target.obj:
            # When we are explicitly checking one object, start the listing
            # where this object is supposed to be. Do not use a limit,
            # but an end marker, in order to fetch all versions of the object.
            extra_args['prefix'] = target.obj
            extra_args['end_marker'] = target.obj + '\x00'  # HACK
        while True:
            try:
                resp = self.api.object_list(
                    account, container, marker=marker, versions=True,
                    **extra_args)
            except exc.NoSuchContainer as err:
                self.container_not_found += 1
                errors.append('Not found: %s' % (err, ))
                break
            except Exception as err:
                self.container_exceptions += 1
                errors.append('Check failed: %s' % (err, ))
                break

            truncated = resp.get('truncated', False)
            if truncated:
                marker = resp['next_marker']

            if resp['objects']:
                # safeguard, probably useless
                if not marker:
                    marker = resp['objects'][-1]['name']
                results.extend(resp['objects'])
                if not truncated or self.limit_listings > 1:
                    break
            else:
                ct_meta = resp
                ct_meta.pop('objects')
                break

        container_listing = dict()
        # Save all object versions, with the most recent first
        for obj in results:
            container_listing.setdefault(obj['name'], list()).append(obj)
        for versions in container_listing.values():
            versions.sort(key=lambda o: o['version'], reverse=True)

        if self.limit_listings <= 1:
            # We just listed the whole container, keep the result in a cache
            self.containers_checked += 1
            self.list_cache[(account, container)] = container_listing, ct_meta
        self._unlock((account, container))

        if recurse > 0:
            for obj_vers in container_listing.values():
                for obj in obj_vers:
                    tcopy = target.copy_object()
                    tcopy.obj = obj['name']
                    tcopy.content_id = obj['id']
                    tcopy.version = str(obj['version'])
                    self._spawn_n(self.check_obj, tcopy, recurse - 1)
        self.send_result(target, errors)
        return container_listing, ct_meta

    def check_account(self, target, recurse=0):
        account = target.account

        cached = self._get_cached_or_lock(account)
        if cached is not None:
            return cached

        self.logger.info('Checking account "%s"', target)
        errors = list()
        marker = None
        results = []
        extra_args = dict()
        if self.limit_listings > 0 and target.container:
            # When we are explicitly checking one container, start the listing
            # where this container is supposed to be, and list only one
            # container.
            extra_args['prefix'] = target.container
            extra_args['limit'] = 1
        while True:
            try:
                resp = self.api.container_list(
                    account, marker=marker, **extra_args)
            except Exception as err:
                self.account_exceptions += 1
                errors.append('Check failed: %s' % (err, ))
                break
            if resp:
                marker = resp[-1][0]
                results.extend(resp)
                if self.limit_listings > 0:
                    break
            else:
                break

        containers = dict()
        for container in results:
            # Name, number of objects, number of bytes
            containers[container[0]] = (container[1], container[2])

        if self.limit_listings <= 0:
            # We just listed the whole account, keep the result in a cache
            self.accounts_checked += 1
            self.list_cache[account] = containers
        self._unlock(account)

        if recurse > 0:
            for container in containers:
                tcopy = target.copy_account()
                tcopy.container = container
                self._spawn_n(self.check_container, tcopy, recurse - 1)

        self.send_result(target, errors)
        return containers

    def check(self, target, recurse=0):
        if target.type == 'chunk':
            self._spawn_n(self.check_chunk, target)
        elif target.type == 'object':
            self._spawn_n(self.check_obj, target, recurse)
        elif target.type == 'container':
            self._spawn_n(self.check_container, target, recurse)
        else:
            self._spawn_n(self.check_account, target, recurse)

    def check_all_accounts(self, recurse=0):
        all_accounts = self.api.account_list()
        for acct in all_accounts:
            self.check(Target(acct), recurse=recurse)

    def fetch_results(self, rate_limiter=None):
        while self.running and not self.result_queue.empty():
            res = self.result_queue.get(True)
            yield res
            # Rate limiting is done on the result queue for now.
            # Someday we could implement a submission queue instead of
            # letting each worker submit tasks to the pool, and do
            # the rate limiting on this queue.
            if rate_limiter is not None:
                self.run_time = rate_limiter(self.run_time)

    def merge_with_delayed_target(self, target):
        """
        Merge the specified target with a delayed one.

        :returns: the delayed target, if there is one, with an error log
            including the errors of the new target. Return the new target
            otherwise.
        """
        tkey = repr(target)
        prev_target = self.delayed_targets.get(tkey, target)
        if prev_target is not target:
            errors = dict(prev_target.error_log)
            errors.update(target.error_log)
            prev_target.error_log = sorted(errors.items())
        return prev_target

    def log_result(self, target):
        """
        Log a check result, if it shows errors. Dispatch the errors to the
        appropriate destinations (log files, queues, etc.).
        """
        # The result may come from a new target, or from an old target
        # we checked another time, or both.
        target = self.merge_with_delayed_target(target)
        if target.has_errors:
            time_in_error, confirmations = target.time_in_error()
            if (time_in_error < self.min_time_in_error or
                    confirmations < self.required_confirmations):
                self.logger.info("Delaying check for %s, %d/%d confirmations",
                                 target, confirmations,
                                 self.required_confirmations)
                self.delayed_targets[repr(target)] = target
            else:
                if target.type == 'chunk':
                    self.logger.info(
                        "Writing error for %s, %d/%d confirmations",
                        target, confirmations, self.required_confirmations)
                    self.write_chunk_error(target,
                                           irreparable=target.irreparable)
                else:
                    self.write_error(target, irreparable=target.irreparable)
                self.delayed_targets.pop(repr(target), None)
            self.logger.warn(
                '%s:%s\n%s',
                target,
                ' irreparable' if target.irreparable else '',
                target.latest_error_result().errors_to_str(err_format='  %s'))

    def run(self, rate_limiter=None):
        """
        Fetch results and write logs until all jobs have finished.

        :returns: a generator yielding check results.
        """
        while self.running and (self.pool.running() + self.pool.waiting()):
            for result in self.fetch_results(rate_limiter):
                self.log_result(result)
                yield result
            sleep(0.1)
        if self.running:
            self.pool.waitall()
        # No rate limiting
        for result in self.fetch_results():
            self.log_result(result)
            yield result
        self.list_cache = CacheDict(self.list_cache.size)

    def stop(self):
        self.logger.info("Stopping")
        self.running = False

    def report(self):
        success = True

        def _report_stat(name, stat):
            print("{0:18}: {1}".format(name, stat))

        print()
        print('Report')
        _report_stat("Accounts checked", self.accounts_checked)
        if self.account_not_found:
            success = False
            _report_stat("Missing accounts", self.account_not_found)
        if self.account_exceptions:
            success = False
            _report_stat("Exceptions", self.account_exceptions)
        print()
        _report_stat("Containers checked", self.containers_checked)
        if self.container_not_found:
            success = False
            _report_stat("Missing containers", self.container_not_found)
        if self.container_exceptions:
            success = False
            _report_stat("Exceptions", self.container_exceptions)
        print()
        _report_stat("Objects checked", self.objects_checked)
        if self.object_not_found:
            success = False
            _report_stat("Missing objects", self.object_not_found)
        if self.object_exceptions:
            success = False
            _report_stat("Exceptions", self.object_exceptions)
        print()
        _report_stat("Chunks checked", self.chunks_checked)
        if self.chunk_not_found:
            success = False
            _report_stat("Missing chunks", self.chunk_not_found)
        if self.chunk_exceptions:
            success = False
            _report_stat("Exceptions", self.chunk_exceptions)
        return success


def run_once(checker, entries=None, rate_limiter=None):
    if entries:
        for entry in entries:
            if isinstance(entry, Target):
                checker.check(entry, recurse=DEFAULT_DEPTH)
            else:
                checker.check(Target(*entry), recurse=DEFAULT_DEPTH)
    else:
        checker.check_all_accounts(recurse=DEFAULT_DEPTH)
    for _ in checker.run(rate_limiter):
        pass
    if not checker.report():
        return 1
    return 0


def run_indefinitely(checker, entries=None, rate_limiter=None,
                     pause_between_passes=0.0):
    def _stop(*args):
        checker.stop()

    import signal
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGQUIT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    while checker.running:
        if checker.delayed_targets:
            run_once(checker,
                     entries=checker.delayed_targets.values(),
                     rate_limiter=rate_limiter)

        run_once(checker, entries, rate_limiter)

        checker.reset_stats()
        if checker.running and pause_between_passes > 0.0:
            checker.logger.info("Pausing for %.3fs", pause_between_passes)
            iterations, rest = divmod(pause_between_passes, 1)
            sleep(rest)
            for _ in range(int(iterations)):
                if not checker.running:
                    break
                sleep(1.0)


def main():
    """
    Main function for legacy integrity crawler.
    """
    import argparse
    from oio.cli import get_logger_from_args, make_logger_args_parser
    parser = argparse.ArgumentParser(description=__doc__,
                                     parents=[make_logger_args_parser()])
    parser.add_argument('namespace', help='Namespace name')
    parser.add_argument(
        'account', nargs='?', help="Account (if not set, check all accounts)")
    t_help = "Element whose integrity should be checked. " \
        "Can be empty (check the whole account), " \
        "CONTAINER (check all objects of the container), " \
        "CONTAINER CONTENT (check all chunks of the object) " \
        "or CONTAINER CONTENT CHUNK (check only one chunk). " \
        "When reading from stdin, expect one element per line " \
        "(starting with account)."
    parser.add_argument('target', metavar='T', nargs='*',
                        help=t_help)
    parser.add_argument('--attempts', type=int, default=1,
                        help=('Number of attempts for '
                              'listing requests (default: 1).'))

    parser.add_argument('--beanstalkd', metavar='IP:PORT',
                        help=("BETA: send broken chunks events to a "
                              "beanstalkd tube. Do not enable this without "
                              "also enabling --confirmations and/or "
                              "--time-in-error, or the system may be "
                              "rebuilding temporary unavailable chunks."))
    parser.add_argument('--beanstalkd-tube',
                        default=BlobRebuilder.DEFAULT_BEANSTALKD_WORKER_TUBE,
                        help=("The beanstalkd tube to send broken chunks "
                              "events to (default=%s)." %
                              BlobRebuilder.DEFAULT_BEANSTALKD_WORKER_TUBE))

    parser.add_argument('--concurrency', '--workers', type=int,
                        default=50,
                        help='Number of concurrent checks (default: 50).')
    parser.add_argument('--confirmations', type=int,
                        default=0,
                        help=("BETA: report an error only after this number "
                              "of confirmations (default: 0, report "
                              "immediately). Makes sense only when running "
                              "this tool as a daemon."))
    parser.add_argument('--daemon',
                        action='store_true',
                        help=("Loop indefinitely, until killed."))
    parser.add_argument('-o', '--output',
                        help=('Output file. Will contain elements in error. '
                              'Can later be passed to stdin to re-check only '
                              'these elements.'))
    parser.add_argument('--output-for-chunk-rebuild',
                        '--output-for-blob-rebuilder',
                        dest='output_for_chunk_rebuild',
                        help="Write chunk errors in a file with a format " +
                        "suitable as 'openio-admin chunk rebuild' input.")
    parser.add_argument('--pause-between-passes', type=float, default=0.0,
                        help=("When running as a daemon, make a pause before "
                              "restarting from the beginning "
                              "(default: 0.0 seconds)."))
    parser.add_argument('-p', '--presence',
                        action='store_true', default=False,
                        help="Presence check, the xattr check is skipped.")
    parser.add_argument('-r', '--ratelimit',
                        help=('Set the hour-based rate limiting policy. '
                              'Ex: "0h30:10;6h45:2;15h30:3;9h45:5;20h00:8".'))
    parser.add_argument('--time-in-error', type=float,
                        default=0.0,
                        help=("BETA: report an error only after the item has "
                              "shown errors for this amount of time "
                              "(default: 0.0 seconds, report immediately). "
                              "Makes sense only when running this tool "
                              "as a daemon."))

    args = parser.parse_args()

    if args.attempts < 1:
        raise ValueError('attempts must be at least 1')

    if not os.isatty(sys.stdin.fileno()):
        source = sys.stdin
        limit_listings = 0  # do full listings, cache the results
        entries = csv.reader(source, delimiter=' ')
    else:
        if args.account:
            entries = [[args.account] + args.target]
            limit_listings = len(args.target)
        else:
            entries = None
            limit_listings = 0
    logger = get_logger_from_args(args)
    checker = Checker(
        args.namespace,
        error_file=args.output,
        concurrency=args.concurrency,
        rebuild_file=args.output_for_chunk_rebuild,
        check_xattr=not args.presence,
        limit_listings=limit_listings,
        request_attempts=args.attempts,
        logger=logger,
        verbose=not args.quiet,
        min_time_in_error=args.time_in_error,
        required_confirmations=args.confirmations,
        beanstalkd_addr=args.beanstalkd,
        beanstalkd_tube=args.beanstalkd_tube,
    )

    if args.ratelimit:
        rate_limiter = ratelimit_function_build(args.ratelimit)
    else:
        rate_limiter = None

    if args.daemon:
        run_indefinitely(checker, entries, rate_limiter,
                         pause_between_passes=args.pause_between_passes)
    else:
        return run_once(checker, entries, rate_limiter)
