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
from oio.common.green import Event, GreenPool, Queue, sleep

import os
import csv
import sys
import argparse

from oio.common import exceptions as exc
from oio.common.fullpath import decode_fullpath
from oio.common.logger import get_logger
from oio.common.storage_method import STORAGE_METHODS
from oio.api.object_storage import ObjectStorageApi
from oio.api.object_storage import _sort_chunks


class Target(object):
    """
    Identify the target of a check.
    """

    def __init__(self, account, container=None, obj=None,
                 content_id=None, version=None, chunk=None):
        self.account = account
        self.container = container
        self.obj = obj
        self.content_id = content_id
        self.version = version
        self.chunk = chunk

    def copy(self):
        return Target(
            self.account,
            self.container,
            self.obj,
            self.content_id,
            self.version,
            self.chunk)

    def copy_object(self):
        return Target(self.account, self.container,
                      self.obj, self.content_id, self.version)

    def copy_container(self):
        return Target(self.account, self.container)

    def copy_account(self):
        return Target(self.account)

    def __repr__(self):
        if self.type == 'chunk':
            return 'chunk=' + self.chunk
        out = 'account=%s' % self.account
        if self.container:
            out += ', container=' + self.container
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

    def __init__(self, target, errors=None):
        self.errors = errors if errors is not None else list()
        self.target = target

    @property
    def health(self):
        """
        Tell the health of the item that has been checked.
        """
        # TODO(FVE): add an intermediate 'warning' level
        return 'error' if self.errors else 'OK'

    def errors_to_str(self, separator='\n', err_format='%s'):
        """
        Pretty print errors stored in this result.
        """
        if not self.errors:
            return str(None)
        return separator.join(err_format % x for x in self.errors)


class Checker(object):
    def __init__(self, namespace, concurrency=50,
                 error_file=None, rebuild_file=None, full=True,
                 limit_listings=0, request_attempts=1,
                 logger=None, verbose=False, integrity=False):
        self.pool = GreenPool(concurrency)
        self.error_file = error_file
        self.full = bool(full)
        self.integrity = bool(integrity)
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
            fd = open(self.rebuild_file, 'a')
            self.rebuild_writer = csv.writer(fd, delimiter='|')

        self.logger = logger or get_logger({'namespace': namespace},
                                           name='integrity', verbose=verbose)
        self.api = ObjectStorageApi(
            namespace,
            logger=self.logger,
            max_retries=request_attempts - 1,
            request_attempts=request_attempts)

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

        self.list_cache = {}
        self.running = {}
        self.result_queue = Queue()

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

    def send_result(self, target, errors=None):
        """
        Put an item in the result queue.
        """
        # TODO(FVE): send to an external queue.
        self.result_queue.put(ItemResult(target, errors))

    def write_error(self, target, irreparable=False):
        if not self.error_file:
            return
        error = list()
        if irreparable:
            error.append('#IRREPARABLE')
        error.append(target.account)
        if target.container:
            error.append(target.container)
        if target.obj:
            error.append(target.obj)
        if target.chunk:
            error.append(target.chunk)
        self.error_writer.writerow(error)

    def write_rebuilder_input(self, target, irreparable=False):
        # FIXME(FVE): cid can be computed from account and container names
        ct_meta = self.list_cache[(target.account, target.container)][1]
        try:
            cid = ct_meta['system']['sys.name'].split('.', 1)[0]
        except KeyError:
            cid = ct_meta['properties']['sys.name'].split('.', 1)[0]
        error = list()
        if irreparable:
            error.append('#IRREPARABLE')
        error.append(cid)
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

        try:
            xattr_meta = self.api.blob_client.chunk_head(
                chunk, xattr=self.full, check_hash=self.integrity)
        except exc.NotFound as err:
            self.chunk_not_found += 1
            errors.append('Not found: %s' % (err, ))
        except exc.FaultyChunk as err:
            self.chunk_exceptions += 1
            errors.append('Faulty: %r' % (err, ))
        except Exception as err:
            self.chunk_exceptions += 1
            errors.append('Check failed: %s' % (err, ))

        if not target.obj and xattr_meta:
            self.complete_target_from_chunk_metadata(target, xattr_meta)

        if target.obj:
            obj_listing, obj_meta = self.check_obj(target.copy_object())
            if chunk not in obj_listing:
                errors.append('Missing from object listing')
                db_meta = dict()
            else:
                db_meta = obj_listing[chunk]

            if db_meta and xattr_meta and self.full:
                errors.extend(
                    self._check_chunk_xattr(target, db_meta, xattr_meta))

        self.send_result(target, errors)
        self.chunks_checked += 1
        return errors, obj_meta

    def check_chunk(self, target):
        errors, _obj_meta = self._check_chunk(target)
        return errors

    def _check_metachunk(self, target, stg_met, pos, chunks,
                         recurse=0):
        """
        Check that a metachunk has the right number of chunks.

        :returns: the list of errors
        """
        required = stg_met.expected_chunks
        errors = list()

        if len(chunks) < required:
            missing_chunks = required - len(chunks)
            if stg_met.ec:
                subs = {x['num'] for x in chunks}
                for sub in range(required):
                    if sub not in subs:
                        errors.append(
                            "Missing chunk at position %d.%d" % (pos, sub))
            else:
                for _ in range(missing_chunks):
                    errors.append("Missing chunk at position %d" % pos)

        if recurse > 0:
            for chunk in chunks:
                tcopy = target.copy()
                tcopy.chunk = chunk['url']
                chunk_errors, _ = self._check_chunk(tcopy)
                if chunk_errors:
                    # The errors have already been reported by _check_chunk,
                    # but we must count this chunk among the unusable chunks
                    # of the current metachunk.
                    errors.append("Unusable chunk %s at position %s" % (
                        chunk['url'], chunk['pos']))

        irreparable = required - len(errors) < stg_met.min_chunks_to_read
        if irreparable:
            errors.append(
                "Unavailable metachunk at position %s (%d/%d chunks)" % (
                    pos, required - len(errors), stg_met.expected_chunks))
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
        for pos, chunks in chunks_by_pos.iteritems():
            tasks.append((pos, self.pool.spawn(
                self._check_metachunk,
                target.copy(), stg_met, pos, chunks,
                recurse=recurse)))
        errors = list()
        for pos, task in tasks:
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
                          self.pool.spawn(self.check_obj,
                                          tcopy,
                                          recurse=recurse)))
        errors = list()
        for version, task in tasks:
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

        if (account, container, obj, vers) in self.running:
            self.running[(account, container, obj, vers)].wait()
        if (account, container, obj, vers) in self.list_cache:
            return self.list_cache[(account, container, obj, vers)]
        self.running[(account, container, obj, vers)] = Event()
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
                    self.running[(account, container, obj, vers)].send(True)
                    del self.running[(account, container, obj, vers)]
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
            self.list_cache[(account, container, obj, vers)] = \
                (chunk_listing, meta)
        self.objects_checked += 1
        self.running[(account, container, obj, vers)].send(True)
        del self.running[(account, container, obj, vers)]

        # Skip the check if we could not locate the object
        if meta:
            errors.extend(
                self._check_obj_policy(target, meta, chunks, recurse=recurse))

        self.send_result(target, errors)
        return chunk_listing, meta

    def check_container(self, target, recurse=0):
        account = target.account
        container = target.container

        if (account, container) in self.running:
            self.running[(account, container)].wait()
        if (account, container) in self.list_cache:
            return self.list_cache[(account, container)]
        self.running[(account, container)] = Event()
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

            if resp.get('truncated', False):
                marker = resp['next_marker']

            if resp['objects']:
                # safeguard, probably useless
                if not marker:
                    marker = resp['objects'][-1]['name']
                results.extend(resp['objects'])
                if self.limit_listings > 1:
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
        self.running[(account, container)].send(True)
        del self.running[(account, container)]

        if recurse > 0:
            for obj_vers in container_listing.values():
                for obj in obj_vers:
                    tcopy = target.copy_object()
                    tcopy.obj = obj['name']
                    tcopy.content_id = obj['id']
                    tcopy.version = str(obj['version'])
                    self.pool.spawn_n(self.check_obj, tcopy, recurse - 1)
        self.send_result(target, errors)
        return container_listing, ct_meta

    def check_account(self, target, recurse=0):
        account = target.account

        if account in self.running:
            self.running[account].wait()
        if account in self.list_cache:
            return self.list_cache[account]
        self.running[account] = Event()
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
        self.running[account].send(True)
        del self.running[account]

        if recurse > 0:
            for container in containers:
                tcopy = target.copy_account()
                tcopy.container = container
                self.pool.spawn_n(self.check_container, tcopy, recurse - 1)

        self.send_result(target, errors)
        return containers

    def check(self, target, recurse=0):
        if target.type == 'chunk':
            self.pool.spawn_n(self.check_chunk, target)
        elif target.type == 'object':
            self.pool.spawn_n(self.check_obj, target, recurse)
        elif target.type == 'container':
            self.pool.spawn_n(self.check_container, target, recurse)
        else:
            self.pool.spawn_n(self.check_account, target, recurse)

    def check_all_accounts(self, recurse=0):
        all_accounts = self.api.account_list()
        for acct in all_accounts:
            self.check(Target(acct), recurse=recurse)

    def fetch_results(self):
        while not self.result_queue.empty():
            res = self.result_queue.get(True)
            yield res

    def log_result(self, result):
        if result.errors:
            if result.target.type == 'chunk':
                # FIXME(FVE): check error criticity
                # and set the irreparable flag.
                self.write_chunk_error(result.target)
            else:
                self.write_error(result.target)
            self.logger.warn('%s:\n%s', result.target,
                             result.errors_to_str(err_format='  %s'))

    def run(self):
        """
        Fetch results and write logs until all jobs have finished.

        :returns: a generator yielding check results.
        """
        while self.pool.running() + self.pool.waiting():
            for result in self.fetch_results():
                self.log_result(result)
                yield result
            sleep(0.1)
        self.pool.waitall()
        for result in self.fetch_results():
            self.log_result(result)
            yield result

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


def main():
    """
    Main function for legacy integrity crawler.
    """
    parser = argparse.ArgumentParser(description=__doc__)
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
    parser.add_argument('-o', '--output',
                        help=('Output file. Will contain elements in error. '
                              'Can later be passed to stdin to re-check only '
                              'these elements.'))
    parser.add_argument('--output-for-blob-rebuilder',
                        help="Write chunk errors in a file with a format " +
                        "suitable as oio-blob-rebuilder input.")
    parser.add_argument('-p', '--presence',
                        action='store_true', default=False,
                        help="Presence check, the xattr check is skipped.")
    parser.add_argument('--concurrency', '--workers', type=int,
                        default=50,
                        help='Number of concurrent checks (default: 50).')
    parser.add_argument('--attempts', type=int, default=1,
                        help=('Number of attempts for '
                              'listing requests (default: 1).'))

    args = parser.parse_args()

    if args.attempts < 1:
        raise ValueError('attempts must be at least 1')

    if not os.isatty(sys.stdin.fileno()):
        source = sys.stdin
        limit_listings = 0  # do full listings, cache the results
        entries = csv.reader(source, delimiter=' ')
    else:
        if args.account:
            entries = [(args.account, )]
            limit_listings = len(args.target)
        else:
            entries = None
            limit_listings = 3
    checker = Checker(
        args.namespace,
        error_file=args.output,
        concurrency=args.concurrency,
        rebuild_file=args.output_for_blob_rebuilder,
        full=not args.presence,
        limit_listings=limit_listings,
        request_attempts=args.attempts,
        verbose=True,
    )
    if entries:
        for entry in entries:
            checker.check(Target(*entry), recurse=limit_listings)
    else:
        checker.check_all_accounts(recurse=limit_listings)
    for _ in checker.run():
        pass
    if not checker.report():
        sys.exit(1)
