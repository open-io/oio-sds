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

"""
Recursively check account, container, content and chunk integrity.
"""


from __future__ import print_function
from oio.common.green import Event, GreenPool

import os
import csv
import sys
import cStringIO
import argparse

from oio.common import exceptions as exc
from oio.common.storage_method import STORAGE_METHODS
from oio.common.utils import cid_from_name
from oio.account.client import AccountClient
from oio.container.client import ContainerClient
from oio.blob.client import BlobClient
from oio.api.object_storage import _sort_chunks


class Target(object):
    def __init__(self, account, container=None, obj=None, chunk=None):
        self.account = account
        self.container = container
        self.obj = obj
        self.chunk = chunk
        self._cid = None

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
            self.chunk)

    def __repr__(self):
        s = "account=" + self.account
        if self.container:
            s += ', container=' + self.container
        if self.obj:
            s += ', obj=' + self.obj
        if self.chunk:
            s += ', chunk=' + self.chunk
        return s


class Checker(object):
    def __init__(self, namespace, concurrency=50,
                 error_file=None, rebuild_file=None, full=True,
                 limit_listings=0, request_attempts=1):
        self.pool = GreenPool(concurrency)
        self.error_file = error_file
        self.full = bool(full)
        # Optimisation for when we are only checking one object
        # or one container.
        # 0 -> do not limit
        # 1 -> limit account listings (list of containers)
        # 2 -> limit container listings (list of objects)
        self.limit_listings = limit_listings
        if self.error_file:
            f = open(self.error_file, 'a')
            self.error_writer = csv.writer(f, delimiter=' ')

        self.rebuild_file = rebuild_file
        if self.rebuild_file:
            self.fd = open(self.rebuild_file, 'a')
            self.rebuild_writer = csv.writer(self.fd, delimiter='|')

        conf = {'namespace': namespace}
        self.account_client = AccountClient(
            conf,
            max_retries=request_attempts - 1)
        self.container_client = ContainerClient(
            conf,
            max_retries=request_attempts - 1,
            request_attempts=request_attempts)
        self.blob_client = BlobClient(conf=conf)

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

    def write_error(self, target, irreparable=False):
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

    def write_rebuilder_input(self, target, obj_meta, irreparable=False):
        error = list()
        if irreparable:
            error.append('#IRREPARABLE')
        error.append(target.cid)
        error.append(obj_meta['id'])
        error.append(target.chunk)
        self.rebuild_writer.writerow(error)

    def write_chunk_error(self, target, obj_meta,
                          chunk=None, irreparable=False):
        if chunk is not None:
            target = target.copy()
            target.chunk = chunk
        if self.error_file:
            self.write_error(target, irreparable=irreparable)
        if self.rebuild_file:
            self.write_rebuilder_input(target, obj_meta,
                                       irreparable=irreparable)

    def _check_chunk_xattr(self, target, obj_meta, xattr_meta):
        error = False
        # Composed position -> erasure coding
        attr_prefix = 'meta' if '.' in obj_meta['pos'] else ''

        attr_key = attr_prefix + 'chunk_size'
        if str(obj_meta['size']) != xattr_meta.get(attr_key):
            print("  Chunk %s '%s' xattr (%s) "
                  "differs from size in meta2 (%s)" %
                  (target, attr_key, xattr_meta.get(attr_key),
                   obj_meta['size']))
            error = True

        attr_key = attr_prefix + 'chunk_hash'
        if obj_meta['hash'] != xattr_meta.get(attr_key):
            print("  Chunk %s '%s' xattr (%s) "
                  "differs from hash in meta2 (%s)" %
                  (target, attr_key, xattr_meta.get(attr_key),
                   obj_meta['hash']))
            error = True
        return error

    def _check_chunk(self, target):
        chunk = target.chunk

        obj_listing, obj_meta = self.check_obj(target)
        error = False
        if chunk not in obj_listing:
            print('  Chunk %s missing from object listing' % target)
            error = True
            db_meta = dict()
        else:
            db_meta = obj_listing[chunk]

        try:
            xattr_meta = self.blob_client.chunk_head(chunk, xattr=self.full)
        except exc.NotFound as e:
            self.chunk_not_found += 1
            error = True
            print('  Not found chunk "%s": %s' % (target, str(e)))
        except exc.FaultyChunk as err:
            self.chunk_exceptions += 1
            error = True
            print('  Exception chunk "%s": %r' % (target, err))
        except Exception as e:
            self.chunk_exceptions += 1
            error = True
            print('  Exception chunk "%s": %s' % (target, str(e)))
        else:
            if db_meta and self.full:
                error = self._check_chunk_xattr(target, db_meta, xattr_meta)

        self.chunks_checked += 1
        return error, obj_meta

    def check_chunk(self, target):
        error, obj_meta = self._check_chunk(target)
        if error:
            self.write_chunk_error(target, obj_meta)

    def _check_metachunk(self, target, obj_meta, stg_met, pos, chunks,
                         recurse=False):
        required = stg_met.expected_chunks
        chunk_errors = list()

        if len(chunks) < required:
            missing_chunks = required - len(chunks)
            print('  Missing %d chunks at position %s of %s' % (
                  missing_chunks, pos, target))
            if stg_met.ec:
                subs = {x['num'] for x in chunks}
                for sub in range(required):
                    if sub not in subs:
                        chunk_errors.append(
                            (target, obj_meta, '%d.%d' % (pos, sub)))
            else:
                for _ in range(missing_chunks):
                    chunk_errors.append((target, obj_meta, str(pos)))

        if recurse:
            for chunk in chunks:
                t = target.copy()
                t.chunk = chunk['url']
                error, obj_meta = self._check_chunk(t)
                if error:
                    chunk_errors.append((t, obj_meta))

        irreparable = required - len(chunk_errors) < stg_met.min_chunks_to_read
        for chunk_error in chunk_errors:
            self.write_chunk_error(*chunk_error, irreparable=irreparable)

    def _check_obj_policy(self, target, obj_meta, chunks, recurse=False):
        """
        Check that the list of chunks of an object matches
        the object's storage policy.
        """
        stg_met = STORAGE_METHODS.load(obj_meta['chunk_method'])
        chunks_by_pos = _sort_chunks(chunks, stg_met.ec)
        for pos, chunks in chunks_by_pos.iteritems():
            self.pool.spawn_n(
                self._check_metachunk,
                target.copy(), obj_meta, stg_met, pos, chunks,
                recurse=recurse)

    def check_obj(self, target, recurse=False):
        account = target.account
        container = target.container
        obj = target.obj

        if (account, container, obj) in self.running:
            self.running[(account, container, obj)].wait()
        if (account, container, obj) in self.list_cache:
            return self.list_cache[(account, container, obj)]
        self.running[(account, container, obj)] = Event()
        print('Checking object "%s"' % target)
        container_listing, ct_meta = self.check_container(target)
        error = False
        if obj not in container_listing:
            print('  Object %s missing from container listing' % target)
            error = True
            # checksum = None
        else:
            # TODO check checksum match
            # checksum = container_listing[obj]['hash']
            pass

        results = []
        meta = dict()
        try:
            meta, results = self.container_client.content_locate(
                account=account, reference=container, path=obj,
                properties=False)
        except exc.NotFound as e:
            self.object_not_found += 1
            error = True
            print('  Not found object "%s": %s' % (target, str(e)))
        except Exception as e:
            self.object_exceptions += 1
            error = True
            print(' Exception object "%s": %s' % (target, str(e)))

        chunk_listing = dict()
        for chunk in results:
            chunk_listing[chunk['url']] = chunk

        if meta:
            self.list_cache[(account, container, obj)] = (chunk_listing, meta)
        self.objects_checked += 1
        self.running[(account, container, obj)].send(True)
        del self.running[(account, container, obj)]

        # Skip the check if we could not locate the object
        if meta:
            self._check_obj_policy(target, meta, results, recurse=recurse)

        if error and self.error_file:
            self.write_error(target)
        return chunk_listing, meta

    def check_container(self, target, recurse=False):
        account = target.account
        container = target.container

        if (account, container) in self.running:
            self.running[(account, container)].wait()
        if (account, container) in self.list_cache:
            return self.list_cache[(account, container)]
        self.running[(account, container)] = Event()
        print('Checking container "%s"' % target)
        account_listing = self.check_account(target)
        error = False
        if container not in account_listing:
            error = True
            print('  Container %s missing from account listing' % target)

        marker = None
        results = []
        ct_meta = dict()
        extra_args = dict()
        if self.limit_listings > 1 and target.obj:
            # When we are explicitly checking one object, start the listing
            # where this object is supposed to be, and list only one object.
            extra_args['prefix'] = target.obj
            extra_args['limit'] = 1
        while True:
            try:
                _, resp = self.container_client.content_list(
                    account=account, reference=container, marker=marker,
                    **extra_args)
            except exc.NotFound as e:
                self.container_not_found += 1
                error = True
                print('  Not found container "%s": %s' % (target, str(e)))
                break
            except Exception as e:
                self.container_exceptions += 1
                error = True
                print('  Exception container "%s": %s' % (target, str(e)))
                break

            if resp['objects']:
                marker = resp['objects'][-1]['name']
                results.extend(resp['objects'])
                if self.limit_listings > 1:
                    break
            else:
                ct_meta = resp
                ct_meta.pop('objects')
                break

        container_listing = dict()
        for obj in results:
            container_listing[obj['name']] = obj

        if self.limit_listings <= 1:
            # We just listed the whole container, keep the result in a cache
            self.containers_checked += 1
            self.list_cache[(account, container)] = container_listing, ct_meta
        self.running[(account, container)].send(True)
        del self.running[(account, container)]

        if recurse:
            for obj in container_listing:
                t = target.copy()
                t.obj = obj
                self.pool.spawn_n(self.check_obj, t, True)
        if error and self.error_file:
            self.write_error(target)
        return container_listing, ct_meta

    def check_account(self, target, recurse=False):
        account = target.account

        if account in self.running:
            self.running[account].wait()
        if account in self.list_cache:
            return self.list_cache[account]
        self.running[account] = Event()
        print('Checking account "%s"' % target)
        error = False
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
                resp = self.account_client.container_list(
                    account, marker=marker, **extra_args)
            except Exception as e:
                self.account_exceptions += 1
                error = True
                print('  Exception account "%s": %s' % (target, str(e)))
                break
            if resp['listing']:
                marker = resp['listing'][-1][0]
                results.extend(resp['listing'])
                if self.limit_listings > 0:
                    break
            else:
                break

        containers = dict()
        for e in results:
            containers[e[0]] = (e[1], e[2])

        if self.limit_listings <= 0:
            # We just listed the whole account, keep the result in a cache
            self.accounts_checked += 1
            self.list_cache[account] = containers
        self.running[account].send(True)
        del self.running[account]

        if recurse:
            for container in containers:
                t = target.copy()
                t.container = container
                self.pool.spawn_n(self.check_container, t, True)

        if error and self.error_file:
            self.write_error(target)
        return containers

    def check(self, target):
        if target.chunk and target.obj and target.container:
            self.pool.spawn_n(self.check_chunk, target)
        elif target.obj and target.container:
            self.pool.spawn_n(self.check_obj, target, True)
        elif target.container:
            self.pool.spawn_n(self.check_container, target, True)
        else:
            self.pool.spawn_n(self.check_account, target, True)

    def wait(self):
        self.pool.waitall()

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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('namespace', help='Namespace name')
    parser.add_argument(
        'account', nargs='?', help="Account (optional if reading from stdin)")
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
    parser.add_argument('-v', '--verbose',
                        action='store_true', help='verbose output')
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
    else:
        if not args.account:
            raise ValueError('missing account argument')
        source = cStringIO.StringIO(' '.join([args.account] + args.target))
        limit_listings = len(args.target)
    checker = Checker(
        args.namespace,
        error_file=args.output,
        concurrency=args.concurrency,
        rebuild_file=args.output_for_blob_rebuilder,
        full=not args.presence,
        limit_listings=limit_listings,
        request_attempts=args.attempts,
    )
    args = csv.reader(source, delimiter=' ')
    for entry in args:
        checker.check(Target(*entry))
    checker.wait()
    if not checker.report():
        sys.exit(1)
