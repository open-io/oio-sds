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
import os
import csv
import sys
from io import StringIO
import argparse

from eventlet.event import Event
from eventlet.greenpool import GreenPool

from oio.common import exceptions as exc
from oio.common.storage_method import STORAGE_METHODS
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
                 error_file=None, rebuild_file=None):
        self.pool = GreenPool(concurrency)
        self.error_file = error_file
        if self.error_file:
            f = open(self.error_file, 'a')
            self.error_writer = csv.writer(f, delimiter=' ')

        self.rebuild_file = rebuild_file
        if self.rebuild_file:
            fd = open(self.rebuild_file, 'a')
            self.rebuild_writer = csv.writer(fd, delimiter='|')

        conf = {'namespace': namespace}
        self.account_client = AccountClient(conf)
        self.container_client = ContainerClient(conf)
        self.blob_client = BlobClient()

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

    def write_error(self, target):
        error = [target.account]
        if target.container:
            error.append(target.container)
        if target.obj:
            error.append(target.obj)
        if target.chunk:
            error.append(target.chunk)
        self.error_writer.writerow(error)

    def write_rebuilder_input(self, target, obj_meta, ct_meta):
        try:
            cid = ct_meta['system']['sys.name'].split('.', 1)[0]
        except KeyError:
            cid = ct_meta['properties']['sys.name'].split('.', 1)[0]
        self.rebuild_writer.writerow((cid, obj_meta['id'], target.chunk))

    def write_chunk_error(self, target, obj_meta, chunk=None):
        if chunk is not None:
            target = target.copy()
            target.chunk = chunk
        if self.error_file:
            self.write_error(target)
        if self.rebuild_file:
            self.write_rebuilder_input(
                target, obj_meta,
                self.list_cache[(target.account, target.container)][1])

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

    def check_chunk(self, target):
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
            xattr_meta = self.blob_client.chunk_head(chunk)
        except exc.NotFound as e:
            self.chunk_not_found += 1
            error = True
            print('  Not found chunk "%s": %s' % (target, str(e)))
        except Exception as e:
            self.chunk_exceptions += 1
            error = True
            print('  Exception chunk "%s": %s' % (target, str(e)))
        else:
            if db_meta:
                error = self._check_chunk_xattr(target, db_meta, xattr_meta)

        if error:
            self.write_chunk_error(target, obj_meta)

        self.chunks_checked += 1

    def check_obj_policy(self, target, obj_meta, chunks):
        """
        Check that the list of chunks of an object matches
        the object's storage policy.
        """
        stg_met = STORAGE_METHODS.load(obj_meta['chunk_method'])
        chunks_by_pos = _sort_chunks(chunks, stg_met.ec)
        if stg_met.ec:
            required = stg_met.ec_nb_data + stg_met.ec_nb_parity
        else:
            required = stg_met.nb_copy
        for pos, clist in chunks_by_pos.iteritems():
            if len(clist) < required:
                print('  Missing %d chunks at position %s of %s' % (
                    required - len(clist), pos, target))
                if stg_met.ec:
                    subs = {x['num'] for x in clist}
                    for sub in range(required):
                        if sub not in subs:
                            self.write_chunk_error(target, obj_meta,
                                                   '%d.%d' % (pos, sub))
                else:
                    self.write_chunk_error(target, obj_meta, str(pos))

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
                account=account, reference=container, path=obj)
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

        self.check_obj_policy(target.copy(), meta, results)

        self.objects_checked += 1
        self.list_cache[(account, container, obj)] = (chunk_listing, meta)
        self.running[(account, container, obj)].send(True)
        del self.running[(account, container, obj)]

        if recurse:
            for chunk in chunk_listing:
                t = target.copy()
                t.chunk = chunk
                self.pool.spawn_n(self.check_chunk, t)
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
        while True:
            try:
                _, resp = self.container_client.content_list(
                    account=account, reference=container, marker=marker)
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
            else:
                ct_meta = resp
                ct_meta.pop('objects')
                break

        container_listing = dict()
        for obj in results:
            container_listing[obj['name']] = obj

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
        while True:
            try:
                resp = self.account_client.container_list(
                    account, marker=marker)
            except Exception as e:
                self.account_exceptions += 1
                error = True
                print('  Exception account "%s": %s' % (target, str(e)))
                break
            if resp['listing']:
                marker = resp['listing'][-1][0]
            else:
                break
            results.extend(resp['listing'])

        containers = dict()
        for e in results:
            containers[e[0]] = (e[1], e[2])

        self.list_cache[account] = containers
        self.running[account].send(True)
        del self.running[account]
        self.accounts_checked += 1

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
        def _report_stat(name, stat):
            print("{0:18}: {1}".format(name, stat))

        print()
        print('Report')
        _report_stat("Accounts checked", self.accounts_checked)
        if self.account_not_found:
            _report_stat("Missing accounts", self.account_not_found)
        if self.account_exceptions:
            _report_stat("Exceptions", self.account_not_found)
        print()
        _report_stat("Containers checked", self.containers_checked)
        if self.container_not_found:
            _report_stat("Missing containers", self.container_not_found)
        if self.container_exceptions:
            _report_stat("Exceptions", self.container_exceptions)
        print()
        _report_stat("Objects checked", self.objects_checked)
        if self.object_not_found:
            _report_stat("Missing objects", self.object_not_found)
        if self.object_exceptions:
            _report_stat("Exceptions", self.object_exceptions)
        print()
        _report_stat("Chunks checked", self.chunks_checked)
        if self.chunk_not_found:
            _report_stat("Missing chunks", self.chunk_not_found)
        if self.chunk_exceptions:
            _report_stat("Exceptions", self.chunk_exceptions)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('namespace', help='Namespace name')
    t_help = "Element whose integrity should be checked. " \
        "Can be ACCOUNT, ACCOUNT CONTAINER, ACCOUNT CONTAINER CONTENT " \
        "or ACCOUNT CONTAINER CONTENT CHUNK."
    parser.add_argument('target', metavar='T', nargs='*',
                        help=t_help)
    parser.add_argument('-o', '--output', help='output file')
    parser.add_argument('--output-for-blob-rebuilder',
                        help="Write chunk errors in a file with a format " +
                        "suitable as oio-blob-rebuilder input")
    parser.add_argument('-v', '--verbose',
                        action='store_true', help='verbose output')

    args = parser.parse_args()

    checker = Checker(args.namespace, error_file=args.output,
                      rebuild_file=args.output_for_blob_rebuilder)
    if not os.isatty(sys.stdin.fileno()):
        source = sys.stdin
    else:
        source = StringIO(u' '.join(args.target))
    args = csv.reader(source, delimiter=' ')
    for entry in args:
        checker.check(Target(*entry))
    checker.wait()
    checker.report()
