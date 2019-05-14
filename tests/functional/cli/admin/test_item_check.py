# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
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
import time

from oio.account.client import AccountClient
from oio.blob.client import BlobClient
from oio.common.autocontainer import HashedContainerBuilder
from oio.common.json import json
from oio.common.utils import cid_from_name
from oio.event.evob import EventTypes
from tests.functional.cli import CliTestCase
from tests.utils import random_str


class ItemCheckTest(CliTestCase):
    """Functionnal tests for item to check."""

    FLAT_BITS = 5

    def setUp(self):
        super(ItemCheckTest, self).setUp()
        self.rawx_services = None

        self.account = "item_check_account_" + random_str(4)
        self.container = "item_check_container" + random_str(4)
        self.obj_name = "item_check_obj_" + random_str(4)
        self.check_opts = self.get_opts(['Type', 'Item', 'Status'])

        self.beanstalkd0.drain_tube('oio-preserved')

        self.account_client = AccountClient(self.conf)
        self.blob_client = BlobClient(self.conf)
        self.autocontainer = HashedContainerBuilder(bits=self.FLAT_BITS)

    def assertCheckOutput(self, expected_items, actual_output):
        super(ItemCheckTest, self).assertListEqual(
            sorted(expected_items),
            sorted(actual_output.rstrip('\n').split('\n')))

    def _wait_events(self, account, container, obj_name):
        self.wait_for_event(
            'oio-preserved',
            fields={'account': account, 'user': container, 'path': obj_name},
            type_=EventTypes.CONTENT_NEW)
        self.wait_for_event(
            'oio-preserved',
            fields={'account': account, 'user': container},
            type_=EventTypes.CONTAINER_STATE)

    def create_object(self, account, container, obj_name):
        opts = self.get_opts(['Name'])
        output = self.openio(
            '--oio-account %s object create %s /etc/passwd --name %s %s'
            % (account, container, obj_name, opts))
        self.assertOutput('%s\n' % obj_name, output)
        opts = self.get_opts([], format='json')
        output = self.openio(
            '--oio-account %s object show %s %s %s'
            % (account, container, obj_name, opts))
        obj_meta = json.loads(output)
        opts = self.get_opts(['Id'])
        output = self.openio(
            '--oio-account %s object locate %s %s %s'
            % (account, container, obj_name, opts))
        obj_chunks = output.rstrip('\n').split('\n')
        self._wait_events(account, container, obj_name)
        return obj_meta, obj_chunks

    def create_object_auto(self, account, obj_name):
        opts = self.get_opts(['Name'])
        output = self.openio(
            '--oio-account %s object create /etc/passwd --name %s '
            '--auto --flat-bits %d %s'
            % (account, obj_name, self.FLAT_BITS, opts))
        self.assertOutput('%s\n' % obj_name, output)
        opts = self.get_opts([], format='json')
        output = self.openio(
            '--oio-account %s object show %s --auto --flat-bits %d %s'
            % (account, obj_name, self.FLAT_BITS, opts))
        obj_meta = json.loads(output)
        opts = self.get_opts(['Id'])
        output = self.openio(
            '--oio-account %s object locate %s --auto --flat-bits %d %s'
            % (account, obj_name, self.FLAT_BITS, opts))
        obj_chunks = output.rstrip('\n').split('\n')
        container = self.autocontainer(obj_name)
        self._wait_events(account, container, obj_name)
        return container, obj_meta, obj_chunks

    def corrupt_chunk(self, chunk):
        _, service_id, chunk_id = chunk.rsplit('/', 2)
        if self.rawx_services is None:
            self.rawx_services = self.conscience.all_services('rawx')
        for rawx_service in self.rawx_services:
            tags = rawx_service['tags']
            rawx_service_id = tags.get('tag.service_id', None)
            if rawx_service_id is None:
                rawx_service_id = rawx_service['addr']
            if rawx_service_id != service_id:
                continue
            rawx_service_path = tags.get('tag.vol', None)
            break
        else:
            self.fail('No service matches with the chunk %s' % chunk)
        chunk_id = chunk_id.upper()
        chunk_path = rawx_service_path + '/' + chunk_id[:3] + '/' + chunk_id
        with open(chunk_path, "wb") as fp:
            fp.write('chunk is dead')

    def test_account_check(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s OK'
            % (self.account, self.container))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk))

        # Check all items
        output = self.openio_admin(
            'account check %s %s'
            % (self.account, self.check_opts))
        self.assertCheckOutput(expected_items, output)

        output = self.openio_admin(
            '--oio-account %s account check %s'
            % (self.account, self.check_opts))
        self.assertCheckOutput(expected_items, output)

    def test_account_with_depth(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        expected_items = list()

        # Check part of items
        expected_items.append('account account=%s OK' % self.account)
        output = self.openio_admin(
            'account check %s --depth 0 %s'
            % (self.account, self.check_opts))
        self.assertCheckOutput(expected_items, output)

        expected_items.append(
            'container account=%s, container=%s OK'
            % (self.account, self.container))
        output = self.openio_admin(
            'account check %s --depth 1 %s'
            % (self.account, self.check_opts))
        self.assertCheckOutput(expected_items, output)

        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        output = self.openio_admin(
            'account check %s --depth 2 %s'
            % (self.account, self.check_opts))
        self.assertCheckOutput(expected_items, output)

        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk))
        output = self.openio_admin(
            'account check %s --depth 3 %s'
            % (self.account, self.check_opts))
        self.assertCheckOutput(expected_items, output)

        output = self.openio_admin(
            'account check %s --depth 4 %s'
            % (self.account, self.check_opts))
        self.assertCheckOutput(expected_items, output)

    def test_account_check_with_checksum(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s OK'
            % (self.account, self.container))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk))

        # Check with checksum
        output = self.openio_admin(
            'account check %s --checksum %s'
            % (self.account, self.check_opts))
        self.assertCheckOutput(expected_items, output)

        # Corrupt the chunk
        corrupted_chunk = random.choice(obj_chunks)
        self.corrupt_chunk(corrupted_chunk)

        # Check without checksum
        output = self.openio_admin(
            'account check %s %s'
            % (self.account, self.check_opts))
        self.assertCheckOutput(expected_items, output)

        expected_items.remove('chunk chunk=%s OK' % (corrupted_chunk))
        expected_items.append('chunk chunk=%s error' % (corrupted_chunk))
        expected_items.remove(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s error'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))

        # Check with checksum
        output = self.openio_admin(
            'account check %s --checksum %s'
            % (self.account, self.check_opts), expected_returncode=1)
        self.assertCheckOutput(expected_items, output)

    def test_account_check_with_missing_chunk(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        missing_chunk = random.choice(obj_chunks)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s OK'
            % (self.account, self.container))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s error'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            if chunk == missing_chunk:
                status = 'error'
            else:
                status = 'OK'
            expected_items.append(
                'chunk chunk=%s %s' % (chunk, status))

        # Delete chunk
        self.blob_client.chunk_delete(missing_chunk)

        # Check with missing chunk
        output = self.openio_admin(
            'account check %s %s'
            % (self.account, self.check_opts), expected_returncode=1)
        self.assertCheckOutput(expected_items, output)

    def test_account_check_with_missing_container(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        missing_container = "item_check_missing_container_" + random_str(4)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s OK'
            % (self.account, self.container))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk))
        expected_items.append(
            'container account=%s, container=%s error'
            % (self.account, missing_container))

        # Create a container only in account service
        metadata = dict()
        metadata["mtime"] = time.time()
        metadata["bytes"] = 0
        metadata["objects"] = 0
        self.account_client.container_update(
            self.account, missing_container, metadata=metadata)

        # Check with missing container
        output = self.openio_admin(
            'account check %s %s'
            % (self.account, self.check_opts), expected_returncode=1)
        self.assertCheckOutput(expected_items, output)

    def test_account_check_with_missing_account(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        mising_account = "item_check_missing_account_" + random_str(4)

        expected_items = list()
        expected_items.append('account account=%s error' % mising_account)

        # Check with missing account
        output = self.openio_admin(
            'account check %s %s'
            % (mising_account, self.check_opts), expected_returncode=1)
        self.assertCheckOutput(expected_items, output)

        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s OK'
            % (self.account, self.container))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk))

        output = self.openio_admin(
            'account check %s %s %s'
            % (self.account, mising_account, self.check_opts),
            expected_returncode=1)
        self.assertCheckOutput(expected_items, output)

    def test_account_check_with_multiple_accounts(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        second_account = "item_check_second_account_" + random_str(4)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s OK'
            % (self.account, self.container))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk))

        # Create a second account
        self.account_client.account_create(second_account)

        # Check only the first account
        output = self.openio_admin(
            'account check %s %s'
            % (self.account, self.check_opts))
        self.assertCheckOutput(expected_items, output)

        # Check two accounts
        expected_items.append('account account=%s OK' % second_account)
        output = self.openio_admin(
            'account check %s %s %s'
            % (self.account, second_account, self.check_opts))
        self.assertCheckOutput(expected_items, output)

    def test_container_check(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s OK'
            % (self.account, self.container))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk))

        # Check all items
        output = self.openio_admin(
            '--oio-account %s container check %s %s'
            % (self.account, self.container, self.check_opts))
        self.assertCheckOutput(expected_items, output)

    def test_container_check_with_cid(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s OK'
            % (self.account, self.container))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk))

        # Check all items
        container_id = cid_from_name(self.account, self.container)
        output = self.openio_admin(
            'container check %s --cid %s'
            % (container_id, self.check_opts))
        self.assertCheckOutput(expected_items, output)

    def test_container_with_depth(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        expected_items = list()

        # Check part of items
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s OK'
            % (self.account, self.container))
        output = self.openio_admin(
            '--oio-account %s container check %s --depth 0 %s'
            % (self.account, self.container, self.check_opts))
        self.assertCheckOutput(expected_items, output)

        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        output = self.openio_admin(
            '--oio-account %s container check %s --depth 1 %s'
            % (self.account, self.container, self.check_opts))
        self.assertCheckOutput(expected_items, output)

        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk))
        output = self.openio_admin(
            '--oio-account %s container check %s --depth 2 %s'
            % (self.account, self.container, self.check_opts))
        self.assertCheckOutput(expected_items, output)

        output = self.openio_admin(
            '--oio-account %s container check %s --depth 3 %s'
            % (self.account, self.container, self.check_opts))
        self.assertCheckOutput(expected_items, output)

        output = self.openio_admin(
            '--oio-account %s container check %s --depth 4 %s'
            % (self.account, self.container, self.check_opts))
        self.assertCheckOutput(expected_items, output)

    def test_container_check_with_checksum(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s OK'
            % (self.account, self.container))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk))

        # Check with checksum
        output = self.openio_admin(
            '--oio-account %s container check %s --checksum %s'
            % (self.account, self.container, self.check_opts))
        self.assertCheckOutput(expected_items, output)

        # Corrupt the chunk
        corrupted_chunk = random.choice(obj_chunks)
        self.corrupt_chunk(corrupted_chunk)

        # Check without checksum
        output = self.openio_admin(
            '--oio-account %s container check %s %s'
            % (self.account, self.container, self.check_opts))
        self.assertCheckOutput(expected_items, output)

        expected_items.remove('chunk chunk=%s OK' % (corrupted_chunk))
        expected_items.append('chunk chunk=%s error' % (corrupted_chunk))
        expected_items.remove(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s error'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))

        # Check with checksum
        output = self.openio_admin(
            '--oio-account %s container check %s --checksum %s'
            % (self.account, self.container, self.check_opts),
            expected_returncode=1)
        self.assertCheckOutput(expected_items, output)

    def test_container_check_with_missing_chunk(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        missing_chunk = random.choice(obj_chunks)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s OK'
            % (self.account, self.container))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s error'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            if chunk == missing_chunk:
                status = 'error'
            else:
                status = 'OK'
            expected_items.append(
                'chunk chunk=%s %s' % (chunk, status))

        # Delete chunk
        self.blob_client.chunk_delete(missing_chunk)

        # Check with missing chunk
        output = self.openio_admin(
            '--oio-account %s container check %s %s'
            % (self.account, self.container, self.check_opts),
            expected_returncode=1)
        self.assertCheckOutput(expected_items, output)

    def test_container_check_with_missing_container(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        missing_container = "item_check_missing_container_" + random_str(4)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s error'
            % (self.account, missing_container))

        # Check with missing container
        output = self.openio_admin(
            '--oio-account %s container check %s %s'
            % (self.account, missing_container, self.check_opts),
            expected_returncode=1)
        self.assertCheckOutput(expected_items, output)

        # Create a container only in account service
        metadata = dict()
        metadata["mtime"] = time.time()
        metadata["bytes"] = 0
        metadata["objects"] = 0
        self.account_client.container_update(
            self.account, missing_container, metadata=metadata)

        # Check with missing container
        output = self.openio_admin(
            '--oio-account %s container check %s %s'
            % (self.account, missing_container, self.check_opts),
            expected_returncode=1)
        self.assertCheckOutput(expected_items, output)

        expected_items.append(
            'container account=%s, container=%s OK'
            % (self.account, self.container))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk))

        output = self.openio_admin(
            '--oio-account %s container check %s %s %s'
            % (self.account, self.container, missing_container,
               self.check_opts), expected_returncode=1)
        self.assertCheckOutput(expected_items, output)

    def test_container_check_with_missing_account(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        expected_items = list()
        expected_items.append('account account=%s error' % self.account)
        expected_items.append(
            'container account=%s, container=%s error'
            % (self.account, self.container))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk))

        # Remove account
        self.account_client.account_flush(self.account)
        self.account_client.account_delete(self.account)

        # Check with missing account
        output = self.openio_admin(
            '--oio-account %s container check %s %s'
            % (self.account, self.container, self.check_opts),
            expected_returncode=1)
        self.assertCheckOutput(expected_items, output)

    def test_container_check_with_multiple_containers(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        second_container = "item_check_second_container_" + random_str(4)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s OK'
            % (self.account, self.container))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk))

        # Create a second container
        self.openio('--oio-account %s container create %s'
                    % (self.account, second_container))

        # Check only the first container
        output = self.openio_admin(
            '--oio-account %s container check %s %s'
            % (self.account, self.container, self.check_opts))
        self.assertCheckOutput(expected_items, output)

        # Check two containers
        expected_items.append(
            'container account=%s, container=%s OK'
            % (self.account, second_container))
        output = self.openio_admin(
            '--oio-account %s container check %s %s %s'
            % (self.account, self.container, second_container,
               self.check_opts))
        self.assertCheckOutput(expected_items, output)

    def test_object_check(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s OK'
            % (self.account, self.container))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk))

        # Check all items
        output = self.openio_admin(
            '--oio-account %s object check %s %s %s'
            % (self.account, self.container, obj_meta['object'],
               self.check_opts))
        self.assertCheckOutput(expected_items, output)

    def test_object_check_with_cid(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s OK'
            % (self.account, self.container))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk))

        # Check all items
        container_id = cid_from_name(self.account, self.container)
        output = self.openio_admin(
            'object check --cid %s %s %s'
            % (container_id, obj_meta['object'], self.check_opts))
        self.assertCheckOutput(expected_items, output)

    def test_object_check_with_object_version(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s OK'
            % (self.account, self.container))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk))

        # Check all items
        output = self.openio_admin(
            '--oio-account %s object check %s %s --object-version %s %s'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['version'], self.check_opts))
        self.assertCheckOutput(expected_items, output)

        # Enable versioning
        output = self.openio(
            '--oio-account %s container set %s --max-version -1'
            % (self.account, self.container))
        self.assertOutput('', output)

        # Create a second version of the object
        second_version_meta, second_version_chunks = self.create_object(
            self.account, self.container, obj_meta['object'])

        # Check first version
        output = self.openio_admin(
            '--oio-account %s object check %s %s --object-version %s %s'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['version'], self.check_opts))
        self.assertCheckOutput(expected_items, output)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s OK'
            % (self.account, self.container))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, second_version_meta['object'],
               second_version_meta['id'], second_version_meta['version']))
        for chunk in second_version_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk))

        # Check second version
        output = self.openio_admin(
            '--oio-account %s object check %s %s --object-version %s %s'
            % (self.account, self.container, second_version_meta['object'],
               second_version_meta['version'], self.check_opts))
        self.assertCheckOutput(expected_items, output)

        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk))

        # Check all versions
        output = self.openio_admin(
            '--oio-account %s object check %s %s %s'
            % (self.account, self.container, obj_meta['object'],
               self.check_opts))
        self.assertCheckOutput(expected_items, output)

    def test_object_check_with_auto(self):
        self.container, obj_meta, obj_chunks = self.create_object_auto(
            self.account, self.obj_name)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s OK'
            % (self.account, self.container))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk))

        # Check all items
        output = self.openio_admin(
            '--oio-account %s object check %s --auto --flat-bits %d %s'
            % (self.account, obj_meta['object'], self.FLAT_BITS,
               self.check_opts))
        self.assertCheckOutput(expected_items, output)

    def test_object_with_depth(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        expected_items = list()

        # Check part of items
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s OK'
            % (self.account, self.container))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        output = self.openio_admin(
            '--oio-account %s object check %s %s --depth 0 %s'
            % (self.account, self.container, obj_meta['object'],
               self.check_opts))
        self.assertCheckOutput(expected_items, output)

        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk))
        output = self.openio_admin(
            '--oio-account %s object check %s %s --depth 1 %s'
            % (self.account, self.container, obj_meta['object'],
               self.check_opts))
        self.assertCheckOutput(expected_items, output)

        output = self.openio_admin(
            '--oio-account %s object check %s %s --depth 2 %s'
            % (self.account, self.container, obj_meta['object'],
               self.check_opts))
        self.assertCheckOutput(expected_items, output)

        output = self.openio_admin(
            '--oio-account %s object check %s %s --depth 3 %s'
            % (self.account, self.container, obj_meta['object'],
               self.check_opts))
        self.assertCheckOutput(expected_items, output)

        output = self.openio_admin(
            '--oio-account %s object check %s %s --depth 4 %s'
            % (self.account, self.container, obj_meta['object'],
               self.check_opts))
        self.assertCheckOutput(expected_items, output)

    def test_object_check_with_checksum(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s OK'
            % (self.account, self.container))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk))

        # Check with checksum
        output = self.openio_admin(
            '--oio-account %s object check %s %s --checksum %s'
            % (self.account, self.container, obj_meta['object'],
               self.check_opts))
        self.assertCheckOutput(expected_items, output)

        # Corrupt the chunk
        corrupted_chunk = random.choice(obj_chunks)
        self.corrupt_chunk(corrupted_chunk)

        # Check without checksum
        output = self.openio_admin(
            '--oio-account %s object check %s %s %s'
            % (self.account, self.container, obj_meta['object'],
               self.check_opts))
        self.assertCheckOutput(expected_items, output)

        expected_items.remove('chunk chunk=%s OK' % (corrupted_chunk))
        expected_items.append('chunk chunk=%s error' % (corrupted_chunk))
        expected_items.remove(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s error'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))

        # Check with checksum
        output = self.openio_admin(
            '--oio-account %s object check %s %s --checksum %s'
            % (self.account, self.container, obj_meta['object'],
               self.check_opts), expected_returncode=1)
        self.assertCheckOutput(expected_items, output)

    def test_object_check_with_missing_chunk(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        missing_chunk = random.choice(obj_chunks)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s OK'
            % (self.account, self.container))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s error'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            if chunk == missing_chunk:
                status = 'error'
            else:
                status = 'OK'
            expected_items.append(
                'chunk chunk=%s %s' % (chunk, status))

        # Delete chunk
        self.blob_client.chunk_delete(missing_chunk)

        # Check with missing chunk
        output = self.openio_admin(
            '--oio-account %s object check %s %s %s'
            % (self.account, self.container, obj_meta['object'],
               self.check_opts), expected_returncode=1)
        self.assertCheckOutput(expected_items, output)

    def test_object_check_with_missing_object(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        missing_obj = "item_check_missing_obj_" + random_str(4)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s OK'
            % (self.account, self.container))
        expected_items.append(
            'object account=%s, container=%s, obj=%s error'
            % (self.account, self.container, missing_obj))

        # Check with missing object
        output = self.openio_admin(
            '--oio-account %s object check %s %s %s'
            % (self.account, self.container, missing_obj, self.check_opts),
            expected_returncode=1)
        self.assertCheckOutput(expected_items, output)

        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk))

        output = self.openio_admin(
            '--oio-account %s object check %s %s %s %s'
            % (self.account, self.container, obj_meta['object'],
               missing_obj, self.check_opts), expected_returncode=1)
        self.assertCheckOutput(expected_items, output)

    def test_object_check_with_missing_container(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s error'
            % (self.account, self.container))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk))

        # Remove container in account service
        self.account_client.account_flush(self.account)

        # Check with missing container
        output = self.openio_admin(
            '--oio-account %s object check %s %s %s'
            % (self.account, self.container, obj_meta['object'],
               self.check_opts), expected_returncode=1)
        self.assertCheckOutput(expected_items, output)

    def test_object_check_with_missing_account(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        expected_items = list()
        expected_items.append('account account=%s error' % self.account)
        expected_items.append(
            'container account=%s, container=%s error'
            % (self.account, self.container))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk))

        # Remove account
        self.account_client.account_flush(self.account)
        self.account_client.account_delete(self.account)

        # Check with missing account
        output = self.openio_admin(
            '--oio-account %s object check %s %s %s'
            % (self.account, self.container, obj_meta['object'],
               self.check_opts), expected_returncode=1)
        self.assertCheckOutput(expected_items, output)

    def test_object_check_with_multiple_objects(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        second_obj = "item_check_second_obj_" + random_str(4)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s OK'
            % (self.account, self.container))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk))

        # Create a second object
        second_obj_meta, second_obj_chunks = self.create_object(
            self.account, self.container, second_obj)

        # Check only the first object
        output = self.openio_admin(
            '--oio-account %s object check %s %s %s'
            % (self.account, self.container, obj_meta['object'],
               self.check_opts))
        self.assertCheckOutput(expected_items, output)

        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, second_obj_meta['object'],
               second_obj_meta['id'], second_obj_meta['version']))
        for chunk in second_obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk))

        # Check two objects
        output = self.openio_admin(
            '--oio-account %s object check %s %s %s %s'
            % (self.account, self.container, obj_meta['object'],
               second_obj, self.check_opts))
        self.assertCheckOutput(expected_items, output)

    def test_chunk_check(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        chunk = random.choice(obj_chunks)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s OK'
            % (self.account, self.container))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        expected_items.append('chunk chunk=%s OK' % (chunk))

        # Check all items
        output = self.openio_admin(
            'chunk check %s %s'
            % (chunk, self.check_opts))
        self.assertCheckOutput(expected_items, output)

    def test_chunk_check_with_checksum(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        chunk = random.choice(obj_chunks)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s OK'
            % (self.account, self.container))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        expected_items.append('chunk chunk=%s OK' % (chunk))

        # Check with checksum
        output = self.openio_admin(
            'chunk check %s --checksum %s'
            % (chunk, self.check_opts))
        self.assertCheckOutput(expected_items, output)

        # Corrupt the chunk
        self.corrupt_chunk(chunk)

        # Check without checksum
        output = self.openio_admin(
            'chunk check %s %s'
            % (chunk, self.check_opts))
        self.assertCheckOutput(expected_items, output)

        expected_items.remove('chunk chunk=%s OK' % (chunk))
        expected_items.append('chunk chunk=%s error' % (chunk))

        # Check with checksum
        output = self.openio_admin(
            'chunk check %s --checksum %s'
            % (chunk, self.check_opts), expected_returncode=1)
        self.assertCheckOutput(expected_items, output)

    def test_chunk_check_with_missing_chunk(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        missing_chunk = random.choice(obj_chunks)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s OK'
            % (self.account, self.container))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        expected_items.append('chunk chunk=%s error' % missing_chunk)

        # Prevent the events
        self._service('@event', 'stop', wait=3)

        try:
            # Delete chunk
            self.blob_client.chunk_delete(missing_chunk)

            # Check with missing chunk
            output = self.openio_admin(
                'chunk check %s %s'
                % (missing_chunk, self.check_opts), expected_returncode=1)
            self.assertCheckOutput(expected_items, output)
        finally:
            self._service('@event', 'start', wait=3)

    def test_chunk_check_with_missing_object(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        chunk = random.choice(obj_chunks)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s OK'
            % (self.account, self.container))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s error'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        expected_items.append('chunk chunk=%s error' % (chunk))

        # Prevent the deletion of chunks
        self._service('@event', 'stop', wait=3)

        try:
            # Delete object
            self.openio(
                '--oio-account %s object delete %s %s'
                % (self.account, self.container, obj_meta['object']))

            # Check with missing object
            output = self.openio_admin(
                'chunk check %s %s'
                % (chunk, self.check_opts), expected_returncode=1)
            self.assertCheckOutput(expected_items, output)
        finally:
            self._service('@event', 'start', wait=3)

    def test_chunk_check_with_missing_container(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        chunk = random.choice(obj_chunks)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s error'
            % (self.account, self.container))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        expected_items.append('chunk chunk=%s OK' % (chunk))

        # Remove container in account service
        self.account_client.account_flush(self.account)

        # Check with missing container
        output = self.openio_admin(
            'chunk check %s %s'
            % (chunk, self.check_opts), expected_returncode=1)
        self.assertCheckOutput(expected_items, output)

    def test_chunk_check_with_missing_account(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        chunk = random.choice(obj_chunks)

        expected_items = list()
        expected_items.append('account account=%s error' % self.account)
        expected_items.append(
            'container account=%s, container=%s error'
            % (self.account, self.container))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        expected_items.append('chunk chunk=%s OK' % (chunk))

        # Remove account
        self.account_client.account_flush(self.account)
        self.account_client.account_delete(self.account)

        # Check with missing account
        output = self.openio_admin(
            'chunk check %s %s'
            % (chunk, self.check_opts), expected_returncode=1)
        self.assertCheckOutput(expected_items, output)

    def test_chunk_check_with_multiple_objects(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        chunk = random.choice(obj_chunks)
        second_obj = "item_check_second_obj_" + random_str(4)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s OK'
            % (self.account, self.container))
        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, obj_meta['object'],
               obj_meta['id'], obj_meta['version']))
        expected_items.append('chunk chunk=%s OK' % (chunk))

        # Create a second object
        second_obj_meta, second_obj_chunks = self.create_object(
            self.account, self.container, second_obj)
        second_chunk = random.choice(second_obj_chunks)

        # Check only the first object
        output = self.openio_admin(
            'chunk check %s %s'
            % (chunk, self.check_opts))
        self.assertCheckOutput(expected_items, output)

        expected_items.append(
            'object account=%s, container=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, second_obj_meta['object'],
               second_obj_meta['id'], second_obj_meta['version']))
        expected_items.append('chunk chunk=%s OK' % (second_chunk))

        # Check two objects
        output = self.openio_admin(
            'chunk check %s %s %s'
            % (chunk, second_chunk, self.check_opts))
        self.assertCheckOutput(expected_items, output)
