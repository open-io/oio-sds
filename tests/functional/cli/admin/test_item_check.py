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

from oio import ObjectStorageApi
from oio.common.autocontainer import HashedContainerBuilder
from oio.common.utils import cid_from_name
from oio.event.evob import EventTypes
from tests.functional.cli import CliTestCase
from tests.utils import random_str


class ItemCheckTest(CliTestCase):
    """Functionnal tests for item to check."""

    FLAT_BITS = 5

    @classmethod
    def setUpClass(cls):
        super(ItemCheckTest, cls).setUpClass()
        cls.check_opts = cls.get_opts(['Type', 'Item', 'Status'])
        cls.api = ObjectStorageApi(cls._cls_ns, endpoint=cls._cls_uri)
        cls.autocontainer = HashedContainerBuilder(bits=cls.FLAT_BITS)

    def setUp(self):
        super(ItemCheckTest, self).setUp()
        self.rawx_services = None

        self.account = "item_check_account_" + random_str(4)
        self.container = "item_check_container" + random_str(4)
        self.obj_name = "item_check_obj_" + random_str(4)

        self.beanstalkd0.drain_tube('oio-preserved')

    def _wait_events(self, account, container, obj_name):
        self.wait_for_event(
            'oio-preserved',
            fields={'account': account, 'user': container, 'path': obj_name},
            types=(EventTypes.CONTENT_NEW, ))
        self.wait_for_event(
            'oio-preserved',
            fields={'account': account, 'user': container},
            types=(EventTypes.CONTAINER_STATE, ))

    def create_object(self, account, container, obj_name):
        self.api.object_create(
            account, container, obj_name=obj_name, data='test_item_check')
        obj_meta, obj_chunks = self.api.object_locate(
            account, container, obj_name)
        self._wait_events(account, container, obj_name)
        return obj_meta, obj_chunks

    def create_object_auto(self, account, obj_name):
        container = self.autocontainer(obj_name)
        self.api.object_create(
            account, container, obj_name=obj_name, data='test_item_check')
        obj_meta, obj_chunks = self.api.object_locate(
            account, container, obj_name)
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
            fp.write(b'chunk is dead')

    def test_account_check(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s OK'
            % (self.account, self.container, cid))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk['url']))

        # Check all items
        output = self.openio_admin(
            'account check %s %s'
            % (self.account, self.check_opts))
        self.assert_list_output(expected_items, output)

        output = self.openio_admin(
            '--oio-account %s account check %s'
            % (self.account, self.check_opts))
        self.assert_list_output(expected_items, output)

    def test_account_with_depth(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        expected_items = list()

        # Check part of items
        expected_items.append('account account=%s OK' % self.account)
        output = self.openio_admin(
            'account check %s --depth 0 %s'
            % (self.account, self.check_opts))
        self.assert_list_output(expected_items, output)

        expected_items.append(
            'container account=%s, container=%s, cid=%s OK'
            % (self.account, self.container, cid))
        output = self.openio_admin(
            'account check %s --depth 1 %s'
            % (self.account, self.check_opts))
        self.assert_list_output(expected_items, output)

        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        output = self.openio_admin(
            'account check %s --depth 2 %s'
            % (self.account, self.check_opts))
        self.assert_list_output(expected_items, output)

        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk['url']))
        output = self.openio_admin(
            'account check %s --depth 3 %s'
            % (self.account, self.check_opts))
        self.assert_list_output(expected_items, output)

        output = self.openio_admin(
            'account check %s --depth 4 %s'
            % (self.account, self.check_opts))
        self.assert_list_output(expected_items, output)

    def test_account_check_with_checksum(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s OK'
            % (self.account, self.container, cid))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk['url']))

        # Check with checksum
        output = self.openio_admin(
            'account check %s --checksum %s'
            % (self.account, self.check_opts))
        self.assert_list_output(expected_items, output)

        # Corrupt the chunk
        corrupted_chunk = random.choice(obj_chunks)
        self.corrupt_chunk(corrupted_chunk['url'])

        # Check without checksum
        output = self.openio_admin(
            'account check %s %s'
            % (self.account, self.check_opts))
        self.assert_list_output(expected_items, output)

        expected_items.remove('chunk chunk=%s OK' % (corrupted_chunk['url']))
        expected_items.append(
            'chunk chunk=%s error' % (corrupted_chunk['url']))
        expected_items.remove(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s error'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))

        # Check with checksum
        output = self.openio_admin(
            'account check %s --checksum %s'
            % (self.account, self.check_opts), expected_returncode=1)
        self.assert_list_output(expected_items, output)

    def test_account_check_with_missing_chunk(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        missing_chunk = random.choice(obj_chunks)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s OK'
            % (self.account, self.container, cid))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s error'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            if chunk['url'] == missing_chunk['url']:
                status = 'error'
            else:
                status = 'OK'
            expected_items.append(
                'chunk chunk=%s %s' % (chunk['url'], status))

        # Delete chunk
        self.api.blob_client.chunk_delete(missing_chunk['url'])

        # Check with missing chunk
        output = self.openio_admin(
            'account check %s %s'
            % (self.account, self.check_opts), expected_returncode=1)
        self.assert_list_output(expected_items, output)

    def test_account_check_with_missing_container(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        missing_container = "item_check_missing_container_" + random_str(4)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s OK'
            % (self.account, self.container, cid))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk['url']))
        cid = cid_from_name(self.account, missing_container)
        expected_items.append(
            'container account=%s, container=%s, cid=%s error'
            % (self.account, missing_container, cid))

        # Create a container only in account service
        metadata = dict()
        metadata["mtime"] = time.time()
        metadata["bytes"] = 0
        metadata["objects"] = 0
        self.api.account.container_update(
            self.account, missing_container, metadata=metadata)

        # Check with missing container
        output = self.openio_admin(
            'account check %s %s'
            % (self.account, self.check_opts), expected_returncode=1)
        self.assert_list_output(expected_items, output)

    def test_account_check_with_missing_account(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        mising_account = "item_check_missing_account_" + random_str(4)

        expected_items = list()
        expected_items.append('account account=%s error' % mising_account)

        # Check with missing account
        output = self.openio_admin(
            'account check %s %s'
            % (mising_account, self.check_opts), expected_returncode=1)
        self.assert_list_output(expected_items, output)

        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s OK'
            % (self.account, self.container, cid))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk['url']))

        output = self.openio_admin(
            'account check %s %s %s'
            % (self.account, mising_account, self.check_opts),
            expected_returncode=1)
        self.assert_list_output(expected_items, output)

    def test_account_check_with_multiple_accounts(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        second_account = "item_check_second_account_" + random_str(4)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s OK'
            % (self.account, self.container, cid))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk['url']))

        # Create a second account
        self.api.account_create(second_account)

        # Check only the first account
        output = self.openio_admin(
            'account check %s %s'
            % (self.account, self.check_opts))
        self.assert_list_output(expected_items, output)

        # Check two accounts
        expected_items.append('account account=%s OK' % second_account)
        output = self.openio_admin(
            'account check %s %s %s'
            % (self.account, second_account, self.check_opts))
        self.assert_list_output(expected_items, output)

    def test_container_check(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s OK'
            % (self.account, self.container, cid))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk['url']))

        # Check all items
        output = self.openio_admin(
            '--oio-account %s container check %s %s'
            % (self.account, self.container, self.check_opts))
        self.assert_list_output(expected_items, output)

    def test_container_check_with_cid(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s OK'
            % (self.account, self.container, cid))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk['url']))

        # Check all items
        output = self.openio_admin(
            'container check %s --cid %s'
            % (cid, self.check_opts))
        self.assert_list_output(expected_items, output)

    def test_container_with_depth(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        expected_items = list()

        # Check part of items
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s OK'
            % (self.account, self.container, cid))
        output = self.openio_admin(
            '--oio-account %s container check %s --depth 0 %s'
            % (self.account, self.container, self.check_opts))
        self.assert_list_output(expected_items, output)

        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        output = self.openio_admin(
            '--oio-account %s container check %s --depth 1 %s'
            % (self.account, self.container, self.check_opts))
        self.assert_list_output(expected_items, output)

        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk['url']))
        output = self.openio_admin(
            '--oio-account %s container check %s --depth 2 %s'
            % (self.account, self.container, self.check_opts))
        self.assert_list_output(expected_items, output)

        output = self.openio_admin(
            '--oio-account %s container check %s --depth 3 %s'
            % (self.account, self.container, self.check_opts))
        self.assert_list_output(expected_items, output)

        output = self.openio_admin(
            '--oio-account %s container check %s --depth 4 %s'
            % (self.account, self.container, self.check_opts))
        self.assert_list_output(expected_items, output)

    def test_container_check_with_checksum(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s OK'
            % (self.account, self.container, cid))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk['url']))

        # Check with checksum
        output = self.openio_admin(
            '--oio-account %s container check %s --checksum %s'
            % (self.account, self.container, self.check_opts))
        self.assert_list_output(expected_items, output)

        # Corrupt the chunk
        corrupted_chunk = random.choice(obj_chunks)
        self.corrupt_chunk(corrupted_chunk['url'])

        # Check without checksum
        output = self.openio_admin(
            '--oio-account %s container check %s %s'
            % (self.account, self.container, self.check_opts))
        self.assert_list_output(expected_items, output)

        expected_items.remove('chunk chunk=%s OK' % (corrupted_chunk['url']))
        expected_items.append(
            'chunk chunk=%s error' % (corrupted_chunk['url']))
        expected_items.remove(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s error'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))

        # Check with checksum
        output = self.openio_admin(
            '--oio-account %s container check %s --checksum %s'
            % (self.account, self.container, self.check_opts),
            expected_returncode=1)
        self.assert_list_output(expected_items, output)

    def test_container_check_with_missing_chunk(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        missing_chunk = random.choice(obj_chunks)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s OK'
            % (self.account, self.container, cid))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s error'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            if chunk['url'] == missing_chunk['url']:
                status = 'error'
            else:
                status = 'OK'
            expected_items.append(
                'chunk chunk=%s %s' % (chunk['url'], status))

        # Delete chunk
        self.api.blob_client.chunk_delete(missing_chunk['url'])

        # Check with missing chunk
        output = self.openio_admin(
            '--oio-account %s container check %s %s'
            % (self.account, self.container, self.check_opts),
            expected_returncode=1)
        self.assert_list_output(expected_items, output)

    def test_container_check_with_missing_container(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        missing_container = "item_check_missing_container_" + random_str(4)
        cid = cid_from_name(self.account, missing_container)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s error'
            % (self.account, missing_container, cid))

        # Check with missing container
        output = self.openio_admin(
            '--oio-account %s container check %s %s'
            % (self.account, missing_container, self.check_opts),
            expected_returncode=1)
        self.assert_list_output(expected_items, output)

        # Create a container only in account service
        metadata = dict()
        metadata["mtime"] = time.time()
        metadata["bytes"] = 0
        metadata["objects"] = 0
        self.api.account.container_update(
            self.account, missing_container, metadata=metadata)

        # Check with missing container
        output = self.openio_admin(
            '--oio-account %s container check %s %s'
            % (self.account, missing_container, self.check_opts),
            expected_returncode=1)
        self.assert_list_output(expected_items, output)

        cid = cid_from_name(self.account, self.container)
        expected_items.append(
            'container account=%s, container=%s, cid=%s OK'
            % (self.account, self.container, cid))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk['url']))

        output = self.openio_admin(
            '--oio-account %s container check %s %s %s'
            % (self.account, self.container, missing_container,
               self.check_opts), expected_returncode=1)
        self.assert_list_output(expected_items, output)

    def test_container_check_with_missing_account(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        expected_items = list()
        expected_items.append('account account=%s error' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s error'
            % (self.account, self.container, cid))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk['url']))

        # Remove account
        self.api.account_flush(self.account)
        self.api.account_delete(self.account)

        # Check with missing account
        output = self.openio_admin(
            '--oio-account %s container check %s %s'
            % (self.account, self.container, self.check_opts),
            expected_returncode=1)
        self.assert_list_output(expected_items, output)

    def test_container_check_with_multiple_containers(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        second_container = "item_check_second_container_" + random_str(4)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s OK'
            % (self.account, self.container, cid))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk['url']))

        # Create a second container
        self.api.container_create(self.account, second_container)

        # Check only the first container
        output = self.openio_admin(
            '--oio-account %s container check %s %s'
            % (self.account, self.container, self.check_opts))
        self.assert_list_output(expected_items, output)

        # Check two containers
        cid = cid_from_name(self.account, second_container)
        expected_items.append(
            'container account=%s, container=%s, cid=%s OK'
            % (self.account, second_container, cid))
        output = self.openio_admin(
            '--oio-account %s container check %s %s %s'
            % (self.account, self.container, second_container,
               self.check_opts))
        self.assert_list_output(expected_items, output)

    def test_object_check(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s OK'
            % (self.account, self.container, cid))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk['url']))

        # Check all items
        output = self.openio_admin(
            '--oio-account %s object check %s %s %s'
            % (self.account, self.container, self.obj_name,
               self.check_opts))
        self.assert_list_output(expected_items, output)

    def test_object_check_with_cid(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s OK'
            % (self.account, self.container, cid))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk['url']))

        # Check all items
        output = self.openio_admin(
            'object check --cid %s %s %s'
            % (cid, self.obj_name, self.check_opts))
        self.assert_list_output(expected_items, output)

    def test_object_check_with_object_version(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s OK'
            % (self.account, self.container, cid))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk['url']))

        # Check all items
        output = self.openio_admin(
            '--oio-account %s object check %s %s --object-version %s %s'
            % (self.account, self.container, self.obj_name,
               obj_meta['version'], self.check_opts))
        self.assert_list_output(expected_items, output)

        # Enable versioning
        system = dict()
        system['sys.m2.policy.version'] = '-1'
        self.api.container_set_properties(
            self.account, self.container, system=system)

        # Create a second version of the object
        second_version_meta, second_version_chunks = self.create_object(
            self.account, self.container, self.obj_name)

        # Check first version
        output = self.openio_admin(
            '--oio-account %s object check %s %s --object-version %s %s'
            % (self.account, self.container, self.obj_name,
               obj_meta['version'], self.check_opts))
        self.assert_list_output(expected_items, output)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s OK'
            % (self.account, self.container, cid))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               second_version_meta['id'], second_version_meta['version']))
        for chunk in second_version_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk['url']))

        # Check second version
        output = self.openio_admin(
            '--oio-account %s object check %s %s --object-version %s %s'
            % (self.account, self.container, self.obj_name,
               second_version_meta['version'], self.check_opts))
        self.assert_list_output(expected_items, output)

        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk['url']))

        # Check all versions
        output = self.openio_admin(
            '--oio-account %s object check %s %s %s'
            % (self.account, self.container, self.obj_name,
               self.check_opts))
        self.assert_list_output(expected_items, output)

    def test_object_check_with_auto(self):
        self.container, obj_meta, obj_chunks = self.create_object_auto(
            self.account, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s OK'
            % (self.account, self.container, cid))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk['url']))

        # Check all items
        output = self.openio_admin(
            '--oio-account %s object check %s --auto --flat-bits %d %s'
            % (self.account, self.obj_name, self.FLAT_BITS,
               self.check_opts))
        self.assert_list_output(expected_items, output)

    def test_object_with_depth(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        expected_items = list()

        # Check part of items
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s OK'
            % (self.account, self.container, cid))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        output = self.openio_admin(
            '--oio-account %s object check %s %s --depth 0 %s'
            % (self.account, self.container, self.obj_name,
               self.check_opts))
        self.assert_list_output(expected_items, output)

        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk['url']))
        output = self.openio_admin(
            '--oio-account %s object check %s %s --depth 1 %s'
            % (self.account, self.container, self.obj_name,
               self.check_opts))
        self.assert_list_output(expected_items, output)

        output = self.openio_admin(
            '--oio-account %s object check %s %s --depth 2 %s'
            % (self.account, self.container, self.obj_name,
               self.check_opts))
        self.assert_list_output(expected_items, output)

        output = self.openio_admin(
            '--oio-account %s object check %s %s --depth 3 %s'
            % (self.account, self.container, self.obj_name,
               self.check_opts))
        self.assert_list_output(expected_items, output)

        output = self.openio_admin(
            '--oio-account %s object check %s %s --depth 4 %s'
            % (self.account, self.container, self.obj_name,
               self.check_opts))
        self.assert_list_output(expected_items, output)

    def test_object_check_with_checksum(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s OK'
            % (self.account, self.container, cid))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk['url']))

        # Check with checksum
        output = self.openio_admin(
            '--oio-account %s object check %s %s --checksum %s'
            % (self.account, self.container, self.obj_name,
               self.check_opts))
        self.assert_list_output(expected_items, output)

        # Corrupt the chunk
        corrupted_chunk = random.choice(obj_chunks)
        self.corrupt_chunk(corrupted_chunk['url'])

        # Check without checksum
        output = self.openio_admin(
            '--oio-account %s object check %s %s %s'
            % (self.account, self.container, self.obj_name,
               self.check_opts))
        self.assert_list_output(expected_items, output)

        expected_items.remove('chunk chunk=%s OK' % (corrupted_chunk['url']))
        expected_items.append(
            'chunk chunk=%s error' % (corrupted_chunk['url']))
        expected_items.remove(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s error'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))

        # Check with checksum
        output = self.openio_admin(
            '--oio-account %s object check %s %s --checksum %s'
            % (self.account, self.container, self.obj_name,
               self.check_opts), expected_returncode=1)
        self.assert_list_output(expected_items, output)

    def test_object_check_with_missing_chunk(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        missing_chunk = random.choice(obj_chunks)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s OK'
            % (self.account, self.container, cid))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s error'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            if chunk['url'] == missing_chunk['url']:
                status = 'error'
            else:
                status = 'OK'
            expected_items.append(
                'chunk chunk=%s %s' % (chunk['url'], status))

        # Delete chunk
        self.api.blob_client.chunk_delete(missing_chunk['url'])

        # Check with missing chunk
        output = self.openio_admin(
            '--oio-account %s object check %s %s %s'
            % (self.account, self.container, self.obj_name,
               self.check_opts), expected_returncode=1)
        self.assert_list_output(expected_items, output)

    def test_object_check_with_missing_object(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        missing_obj = "item_check_missing_obj_" + random_str(4)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s OK'
            % (self.account, self.container, cid))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s error'
            % (self.account, self.container, cid, missing_obj))

        # Check with missing object
        output = self.openio_admin(
            '--oio-account %s object check %s %s %s'
            % (self.account, self.container, missing_obj, self.check_opts),
            expected_returncode=1)
        self.assert_list_output(expected_items, output)

        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk['url']))

        output = self.openio_admin(
            '--oio-account %s object check %s %s %s %s'
            % (self.account, self.container, self.obj_name,
               missing_obj, self.check_opts), expected_returncode=1)
        self.assert_list_output(expected_items, output)

    def test_object_check_with_missing_container(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s error'
            % (self.account, self.container, cid))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk['url']))

        # Remove container in account service
        self.api.account_flush(self.account)

        # Check with missing container
        output = self.openio_admin(
            '--oio-account %s object check %s %s %s'
            % (self.account, self.container, self.obj_name,
               self.check_opts), expected_returncode=1)
        self.assert_list_output(expected_items, output)

    def test_object_check_with_missing_account(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        expected_items = list()
        expected_items.append('account account=%s error' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s error'
            % (self.account, self.container, cid))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk['url']))

        # Remove account
        self.api.account_flush(self.account)
        self.api.account_delete(self.account)

        # Check with missing account
        output = self.openio_admin(
            '--oio-account %s object check %s %s %s'
            % (self.account, self.container, self.obj_name,
               self.check_opts), expected_returncode=1)
        self.assert_list_output(expected_items, output)

    def test_object_check_with_multiple_objects(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        second_obj = "item_check_second_obj_" + random_str(4)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s OK'
            % (self.account, self.container, cid))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        for chunk in obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk['url']))

        # Create a second object
        second_obj_meta, second_obj_chunks = self.create_object(
            self.account, self.container, second_obj)

        # Check only the first object
        output = self.openio_admin(
            '--oio-account %s object check %s %s %s'
            % (self.account, self.container, self.obj_name,
               self.check_opts))
        self.assert_list_output(expected_items, output)

        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, second_obj,
               second_obj_meta['id'], second_obj_meta['version']))
        for chunk in second_obj_chunks:
            expected_items.append(
                'chunk chunk=%s OK' % (chunk['url']))

        # Check two objects
        output = self.openio_admin(
            '--oio-account %s object check %s %s %s %s'
            % (self.account, self.container, self.obj_name,
               second_obj, self.check_opts))
        print(expected_items)
        print(output)
        self.assert_list_output(expected_items, output)

    def test_chunk_check(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        chunk = random.choice(obj_chunks)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s OK'
            % (self.account, self.container, cid))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        expected_items.append('chunk chunk=%s OK' % (chunk['url']))

        # Check all items
        output = self.openio_admin(
            'chunk check %s %s'
            % (chunk['url'], self.check_opts))
        self.assert_list_output(expected_items, output)

    def test_chunk_check_with_checksum(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        chunk = random.choice(obj_chunks)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s OK'
            % (self.account, self.container, cid))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        expected_items.append('chunk chunk=%s OK' % (chunk['url']))

        # Check with checksum
        output = self.openio_admin(
            'chunk check %s --checksum %s'
            % (chunk['url'], self.check_opts))
        self.assert_list_output(expected_items, output)

        # Corrupt the chunk
        self.corrupt_chunk(chunk['url'])

        # Check without checksum
        output = self.openio_admin(
            'chunk check %s %s'
            % (chunk['url'], self.check_opts))
        self.assert_list_output(expected_items, output)

        expected_items.remove('chunk chunk=%s OK' % (chunk['url']))
        expected_items.append('chunk chunk=%s error' % (chunk['url']))

        # Check with checksum
        output = self.openio_admin(
            'chunk check %s --checksum %s'
            % (chunk['url'], self.check_opts), expected_returncode=1)
        self.assert_list_output(expected_items, output)

    def test_chunk_check_with_missing_chunk(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        missing_chunk = random.choice(obj_chunks)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s OK'
            % (self.account, self.container, cid))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        expected_items.append('chunk chunk=%s error' % missing_chunk['url'])

        # Prevent the events
        self._service('@event', 'stop', wait=3)

        try:
            # Delete chunk
            self.api.blob_client.chunk_delete(missing_chunk['url'])

            # Check with missing chunk
            output = self.openio_admin(
                'chunk check %s %s'
                % (missing_chunk['url'], self.check_opts),
                expected_returncode=1)
            self.assert_list_output(expected_items, output)
        finally:
            self._service('@event', 'start', wait=3)

    def test_chunk_check_with_missing_object(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        chunk = random.choice(obj_chunks)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s OK'
            % (self.account, self.container, cid))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s error'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        expected_items.append('chunk chunk=%s error' % (chunk['url']))

        # Prevent the deletion of chunks
        self._service('@event', 'stop', wait=3)

        try:
            # Delete object
            self.api.object_delete(self.account, self.container, self.obj_name)

            # Check with missing object
            output = self.openio_admin(
                'chunk check %s %s'
                % (chunk['url'], self.check_opts), expected_returncode=1)
            self.assert_list_output(expected_items, output)
        finally:
            self._service('@event', 'start', wait=3)

    def test_chunk_check_with_missing_container(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        chunk = random.choice(obj_chunks)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s error'
            % (self.account, self.container, cid))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        expected_items.append('chunk chunk=%s OK' % (chunk['url']))

        # Remove container in account service
        self.api.account_flush(self.account)

        # Check with missing container
        output = self.openio_admin(
            'chunk check %s %s'
            % (chunk['url'], self.check_opts), expected_returncode=1)
        self.assert_list_output(expected_items, output)

    def test_chunk_check_with_missing_account(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        chunk = random.choice(obj_chunks)

        expected_items = list()
        expected_items.append('account account=%s error' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s error'
            % (self.account, self.container, cid))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        expected_items.append('chunk chunk=%s OK' % (chunk['url']))
        # Remove account
        self.api.account_flush(self.account)
        self.api.account_delete(self.account)

        # Check with missing account
        output = self.openio_admin(
            'chunk check %s %s'
            % (chunk['url'], self.check_opts), expected_returncode=1)
        self.assert_list_output(expected_items, output)

    def test_chunk_check_with_multiple_objects(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        chunk = random.choice(obj_chunks)
        second_obj = "item_check_second_obj_" + random_str(4)

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s OK'
            % (self.account, self.container, cid))
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, self.obj_name,
               obj_meta['id'], obj_meta['version']))
        expected_items.append('chunk chunk=%s OK' % (chunk['url']))

        # Create a second object
        second_obj_meta, second_obj_chunks = self.create_object(
            self.account, self.container, second_obj)
        second_chunk = random.choice(second_obj_chunks)

        # Check only the first object
        output = self.openio_admin(
            'chunk check %s %s'
            % (chunk['url'], self.check_opts))
        self.assert_list_output(expected_items, output)

        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s OK'
            % (self.account, self.container, cid, second_obj,
               second_obj_meta['id'], second_obj_meta['version']))
        expected_items.append('chunk chunk=%s OK' % (second_chunk['url']))

        # Check two objects
        output = self.openio_admin(
            'chunk check %s %s %s'
            % (chunk['url'], second_chunk['url'], self.check_opts))
        self.assert_list_output(expected_items, output)
