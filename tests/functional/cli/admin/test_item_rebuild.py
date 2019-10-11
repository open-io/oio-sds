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
from tempfile import mkstemp

from oio import ObjectStorageApi
from oio.common.storage_method import STORAGE_METHODS
from oio.common.utils import cid_from_name
from oio.event.evob import EventTypes
from tests.functional.cli import CliTestCase
from tests.utils import random_str


class ItemRebuildTest(CliTestCase):
    """Functionnal tests for item to rebuild."""

    @classmethod
    def setUpClass(cls):
        super(ItemRebuildTest, cls).setUpClass()
        cls.api = ObjectStorageApi(cls._cls_ns, endpoint=cls._cls_uri)

    def setUp(self):
        super(ItemRebuildTest, self).setUp()
        self.rawx_services = None

        self.container = "item_rebuild_container" + random_str(4)
        self.obj_name = "item_rebuild_obj_" + random_str(4)

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
            account, container, obj_name=obj_name, data='test_item_rebuild')
        obj_meta, obj_chunks = self.api.object_locate(
            account, container, obj_name)
        self._wait_events(account, container, obj_name)
        return obj_meta, obj_chunks

    def test_chunk_rebuild(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name)
        cid = cid_from_name(self.account, self.container)

        stg_met = STORAGE_METHODS.load(obj_meta['chunk_method'])
        if stg_met.expected_chunks <= stg_met.min_chunks_to_read:
            self.skipTest('')

        expected_items = list()
        expected_items.append('account account=%s OK' % self.account)
        expected_items.append(
            'container account=%s, container=%s, cid=%s OK'
            % (self.account, self.container, cid))

        # Delete first chunk
        missing_chunk = random.choice(obj_chunks)
        self.api.blob_client.chunk_delete(missing_chunk['url'])
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

        second_obj = "item_rebuild_second_obj_" + random_str(4)
        second_obj_meta, second_obj_chunks = self.create_object(
            self.account, self.container, second_obj)

        # Delete first chunk
        second_missing_chunk = random.choice(second_obj_chunks)
        self.api.blob_client.chunk_delete(second_missing_chunk['url'])
        expected_items.append(
            'object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, '
            'version=%s error'
            % (self.account, self.container, cid, second_obj,
               second_obj_meta['id'], second_obj_meta['version']))
        for chunk in second_obj_chunks:
            if chunk['url'] == second_missing_chunk['url']:
                status = 'error'
            else:
                status = 'OK'
            expected_items.append(
                'chunk chunk=%s %s' % (chunk['url'], status))

        # Check with missing chunks
        _, chunks_to_repair_file = mkstemp()
        opts = self.get_opts(['Type', 'Item', 'Status'])
        output = self.openio_admin(
            '--oio-account %s container check %s '
            '--output-for-chunk-rebuild "%s" %s'
            % (self.account, self.container, chunks_to_repair_file, opts),
            expected_returncode=1)
        self.assert_list_output(expected_items, output)

        expected_items = list()
        expected_items.append(
            '%s|%s|%s|%s OK' % (
                self.ns, cid, obj_meta['id'],
                missing_chunk['url']))
        expected_items.append(
            '%s|%s|%s|%s OK' % (
                self.ns, cid, second_obj_meta['id'],
                second_missing_chunk['url']))

        # Rebuild missing chunks
        opts = self.get_opts(['Chunk', 'Status'])
        output = self.openio_admin(
            '--oio-account %s chunk rebuild --input-file "%s" %s'
            % (self.account, chunks_to_repair_file, opts))
        self.assert_list_output(expected_items, output)
