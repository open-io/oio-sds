# Copyright (C) 2018 OpenIO SAS, as part of OpenIO SDS
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

from oio.api.object_storage import ObjectStorageApi
from oio.conscience.client import ConscienceClient
from oio.common.utils import cid_from_name
from oio.common.fullpath import encode_fullpath
from oio.common.constants import chunk_xattr_keys, \
    CHUNK_XATTR_CONTENT_FULLPATH_PREFIX, OIO_VERSION
from oio.blob.converter import BlobConverter
from oio.blob.utils import read_chunk_metadata
from oio.crawler.integrity import Checker, Target
from tests.utils import BaseTestCase, random_str
from tests.functional.blob import convert_to_old_chunk


class TestBlobConverter(BaseTestCase):

    def setUp(self):
        super(TestBlobConverter, self).setUp()
        self.container = random_str(16)
        self.path = random_str(16)
        self.api = ObjectStorageApi(self.ns)
        self.conscience = ConscienceClient(self.conf)

        self.api.container_create(self.account, self.container)
        _, chunks = self.api.container.content_prepare(
            self.account, self.container, self.path, 1)
        services = self.conscience.all_services('rawx')
        self.rawx_volumes = dict()
        for rawx in services:
            tags = rawx['tags']
            service_id = tags.get('tag.service_id', None)
            if service_id is None:
                service_id = rawx['addr']
            volume = tags.get('tag.vol', None)
            self.rawx_volumes[service_id] = volume

        self.api.object_create(
            self.account, self.container, obj_name=self.path, data="chunk")
        meta, self.chunks = self.api.object_locate(
            self.account, self.container, self.path)
        self.version = meta['version']
        self.content_id = meta['id']

    def _chunk_path(self, chunk):
        url = chunk['url']
        volume_id = url.split('/', 3)[2]
        chunk_id = url.split('/', 3)[3]
        volume = self.rawx_volumes[volume_id]
        return volume + '/' + chunk_id[:3] + '/' + chunk_id

    def _converter_and_check(self, chunk_volume, chunk_path,
                             chunk_id_info, expected_raw_meta=None,
                             expected_errors=0):
        conf = self.conf
        conf['volume'] = self.rawx_volumes[chunk_volume]
        converter = BlobConverter(conf)
        converter.safe_convert_chunk(chunk_path)
        self.assertEqual(1, converter.total_chunks_processed)
        self.assertEqual(1, converter.passes)
        self.assertEqual(expected_errors, converter.errors)

        checker = Checker(self.ns)
        for chunk_id, info in chunk_id_info.iteritems():
            account, container, path, version, content_id = info
            fullpath = encode_fullpath(
                account, container, path, version, content_id)
            cid = cid_from_name(account, container)
            meta, raw_meta = read_chunk_metadata(chunk_path, chunk_id)

            self.assertEqual(meta.get('chunk_id'), chunk_id)
            self.assertEqual(meta.get('container_id'), cid)
            self.assertEqual(meta.get('content_path'), path)
            self.assertEqual(meta.get('content_version'), version)
            self.assertEqual(meta.get('content_id'), content_id)
            self.assertEqual(meta.get('full_path'), fullpath)

            checker.check(Target(
                account, container=container, obj=path,
                chunk='http://' + converter.volume_id + '/' + chunk_id))
            checker.wait()
            self.assertTrue(checker.report())

            if expected_raw_meta:
                self.assertDictEqual(expected_raw_meta, raw_meta)
                continue

            self.assertNotIn(chunk_xattr_keys['chunk_id'], raw_meta)
            self.assertNotIn(chunk_xattr_keys['container_id'], raw_meta)
            self.assertNotIn(chunk_xattr_keys['content_path'], raw_meta)
            self.assertNotIn(chunk_xattr_keys['content_version'], raw_meta)
            self.assertNotIn(chunk_xattr_keys['content_id'], raw_meta)
            self.assertIn(CHUNK_XATTR_CONTENT_FULLPATH_PREFIX + chunk_id,
                          raw_meta)
            for k, v in raw_meta.iteritems():
                if k.startswith('oio:'):
                    self.fail('old fullpath always existing')
            self.assertEqual(raw_meta[chunk_xattr_keys['oio_version']],
                             OIO_VERSION)

    def test_converter(self):
        chunk = random.choice(self.chunks)
        chunk_volume = chunk['url'].split('/')[2]
        chunk_id = chunk['url'].split('/')[3]
        chunk_path = self._chunk_path(chunk)

        self._converter_and_check(
            chunk_volume, chunk_path,
            {chunk_id: (self.account, self.container, self.path, self.version,
                        self.content_id)})

    def test_converter_old_chunk(self):
        for c in self.chunks:
            convert_to_old_chunk(
                self._chunk_path(c), self.account, self.container, self.path,
                self.version, self.content_id)

        chunk = random.choice(self.chunks)
        chunk_volume = chunk['url'].split('/')[2]
        chunk_id = chunk['url'].split('/')[3]
        chunk_path = self._chunk_path(chunk)

        self._converter_and_check(
            chunk_volume, chunk_path,
            {chunk_id: (self.account, self.container, self.path, self.version,
                        self.content_id)})

    def test_converter_old_chunk_with_wrong_path(self):
        for c in self.chunks:
            convert_to_old_chunk(
                self._chunk_path(c), self.account, self.container,
                self.path + '+', self.version, self.content_id)

        chunk = random.choice(self.chunks)
        chunk_volume = chunk['url'].split('/')[2]
        chunk_id = chunk['url'].split('/')[3]
        chunk_path = self._chunk_path(chunk)

        self._converter_and_check(
            chunk_volume, chunk_path,
            {chunk_id: (self.account, self.container, self.path, self.version,
                        self.content_id)})

    def test_converter_old_chunk_with_wrong_content_id(self):
        for c in self.chunks:
            convert_to_old_chunk(
                self._chunk_path(c), self.account, self.container, self.path,
                self.version, '0123456789ABCDEF0123456789ABCDEF')

        chunk = random.choice(self.chunks)
        chunk_volume = chunk['url'].split('/')[2]
        chunk_id = chunk['url'].split('/')[3]
        chunk_path = self._chunk_path(chunk)

        self._converter_and_check(
            chunk_volume, chunk_path,
            {chunk_id: (self.account, self.container, self.path, self.version,
                        self.content_id)})

    def test_converter_old_chunk_with_old_fullpath(self):
        for c in self.chunks:
            convert_to_old_chunk(
                self._chunk_path(c), self.account, self.container, self.path,
                self.version, self.content_id, add_old_fullpath=True)

        chunk = random.choice(self.chunks)
        chunk_volume = chunk['url'].split('/')[2]
        chunk_id = chunk['url'].split('/')[3]
        chunk_path = self._chunk_path(chunk)

        self._converter_and_check(
            chunk_volume, chunk_path,
            {chunk_id: (self.account, self.container, self.path, self.version,
                        self.content_id)})

    def test_converter_old_chunk_with_old_fullpath_and_wrong_path(self):
        for c in self.chunks:
            convert_to_old_chunk(
                self._chunk_path(c), self.account, self.container,
                self.path, self.version, self.content_id,
                add_old_fullpath=True)
            convert_to_old_chunk(
                self._chunk_path(c), self.account, self.container,
                self.path + '+', self.version, self.content_id)

        chunk = random.choice(self.chunks)
        chunk_volume = chunk['url'].split('/')[2]
        chunk_id = chunk['url'].split('/')[3]
        chunk_path = self._chunk_path(chunk)

        self._converter_and_check(
            chunk_volume, chunk_path,
            {chunk_id: (self.account, self.container, self.path, self.version,
                        self.content_id)})

    def test_converter_old_chunk_with_wrong_fullpath(self):
        for c in self.chunks:
            convert_to_old_chunk(
                self._chunk_path(c), self.account, self.container,
                self.path, 'None', '0123456789ABCDEF0123456789ABCDEF',
                add_old_fullpath=True)
            convert_to_old_chunk(
                self._chunk_path(c), self.account, self.container,
                self.path, self.version, self.content_id)

        chunk = random.choice(self.chunks)
        chunk_volume = chunk['url'].split('/')[2]
        chunk_id = chunk['url'].split('/')[3]
        chunk_path = self._chunk_path(chunk)

        self._converter_and_check(
            chunk_volume, chunk_path,
            {chunk_id: (self.account, self.container, self.path, self.version,
                        self.content_id)})

    def test_converter_linked_chunk(self):
        self.api.object_link(
            self.account, self.container, self.path,
            self.account, self.container, self.path + '.link')

        linked_meta, linked_chunks = self.api.object_locate(
            self.account, self.container, self.path + '.link')
        self.assertNotEqual(self.content_id, linked_meta['id'])

        chunk = random.choice(self.chunks)
        chunk_volume = chunk['url'].split('/')[2]
        chunk_id = chunk['url'].split('/')[3]
        chunk_path = self._chunk_path(chunk)
        for c in linked_chunks:
            if chunk_volume == c['url'].split('/')[2]:
                linked_chunk_id2 = c['url'].split('/')[3]
                break

        linked_chunk = random.choice(linked_chunks)
        linked_chunk_volume = linked_chunk['url'].split('/')[2]
        linked_chunk_id = linked_chunk['url'].split('/')[3]
        linked_chunk_path = self._chunk_path(linked_chunk)
        for c in self.chunks:
            if linked_chunk_volume == c['url'].split('/')[2]:
                chunk_id2 = c['url'].split('/')[3]
                break

        self._converter_and_check(
            chunk_volume, chunk_path,
            {chunk_id: (self.account, self.container, self.path, self.version,
                        self.content_id),
             linked_chunk_id2: (self.account, self.container,
                                self.path + '.link', linked_meta['version'],
                                linked_meta['id'])})

        self._converter_and_check(
            linked_chunk_volume, linked_chunk_path,
            {chunk_id2: (self.account, self.container, self.path, self.version,
                         self.content_id),
             linked_chunk_id: (self.account, self.container,
                               self.path + '.link', linked_meta['version'],
                               linked_meta['id'])})

    def test_converter_old_linked_chunk(self):
        self.api.object_link(
            self.account, self.container, self.path,
            self.account, self.container, self.path + '.link')

        linked_meta, linked_chunks = self.api.object_locate(
            self.account, self.container, self.path + '.link')
        self.assertNotEqual(self.content_id, linked_meta['id'])

        for c in linked_chunks:
            convert_to_old_chunk(
                self._chunk_path(c), self.account, self.container,
                self.path + '.link', 'None',
                '0123456789ABCDEF0123456789ABCDEF', add_old_fullpath=True)
        for c in self.chunks:
            convert_to_old_chunk(
                self._chunk_path(c), self.account, self.container, self.path,
                self.version, self.content_id)

        chunk = random.choice(self.chunks)
        chunk_volume = chunk['url'].split('/')[2]
        chunk_id = chunk['url'].split('/')[3]
        chunk_path = self._chunk_path(chunk)
        for c in linked_chunks:
            if chunk_volume == c['url'].split('/')[2]:
                linked_chunk_id2 = c['url'].split('/')[3]
                break

        linked_chunk = random.choice(linked_chunks)
        linked_chunk_volume = linked_chunk['url'].split('/')[2]
        linked_chunk_id = linked_chunk['url'].split('/')[3]
        linked_chunk_path = self._chunk_path(linked_chunk)
        for c in self.chunks:
            if linked_chunk_volume == c['url'].split('/')[2]:
                chunk_id2 = c['url'].split('/')[3]
                break

        self._converter_and_check(
            chunk_volume, chunk_path,
            {chunk_id: (self.account, self.container, self.path, self.version,
                        self.content_id),
             linked_chunk_id2: (self.account, self.container,
                                self.path + '.link', linked_meta['version'],
                                linked_meta['id'])})

        self._converter_and_check(
            linked_chunk_volume, linked_chunk_path,
            {chunk_id2: (self.account, self.container, self.path, self.version,
                         self.content_id),
             linked_chunk_id: (self.account, self.container,
                               self.path + '.link', linked_meta['version'],
                               linked_meta['id'])})

    def test_converter_old_chunk_with_link_on_same_object(self):
        for c in self.chunks:
            convert_to_old_chunk(
                self._chunk_path(c), self.account, self.container, self.path,
                self.version, self.content_id)

        self.api.object_link(
            self.account, self.container, self.path,
            self.account, self.container, self.path)

        linked_meta, linked_chunks = self.api.object_locate(
            self.account, self.container, self.path)
        self.assertNotEqual(self.content_id, linked_meta['id'])

        linked_chunk = random.choice(linked_chunks)
        linked_chunk_volume = linked_chunk['url'].split('/')[2]
        linked_chunk_id = linked_chunk['url'].split('/')[3]
        linked_chunk_path = self._chunk_path(linked_chunk)

        # old xattr not removed
        _, expected_raw_meta = read_chunk_metadata(linked_chunk_path,
                                                   linked_chunk_id)
        expected_raw_meta[chunk_xattr_keys['oio_version']] = OIO_VERSION

        self._converter_and_check(
            linked_chunk_volume, linked_chunk_path,
            {linked_chunk_id: (self.account, self.container,
                               self.path, linked_meta['version'],
                               linked_meta['id'])},
            expected_raw_meta=expected_raw_meta, expected_errors=1)

    def test_converter_old_linked_chunk_with_link_on_same_object(self):
        self.api.object_link(
            self.account, self.container, self.path,
            self.account, self.container, self.path + '.link')

        linked_meta, linked_chunks = self.api.object_locate(
            self.account, self.container, self.path + '.link')
        self.assertNotEqual(self.content_id, linked_meta['id'])

        for c in linked_chunks:
            convert_to_old_chunk(
                self._chunk_path(c), self.account, self.container,
                self.path + '.link', 'None',
                '0123456789ABCDEF0123456789ABCDEF', add_old_fullpath=True)
        for c in self.chunks:
            convert_to_old_chunk(
                self._chunk_path(c), self.account, self.container, self.path,
                self.version, self.content_id, add_old_fullpath=True)

        self.api.object_link(
            self.account, self.container, self.path + '.link',
            self.account, self.container, self.path + '.link')

        linked_meta, linked_chunks = self.api.object_locate(
            self.account, self.container, self.path + '.link')
        self.assertNotEqual(self.content_id, linked_meta['id'])

        chunk = random.choice(self.chunks)
        chunk_volume = chunk['url'].split('/')[2]
        chunk_id = chunk['url'].split('/')[3]
        chunk_path = self._chunk_path(chunk)
        for c in linked_chunks:
            if chunk_volume == c['url'].split('/')[2]:
                linked_chunk_id2 = c['url'].split('/')[3]
                break

        linked_chunk = random.choice(linked_chunks)
        linked_chunk_volume = linked_chunk['url'].split('/')[2]
        linked_chunk_id = linked_chunk['url'].split('/')[3]
        linked_chunk_path = self._chunk_path(linked_chunk)
        for c in self.chunks:
            if linked_chunk_volume == c['url'].split('/')[2]:
                chunk_id2 = c['url'].split('/')[3]
                break

        self._converter_and_check(
            chunk_volume, chunk_path,
            {chunk_id: (self.account, self.container, self.path, self.version,
                        self.content_id),
             linked_chunk_id2: (self.account, self.container,
                                self.path + '.link', linked_meta['version'],
                                linked_meta['id'])})

        self._converter_and_check(
            linked_chunk_volume, linked_chunk_path,
            {chunk_id2: (self.account, self.container, self.path, self.version,
                         self.content_id),
             linked_chunk_id: (self.account, self.container,
                               self.path + '.link', linked_meta['version'],
                               linked_meta['id'])})

    def test_converter_with_versioning(self):
        self.api.container_set_properties(
            self.account, self.container,
            system={'sys.m2.policy.version': '2'})
        self.api.object_create(
            self.account, self.container, obj_name=self.path, data='version')

        versioned_meta, versioned_chunks = self.api.object_locate(
            self.account, self.container, self.path)
        self.assertNotEqual(self.content_id, versioned_meta['id'])

        chunk = random.choice(self.chunks)
        chunk_volume = chunk['url'].split('/')[2]
        chunk_id = chunk['url'].split('/')[3]
        chunk_path = self._chunk_path(chunk)

        versioned_chunk = random.choice(versioned_chunks)
        versioned_chunk_volume = versioned_chunk['url'].split('/')[2]
        versioned_chunk_id = versioned_chunk['url'].split('/')[3]
        versioned_chunk_path = self._chunk_path(versioned_chunk)

        self._converter_and_check(
            chunk_volume, chunk_path,
            {chunk_id: (self.account, self.container, self.path, self.version,
                        self.content_id)})

        self._converter_and_check(
            versioned_chunk_volume, versioned_chunk_path,
            {versioned_chunk_id: (self.account, self.container, self.path,
                                  versioned_meta['version'],
                                  versioned_meta['id'])})

    def test_converter_old_chunk_with_versioning(self):
        for c in self.chunks:
            convert_to_old_chunk(
                self._chunk_path(c), self.account, self.container, self.path,
                self.version, self.content_id)

        self.api.container_set_properties(
            self.account, self.container,
            system={'sys.m2.policy.version': '2'})
        self.api.object_create(
            self.account, self.container, obj_name=self.path, data='version')

        versioned_meta, versioned_chunks = self.api.object_locate(
            self.account, self.container, self.path)
        self.assertNotEqual(self.content_id, versioned_meta['id'])
        for c in versioned_chunks:
            convert_to_old_chunk(
                self._chunk_path(c), self.account, self.container, self.path,
                versioned_meta['version'], versioned_meta['id'])

        chunk = random.choice(self.chunks)
        chunk_volume = chunk['url'].split('/')[2]
        chunk_id = chunk['url'].split('/')[3]
        chunk_path = self._chunk_path(chunk)

        versioned_chunk = random.choice(versioned_chunks)
        versioned_chunk_volume = versioned_chunk['url'].split('/')[2]
        versioned_chunk_id = versioned_chunk['url'].split('/')[3]
        versioned_chunk_path = self._chunk_path(versioned_chunk)

        self._converter_and_check(
            chunk_volume, chunk_path,
            {chunk_id: (self.account, self.container, self.path, self.version,
                        self.content_id)})

        self._converter_and_check(
            versioned_chunk_volume, versioned_chunk_path,
            {versioned_chunk_id: (self.account, self.container, self.path,
                                  versioned_meta['version'],
                                  versioned_meta['id'])})
