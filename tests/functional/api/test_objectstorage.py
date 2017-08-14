# Copyright (C) 2016 OpenIO SAS

# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# You should have received a copy of the GNU Lesser General Public
# License along with this library.


import logging
from oio.api.object_storage import ObjectStorageApi
from oio.api.object_storage import _sort_chunks as sort_chunks
from oio.common import exceptions as exc
from tests.utils import random_str, random_data, BaseTestCase


class TestObjectStorageAPI(BaseTestCase):

    def setUp(self):
        super(TestObjectStorageAPI, self).setUp()
        self.api = ObjectStorageApi(self.ns, endpoint=self.uri)
        self.created = list()

    def tearDown(self):
        super(TestObjectStorageAPI, self).tearDown()
        for ct, name in self.created:
            try:
                self.api.object_delete(self.account, ct, name)
            except Exception:
                logging.exception("Failed to delete %s/%s/%s//%s",
                                  self.ns, self.account, ct, name)

    def _create(self, name, metadata=None):
        return self.api.container_create(self.account, name,
                                         properties=metadata)

    def _delete(self, name):
        self.api.container_delete(self.account, name)

    def _clean(self, name, clear=False):
        if clear:
            # must clean properties before
            self.api.container_del_properties(self.account, name, [])
        self._delete(name)

    def _get_properties(self, name, properties=None):
        return self.api.container_get_properties(
            self.account, name, properties=properties)

    def _set_properties(self, name, properties=None):
        return self.api.container_set_properties(
            self.account, name, properties=properties)

    def test_container_show(self):
        # container_show on unknown container
        name = random_str(32)
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_show, self.account, name)

        self._create(name)
        # container_show on existing container
        res = self.api.container_show(self.account, name)
        self.assertIsNot(res['properties'], None)

        self._delete(name)
        # container_show on deleted container
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_show, self.account, name)

    def test_container_create(self):
        name = random_str(32)
        res = self._create(name)
        self.assertEqual(res, True)

        # second create
        res = self._create(name)
        self.assertEqual(res, False)

        # clean
        self._delete(name)

    def test_create_properties(self):
        name = random_str(32)

        metadata = {
            random_str(32): random_str(32),
            random_str(32): random_str(32),
        }
        res = self._create(name, metadata)
        self.assertEqual(res, True)

        data = self._get_properties(name)

        self.assertEqual(data['properties'], metadata)

        # clean
        self._clean(name, True)

    def test_container_delete(self):
        name = random_str(32)

        # container_delete on unknown container
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_delete, self.account, name)

        res = self._create(name)
        self.assertEqual(res, True)
        # container_delete on existing container
        self._delete(name)

        # verify deleted
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_show, self.account, name)

        # second delete
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_delete, self.account, name)

        # verify deleted
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_show, self.account, name)

    def test_container_get_properties(self):
        name = random_str(32)

        # container_get_properties on unknown container
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_get_properties,
            self.account, name)

        res = self._create(name)
        self.assertEqual(res, True)

        # container_get_properties on existing container
        data = self.api.container_get_properties(self.account, name)
        self.assertEqual(data['properties'], {})
        self.assertIsNot(data['system'], None)
        self.assertIn("sys.user.name", data['system'])

        # container_get_properties
        metadata = {
            random_str(32): random_str(32),
            random_str(32): random_str(32),
        }
        self._set_properties(name, metadata)

        data = self.api.container_get_properties(self.account, name)
        self.assertEqual(data['properties'], metadata)

        # clean
        self._clean(name, True)

        # container_get_properties on deleted container
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_get_properties,
            self.account, name)

    def test_container_get_properties_filtered(self):
        self.skipTest("Server side properties filtering not implemented")
        name = random_str(32)

        res = self._create(name)
        self.assertEqual(res, True)

        # container_get_properties on existing container
        data = self.api.container_get_properties(self.account, name)
        self.assertEqual(data['properties'], {})

        # container_get_properties
        metadata = {
            random_str(32): random_str(32),
            random_str(32): random_str(32),
        }
        self._set_properties(name, metadata)

        # container_get_properties specify key
        key = metadata.keys().pop(0)

        data = self.api.container_get_properties(self.account, name, [key])
        self.assertEqual({key: metadata[key]}, data['properties'])

        # clean
        self._clean(name, True)

    def test_container_set_properties(self):
        name = random_str(32)

        metadata = {
            random_str(32): random_str(32),
            random_str(32): random_str(32),
        }

        # container_set_properties on unknown container
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_set_properties,
            self.account, name, metadata)

        res = self._create(name)
        self.assertEqual(res, True)

        # container_set_properties on existing container
        self.api.container_set_properties(self.account, name, metadata)
        data = self._get_properties(name)
        self.assertEqual(data['properties'], metadata)

        # container_set_properties
        key = random_str(32)
        value = random_str(32)
        metadata2 = {key: value}
        self._set_properties(name, metadata2)
        metadata.update(metadata2)

        data = self._get_properties(name)
        self.assertEqual(data['properties'], metadata)

        # container_set_properties overwrite key
        key = metadata.keys().pop(0)
        value = random_str(32)
        metadata3 = {key: value}

        metadata.update(metadata3)
        self.api.container_set_properties(self.account, name, metadata3)
        data = self._get_properties(name)
        self.assertEqual(data['properties'], metadata)

        # clean
        self._clean(name, True)

        # container_set_properties on deleted container
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_set_properties,
            self.account, name, metadata)

    def test_del_properties(self):
        name = random_str(32)

        metadata = {
            random_str(32): random_str(32),
            random_str(32): random_str(32),
        }

        # container_del_properties on unknown container
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_del_properties,
            self.account, name, [])

        res = self._create(name, metadata)
        self.assertEqual(res, True)

        key = metadata.keys().pop()
        del metadata[key]

        # container_del_properties on existing container
        self.api.container_del_properties(self.account, name, [key])
        data = self._get_properties(name)
        self.assertNotIn(key, data['properties'])

        key = random_str(32)
        # We do not check if a property exists before deleting it
        # self.assertRaises(
        #     exc.NoSuchContainer, self.api.container_del_properties,
        #     self.account, name, [key])
        self.api.container_del_properties(self.account, name, [key])

        data = self._get_properties(name)
        self.assertEqual(data['properties'], metadata)

        # clean
        self._clean(name, True)

        # container_del_properties on deleted container
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_del_properties,
            self.account, name, metadata.keys())

    def test_object_create_mime_type(self):
        name = random_str(32)
        self.api.object_create(self.account, name, data="data", obj_name=name,
                               mime_type='text/custom')
        meta, _ = self.api.object_locate(self.account, name, name)
        self.assertEqual(meta['mime_type'], 'text/custom')

    def _upload_data(self, name):
        chunksize = int(self.conf["chunk_size"])
        size = int(chunksize * 12)
        data = random_data(int(size))
        self.api.object_create(self.account, name, obj_name=name,
                               data=data)
        self.created.append((name, name))
        _, chunks = self.api.object_locate(self.account, name, name)
        logging.debug("Chunks: %s", chunks)
        return sort_chunks(chunks, False), data

    def _fetch_range(self, name, range_):
        if not isinstance(range_[0], tuple):
            ranges = (range_, )
        else:
            ranges = range_
        stream = self.api.object_fetch(
                self.account, name, name, ranges=ranges)[1]
        data = ""
        for chunk in stream:
            data += chunk
        return data

    def test_object_fetch_range_start(self):
        """From 0 to somewhere"""
        name = random_str(16)
        _, data = self._upload_data(name)
        end = 666
        fdata = self._fetch_range(name, (0, end))
        self.assertEqual(len(fdata), end+1)
        self.assertEqual(fdata, data[0:end+1])

    def test_object_fetch_range_end(self):
        """From somewhere to end"""
        name = random_str(16)
        chunks, data = self._upload_data(name)
        start = 666
        last = max(chunks.keys())
        end = chunks[last][0]['offset'] + chunks[last][0]['size']
        fdata = self._fetch_range(name, (start, end))
        self.assertEqual(len(fdata), len(data) - start)
        self.assertEqual(fdata, data[start:])

    def test_object_fetch_range_metachunk_start(self):
        """From the start of the second metachunk to somewhere"""
        name = random_str(16)
        chunks, data = self._upload_data(name)
        start = chunks[1][0]['offset']
        end = start + 666
        fdata = self._fetch_range(name, (start, end))
        self.assertEqual(len(fdata), end-start+1)
        self.assertEqual(fdata, data[start:end+1])

    def test_object_fetch_range_metachunk_end(self):
        """From somewhere to end of the first metachunk"""
        name = random_str(16)
        chunks, data = self._upload_data(name)
        start = 666
        end = chunks[0][0]['size'] - 1
        fdata = self._fetch_range(name, (start, end))
        self.assertEqual(len(fdata), end-start+1)
        self.assertEqual(fdata, data[start:end+1])

    def test_object_fetch_range_2_metachunks(self):
        """
        From somewhere in the first metachunk
        to somewhere in the second metachunk
        """
        name = random_str(16)
        chunks, data = self._upload_data(name)
        start = 666
        end = start + chunks[0][0]['size'] - 1
        fdata = self._fetch_range(name, (start, end))
        self.assertEqual(len(fdata), end-start+1)
        self.assertEqual(fdata, data[start:end+1])

    def test_object_fetch_several_ranges(self):
        """
        Download several ranges at once.
        """
        name = random_str(16)
        chunks, data = self._upload_data(name)
        start = 666
        end = start + chunks[0][0]['size'] - 1
        fdata = self._fetch_range(name, ((start, end), (end+1, end+2)))
        self.assertEqual(len(fdata), end-start+3)
        self.assertEqual(fdata, data[start:end+3])

        # Notice that we download some bytes from the second metachunk
        # before some from the first.
        fdata = self._fetch_range(
            name,
            ((chunks[0][0]['size'], chunks[0][0]['size'] + 2),
             (0, 1), (1, 2), (4, 6)))
        self.assertEqual(len(fdata), 10)
        self.assertEqual(
            fdata,
            data[chunks[0][0]['size']:chunks[0][0]['size'] + 3] +
            data[0:2] + data[1:3] + data[4:7])

    def test_object_create_then_append(self):
        """Create an object then append data"""
        name = random_str(16)
        self.api.object_create(self.account, name, data="1"*128, obj_name=name)
        _, size, _ = self.api.object_create(
            self.account, name, data="2"*128, obj_name=name, append=True)
        self.assertEqual(size, 128)
        _, data = self.api.object_fetch(self.account, name, name)
        data = "".join(data)
        self.assertEqual(len(data), 256)
        self.assertEqual(data, "1" * 128 + "2" * 128)

    def test_object_create_from_append(self):
        """Create an object with append operation"""
        name = random_str(16)
        self.api.container_create(self.account, name)
        self.api.object_create(self.account, name, data="1"*128, obj_name=name,
                               append=True)
        _, data = self.api.object_fetch(self.account, name, name)
        data = "".join(data)
        self.assertEqual(len(data), 128)
        self.assertEqual(data, "1"*128)

    def test_container_object_create_from_append(self):
        """Try to create container and object with append operation"""
        name = random_str(16)
        _chunks, size, checksum = self.api.object_create(
            self.account, name, data="1"*128, obj_name=name, append=True)
        self.assertEqual(size, 128)

        meta = self.api.object_get_properties(self.account, name, name)
        self.assertEqual(meta.get('hash', "").lower(), checksum.lower())
