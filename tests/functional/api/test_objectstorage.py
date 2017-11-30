# Copyright (C) 2016-2017 OpenIO SAS, as part of OpenIO SDS
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


import logging
import time
from oio.api.object_storage import ObjectStorageApi
from oio.common.constants import CHUNK_HEADERS
from oio.common.http_urllib3 import get_pool_manager
from oio.common.storage_functions import _sort_chunks as sort_chunks
from oio.common import exceptions as exc
from tests.utils import random_str, random_data, BaseTestCase


class ObjectStorageApiTestBase(BaseTestCase):

    def setUp(self):
        super(ObjectStorageApiTestBase, self).setUp()
        self.api = ObjectStorageApi(self.ns, endpoint=self.uri)
        self.created = list()

    def tearDown(self):
        super(ObjectStorageApiTestBase, self).tearDown()
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

    def _upload_empty(self, container, *objs, **kwargs):
        """Upload empty objects to `container`"""
        for obj in objs:
            self.api.object_create(self.account, container,
                                   obj_name=obj, data="", **kwargs)
            self.created.append((container, obj))


class TestObjectStorageApi(ObjectStorageApiTestBase):

    def test_container_show(self):
        # container_show on unknown container
        name = random_str(32)
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_show, self.account, name)

        self._create(name)
        # container_show on existing container
        res = self.api.container_show(self.account, name,
                                      headers={'X-oio-req-id': 'Salut!'})
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

    def test_container_create_many(self):
        containers = [random_str(8) for _ in range(8)]
        props = {'a': 'a'}
        res = self.api.container_create_many(self.account, containers,
                                             properties=props)
        for container in containers:
            self.assertIn(container, [x[0] for x in res])
        for container in res:
            self.assertTrue(container[1])
        props_gotten = self.api.container_get_properties(
            self.account, containers[0])
        self.assertDictEqual(props, props_gotten['properties'])
        for container in containers:
            self.api.container_delete(self.account, container)

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

    def test_container_refresh(self):
        account = random_str(32)
        # container_refresh on unknown container
        name = random_str(32)
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_refresh, account, name)

        self.api.container_create(account, name)
        time.sleep(0.5)  # ensure container event have been processed
        # container_refresh on existing container
        self.api.container_refresh(account, name)
        time.sleep(0.5)  # ensure container event have been processed
        res = self.api.container_list(account, prefix=name)
        name_container, nb_objects, nb_bytes, _ = res[0]
        self.assertEqual(name_container, name)
        self.assertEqual(nb_objects, 0)
        self.assertEqual(nb_bytes, 0)

        self.api.object_create(account, name, data="data", obj_name=name)
        time.sleep(0.5)  # ensure container event have been processed
        # container_refresh on existing container with data
        self.api.container_refresh(account, name)
        time.sleep(0.5)  # ensure container event have been processed
        res = self.api.container_list(account, prefix=name)
        name_container, nb_objects, nb_bytes, _ = res[0]
        self.assertEqual(name_container, name)
        self.assertEqual(nb_objects, 1)
        self.assertEqual(nb_bytes, 4)

        self.api.object_delete(account, name, name)
        time.sleep(0.5)  # ensure container event have been processed
        self.api.container_delete(account, name)
        time.sleep(0.5)  # ensure container event have been processed
        # container_refresh on deleted container
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_refresh, account, name)

        self.api.account_delete(account)

    def test_container_refresh_user_not_found(self):
        name = random_str(32)
        self.api.account.container_update(name, name, {"mtime": time.time()})
        self.api.container_refresh(name, name)
        containers = self.api.container_list(name)
        self.assertEqual(len(containers), 0)
        self.api.account_delete(name)

    def test_account_refresh(self):
        # account_refresh on unknown account
        account = random_str(32)
        self.assertRaises(
            exc.NoSuchAccount, self.api.account_refresh, account)

        # account_refresh on existing account
        self.api.account_create(account)
        self.api.account_refresh(account)
        time.sleep(0.5)  # ensure container event have been processed
        res = self.api.account_show(account)
        self.assertEqual(res["bytes"], 0)
        self.assertEqual(res["objects"], 0)
        self.assertEqual(res["containers"], 0)

        name = random_str(32)
        self.api.object_create(account, name, data="data", obj_name=name)
        time.sleep(0.5)  # ensure container event have been processed
        self.api.account_refresh(account)
        time.sleep(0.5)  # ensure container event have been processed
        res = self.api.account_show(account)
        self.assertEqual(res["bytes"], 4)
        self.assertEqual(res["objects"], 1)
        self.assertEqual(res["containers"], 1)

        self.api.object_delete(account, name, name)
        time.sleep(0.5)  # ensure container event have been processed
        self.api.container_delete(account, name)
        time.sleep(0.5)  # ensure container event have been processed
        self.api.account_delete(account)
        # account_refresh on deleted account
        self.assertRaises(
            exc.NoSuchAccount, self.api.account_refresh, account)

    def test_account_refresh_all(self):
        # clear accounts
        accounts = self.api.account_list()
        for account in accounts:
            try:
                self.api.account_flush(account)
                self.api.account_delete(account)
            except exc.NoSuchAccount:  # account remove in the meantime
                pass

        # With 0 account
        self.api.account_refresh()

        # With 2 accounts
        account1 = random_str(32)
        self.api.account_create(account1)
        account2 = random_str(32)
        self.api.account_create(account2)
        self.api.account_refresh()
        res = self.api.account_show(account1)
        self.assertEqual(res["bytes"], 0)
        self.assertEqual(res["objects"], 0)
        self.assertEqual(res["containers"], 0)
        res = self.api.account_show(account2)
        self.assertEqual(res["bytes"], 0)
        self.assertEqual(res["objects"], 0)
        self.assertEqual(res["containers"], 0)

        self.api.account_delete(account1)
        self.api.account_delete(account2)

    def test_account_flush(self):
        # account_flush on unknown account
        account = random_str(32)
        self.assertRaises(
            exc.NoSuchAccount, self.api.account_flush, account)

        # account_flush on existing account
        name1 = random_str(32)
        self.api.container_create(account, name1)
        name2 = random_str(32)
        self.api.container_create(account, name2)
        time.sleep(0.5)  # ensure container event have been processed
        self.api.account_flush(account)
        containers = self.api.container_list(account)
        self.assertEqual(len(containers), 0)
        res = self.api.account_show(account)
        self.assertEqual(res["bytes"], 0)
        self.assertEqual(res["objects"], 0)
        self.assertEqual(res["containers"], 0)

        self.api.container_delete(account, name1)
        self.api.container_delete(account, name2)
        time.sleep(0.5)  # ensure container event have been processed
        self.api.account_delete(account)

        # account_flush on deleted account
        self.assertRaises(
            exc.NoSuchAccount, self.api.account_flush, account)

    def test_object_create_then_truncate(self):
        """Create an object then truncate data"""
        name = random_str(16)
        self.api.object_create(self.account, name, data="1"*128, obj_name=name)
        self.api.object_truncate(self.account, name, name, size=64)
        _, data = self.api.object_fetch(self.account, name, name)
        data = "".join(data)
        self.assertEqual(len(data), 64)
        self.assertEqual(data, "1" * 64)

    def test_object_create_append_then_truncate(self):
        """Create an object, append data then truncate on chunk boundary"""
        name = random_str(16)
        self.api.object_create(self.account, name, data="1"*128, obj_name=name)
        _, size, _ = self.api.object_create(
            self.account, name, data="2"*128, obj_name=name, append=True)
        self.assertEqual(size, 128)

        self.api.object_truncate(self.account, name, name, size=128)
        _, data = self.api.object_fetch(self.account, name, name)
        data = "".join(data)
        self.assertEqual(len(data), 128)
        self.assertEqual(data, "1" * 128)

        self.api.object_truncate(self.account, name, name, size=128)

    def test_object_create_then_invalid_truncate(self):
        """Create an object, append data then try to truncate outside object
           range"""
        name = random_str(16)
        self.api.object_create(self.account, name, data="1"*128, obj_name=name)
        self.assertRaises(
            exc.OioException, self.api.object_truncate, self.account, name,
            name, size=-1)
        self.assertRaises(
            exc.OioException, self.api.object_truncate, self.account, name,
            name, size=129)

    def test_object_delete_many(self):
        container = random_str(8)
        objects = ["obj%d" % i for i in range(8)]
        for obj in objects:
            self.api.object_create(self.account, container,
                                   obj_name=obj, data=obj)
        res = self.api.object_delete_many(self.account, container, objects)
        self.assertEqual(len(objects), len(res))
        for obj in objects:
            self.assertIn(obj, [x[0] for x in res])
        for obj in res:
            self.assertTrue(obj[1])

        res = self.api.object_delete_many(self.account, container, ["dahu"])
        self.assertFalse(res[0][1])

    def test_container_snapshot(self):
        name = random_str(16)
        self.api.container_create(self.account, name)
        test_object = "test_object"
        self.api.object_create(self.account, name, data="0"*128,
                               obj_name=test_object)
        # Snapshot cannot have same name and same account
        self.assertRaises(exc.ClientException,
                          self.api.container_snapshot,
                          self.account, name, self.account, name)
        snapshot_name = random_str(16)
        self.assertNotEqual(snapshot_name, name)
        # Non existing snapshot should work
        self.api.container_snapshot(self.account, name, self.account,
                                    snapshot_name)
        # Already taken snapshot name should failed
        self.assertRaises(exc.ClientException,
                          self.api.container_snapshot,
                          self.account, name, self.account, snapshot_name)
        # Check Container Frozen so create should failed
        self.assertRaises(exc.ServiceBusy,
                          self.api.object_create,
                          self.account, snapshot_name,
                          data="1"*128,
                          obj_name="should_not_be_created")

        # fullpath is set on every chunk
        chunk_list = self.api.object_locate(self.account, name, test_object)[1]
        # check that every chunk is different from the target
        snapshot_list = self.api.object_locate(self.account, snapshot_name,
                                               test_object)[1]

        for c, t in zip(chunk_list, snapshot_list):
            self.assertNotEqual(c['url'], t['url'])
        # check target can be used
        self.api.object_create(self.account, name, data="0"*128,
                               obj_name="should_be_created")
        # Generate hard links of each chunk of the object
        url_list = [c['url'] for c in chunk_list]
        copy_list = self.api._generate_copies(url_list)
        # every chunks should have the fullpath
        fullpath = self.api._generate_fullpath(
            self.account, snapshot_name, 'copy', 12456)
        self.api._link_chunks(url_list, copy_list, fullpath[0])
        # check that every copy exists
        pool_manager = get_pool_manager()
        for copy in copy_list:
            resp = pool_manager.request('HEAD', copy)
            self.assertEqual(resp.status, 200)
            self.assertIn(fullpath[0],
                          resp.headers[CHUNK_HEADERS['full_path']].split(','))
        # Snapshot on non existing container should failed
        self.assertRaises(exc.NoSuchContainer,
                          self.api.container_snapshot,
                          random_str(16), random_str(16),
                          random_str(16), random_str(16))
        # Snapshot need to have a account
        self.assertRaises(exc.ClientException,
                          self.api.container_snapshot,
                          self.account, name, None, random_str(16))
        # Snapshot need to have a name
        self.assertRaises(exc.ClientException,
                          self.api.container_snapshot,
                          self.account, name, random_str(16), None)

    def test_object_create_long_name(self):
        """Create an objet whose name has the maximum length allowed"""
        cname = random_str(16)
        path = random_str(1023)
        self.api.object_create(self.account, cname,
                               data="1"*128, obj_name=path)


class TestObjectList(ObjectStorageApiTestBase):

    def setUp(self):
        super(TestObjectList, self).setUp()
        self.cname = random_str(16)

    def tearDown(self):
        super(TestObjectList, self).tearDown()

    def _upload_empty(self, *objs, **kwargs):
        super(TestObjectList, self)._upload_empty(self.cname, *objs, **kwargs)

    def test_object_list(self):
        objects = ['a', 'b', 'c']
        self._upload_empty(*objects)
        res = self.api.object_list(self.account, self.cname)
        self.assertIn('objects', res)
        self.assertIn('prefixes', res)
        self.assertIn('truncated', res)
        self.assertListEqual(objects, [x['name'] for x in res['objects']])
        self.assertFalse(res['prefixes'])
        self.assertFalse(res['truncated'])

    def test_object_list_limit(self):
        objects = ['a', 'b', 'c']
        self._upload_empty(*objects)
        res = self.api.object_list(self.account, self.cname, limit=2)
        self.assertIn('objects', res)
        self.assertIn('prefixes', res)
        self.assertIn('truncated', res)
        self.assertIn('next_marker', res)
        self.assertListEqual(objects[:2], [x['name'] for x in res['objects']])
        self.assertFalse(res['prefixes'])
        self.assertTrue(res['truncated'])

        res = self.api.object_list(self.account, self.cname, limit=2,
                                   marker=res['next_marker'])
        self.assertIn('objects', res)
        self.assertIn('prefixes', res)
        self.assertIn('truncated', res)
        self.assertListEqual(objects[2:], [x['name'] for x in res['objects']])
        self.assertFalse(res['prefixes'])
        self.assertFalse(res['truncated'])

    def test_object_list_marker(self):
        objects = ['a', 'b', 'c']
        self._upload_empty(*objects)
        res = self.api.object_list(self.account, self.cname, marker='a')
        self.assertIn('objects', res)
        self.assertIn('prefixes', res)
        self.assertIn('truncated', res)
        self.assertListEqual(objects[1:], [x['name'] for x in res['objects']])
        self.assertFalse(res['prefixes'])
        self.assertFalse(res['truncated'])

    def test_object_list_delimiter(self):
        objects = ['1/a', '1/b', '2/c']
        self._upload_empty(*objects)
        res = self.api.object_list(self.account, self.cname, delimiter='/')
        self.assertIn('objects', res)
        self.assertIn('prefixes', res)
        self.assertIn('truncated', res)
        self.assertFalse(res['objects'])
        self.assertListEqual(['1/', '2/'], res['prefixes'])
        self.assertFalse(res['truncated'])

        self._upload_empty('a')
        res = self.api.object_list(self.account, self.cname, delimiter='/')
        self.assertIn('objects', res)
        self.assertIn('prefixes', res)
        self.assertIn('truncated', res)
        self.assertListEqual(['a'], [x['name'] for x in res['objects']])
        self.assertListEqual(['1/', '2/'], res['prefixes'])
        self.assertFalse(res['truncated'])

    def test_object_list_delimiter_limit_marker(self):
        objects = ['1/a', '1/b', '1/c', '2/d', '2/e']
        self._upload_empty(*objects)
        res = self.api.object_list(self.account, self.cname,
                                   delimiter='/', limit=1)
        self.assertIn('objects', res)
        self.assertIn('prefixes', res)
        self.assertIn('truncated', res)
        self.assertFalse(res['objects'])
        self.assertListEqual(['1/'], res['prefixes'])
        self.assertTrue(res['truncated'])

        res = self.api.object_list(self.account, self.cname,
                                   delimiter='/', limit=1,
                                   marker=res['next_marker'])
        self.assertIn('objects', res)
        self.assertIn('prefixes', res)
        self.assertIn('truncated', res)
        self.assertFalse(res['objects'])
        self.assertListEqual(['2/'], res['prefixes'])

        res = self.api.object_list(self.account, self.cname,
                                   delimiter='/', limit=1,
                                   marker='1/')
        self.assertIn('objects', res)
        self.assertIn('prefixes', res)
        self.assertIn('truncated', res)
        self.assertFalse(res['objects'])
        self.assertListEqual(['2/'], res['prefixes'])
