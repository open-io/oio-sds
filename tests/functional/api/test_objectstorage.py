# Copyright (C) 2016-2020 OpenIO SAS, as part of OpenIO SDS
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


import copy
import logging
import random
import time
from mock import MagicMock as Mock, patch
from functools import partial
from urllib3 import HTTPResponse
from oio.api.object_storage import ObjectStorageApi
from oio.common import exceptions as exc
from oio.common.constants import REQID_HEADER
from oio.common.http_eventlet import CustomHTTPResponse
from oio.common.storage_functions import _sort_chunks as sort_chunks
from oio.common.utils import cid_from_name, request_id, depaginate
from oio.common.fullpath import encode_fullpath
from oio.common.storage_method import STORAGE_METHODS, EC_SEGMENT_SIZE
from oio.event.evob import EventTypes
from tests.utils import random_str, random_data, random_id, BaseTestCase


class ObjectStorageApiTestBase(BaseTestCase):

    @classmethod
    def setUpClass(cls):
        super(ObjectStorageApiTestBase, cls).setUpClass()
        cls._cls_reload_meta()

    def setUp(self):
        super(ObjectStorageApiTestBase, self).setUp()
        self.api = ObjectStorageApi(self.ns, endpoint=self.uri)
        self.created = list()
        self.beanstalkd0.drain_tube('oio-preserved')

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


class UnreliableResponse(CustomHTTPResponse):
    """
    The first instance of this class will raise an exception after
    a predefined number of calls to its read() method. Other instances
    will behave like normal instances of CustomHTTPResponse.
    """

    inst_count = 0

    @classmethod
    def reset_instance_count(cls):
        cls.inst_count = 0

    def __init__(self, *args, **kwargs):
        CustomHTTPResponse.__init__(self, *args, **kwargs)
        self._read_count = 0
        self._limit_reads = self.__class__.inst_count == 0
        self.__class__.inst_count += 1

    def read(self, amount=None):
        if self._limit_reads:
            if self._read_count > 2:
                raise IOError('Failed to read more data')
            elif self._read_count > 1:
                # Short read
                if amount:
                    amount -= 3
                else:
                    amount = 1
        res = CustomHTTPResponse.read(self, amount=amount)
        self._read_count += 1
        return res


class TestObjectStorageApi(ObjectStorageApiTestBase):

    def test_container_show(self):
        # container_show on unknown container
        name = random_str(32)
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_show, self.account, name)

        self._create(name)
        # container_show on existing container
        res = self.api.container_show(self.account, name,
                                      headers={REQID_HEADER: 'Salut!'})
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

    def test_container_create_invalid_name(self):
        # Ah, those latin1 users!
        name = (u"Beno\xeet-" + random_str(8)).encode('latin1')
        self.assertRaises(exc.ClientException, self._create, name)

    def test_create_properties(self):
        name = random_str(32)

        metadata = {
            random_str(32): random_str(32),
            random_str(32): random_str(32),
        }
        res = self._create(name, metadata)
        self.assertEqual(res, True)

        data = self._get_properties(name)

        self.assertDictEqual(data['properties'], metadata)

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

    def test_container_autocreate_properties(self):
        cname = random_str(16)
        path = random_str(8)
        props = {'properties': {'is_admin': 'false'},
                 'system': {'sys.m2.bucket.name': cname}}
        self.api.object_create(self.account, cname,
                               data=b'1'*128, obj_name=path,
                               container_properties=props)
        data = self._get_properties(cname)
        self.assertEqual(cname, data['system'].get('sys.m2.bucket.name'))
        self.assertEqual('false', data['properties'].get('is_admin'))

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
        self.assertDictEqual(data['properties'], metadata)

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
        key = random.choice(list(metadata.keys()))

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
        event_url = {
            'ns': self.ns,
            'account': self.account,
            'user': name,
            'id': cid_from_name(self.account, name)
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
        self.assertDictEqual(data['properties'], metadata)
        event = self.wait_for_event(
            'oio-preserved', types=[EventTypes.CONTAINER_UPDATE])
        self.assertDictEqual(event_url, event.url)
        self.assertDictEqual({}, event.data['system'])
        self.assertDictEqual(metadata, event.data['properties'])

        # container_set_properties
        key = random_str(32)
        value = random_str(32)
        metadata2 = {key: value}
        self._set_properties(name, metadata2)
        metadata.update(metadata2)
        data = self._get_properties(name)
        self.assertDictEqual(data['properties'], metadata)
        event = self.wait_for_event(
            'oio-preserved', types=[EventTypes.CONTAINER_UPDATE])
        self.assertDictEqual(event_url, event.url)
        self.assertDictEqual({}, event.data['system'])
        self.assertDictEqual(metadata2, event.data['properties'])

        # container_set_properties overwrite key
        key = random.choice(list(metadata.keys()))
        value = random_str(32)
        metadata3 = {key: value}
        metadata.update(metadata3)
        self.api.container_set_properties(self.account, name, metadata3)
        data = self._get_properties(name)
        self.assertDictEqual(data['properties'], metadata)
        event = self.wait_for_event(
            'oio-preserved', types=[EventTypes.CONTAINER_UPDATE])
        self.assertDictEqual(event_url, event.url)
        self.assertDictEqual({}, event.data['system'])
        self.assertDictEqual(metadata3, event.data['properties'])

        # container_set_properties and clear old keys
        key = random.choice(list(metadata.keys()))
        value = random_str(32)
        event_properties = {key: None for key in metadata}
        metadata = {key: value}
        event_properties.update(metadata)
        self.api.container_set_properties(self.account, name, metadata,
                                          clear=True)
        data = self._get_properties(name)
        self.assertDictEqual(data['properties'], metadata)
        event = self.wait_for_event(
            'oio-preserved', types=[EventTypes.CONTAINER_UPDATE])
        self.assertDictEqual(event_url, event.url)
        self.assertDictEqual({}, event.data['system'])
        self.assertDictEqual(event_properties, event.data['properties'])

        # clean
        self._clean(name, True)

        # container_set_properties on deleted container
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_set_properties,
            self.account, name, metadata)

    def test_container_del_set_same_property(self):
        name = random_str(32)

        metadata = {
            random_str(32): random_str(32),
            random_str(32): random_str(32)
        }
        event_url = {
            'ns': self.ns,
            'account': self.account,
            'user': name,
            'id': cid_from_name(self.account, name)
        }

        res = self._create(name)
        self.assertEqual(res, True)

        # container_set_properties properties
        self.api.container_set_properties(self.account, name, metadata)
        data = self._get_properties(name)
        self.assertDictEqual(data['properties'], metadata)
        event = self.wait_for_event(
            'oio-preserved', types=[EventTypes.CONTAINER_UPDATE])
        self.assertDictEqual(event_url, event.url)
        self.assertDictEqual({}, event.data['system'])
        self.assertDictEqual(metadata, event.data['properties'])

        # container_del_properties a property
        _metadata = metadata.copy()
        key, _ = _metadata.popitem()
        self.api.container_del_properties(self.account, name, [key])
        data = self._get_properties(name)
        self.assertDictEqual(data['properties'], _metadata)
        event = self.wait_for_event(
            'oio-preserved', types=[EventTypes.CONTAINER_UPDATE])
        self.assertDictEqual(event_url, event.url)
        self.assertDictEqual({}, event.data['system'])
        self.assertDictEqual({key: None}, event.data['properties'])

        # container_set_properties the same property with the same value
        _metadata = {key: metadata[key]}
        self.api.container_set_properties(self.account, name, _metadata)
        data = self._get_properties(name)
        self.assertDictEqual(data['properties'], metadata)
        event = self.wait_for_event(
            'oio-preserved', types=[EventTypes.CONTAINER_UPDATE])
        self.assertDictEqual(event_url, event.url)
        self.assertDictEqual({}, event.data['system'])
        self.assertDictEqual(_metadata, event.data['properties'])

    def _flush_and_check(self, cname, fast=False):
        self.api.container_flush(self.account, cname, limit=50)
        self.wait_for_score(('account', 'meta2'))
        properties = self.api.container_get_properties(self.account, cname)
        self.assertEqual(properties['system']['sys.m2.objects'], '0')
        self.assertEqual(properties['system']['sys.m2.usage'], '0')
        all_objects = self.api.object_list(self.account, cname)
        self.assertEqual(0, len(all_objects['objects']))
        self.beanstalkd0.drain_buried('oio')

    # These tests are numbered to force them to be run in order
    def test_container_flush_0_no_container(self):
        name = random_str(16)
        self.assertRaises(exc.NoSuchContainer,
                          self.api.container_flush, self.account, name)

    def test_container_flush_0_no_container_fast(self):
        name = random_str(16)
        self.assertRaises(exc.NoSuchContainer,
                          self.api.container_flush, self.account, name, True)

    def test_container_flush_1_empty_container(self):
        name = random_str(16)
        self.api.container_create(self.account, name)
        self._flush_and_check(name)

    def test_container_flush_1_empty_container_fast(self):
        name = random_str(16)
        self.api.container_create(self.account, name)
        self._flush_and_check(name, fast=True)

    def test_container_flush_1_object(self):
        name = random_str(16)
        self.api.object_create(self.account, name, obj_name='content',
                               data='data')
        self._flush_and_check(name)

    def test_container_flush_1_object_fast(self):
        name = random_str(16)
        self.api.object_create(self.account, name, obj_name='content',
                               data='data')
        self._flush_and_check(name, fast=True)

    def test_container_flush_2_many_objects(self):
        name = random_str(16)

        # many contents (must be more than the listing limit)
        for i in range(128):
            self.api.object_create(self.account, name,
                                   obj_name='content'+str(i), data='data',
                                   chunk_checksum_algo=None)
        self._flush_and_check(name)

    def test_container_flush_2_many_objects_fast(self):
        name = random_str(16)

        # many contents (must be more than the listing limit)
        for i in range(128):
            self.api.object_create(self.account, name,
                                   obj_name='content'+str(i), data='data',
                                   chunk_checksum_algo=None)
        self._flush_and_check(name, fast=True)

    def test_container_del_properties(self):
        name = random_str(32)

        metadata = {
            random_str(32): random_str(32),
            random_str(32): random_str(32),
            random_str(32): random_str(32),
            random_str(32): random_str(32),
            random_str(32): random_str(32),
        }
        event_url = {
            'ns': self.ns,
            'account': self.account,
            'user': name,
            'id': cid_from_name(self.account, name)
        }

        # container_del_properties on unknown container
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_del_properties,
            self.account, name, [])

        res = self._create(name, metadata)
        self.assertEqual(res, True)
        event = self.wait_for_event(
            'oio-preserved', types=[EventTypes.CONTAINER_NEW])
        self.assertDictEqual(event_url, event.url)
        self.assertDictEqual({}, event.data['system'])
        self.assertDictEqual(metadata, event.data['properties'])

        key, _ = metadata.popitem()

        # container_del_properties on existing container
        self.api.container_del_properties(self.account, name, [key])
        data = self._get_properties(name)
        self.assertNotIn(key, data['properties'])
        event = self.wait_for_event(
            'oio-preserved', types=[EventTypes.CONTAINER_UPDATE])
        self.assertDictEqual(event_url, event.url)
        self.assertDictEqual({}, event.data['system'])
        self.assertDictEqual({key: None}, event.data['properties'])

        key = random_str(32)
        # We do not check if a property exists before deleting it
        # self.assertRaises(
        #     exc.NoSuchContainer, self.api.container_del_properties,
        #     self.account, name, [key])
        self.api.container_del_properties(self.account, name, [key])
        data = self._get_properties(name)
        self.assertDictEqual(data['properties'], metadata)
        event = self.wait_for_event(
            'oio-preserved', types=[EventTypes.CONTAINER_UPDATE])
        self.assertDictEqual(event_url, event.url)
        self.assertDictEqual({}, event.data['system'])
        self.assertDictEqual({key: None}, event.data['properties'])

        # Delete all container properties
        self.api.container_del_properties(self.account, name, [])
        data = self._get_properties(name)
        self.assertDictEqual({}, data['properties'])
        event = self.wait_for_event(
            'oio-preserved', types=[EventTypes.CONTAINER_UPDATE])
        self.assertDictEqual(event_url, event.url)
        self.assertDictEqual({}, event.data['system'])
        self.assertDictEqual({key: None for key in metadata},
                             event.data['properties'])

        # clean
        self._clean(name, True)

        # container_del_properties on deleted container
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_del_properties,
            self.account, name, list(metadata.keys()))

    def test_container_touch(self):
        name = random_str(32)

        self._create(name)
        for i in range(10):
            reqid = 'content' + name + str(i)
            self.api.object_create(
                self.account, name, obj_name=reqid, data='data',
                reqid=reqid)
        meta = self.api.container_get_properties(self.account, name)
        objects = meta['system']['sys.m2.objects']
        self.assertEqual('10', objects)
        usage = meta['system']['sys.m2.usage']
        self.assertEqual('40', usage)
        damaged_objects = meta['system']['sys.m2.objects.damaged']
        missing_chunks = meta['system']['sys.m2.chunks.missing']
        for i in range(10):
            reqid = 'content' + name + str(i)
            self.wait_for_event(
                'oio-preserved', reqid=reqid, types=[EventTypes.CONTENT_NEW])
        self.wait_for_event(
            'oio-preserved', fields={'user': name},
            types=[EventTypes.CONTAINER_STATE])
        containers = self.api.container_list(self.account)
        for container in containers:
            if container[0] == name:
                self.assertListEqual(
                    [name, int(objects), int(usage), 0, container[4]],
                    container)
                break
        else:
            self.fail("No container in account")

        self.api.account_flush(self.account)
        self.assertFalse(self.api.container_list(self.account))

        self.beanstalkd0.drain_tube('oio-preserved')
        reqid = request_id()
        self.api.container_touch(self.account, name, reqid=reqid)
        self.wait_for_event(
            'oio-preserved', fields={'user': name},
            types=[EventTypes.CONTAINER_STATE])
        containers = self.api.container_list(self.account)
        self.assertEqual(1, len(containers))
        self.assertListEqual(
            [name, int(objects), int(usage), 0, containers[0][4]],
            containers[0])

        self.api.account_flush(self.account)
        self.assertFalse(self.api.container_list(self.account))

        self.api.container_touch(self.account, name, recompute=True)
        self.wait_for_event(
            'oio-preserved', fields={'user': name},
            types=[EventTypes.CONTAINER_STATE])
        meta = self.api.container_get_properties(self.account, name)
        self.assertEqual(objects, meta['system']['sys.m2.objects'])
        self.assertEqual(usage, meta['system']['sys.m2.usage'])
        self.assertEqual(damaged_objects,
                         meta['system']['sys.m2.objects.damaged'])
        self.assertEqual(missing_chunks,
                         meta['system']['sys.m2.chunks.missing'])
        containers = self.api.container_list(self.account)
        self.assertEqual(1, len(containers))
        self.assertListEqual(
            [name, int(objects), int(usage), 0, containers[0][4]],
            containers[0])

    def test_object_create_invalid_name(self):
        ct = random_str(32)
        obj = u"Beno\xeet".encode('latin1')
        self._create(ct)
        self.assertRaises(exc.ClientException, self.api.object_create,
                          self.account, ct, data=b"data", obj_name=obj)
        self._clean(ct)

    def test_object_create_mime_type(self):
        name = random_str(32)
        self.api.object_create(self.account, name, data="data", obj_name=name,
                               mime_type='text/custom')
        meta, _ = self.api.object_locate(self.account, name, name)
        self.assertEqual(meta['mime_type'], 'text/custom')

    def _upload_data(self, name):
        chunksize = int(self.conf["chunk_size"])
        size = chunksize * 12
        data = random_data(size)
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
        data = b''.join(stream)
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

    def test_object_fetch_range_recover(self):
        """
        Check that the client can continue reading after the failure
        of a chunk in the middle of the download.
        """
        ec_k = 6  # FIXME(FVE): load actual number from the storage policy
        fragment_size = EC_SEGMENT_SIZE // ec_k
        if (not self.conf['storage_policy'].startswith('EC') or
                self.conf['chunk_size'] <= (fragment_size * 3)):
            self.skipTest('Run only in EC mode and when chunk size > %d' %
                          fragment_size * 3)
        name = 'range_test_' + random_str(6)
        _, data = self._upload_data(name)

        # Start reading the object just before the end of an EC segment
        start = EC_SEGMENT_SIZE - 16
        # End reading a few bytes after the start of an EC segment
        end = start + EC_SEGMENT_SIZE + 31  # Over 3 segments
        expected_data = data[start:end+1]
        logging.debug("Fetching %d bytes (%d-%d)", end-start+1, start, end)
        UnreliableResponse.reset_instance_count()
        with patch(
                'oio.common.http_eventlet.CustomHttpConnection.response_class',
                UnreliableResponse):
            fetched_data = self._fetch_range(name, (start, end))
        self.assertEqual(expected_data, fetched_data)

    def test_object_create_then_append(self):
        """Create an object then append data"""
        name = random_str(16)
        self.api.object_create(self.account, name, data=b'1'*64, obj_name=name)
        _, size, _ = self.api.object_create(
            self.account, name, data=b'2'*128, obj_name=name, append=True)
        self.assertEqual(size, 128)
        _, data = self.api.object_fetch(self.account, name, name)
        data = b''.join(data)
        self.assertEqual(len(data), 192)
        self.assertEqual(data, b'1' * 64 + b'2' * 128)

    def test_object_create_from_append(self):
        """Create an object with append operation"""
        name = random_str(16)
        self.api.container_create(self.account, name)
        self.api.object_create(self.account, name, data=b'1'*128,
                               obj_name=name, append=True)
        _, data = self.api.object_fetch(self.account, name, name)
        data = b''.join(data)
        self.assertEqual(len(data), 128)
        self.assertEqual(data, b'1'*128)

    def test_container_object_create_from_append(self):
        """Try to create container and object with append operation"""
        name = random_str(16)
        _chunks, size, checksum = self.api.object_create(
            self.account, name, data=b'1'*128, obj_name=name, append=True)
        self.assertEqual(size, 128)

        meta = self.api.object_get_properties(self.account, name, name)
        self.assertEqual(meta.get('hash', "").lower(), checksum.lower())

    def test_object_create_conflict_delete_chunks(self):
        # pylint: disable=no-member
        name = random_str(16)
        # Simulate a conflict error
        self.api.container.content_create = \
            Mock(side_effect=exc.Conflict(409))
        self.api._blob_client = Mock(wraps=self.api.blob_client)
        # Ensure the error is passed to the upper level
        self.assertRaises(
            exc.Conflict, self.api.object_create, self.account,
            name, obj_name=name, data=name)
        # Ensure that the chunk deletion has been called with proper args
        create_kwargs = self.api.container.content_create.call_args[1]
        chunks = create_kwargs['data']['chunks']
        self.api.blob_client.chunk_delete_many.assert_called_once()
        self.assertEqual(
            chunks, self.api.blob_client.chunk_delete_many.call_args[0][0])
        # Ensure the chunks have actually been deleted
        for chunk in chunks:
            self.assertRaises(
                exc.NotFound, self.api.blob_client.chunk_head,
                chunk.get('real_url', chunk['url']))

    def test_object_create_commit_deadline_delete_chunks(self):
        # pylint: disable=no-member
        name = random_str(16)
        # Simulate a deadline during commit
        self.api.container.content_create = \
            Mock(wraps=partial(self.api.container.content_create,
                               deadline=0.0))
        self.api._blob_client = Mock(wraps=self.api.blob_client)
        # Ensure the error is passed to the upper level
        self.assertRaises(
            exc.DeadlineReached, self.api.object_create, self.account,
            name, obj_name=name, data=name)
        # Ensure that the chunk deletion has been called with proper args
        create_kwargs = self.api.container.content_create.call_args[1]
        chunks = create_kwargs['data']['chunks']
        self.api.blob_client.chunk_delete_many.assert_called_once()
        self.assertEqual(
            chunks, self.api.blob_client.chunk_delete_many.call_args[0][0])
        # Ensure the chunks have actually been deleted
        for chunk in chunks:
            self.assertRaises(
                exc.NotFound, self.api.blob_client.chunk_head,
                chunk.get('real_url', chunk['url']))

    def test_object_create_prepare_deadline_delete_chunks(self):
        # pylint: disable=no-member
        name = random_str(16)

        class _Preparer(object):
            def __init__(self, func):
                self.func = func
                self.call_count = 0

            def __call__(self, *args, **kwargs):
                if self.call_count > 1:
                    raise exc.DeadlineReached()
                res = self.func(*args, **kwargs)
                # Hack the size of chunks, will become chunk_size
                for chunk in res[1]:
                    chunk['size'] = 4
                res[0]['chunk_size'] = 4
                self.call_count += 1
                return res

        # Simulate a deadline during prepare
        self.api.container.content_prepare = \
            Mock(side_effect=_Preparer(self.api.container.content_prepare))
        self.api._blob_client = Mock(wraps=self.api.blob_client)
        # Ensure the error is passed to the upper level
        self.assertRaises(
            exc.DeadlineReached, self.api.object_create, self.account,
            name, obj_name=name, data=name*4)
        # Ensure that the chunk deletion has been called with proper args
        self.api.blob_client.chunk_delete_many.assert_called_once()

    def test_buckets_list(self):
        account = random_str(32)

        bucket_names = list()
        bucket_names.append(random_str(32).lower())
        bucket_names.append(random_str(32).lower())

        container_names = list()
        container_names += bucket_names
        container_names.append(  # path (CH)
            "%2F".join([random_str(32).lower(), random_str(32).lower()]))
        container_names.append(  # segments (MPU)
            random_str(32).lower() + "+segments")

        for container_name in container_names:
            self.api.container_create(account, container_name)
        for _ in container_names:
            self.wait_for_event(
                'oio-preserved', types=[EventTypes.CONTAINER_NEW])

        buckets = self.api.container_list(account, s3_buckets_only=True)
        self.assertListEqual(
            sorted(bucket_names), [b[0] for b in buckets])

        containers = self.api.container_list(account)
        self.assertListEqual(
            sorted(container_names), [b[0] for b in containers])

    def test_buckets_list_with_prefix(self):
        account = random_str(32)
        prefix = random_str(32).lower()

        bucket_names_with_prefix = list()
        bucket_names_with_prefix.append(prefix)
        bucket_names_with_prefix.append(prefix + "test")

        container_names = list()
        container_names += bucket_names_with_prefix
        container_names.append(random_str(32).lower())  # No prefix
        container_names.append(  # path (CH) with prefix
            "%2F".join([prefix, random_str(32).lower()]))
        container_names.append(  # segments (MPU) with prefix
            prefix + "+segments")

        for container_name in container_names:
            self.api.container_create(account, container_name)
        for _ in container_names:
            self.wait_for_event(
                'oio-preserved', types=[EventTypes.CONTAINER_NEW])

        buckets = self.api.container_list(account, s3_buckets_only=True,
                                          prefix=prefix)
        self.assertListEqual(
            sorted(bucket_names_with_prefix), [b[0] for b in buckets])

        containers = self.api.container_list(account)
        self.assertListEqual(
            sorted(container_names), [b[0] for b in containers])

    def test_buckets_list_check_name(self):
        account = random_str(32)

        bucket_names = list()
        bucket_names.append(  # Name
            random_str(16).lower() + "." + random_str(16).lower())
        bucket_names.append(  # OK label
            random_str(10).lower() + '.' + random_str(10).lower())

        container_names = list()
        container_names += bucket_names
        container_names.append(random_str(2).lower())  # Too small name
        container_names.append(random_str(64).lower())  # Too long name
        container_names.append(  # Underscore name
            random_str(16).lower() + "_" + random_str(16).lower())
        container_names.append("." + random_str(16).lower())  # Start with dot
        container_names.append(random_str(32).upper())  # Uppercase
        container_names.append("192.168.5.4")  # IP address
        container_names.append(  # KO label
            random_str(10).lower() + '.' + random_str(10))

        for container_name in container_names:
            self.api.container_create(account, container_name)
        for _ in container_names:
            self.wait_for_event(
                'oio-preserved', types=[EventTypes.CONTAINER_NEW])

        buckets = self.api.container_list(account, s3_buckets_only=True)
        self.assertListEqual(
            sorted(bucket_names), [b[0] for b in buckets])

        containers = self.api.container_list(account)
        self.assertListEqual(
            sorted(container_names), [b[0] for b in containers])

    def test_container_refresh(self):
        self.wait_for_score(('account', 'meta2'))
        account = random_str(32)
        # container_refresh on unknown container
        name = random_str(32)
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_refresh, account, name)

        reqid = request_id()
        self.api.container_create(account, name, reqid=reqid)
        ref_time = time.time()
        # ensure container event has been emitted and processed
        self.wait_for_event('oio-preserved', types=[EventTypes.CONTAINER_NEW])

        # container_refresh on existing container
        self.api.container_refresh(account, name)
        # Container events are buffered 1s by default.
        # See "events.common.pending.delay" configuration parameter.
        self.wait_for_event('oio-preserved',
                            types=[EventTypes.CONTAINER_STATE])
        res = self.api.container_list(account, prefix=name)
        container_name, nb_objects, nb_bytes, _, mtime = res[0]
        self.assertEqual(name, container_name)
        self.assertEqual(0, nb_objects)
        self.assertEqual(0, nb_bytes)
        self.assertGreater(mtime, ref_time)

        ref_time = mtime
        reqid = request_id()
        self.api.object_create(account, name, data="data", obj_name=name,
                               reqid=reqid)
        self.wait_for_event('oio-preserved', reqid=reqid)
        self.wait_for_event('oio-preserved',
                            types=[EventTypes.CONTAINER_STATE])
        self.beanstalkd0.drain_tube('oio-preserved')
        # container_refresh on existing container with data
        self.api.container_refresh(account, name)
        self.wait_for_event('oio-preserved',
                            types=[EventTypes.CONTAINER_STATE])
        res = self.api.container_list(account, prefix=name)
        container_name, nb_objects, nb_bytes, _, mtime = res[0]
        self.assertEqual(name, container_name)
        self.assertEqual(1, nb_objects)
        self.assertEqual(4, nb_bytes)
        self.assertGreater(mtime, ref_time)

        self.api.object_delete(account, name, name)
        self.api.container_delete(account, name)
        # Again, wait for the container event to be processed.
        self.wait_for_event('oio-preserved',
                            types=[EventTypes.ACCOUNT_SERVICES])
        # container_refresh on deleted container
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_refresh, account, name)

        self.api.account_delete(account)

    def test_container_refresh_user_not_found(self):
        name = random_str(32)
        self.wait_for_score(('account', 'meta2'))
        self.api.account.container_update(name, name, {"mtime": time.time()})
        self.api.container_refresh(name, name)
        containers = self.api.container_list(name)
        self.assertEqual(0, len(containers))
        self.api.account_delete(name)

    def test_account_refresh(self):
        # account_refresh on unknown account
        account = random_str(32)
        self.wait_for_score(('account', 'meta2'))
        self.assertRaises(
            exc.NoSuchAccount, self.api.account_refresh, account)

        # account_refresh on existing account
        self.api.account_create(account)
        self.api.account_refresh(account)
        self.beanstalkd.wait_until_empty('oio')
        res = self.api.account_show(account)
        self.assertEqual(res["bytes"], 0)
        self.assertEqual(res["objects"], 0)
        self.assertEqual(res["containers"], 0)

        name = random_str(32)
        self.api.object_create(account, name, data="data", obj_name=name)
        self.wait_for_event('oio-preserved',
                            fields={'account': account},
                            types=[EventTypes.CONTAINER_STATE])
        self.beanstalkd0.drain_tube('oio-preserved')
        self.api.account_refresh(account)
        self.wait_for_event('oio-preserved',
                            fields={'account': account},
                            types=[EventTypes.CONTAINER_STATE])
        res = self.api.account_show(account)
        self.assertEqual(res["bytes"], 4)
        self.assertEqual(res["objects"], 1)
        self.assertEqual(res["containers"], 1)

        self.api.object_delete(account, name, name)
        self.api.container_delete(account, name)
        # Again, wait for the container event to be processed.
        self.wait_for_event('oio-preserved',
                            types=[EventTypes.ACCOUNT_SERVICES])
        self.api.account_delete(account)
        # account_refresh on deleted account
        self.assertRaises(
            exc.NoSuchAccount, self.api.account_refresh, account)

    def test_account_refresh_all(self):
        self.wait_for_score(('account', 'meta2'))
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
        self.wait_for_score(('account', 'meta2'))
        # account_flush on unknown account
        account = random_str(32)
        self.assertRaises(
            exc.NoSuchAccount, self.api.account_flush, account)

        # account_flush on existing account
        name1 = random_str(32)
        self.api.container_create(account, name1)
        name2 = random_str(32)
        self.api.container_create(account, name2)
        self.beanstalkd.wait_until_empty('oio')
        time.sleep(0.1)
        self.api.account_flush(account)
        containers = self.api.container_list(account)
        self.assertEqual(len(containers), 0)
        res = self.api.account_show(account)
        self.assertEqual(res["bytes"], 0)
        self.assertEqual(res["objects"], 0)
        self.assertEqual(res["containers"], 0)

        self.api.container_delete(account, name1)
        self.api.container_delete(account, name2)
        self.beanstalkd.wait_until_empty('oio')
        time.sleep(0.1)
        self.api.account_delete(account)

        # account_flush on deleted account
        self.assertRaises(
            exc.NoSuchAccount, self.api.account_flush, account)

    def _link_and_check(self, target_container, target_obj,
                        link_container, link_obj, expected_data,
                        target_content_id=None, target_version=None,
                        link_content_id=None, **kwargs):
        self.api.object_link(
            self.account, target_container, target_obj,
            self.account, link_container, link_obj,
            target_content_id=target_content_id, target_version=target_version,
            link_content_id=link_content_id, **kwargs)

        original_meta, data = self.api.object_fetch(
            self.account, link_container, link_obj)
        data = b''.join(data)
        cid = cid_from_name(self.account, link_container)
        fullpath = encode_fullpath(
            self.account, link_container, link_obj, original_meta['version'],
            original_meta['id'])
        self.assertEqual(len(data), len(expected_data))
        self.assertEqual(data, expected_data)
        self.assertEqual(link_obj, original_meta['name'])
        self.assertEqual(cid, original_meta['container_id'])
        if link_content_id:
            self.assertEqual(link_content_id, original_meta['id'])

        meta, chunks = self.api.object_locate(
            self.account, link_container, link_obj, content=link_content_id)
        del original_meta['ns']
        del original_meta['container_id']
        self.assertDictEqual(original_meta, meta)

        for chunk in chunks:
            meta = self.api.blob_client.chunk_head(chunk['url'])
            self.assertEqual(cid, meta['container_id'])
            self.assertEqual(original_meta['name'], meta['content_path'])
            self.assertEqual(str(original_meta['version']),
                             str(meta['content_version']))
            self.assertEqual(original_meta['id'], meta['content_id'])
            self.assertEqual(fullpath, meta['full_path'])
            self.assertEqual(original_meta['chunk_method'],
                             meta['content_chunkmethod'])
            self.assertEqual(original_meta['policy'], meta['content_policy'])
            self.assertEqual(chunk['pos'], meta['chunk_pos'])

    def test_object_link_different_container(self):
        target_container = random_str(16)
        target_obj = random_str(16)
        target_content_id = random_id(32)

        self.api.object_create(
            self.account, target_container, data="1"*128, obj_name=target_obj,
            content_id=target_content_id)
        obj = self.api.object_show(self.account, target_container, target_obj,
                                   content=target_content_id)
        target_version = obj['version']

        # send target path
        link_container = random_str(16)
        link_obj = random_str(16)
        self._link_and_check(
            target_container, target_obj, link_container, link_obj, b'1'*128)

        # send target content ID
        link_container = random_str(16)
        link_obj = random_str(16)
        self._link_and_check(
            target_container, None, link_container, link_obj, b'1'*128,
            target_content_id=target_content_id)

        # send target path and version
        link_container = random_str(16)
        link_obj = random_str(16)
        self._link_and_check(
            target_container, target_obj, link_container, link_obj, b'1'*128,
            target_version=target_version)

        # send target path and wrong version
        link_container = random_str(16)
        link_obj = random_str(16)
        self.assertRaises(exc.NoSuchObject, self.api.object_link,
                          self.account, target_container, target_obj,
                          self.account, link_container, link_obj,
                          target_version='0')

        # send link content ID
        link_container = random_str(16)
        link_obj = random_str(16)
        link_content_id = random_id(32)
        self._link_and_check(
            target_container, target_obj, link_container, link_obj, b'1'*128,
            link_content_id=link_content_id)

    def test_object_link_different_container_no_autocreate(self):
        target_container = random_str(16)
        link_container = random_str(16)
        target_obj = random_str(16)
        link_obj = random_str(16)
        self.api.object_create(self.account, target_container, data="1"*128,
                               obj_name=target_obj)
        self.assertRaises(
            exc.NotFound,
            self.api.object_link, self.account, target_container,
            target_obj, self.account, link_container, link_obj,
            autocreate=False)

    def test_object_link_same_container(self):
        target_container = random_str(16)
        target_obj = random_str(16)
        link_container = target_container
        target_content_id = random_id(32)

        self.api.object_create(
            self.account, target_container, data="1"*128, obj_name=target_obj,
            content_id=target_content_id)
        obj = self.api.object_show(self.account, target_container, target_obj,
                                   content=target_content_id)
        target_version = obj['version']

        # send target path
        link_obj = random_str(16)
        self._link_and_check(
            target_container, target_obj, link_container, link_obj, b'1'*128)

        # send target content ID
        link_obj = random_str(16)
        self._link_and_check(
            target_container, None, link_container, link_obj, b'1'*128,
            target_content_id=target_content_id)

        # send target path and version
        link_obj = random_str(16)
        self._link_and_check(
            target_container, target_obj, link_container, link_obj, b'1'*128,
            target_version=target_version)

        # send target and wrong version
        link_obj = random_str(16)
        self.assertRaises(exc.NoSuchObject, self.api.object_link,
                          self.account, target_container, target_obj,
                          self.account, link_container, link_obj,
                          target_version='0')

        # send link content ID
        link_obj = random_str(16)
        link_content_id = random_id(32)
        self._link_and_check(
            target_container, target_obj, link_container, link_obj, b'1'*128,
            link_content_id=link_content_id)

    def test_object_link_same_name_same_container(self):
        """ Considered as a rename"""
        container = random_str(16)
        obj = random_str(16)
        self.api.object_create(self.account, container, data="1"*128,
                               obj_name=obj)
        self._link_and_check(
            container, obj, container, obj, b'1'*128)

    def test_object_link_with_already_existing_name(self):
        target_container = random_str(16)
        link_container = random_str(16)
        target_obj = random_str(16)
        link_obj = random_str(16)
        self.api.object_create(self.account, target_container, data="1"*128,
                               obj_name=target_obj)
        self.api.object_create(self.account, target_container, data="0"*128,
                               obj_name=link_obj)
        self._link_and_check(
            target_container, target_obj, link_container, link_obj, b'1'*128)

    def test_object_link_with_metadata(self):
        target_container = random_str(16)
        link_container = random_str(16)
        target_obj = random_str(16)
        link_obj = random_str(16)
        self.api.object_create(self.account, target_container, data="1"*128,
                               obj_name=target_obj,
                               metadata={'AAA': '1', 'BBB': '1'})
        self.api.object_link(self.account, target_container, target_obj,
                             self.account, link_container, link_obj,
                             metadata={'BBB': '2'})
        metadata, _ = self.api.object_fetch(self.account, link_container,
                                            link_obj)
        self.assertDictEqual(metadata.get('properties', {}),
                             {'AAA': '1', 'BBB': '1'})

        self.api.object_link(self.account, target_container, target_obj,
                             self.account, link_container, link_obj,
                             metadata={'BBB': '2'},
                             properties_directive='REPLACE')
        metadata, _ = self.api.object_fetch(self.account, link_container,
                                            link_obj)
        self.assertDictEqual(metadata.get('properties', {}),
                             {'BBB': '2'})

    def test_object_create_then_truncate(self):
        """Create an object then truncate data"""
        name = random_str(16)
        self.api.object_create(self.account, name,
                               data=b'1'*128, obj_name=name)
        self.api.object_truncate(self.account, name, name, size=64)
        _, data = self.api.object_fetch(self.account, name, name)
        data = b''.join(data)
        self.assertEqual(len(data), 64)
        self.assertEqual(data, b'1' * 64)

    def test_object_create_append_then_truncate(self):
        """Create an object, append data then truncate on chunk boundary"""
        name = random_str(16)
        self.api.object_create(self.account, name,
                               data=b'1'*128, obj_name=name)
        _, size, _ = self.api.object_create(
            self.account, name, data=b'2'*128, obj_name=name, append=True)
        self.assertEqual(size, 128)

        self.api.object_truncate(self.account, name, name, size=128)
        _, data = self.api.object_fetch(self.account, name, name)
        data = b''.join(data)
        self.assertEqual(len(data), 128)
        self.assertEqual(data, b'1' * 128)

        self.api.object_truncate(self.account, name, name, size=128)

    def test_object_create_then_invalid_truncate(self):
        """Create an object, append data then try to truncate outside object
           range"""
        name = random_str(16)
        self.api.object_create(self.account, name,
                               data=b'1'*128, obj_name=name)
        self.assertRaises(
            exc.OioException, self.api.object_truncate, self.account, name,
            name, size=-1)
        self.assertRaises(
            exc.OioException, self.api.object_truncate, self.account, name,
            name, size=129)

    def test_object_create_content_id(self):
        def _check_content_id(content_id=None):
            name = random_str(32)
            chunks, _, _ = self.api.object_create(
                self.account, name, data=b"data", obj_name=name,
                content_id=content_id)
            obj_meta = self.api.object_show(self.account, name, name)
            if content_id is not None:
                self.assertEqual(content_id, obj_meta['id'])
            headers, _ = self.api.blob_client.chunk_get(chunks[0]['url'])
            self.assertEqual(obj_meta['id'], headers['content_id'])

        _check_content_id()
        _check_content_id(content_id=random_id(32))

    def test_object_delete_many(self):
        container = random_str(8)
        objects = ["obj%d" % i for i in range(8)]
        for obj in objects:
            self.api.object_create(self.account, container,
                                   obj_name=obj, data=obj.encode('utf-8'))
        res = self.api.object_delete_many(self.account, container, objects)
        self.assertEqual(len(objects), len(res))
        for obj in objects:
            self.assertIn(obj, [x[0] for x in res])
        for obj in res:
            self.assertTrue(obj[1])

        res = self.api.object_delete_many(self.account, container, ["dahu"])
        self.assertFalse(res[0][1])

    def test_container_snapshot_failure(self):
        cname = 'container-' + random_str(6)
        cname2 = cname + '.snapshot'

        # Creating a snapshot on non existing container should fail
        self.assertRaises(exc.NoSuchContainer,
                          self.api.container_snapshot,
                          self.account, cname,
                          self.account, cname2)

        self._create(cname)
        # Snapshot cannot have same name and same account
        self.assertRaises(exc.ClientException,
                          self.api.container_snapshot,
                          self.account, cname,
                          self.account, cname)

        # Snapshots need to have an account name
        self.assertRaises(exc.ClientException,
                          self.api.container_snapshot,
                          self.account, cname,
                          None, cname2)

        # Snapshots need to have a name
        self.assertRaises(exc.ClientException,
                          self.api.container_snapshot,
                          self.account, cname,
                          cname2, None)

    def test_container_snapshot(self):
        container = 'container-' + random_str(6)
        snapshot = container + '.snapshot'
        self.api.container_create(self.account, container)
        test_object = "test_object_%d"
        for i in range(10):
            self.api.object_create(self.account, container, data=b'0'*128,
                                   obj_name=test_object % i,
                                   chunk_checksum_algo=None)

        # Non existing snapshot should work
        self.api.container_snapshot(self.account, container,
                                    self.account, snapshot)
        # Check sys.user.name is correct
        ret = self.api.container_get_properties(self.account, snapshot)
        self.assertEqual(snapshot, ret['system']['sys.user.name'])
        self.assertEqual(self.account, ret['system']['sys.account'])

        # Already taken snapshot name should fail
        self.assertRaises(exc.ClientException,
                          self.api.container_snapshot,
                          self.account, container, self.account, snapshot)

        # Check Container Frozen so create should fail
        self.assertRaises(exc.ServiceBusy,
                          self.api.object_create,
                          self.account, snapshot,
                          data=b'1'*128,
                          obj_name="should_not_be_created")

        for i in range(10):
            _, chunks = self.api.object_locate(self.account, container,
                                               test_object % i)
            _, chunks_copies = self.api.object_locate(self.account, snapshot,
                                                      test_object % i)

            zipped = zip(sorted(chunks, key=lambda x: x['pos']),
                         sorted(chunks_copies, key=lambda x: x['pos']))
            for chunk, chunk_copy in zipped:
                # check that every chunk is different from the target
                self.assertNotEqual(chunk['url'], chunk_copy['url'])

                # check the metadata
                meta = self.api._blob_client.chunk_head(chunk['url'])
                meta_copies = self.api._blob_client.chunk_head(
                    chunk_copy['url'])

                fullpath = encode_fullpath(
                    self.account, snapshot, test_object % i,
                    meta['content_version'], meta['content_id'])
                container_id = cid_from_name(self.account, snapshot)

                self.assertEqual(fullpath, meta_copies['full_path'])
                del meta['full_path']
                del meta_copies['full_path']
                self.assertEqual(container_id, meta_copies['container_id'])
                del meta['container_id']
                del meta_copies['container_id']
                del meta['chunk_id']
                del meta_copies['chunk_id']
                self.assertDictEqual(meta, meta_copies)

        # check target can be used
        self.api.object_create(self.account, container, data="0"*128,
                               obj_name="should_be_created")

    def test_object_create_long_name(self):
        """Create an objet whose name has the maximum length allowed"""
        cname = random_str(16)
        path = random_str(1023)
        self.api.object_create(self.account, cname,
                               data=b'1'*128, obj_name=path)

    def test_object_head_trust_level_0(self):
        cname = random_str(16)
        path = random_str(1023)

        # object doesn't exist
        self.assertFalse(self.api.object_head(self.account, cname, path))

        # object exists
        self._upload_empty(cname, path)
        self.assertTrue(self.api.object_head(self.account, cname, path))

    def test_object_head_trust_level_2(self):
        cname = random_str(16)
        path = random_str(1023)

        # object doesn't exist
        self.assertFalse(self.api.object_head(self.account, cname, path,
                                              trust_level=2))

        # object exists
        self._upload_empty(cname, path)
        self.assertTrue(self.api.object_head(self.account, cname, path,
                                             trust_level=2))

        # chunk missing
        self.api.blob_client.http_pool.request = \
            Mock(return_value=HTTPResponse(status=404, reason="Not Found"))
        self.assertFalse(self.api.object_head(self.account, cname, path,
                                              trust_level=2))

    def test_object_create_without_autocreate_and_missing_container(self):
        name = random_str(32)
        self.assertRaises(
            exc.NoSuchContainer, self.api.object_create, self.account, name,
            data="data", obj_name=name, autocreate=False)

    def test_object_create_without_autocreate_and_existing_container(self):
        name = random_str(32)
        self._create(name)
        self.api.object_create(self.account, name, data="data", obj_name=name,
                               autocreate=False)


class TestObjectChangePolicy(ObjectStorageApiTestBase):

    def setUp(self):
        super(TestObjectChangePolicy, self).setUp()
        self.chunk_size = self.conf['chunk_size']
        self.nb_rawx = len(self.conf['services']['rawx'])

    def _test_change_policy(self, data_size, old_policy, new_policy,
                            versioning=False):
        if 'EC' in (old_policy, new_policy) and self.nb_rawx < 9:
            self.skipTest("need at least 9 rawx to run")
        elif 'THREECOPIES' in (old_policy, new_policy) and self.nb_rawx < 3:
            self.skipTest("need at least 3 rawx to run")
        elif 'TWOCOPIES' in (old_policy, new_policy) and self.nb_rawx < 2:
            self.skipTest("need at least 2 rawx to run")
        elif 'SINGLE' in (old_policy, new_policy) and self.nb_rawx < 1:
            self.skipTest("need at least 1 rawx to run")

        name = 'change-policy-' + random_str(6)
        self._create(name)

        if versioning:
            self.api.container_set_properties(
                self.account, name, system={'sys.m2.policy.version': '-1'})
            self.api.object_create(
                self.account, name, obj_name=name, data=random_data(42))
        data = random_data(data_size)
        self.api.object_create(
            self.account, name, obj_name=name,
            data=data, policy=old_policy, properties={'test': 'it works'})
        obj1, chunks1 = self.api.object_locate(self.account, name, name)
        cnt_props1 = self.api.container_get_properties(self.account, name)
        if versioning:
            self.api.object_delete(self.account, name, name)
        self.wait_for_event('oio-preserved',
                            types=[EventTypes.CONTAINER_STATE], timeout=1.0)
        cnt_info1 = [cont_info
                     for cont_info in self.api.container_list(self.account)
                     if cont_info[0] == name]

        self.api.object_change_policy(
            self.account, name, name, new_policy, version=obj1['version'])
        # One of the checks below verifies that the old chunks have actually
        # been deleted. Since this is an asynchronous process, we used to see
        # random failures when the event treatment was a little slow.
        evt = self.wait_for_event('oio-preserved',
                                  types=(EventTypes.CHUNK_DELETED,
                                         EventTypes.CONTENT_BROKEN),
                                  timeout=5.0)
        if evt.event_type == EventTypes.CONTENT_BROKEN:
            self.logger.warning("One of the new chunks was not uploaded, "
                                "wait a few seconds for the rebuilder "
                                "to rebuild it.")
            self.wait_for_event('oio-preserved',
                                types=(EventTypes.CHUNK_NEW, ),
                                timeout=6.0)

        obj2, chunks2 = self.api.object_locate(
            self.account, name, name, version=obj1['version'])
        cnt_props2 = self.api.container_get_properties(self.account, name)

        self.wait_for_event('oio-preserved',
                            types=[EventTypes.CONTAINER_STATE], timeout=2.0)
        cnt_info2 = [cont_info
                     for cont_info in self.api.container_list(self.account)
                     if cont_info[0] == name]

        self.assertNotEqual(obj1['id'], obj2['id'])
        self.assertEqual(old_policy, obj1['policy'])
        self.assertEqual(new_policy, obj2['policy'])
        obj1['id'] = obj2['id']
        obj1['chunk_method'] = obj2['chunk_method']
        obj1['policy'] = obj2['policy']
        self.assertDictEqual(obj1, obj2)
        self.assertEqual(cnt_props1['system']['sys.m2.objects'],
                         cnt_props2['system']['sys.m2.objects'])
        self.assertEqual(cnt_props1['system']['sys.m2.usage'],
                         cnt_props2['system']['sys.m2.usage'])
        self.assertListEqual(cnt_info1[:-1], cnt_info2[:-1])

        _, stream = self.api.object_fetch(
            self.account, name, name, version=obj2['version'])
        self.assertEqual(data, b''.join(stream))

        stg_met2 = STORAGE_METHODS.load(obj2['chunk_method'])
        chunks_by_pos2 = sort_chunks(chunks2, stg_met2.ec)
        if stg_met2.ec:
            required = stg_met2.ec_nb_data + stg_met2.ec_nb_parity
        else:
            required = stg_met2.nb_copy
        for pos, clist in chunks_by_pos2.items():
            self.assertEqual(required, len(clist))

        for chunk in chunks1:
            self.assertRaises(
                exc.NotFound, self.api.blob_client.chunk_head, chunk['url'])
        for chunk in chunks2:
            meta = self.api.blob_client.chunk_head(chunk['url'])
            self.assertEqual(chunk['url'].rsplit('/', 1)[-1], meta['chunk_id'])
            self.assertEqual(chunk['pos'], meta['chunk_pos'])
            self.assertGreaterEqual(self.chunk_size, int(meta['chunk_size']))
            self.assertEqual(
                cid_from_name(self.account, name), meta['container_id'])
            self.assertEqual(obj2['chunk_method'], meta['content_chunkmethod'])
            self.assertEqual(obj2['id'], meta['content_id'])
            self.assertEqual(obj2['name'], meta['content_path'])
            self.assertEqual(obj2['policy'], meta['content_policy'])
            self.assertEqual(obj2['version'], meta['content_version'])

    def test_change_content_0_byte_policy_single_to_ec(self):
        self._test_change_policy(0, 'SINGLE', 'EC')

    def test_change_content_0_byte_policy_ec_to_twocopies(self):
        self._test_change_policy(0, 'EC', 'TWOCOPIES')

    def test_change_content_1_byte_policy_single_to_ec(self):
        self._test_change_policy(1, 'SINGLE', 'EC')

    def test_change_content_chunksize_bytes_policy_twocopies_to_ec(self):
        self._test_change_policy(
            self.chunk_size, 'TWOCOPIES', 'EC')

    def test_change_content_2xchunksize_bytes_policy_threecopies_to_ec(self):
        self._test_change_policy(
            self.chunk_size * 2, 'THREECOPIES', 'EC')

    def test_change_content_1_byte_policy_ec_to_threecopies(self):
        self._test_change_policy(
            1, 'EC', 'THREECOPIES')

    def test_change_content_chunksize_bytes_policy_ec_to_twocopies(self):
        self._test_change_policy(
            self.chunk_size, 'EC', 'TWOCOPIES')

    def test_change_content_2xchunksize_bytes_policy_ec_to_single(self):
        self._test_change_policy(
            self.chunk_size * 2, 'EC', 'SINGLE')

    def test_change_content_0_byte_policy_twocopies_to_threecopies(self):
        self._test_change_policy(
            0, 'TWOCOPIES', 'THREECOPIES')

    def test_change_content_chunksize_bytes_policy_single_to_twocopies(self):
        self._test_change_policy(
            self.chunk_size, 'SINGLE', 'TWOCOPIES')

    def test_change_content_2xchunksize_bytes_policy_3copies_to_single(self):
        self._test_change_policy(
            self.chunk_size * 2, 'THREECOPIES', 'SINGLE')

    def test_change_content_with_same_policy(self):
        self.assertRaises(exc.Conflict,
                          self._test_change_policy,
                          1, 'TWOCOPIES', 'TWOCOPIES')

    def test_change_policy_with_versioning(self):
        self._test_change_policy(
            1, 'SINGLE', 'TWOCOPIES', versioning=True)

    def test_change_policy_unknown_storage_policy(self):
        name = random_str(32)
        self._create(name)

        self.api.object_create(self.account, name, obj_name=name, data='data')
        obj = self.api.object_get_properties(self.account, name, name)
        self.assertRaises(
            exc.ClientException, self.api.object_change_policy,
            self.account, name, name, 'UNKNOWN', version=obj['version'])

    def test_change_policy_with_delete_marker(self):
        name = random_str(32)
        self._create(name)
        self.api.container_set_properties(
            self.account, name, system={'sys.m2.policy.version': '-1'})

        self.api.object_create(self.account, name, obj_name=name, data='data')
        self.api.object_delete(self.account, name, name)
        obj = self.api.object_get_properties(self.account, name, name)
        self.assertRaises(
            exc.NoSuchObject, self.api.object_change_policy,
            self.account, name, name, 'SINGLE', version=obj['version'])
        self.assertRaises(
            exc.ClientException, self.api.object_create,
            self.account, name, obj_name=name, version=obj['version'],
            data='data', policy='SINGLE', change_policy=True)

    def test_change_policy_without_version(self):
        name = random_str(32)
        self._create(name)

        self.api.object_create(self.account, name, data='data', obj_name=name)
        self.assertRaises(
            exc.NoSuchContainer, self.api.object_create,
            self.account, name, data='data', obj_name=name,
            policy='SINGLE', change_policy=True)

    def test_change_policy_with_unknow_version(self):
        name = random_str(32)
        self._create(name)

        self.api.object_create(self.account, name, data='data', obj_name=name)
        self.assertRaises(
            exc.NoSuchContainer, self.api.object_create,
            self.account, name, obj_name=name, version='12344567890',
            data='data', policy='SINGLE', change_policy=True)

    def test_change_policy_with_unknow_object(self):
        name = random_str(32)
        self._create(name)

        self.assertRaises(
            exc.NoSuchContainer, self.api.object_create,
            self.account, name, obj_name=name, version='12344567890',
            data='data', policy='SINGLE', change_policy=True)

    def test_change_policy_with_unknow_container(self):
        name = random_str(32)

        self.assertRaises(
            exc.NoSuchContainer, self.api.object_create,
            self.account, name, obj_name=name, version='12344567890',
            data='data', policy='SINGLE', change_policy=True)

    def test_change_policy_with_different_data(self):
        name = random_str(32)
        self._create(name)

        self.api.object_create(self.account, name, obj_name=name, data='data')
        obj = self.api.object_get_properties(self.account, name, name)
        self.assertRaises(
            exc.ClientException, self.api.object_create,
            self.account, name, obj_name=name, version=obj['version'],
            data='test', policy='SINGLE', change_policy=True)


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

    def test_depaginate_object_list_with_service_busy(self):
        container = random_str(32)

        object_names = list()
        for i in range(8):
            _, _, _, meta = self.api.object_create_ext(
                self.account, container, data="depaginate",
                obj_name="depaginate-"+str(i))
            object_names.append(meta['name'])

        def my_object_list(*args, **kwargs):
            my_object_list.i += 1
            if i % 2 == 0:
                raise exc.ServiceBusy()
            return self.api.object_list(*args, **kwargs)
        my_object_list.i = -1

        obj_gen = depaginate(
            my_object_list,
            listing_key=lambda x: x['objects'],
            marker_key=lambda x: x.get('next_marker'),
            truncated_key=lambda x: x['truncated'],
            account=self.account, container=container, attempts=2, limit=2)
        self.assertListEqual(object_names, [obj['name'] for obj in obj_gen])

    def test_object_create_ext(self):
        name = random_str(32)
        self._create(name)
        _, size, _, metadata = self.api.object_create_ext(
            self.account, name, data="data", obj_name=name)
        self.assertEqual(metadata['ns'], self.ns)
        self.assertIn('version', metadata)

        props = self.api.object_get_properties(self.account, name, name)
        self.assertEqual(metadata['version'], props['version'])
        self.assertEqual(int(props['length']), size)


class TestContainerStorageApiUsingCache(ObjectStorageApiTestBase):

    def setUp(self):
        super(TestContainerStorageApiUsingCache, self).setUp()
        self.cache = dict()
        self.api = ObjectStorageApi(self.ns, endpoint=self.uri,
                                    cache=self.cache)

        self.container = random_str(8)
        self.api.container_create(self.account, self.container)
        self.assertEqual(0, len(self.cache))

        self.api.container._direct_request = Mock(
            side_effect=self.api.container._direct_request)

    def tearDown(self):
        super(TestContainerStorageApiUsingCache, self).tearDown()
        self.api.container_delete(self.account, self.container)
        self.assertEqual(0, len(self.cache))

    def test_container_properties_get_cached(self):
        expected_container_meta = self.api.container_get_properties(
            self.account, self.container)
        self.assertIsNotNone(expected_container_meta)
        expected_container_meta = expected_container_meta.copy()
        self.assertEqual(1, self.api.container._direct_request.call_count)
        self.assertEqual(1, len(self.cache))

        container_meta = self.api.container_get_properties(
            self.account, self.container)
        self.assertDictEqual(expected_container_meta, container_meta)
        self.assertEqual(1, self.api.container._direct_request.call_count)
        self.assertEqual(1, len(self.cache))

    def test_container_properties_decache_on_set(self):
        expected_container_meta = self.api.container_get_properties(
            self.account, self.container)
        self.assertIsNotNone(expected_container_meta)
        properties = {'test1': '1', 'test2': '2'}
        self.api.container_set_properties(
            self.account, self.container, properties)
        self.assertEqual(2, self.api.container._direct_request.call_count)
        self.assertEqual(0, len(self.cache))

        container_meta = self.api.container_get_properties(
            self.account, self.container)
        self.assertDictEqual(properties,
                             container_meta['properties'])
        self.assertEqual(3, self.api.container._direct_request.call_count)
        self.assertEqual(1, len(self.cache))

        container_meta = self.api.container_get_properties(
            self.account, self.container)
        self.assertDictEqual(properties, container_meta['properties'])
        self.assertEqual(3, self.api.container._direct_request.call_count)
        self.assertEqual(1, len(self.cache))

    def test_container_properties_decache_on_del(self):
        properties = {'test1': '1', 'test2': '2'}
        # Set properties
        self.api.container_set_properties(
            self.account, self.container, properties)
        # Load the cache
        self.api.container_get_properties(
            self.account, self.container)
        # Delete properties (and drop the cache)
        self.api.container_del_properties(
            self.account, self.container, list(properties.keys()))
        self.assertEqual(3, self.api.container._direct_request.call_count)
        self.assertEqual(0, len(self.cache))

        container_meta = self.api.container_get_properties(
            self.account, self.container)
        self.assertDictEqual(dict(), container_meta['properties'])
        self.assertEqual(4, self.api.container._direct_request.call_count)
        self.assertEqual(1, len(self.cache))

        container_meta = self.api.container_get_properties(
            self.account, self.container)
        self.assertDictEqual(dict(), container_meta['properties'])
        self.assertEqual(4, self.api.container._direct_request.call_count)
        self.assertEqual(1, len(self.cache))


class TestObjectStorageApiUsingCache(ObjectStorageApiTestBase):

    def setUp(self):
        super(TestObjectStorageApiUsingCache, self).setUp()
        self.cache = dict()
        self.api = ObjectStorageApi(self.ns, endpoint=self.uri,
                                    cache=self.cache)

        self.container = random_str(8)
        self.path = random_str(8)
        self.api.object_create(self.account, self.container,
                               obj_name=self.path, data='cache')
        self.created.append((self.container, self.path))
        self.assertEqual(0, len(self.cache))

        self.api.container._direct_request = Mock(
            side_effect=self.api.container._direct_request)

    def tearDown(self):
        super(TestObjectStorageApiUsingCache, self).tearDown()
        self.assertEqual(0, len(self.cache))

    def test_object_properties(self):
        expected_obj_meta = self.api.object_get_properties(
            self.account, self.container, self.path)
        self.assertIsNotNone(expected_obj_meta)
        expected_obj_meta = expected_obj_meta.copy()
        self.assertEqual(1, self.api.container._direct_request.call_count)
        self.assertEqual(1, len(self.cache))

        obj_meta = self.api.object_get_properties(
            self.account, self.container, self.path)
        self.assertDictEqual(expected_obj_meta, obj_meta)
        self.assertEqual(1, self.api.container._direct_request.call_count)
        self.assertEqual(1, len(self.cache))

        properties = {'test1': '1', 'test2': '2'}
        self.api.object_set_properties(
            self.account, self.container, self.path, properties)
        self.assertEqual(2, self.api.container._direct_request.call_count)
        self.assertEqual(0, len(self.cache))

        expected_obj_meta['properties'] = properties
        obj_meta = self.api.object_get_properties(
            self.account, self.container, self.path)
        self.assertDictEqual(expected_obj_meta, obj_meta)
        self.assertEqual(3, self.api.container._direct_request.call_count)
        self.assertEqual(1, len(self.cache))

        obj_meta = self.api.object_get_properties(
            self.account, self.container, self.path)
        self.assertDictEqual(expected_obj_meta, obj_meta)
        self.assertEqual(3, self.api.container._direct_request.call_count)
        self.assertEqual(1, len(self.cache))

        self.api.object_del_properties(
            self.account, self.container, self.path, list(properties.keys()))
        self.assertEqual(4, self.api.container._direct_request.call_count)
        self.assertEqual(0, len(self.cache))

        expected_obj_meta['properties'] = dict()
        obj_meta = self.api.object_get_properties(
            self.account, self.container, self.path)
        self.assertDictEqual(expected_obj_meta, obj_meta)
        self.assertEqual(5, self.api.container._direct_request.call_count)
        self.assertEqual(1, len(self.cache))

        obj_meta = self.api.object_get_properties(
            self.account, self.container, self.path)
        self.assertDictEqual(expected_obj_meta, obj_meta)
        self.assertEqual(5, self.api.container._direct_request.call_count)
        self.assertEqual(1, len(self.cache))

    def test_object_locate(self):
        properties = {'test1': '1', 'test2': '2'}
        self.api.object_set_properties(
            self.account, self.container, self.path, properties)
        self.assertEqual(1, self.api.container._direct_request.call_count)
        self.assertEqual(0, len(self.cache))

        expected_obj_meta, expected_chunks = self.api.object_locate(
            self.account, self.container, self.path, properties=False)
        self.assertIsNotNone(expected_obj_meta)
        self.assertIsNotNone(expected_chunks)
        expected_obj_meta = expected_obj_meta.copy()
        expected_chunks = copy.deepcopy(expected_chunks)
        for expected_chunk in expected_chunks:
            del expected_chunk['score']
        self.assertEqual(2, self.api.container._direct_request.call_count)
        self.assertEqual(1, len(self.cache))

        obj_meta, chunks = self.api.object_locate(
            self.account, self.container, self.path, properties=False)
        for chunk in chunks:
            del chunk['score']
        self.assertDictEqual(expected_obj_meta, obj_meta)
        self.assertListEqual(expected_chunks, chunks)
        self.assertEqual(2, self.api.container._direct_request.call_count)
        self.assertEqual(1, len(self.cache))

        expected_obj_meta['properties'] = properties
        obj_meta, chunks = self.api.object_locate(
            self.account, self.container, self.path, properties=True)
        for chunk in chunks:
            del chunk['score']
        self.assertDictEqual(expected_obj_meta, obj_meta)
        self.assertListEqual(expected_chunks, chunks)
        self.assertEqual(3, self.api.container._direct_request.call_count)
        self.assertEqual(1, len(self.cache))

        obj_meta, chunks = self.api.object_locate(
            self.account, self.container, self.path, properties=True)
        for chunk in chunks:
            del chunk['score']
        self.assertDictEqual(expected_obj_meta, obj_meta)
        self.assertListEqual(expected_chunks, chunks)
        self.assertEqual(3, self.api.container._direct_request.call_count)
        self.assertEqual(1, len(self.cache))

        expected_obj_meta['properties'] = dict()
        obj_meta, chunks = self.api.object_locate(
            self.account, self.container, self.path, properties=False)
        for chunk in chunks:
            del chunk['score']
        self.assertDictEqual(expected_obj_meta, obj_meta)
        self.assertListEqual(expected_chunks, chunks)
        self.assertEqual(3, self.api.container._direct_request.call_count)
        self.assertEqual(1, len(self.cache))

        expected_obj_meta['properties'] = properties
        obj_meta = self.api.object_get_properties(
            self.account, self.container, self.path)
        self.assertDictEqual(expected_obj_meta, obj_meta)
        self.assertEqual(3, self.api.container._direct_request.call_count)
        self.assertEqual(1, len(self.cache))

    def test_object_fetch(self):
        expected_obj_meta, stream = self.api.object_fetch(
            self.account, self.container, self.path)
        self.assertIsNotNone(expected_obj_meta)
        data = b''
        for chunk in stream:
            data += chunk
        self.assertEqual(b'cache', data)
        self.assertEqual(1, self.api.container._direct_request.call_count)
        self.assertEqual(1, len(self.cache))

        obj_meta, stream = self.api.object_fetch(
            self.account, self.container, self.path)
        self.assertDictEqual(expected_obj_meta, obj_meta)
        data = b''
        for chunk in stream:
            data += chunk
        self.assertEqual(b'cache', data)
        self.assertEqual(1, self.api.container._direct_request.call_count)
        self.assertEqual(1, len(self.cache))

        # Make the cache invalid
        self.api.object_delete(
            self.account, self.container, self.path, cache=None)
        self.assertEqual(2, self.api.container._direct_request.call_count)
        self.assertEqual(1, len(self.cache))
        self.wait_for_event(
            'oio-preserved', types=[EventTypes.CONTENT_DELETED])

        obj_meta, stream = self.api.object_fetch(
            self.account, self.container, self.path)
        self.assertDictEqual(expected_obj_meta, obj_meta)
        try:
            data = b''
            for chunk in stream:
                data += chunk
            self.fail('This should not happen with the deleted chunks')
        except (exc.UnrecoverableContent, exc.NoSuchObject):
            # A former version raised UnrecoverableContent, but newer versions
            # do one retry, and thus see that the object does not exist.
            pass
        self.assertEqual(3, self.api.container._direct_request.call_count)
        self.assertEqual(0, len(self.cache))

        self.assertRaises(
            exc.NoSuchObject, self.api.object_fetch,
            self.account, self.container, self.path)
        self.assertEqual(4, self.api.container._direct_request.call_count)
        self.assertEqual(0, len(self.cache))

    def test_object_fetch_dirty_cache(self):
        # Fetch the original object to make sure the cache is filled.
        self.api.object_fetch(
            self.account, self.container, self.path)
        # Make the cache invalid by overwriting the object without
        # clearing the cache.
        self.api.object_create(self.account, self.container,
                               obj_name=self.path, data='overwritten',
                               cache=None)
        # Wait for the original chunks to be deleted.
        self.wait_for_event('oio-preserved',
                            types=(EventTypes.CHUNK_DELETED, ), timeout=5.0)
        # Read the object. An error will be raised internally, but the latest
        # object should be fetched.
        meta, stream = self.api.object_fetch(
            self.account, self.container, self.path)
        data = b''
        for chunk in stream:
            data += chunk
        self.assertEqual(b'overwritten', data)
        self.assertEqual(len('overwritten'), int(meta['size']))
