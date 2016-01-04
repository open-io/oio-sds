# Copyright (C) 2015 OpenIO, original work as part of
# OpenIO Software Defined Storage
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
import StringIO
import hashlib
import os

import time
from mock import MagicMock as Mock

from oio.common.exceptions import InconsistentContent, NotFound, \
    ContentNotFound, ClientException
from oio.common.utils import cid_from_name
from oio.container.client import ContainerClient
from oio.content.factory import ContentFactory
from oio.content.dup import DupContent
from oio.content.rain import RainContent
from tests.utils import BaseTestCase


def md5_stream(stream):
    checksum = hashlib.md5()
    for data in stream:
        checksum.update(data)
    return checksum.hexdigest().upper()


def md5_data(data):
    checksum = hashlib.md5()
    checksum.update(data)
    return checksum.hexdigest().upper()


def random_data(data_size):
    return os.urandom(data_size)


class TestContentFactory(BaseTestCase):
    def setUp(self):
        super(TestContentFactory, self).setUp()
        self.namespace = self.conf['namespace']
        self.chunk_size = self.conf['chunk_size']
        self.gridconf = {"namespace": self.namespace}
        self.content_factory = ContentFactory(self.gridconf)
        self.container_name = "TestContentFactory%f" % time.time()
        self.container_client = ContainerClient(self.gridconf)
        self.container_client.container_create(acct=self.account,
                                               ref=self.container_name)
        self.container_id = cid_from_name(self.account,
                                          self.container_name).upper()

    def tearDown(self):
        super(TestContentFactory, self).tearDown()

    def test_extract_datasec(self):
        self.content_factory.ns_info = {
            "data_security": {
                "DUPONETWO": "DUP:distance=1|nb_copy=2",
                "RAIN": "RAIN:k=6|m=2|algo=liber8tion"
            },
            "storage_policy": {
                "RAIN": "NONE:RAIN:NONE",
                "SINGLE": "NONE:NONE:NONE",
                "TWOCOPIES": "NONE:DUPONETWO:NONE"
            }
        }

        ds_type, ds_args = self.content_factory._extract_datasec("RAIN")
        self.assertEqual(ds_type, "RAIN")
        self.assertEqual(ds_args, {
            "k": "6",
            "m": "2",
            "algo": "liber8tion"
        })

        ds_type, ds_args = self.content_factory._extract_datasec("SINGLE")
        self.assertEqual(ds_type, "DUP")
        self.assertEqual(ds_args, {
            "nb_copy": "1",
            "distance": "0"
        })

        ds_type, ds_args = self.content_factory._extract_datasec("TWOCOPIES")
        self.assertEqual(ds_type, "DUP")
        self.assertEqual(ds_args, {
            "nb_copy": "2",
            "distance": "1"
        })

        self.assertRaises(InconsistentContent,
                          self.content_factory._extract_datasec,
                          "UnKnOwN")

    def test_get_rain(self):
        meta = {
            "chunk-method": "plain/rain?algo=liber8tion&k=6&m=2",
            "ctime": "1450176946",
            "deleted": "False",
            "hash": "E952A419957A6E405BFC53EC65483F73",
            "hash-method": "md5",
            "id": "3FA2C4A1ED2605005335A276890EC458",
            "length": "658",
            "mime-type": "application/octet-stream",
            "name": "tox.ini",
            "policy": "RAIN",
            "version": "1450176946676289"
        }
        chunks = [
            {
                "url": "http://127.0.0.1:6012/A0A0",
                "pos": "0.p0", "size": 512,
                "hash": "E7D4E4AD460971CA2E3141F2102308D4"},
            {
                "url": "http://127.0.0.1:6010/A01",
                "pos": "0.1", "size": 146,
                "hash": "760AB5DA7C51A3654F1CA622687CD6C3"},
            {
                "url": "http://127.0.0.1:6011/A00",
                "pos": "0.0", "size": 512,
                "hash": "B1D08B86B8CAA90A2092CCA0DF9201DB"},
            {
                "url": "http://127.0.0.1:6013/A0A1",
                "pos": "0.p1", "size": 512,
                "hash": "DA9D7F72AEEA5791565724424CE45C16"}
        ]
        self.content_factory.container_client.content_show = Mock(
            return_value=(meta, chunks))
        c = self.content_factory.get("xxx_container_id", "xxx_content_id")
        self.assertEqual(type(c), RainContent)
        self.assertEqual(c.content_id, "3FA2C4A1ED2605005335A276890EC458")
        self.assertEqual(c.length, 658)
        self.assertEqual(c.path, "tox.ini")
        self.assertEqual(c.version, "1450176946676289")
        self.assertEqual(c.algo, "liber8tion")
        self.assertEqual(c.k, 6)
        self.assertEqual(c.m, 2)
        self.assertEqual(len(c.chunks), 4)
        self.assertEqual(c.chunks[0].raw(), chunks[2])
        self.assertEqual(c.chunks[1].raw(), chunks[1])
        self.assertEqual(c.chunks[2].raw(), chunks[0])
        self.assertEqual(c.chunks[3].raw(), chunks[3])

    def test_get_dup(self):
        meta = {
            "chunk-method": "plain/bytes",
            "ctime": "1450176946",
            "deleted": "False",
            "hash": "E952A419957A6E405BFC53EC65483F73",
            "hash-method": "md5",
            "id": "3FA2C4A1ED2605005335A276890EC458",
            "length": "658",
            "mime-type": "application/octet-stream",
            "name": "tox.ini",
            "policy": "TWOCOPIES",
            "version": "1450176946676289"
        }
        chunks = [
            {
                "url": "http://127.0.0.1:6010/A0",
                "pos": "0", "size": 658,
                "hash": "E952A419957A6E405BFC53EC65483F73"},
            {
                "url": "http://127.0.0.1:6011/A1",
                "pos": "0", "size": 658,
                "hash": "E952A419957A6E405BFC53EC65483F73"}
        ]
        self.content_factory.container_client.content_show = Mock(
            return_value=(meta, chunks))
        c = self.content_factory.get("xxx_container_id", "xxx_content_id")
        self.assertEqual(type(c), DupContent)
        self.assertEqual(c.content_id, "3FA2C4A1ED2605005335A276890EC458")
        self.assertEqual(c.length, 658)
        self.assertEqual(c.path, "tox.ini")
        self.assertEqual(c.version, "1450176946676289")
        self.assertEqual(c.nb_copy, 2)
        self.assertEqual(c.distance, 1)
        self.assertEqual(len(c.chunks), 2)
        self.assertEqual(c.chunks[0].raw(), chunks[0])
        self.assertEqual(c.chunks[1].raw(), chunks[1])

    def test_new_rain(self):
        meta = {
            "chunk-method": "plain/rain?algo=liber8tion&k=6&m=2",
            "ctime": "1450341162",
            "deleted": "False",
            "hash": "",
            "hash-method": "md5",
            "id": "F4B1C8DD132705007DE8B43D0709DAA2",
            "length": "1000",
            "mime-type": "application/octet-stream",
            "name": "titi",
            "policy": "RAIN",
            "version": "1450341162332663"
        }
        chunks = [
            {
                "url": "http://127.0.0.1:6010/0_p1",
                "pos": "0.p1", "size": 1048576,
                "hash": "00000000000000000000000000000000"},
            {
                "url": "http://127.0.0.1:6011/0_p0",
                "pos": "0.p0", "size": 1048576,
                "hash": "00000000000000000000000000000000"},
            {
                "url": "http://127.0.0.1:6016/0_1",
                "pos": "0.1", "size": 1048576,
                "hash": "00000000000000000000000000000000"},
            {
                "url": "http://127.0.0.1:6017/0_0",
                "pos": "0.0", "size": 1048576,
                "hash": "00000000000000000000000000000000"}
        ]
        self.content_factory.container_client.content_prepare = Mock(
            return_value=(meta, chunks))
        c = self.content_factory.new("xxx_container_id", "titi",
                                     1000, "RAIN")
        self.assertEqual(type(c), RainContent)
        self.assertEqual(c.content_id, "F4B1C8DD132705007DE8B43D0709DAA2")
        self.assertEqual(c.length, 1000)
        self.assertEqual(c.path, "titi")
        self.assertEqual(c.version, "1450341162332663")
        self.assertEqual(c.algo, "liber8tion")
        self.assertEqual(c.k, 6)
        self.assertEqual(c.m, 2)
        self.assertEqual(len(c.chunks), 4)
        self.assertEqual(c.chunks[0].raw(), chunks[3])
        self.assertEqual(c.chunks[1].raw(), chunks[2])
        self.assertEqual(c.chunks[2].raw(), chunks[1])
        self.assertEqual(c.chunks[3].raw(), chunks[0])

    def _new_content(self, stgpol, data):
        old_content = self.content_factory.new(self.container_id, "titi",
                                               len(data), stgpol)
        old_content.upload(StringIO.StringIO(data))
        return self.content_factory.get(self.container_id,
                                        old_content.content_id)

    def _test_change_policy(self, data_size, old_policy, new_policy):
        if (old_policy == "RAIN" or new_policy == "RAIN") \
                and len(self.conf['rawx']) < 8:
            self.skipTest("RAIN: Need more than 8 rawx to run")

        data = random_data(data_size)
        obj_type = {
            "SINGLE": DupContent,
            "TWOCOPIES": DupContent,
            "THREECOPIES": DupContent,
            "RAIN": RainContent
        }
        old_content = self._new_content(old_policy, data)
        self.assertEqual(type(old_content), obj_type[old_policy])

        changed_content = self.content_factory.change_policy(
            old_content.container_id, old_content.content_id, new_policy)

        self.assertRaises(NotFound, self.container_client.content_show,
                          self.account,
                          cid=old_content.container_id,
                          content=old_content.content_id)

        new_content = self.content_factory.get(self.container_id,
                                               changed_content.content_id)
        self.assertEqual(type(new_content), obj_type[new_policy])

        downloaded_data = "".join(new_content.download())

        self.assertEqual(downloaded_data, data)

    def test_change_content_0_byte_policy_single_to_rain(self):
        self._test_change_policy(0, "SINGLE", "RAIN")

    def test_change_content_0_byte_policy_rain_to_twocopies(self):
        self._test_change_policy(0, "RAIN", "TWOCOPIES")

    def test_change_content_1_byte_policy_single_to_rain(self):
        self._test_change_policy(1, "SINGLE", "RAIN")

    def test_change_content_chunksize_bytes_policy_twocopies_to_rain(self):
        self._test_change_policy(self.chunk_size, "TWOCOPIES", "RAIN")

    def test_change_content_2xchunksize_bytes_policy_threecopies_to_rain(self):
        self._test_change_policy(self.chunk_size * 2, "THREECOPIES", "RAIN")

    def test_change_content_1_byte_policy_rain_to_threecopies(self):
        self._test_change_policy(1, "RAIN", "THREECOPIES")

    def test_change_content_chunksize_bytes_policy_rain_to_twocopies(self):
        self._test_change_policy(self.chunk_size, "RAIN", "TWOCOPIES")

    def test_change_content_2xchunksize_bytes_policy_rain_to_single(self):
        self._test_change_policy(self.chunk_size * 2, "RAIN", "SINGLE")

    def test_change_content_0_byte_policy_twocopies_to_threecopies(self):
        self._test_change_policy(0, "TWOCOPIES", "THREECOPIES")

    def test_change_content_chunksize_bytes_policy_single_to_twocopies(self):
        self._test_change_policy(self.chunk_size, "SINGLE", "TWOCOPIES")

    def test_change_content_2xchunksize_bytes_policy_3copies_to_single(self):
        self._test_change_policy(self.chunk_size * 2, "THREECOPIES", "SINGLE")

    def test_change_content_with_same_policy(self):
        data = random_data(10)
        old_content = self._new_content("TWOCOPIES", data)
        changed_content = self.content_factory.change_policy(
            old_content.container_id, old_content.content_id, "TWOCOPIES")
        self.assertEqual(old_content.content_id, changed_content.content_id)

    def test_change_policy_unknown_content(self):
        self.assertRaises(ContentNotFound, self.content_factory.change_policy,
                          self.container_id, "1234", "SINGLE")

    def test_change_policy_unknown_storage_policy(self):
        data = random_data(10)
        old_content = self._new_content("TWOCOPIES", data)
        self.assertRaises(ClientException, self.content_factory.change_policy,
                          self.container_id, old_content.content_id, "UnKnOwN")
