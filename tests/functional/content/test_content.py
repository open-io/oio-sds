# -*- coding: utf-8 -*-
# Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
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

import hashlib

import os
import time
from io import BytesIO
from mock import MagicMock as Mock
from testtools.matchers import Contains
from testtools.matchers import Not
from testtools.testcase import ExpectedException

from six import PY2

from oio.blob.client import BlobClient
from oio.common.exceptions import ContentNotFound, OrphanChunk
from oio.common.utils import cid_from_name
from oio.common.fullpath import encode_fullpath
from oio.container.client import ContainerClient
from oio.content.factory import ContentFactory
from oio.content.plain import PlainContent
from oio.content.ec import ECContent
from tests.utils import BaseTestCase, ec, strange_paths


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

        self.wait_for_score(('meta2', ))
        self.namespace = self.conf['namespace']
        self.chunk_size = self.conf['chunk_size']
        self.gridconf = {"namespace": self.namespace}
        self.content_factory = ContentFactory(self.gridconf)
        self.container_name = "TestContentFactory%f" % time.time()
        self.blob_client = BlobClient(conf=self.conf)
        self.container_client = ContainerClient(self.gridconf)
        self.container_client.container_create(account=self.account,
                                               reference=self.container_name)
        self.container_id = cid_from_name(self.account,
                                          self.container_name).upper()
        self.stgpol = "SINGLE"
        self.stgpol_twocopies = "TWOCOPIES"
        self.stgpol_threecopies = "THREECOPIES"
        self.stgpol_ec = "EC"

    def tearDown(self):
        super(TestContentFactory, self).tearDown()

    def test_get_ec(self):
        meta = {
            "chunk_method": "ec/algo=liberasurecode_rs_vand,k=6,m=2",
            "ctime": "1450176946",
            "deleted": "False",
            "hash": "E952A419957A6E405BFC53EC65483F73",
            "hash_method": "md5",
            "id": "3FA2C4A1ED2605005335A276890EC458",
            "length": "658",
            "mime_type": "application/octet-stream",
            "name": "tox.ini",
            "policy": self.stgpol_ec,
            "version": "1450176946676289",
            "oio_version": "4.2",
        }
        chunks = [
            {
                "url": "http://127.0.0.1:6012/A0A0",
                "pos": "0.0", "size": 512,
                "hash": "E7D4E4AD460971CA2E3141F2102308D4"},
            {
                "url": "http://127.0.0.1:6010/A01",
                "pos": "0.1", "size": 146,
                "hash": "760AB5DA7C51A3654F1CA622687CD6C3"},
            {
                "url": "http://127.0.0.1:6011/A00",
                "pos": "0.2", "size": 512,
                "hash": "B1D08B86B8CAA90A2092CCA0DF9201DB"},
            {
                "url": "http://127.0.0.1:6013/A0A1",
                "pos": "0.3", "size": 512,
                "hash": "DA9D7F72AEEA5791565724424CE45C16"}
        ]
        self.content_factory.container_client.content_locate = Mock(
            return_value=(meta, chunks))
        c = self.content_factory.get("xxx_container_id", "xxx_content_id",
                                     account=self.account,
                                     container_name=self.container_name)
        self.assertEqual(type(c), ECContent)
        self.assertEqual(c.content_id, "3FA2C4A1ED2605005335A276890EC458")
        self.assertEqual(c.length, 658)
        self.assertEqual(c.path, "tox.ini")
        self.assertEqual(c.full_path,
                         encode_fullpath(self.account, self.container_name,
                                         "tox.ini", meta['version'],
                                         meta['id']))
        self.assertEqual(c.version, "1450176946676289")
        # TODO test storage method
        self.assertEqual(len(c.chunks), 4)
        self.assertEqual(c.chunks[0].raw(), chunks[0])
        self.assertEqual(c.chunks[1].raw(), chunks[1])
        self.assertEqual(c.chunks[2].raw(), chunks[2])
        self.assertEqual(c.chunks[3].raw(), chunks[3])

    def test_get_plain(self):
        meta = {
            "chunk_method": "plain/nb_copy=2",
            "ctime": "1450176946",
            "deleted": "False",
            "hash": "E952A419957A6E405BFC53EC65483F73",
            "hash_method": "md5",
            "id": "3FA2C4A1ED2605005335A276890EC458",
            "length": "658",
            "mime_type": "application/octet-stream",
            "name": "tox.ini",
            "policy": self.stgpol_twocopies,
            "version": "1450176946676289",
            "oio_version": "4.2",
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
        self.content_factory.container_client.content_locate = Mock(
            return_value=(meta, chunks))
        c = self.content_factory.get("xxx_container_id", "xxx_content_id",
                                     account=self.account,
                                     container_name=self.container_name)
        self.assertEqual(type(c), PlainContent)
        self.assertEqual(c.content_id, "3FA2C4A1ED2605005335A276890EC458")
        self.assertEqual(c.length, 658)
        self.assertEqual(c.path, "tox.ini")
        self.assertEqual(c.version, "1450176946676289")
        self.assertEqual(c.full_path,
                         encode_fullpath(self.account, self.container_name,
                                         "tox.ini", meta['version'],
                                         meta['id']))
        # TODO test storage_method
        self.assertEqual(len(c.chunks), 2)
        self.assertEqual(c.chunks[0].raw(), chunks[0])
        self.assertEqual(c.chunks[1].raw(), chunks[1])

    def test_get_unknown_content(self):
        self.assertRaises(ContentNotFound, self.content_factory.get,
                          self.container_id, "1234")

    def test_new_ec(self):
        meta = {
            "chunk_method": "ec/algo=liberasurecode_rs_vand,k=6,m=2",
            "ctime": "1450341162",
            "deleted": "False",
            "hash": "",
            "hash_method": "md5",
            "id": "F4B1C8DD132705007DE8B43D0709DAA2",
            "length": "1000",
            "mime_type": "application/octet-stream",
            "name": "titi",
            "policy": self.stgpol_ec,
            "version": "1450341162332663",
            "oio_version": "4.2",
        }
        chunks = [
            {
                "url": "http://127.0.0.1:6010/0_p1",
                "pos": "0.3", "size": 1048576,
                "hash": "00000000000000000000000000000000"},
            {
                "url": "http://127.0.0.1:6011/0_p0",
                "pos": "0.2", "size": 1048576,
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
                                     1000, self.stgpol_ec,
                                     account=self.account,
                                     container_name=self.container_name)
        self.assertEqual(type(c), ECContent)
        self.assertEqual(c.content_id, "F4B1C8DD132705007DE8B43D0709DAA2")
        self.assertEqual(c.length, 1000)
        self.assertEqual(c.path, "titi")
        self.assertEqual(c.version, "1450341162332663")
        # TODO test storage_method
        self.assertEqual(len(c.chunks), 4)
        self.assertEqual(c.chunks[0].raw(), chunks[3])
        self.assertEqual(c.chunks[1].raw(), chunks[2])
        self.assertEqual(c.chunks[2].raw(), chunks[1])
        self.assertEqual(c.chunks[3].raw(), chunks[0])

    def _new_content(self, stgpol, data, path="titi", account=None,
                     container_name=None, mime_type=None, properties=None):
        old_content = self.content_factory.new(self.container_id, path,
                                               len(data), stgpol,
                                               account=account,
                                               container_name=container_name)
        if properties:
            old_content.properties = properties
        if mime_type:
            old_content.mime_type = mime_type
        old_content.create(BytesIO(data))
        return self.content_factory.get(self.container_id,
                                        old_content.content_id)

    def _test_move_chunk(self, policy):
        data = random_data(self.chunk_size)
        content = self._new_content(policy, data)

        mc = content.chunks.filter(metapos=0)
        chunk_id = mc[0].id
        chunk_url = mc[0].url
        chunk_host = mc[0].host
        chunk_meta, chunk_stream = self.blob_client.chunk_get(chunk_url)
        chunk_hash = md5_stream(chunk_stream)
        new_chunk = content.move_chunk(chunk_id, service_id=chunk_host)

        content_updated = self.content_factory.get(self.container_id,
                                                   content.content_id)

        hosts = []
        for c in content_updated.chunks.filter(metapos=0):
            self.assertThat(hosts, Not(Contains(c.host)))
            self.assertNotEqual(c.url, chunk_url)
            hosts.append(c.host)

        new_chunk_meta, new_chunk_stream = self.blob_client.chunk_get(
            new_chunk["url"])
        new_chunk_hash = md5_stream(new_chunk_stream)

        self.assertEqual(new_chunk_hash, chunk_hash)
        self.assertGreaterEqual(new_chunk_meta['chunk_mtime'],
                                chunk_meta['chunk_mtime'])

        del chunk_meta["chunk_id"]
        del new_chunk_meta["chunk_id"]
        del chunk_meta["chunk_mtime"]
        del new_chunk_meta["chunk_mtime"]
        self.assertEqual(new_chunk_meta, chunk_meta)

    def test_single_move_chunk(self):
        self._test_move_chunk(self.stgpol)

    def test_twocopies_move_chunk(self):
        self._test_move_chunk(self.stgpol_twocopies)

    @ec
    def test_ec_move_chunk(self):
        self._test_move_chunk(self.stgpol_ec)

    def test_move_chunk_not_in_content(self):
        data = random_data(self.chunk_size)
        content = self._new_content(self.stgpol_twocopies, data)
        with ExpectedException(OrphanChunk):
            content.move_chunk("1234")

    def test_strange_paths(self):
        answers = dict()
        for cname in strange_paths:
            content = self._new_content(self.stgpol, b"nobody cares", cname)
            answers[cname] = content

        _, listing = self.container_client.content_list(self.account,
                                                        self.container_name)
        if PY2:
            obj_set = {k["name"].encode('utf-8') for k in listing["objects"]}
        else:
            obj_set = {k["name"] for k in listing["objects"]}
        try:
            # Ensure the saved path is the one we gave the object
            for cname in answers:
                self.assertEqual(cname, answers[cname].path)
                fullpath = encode_fullpath(
                    self.account, self.container_name, cname,
                    answers[cname].version, answers[cname].content_id)
                self.assertEqual(answers[cname].full_path, fullpath)
            # Ensure all objects appear in listing
            for cname in strange_paths:
                self.assertIn(cname, obj_set)

        finally:
            # Cleanup
            for cname in answers:
                try:
                    content.delete()
                except Exception:
                    pass
