# -*- coding: utf-8 -*-
# Copyright (C) 2015-2017 OpenIO SAS, as part of
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

import hashlib

import os
import time
from io import BytesIO
from mock import MagicMock as Mock
from testtools.matchers import Contains
from testtools.matchers import Not
from testtools.testcase import ExpectedException

from oio.blob.client import BlobClient
from oio.common.exceptions import NotFound, \
    ContentNotFound, ClientException, OrphanChunk
from oio.common.utils import cid_from_name
from oio.container.client import ContainerClient
from oio.content.factory import ContentFactory
from oio.content.plain import PlainContent
from oio.content.ec import ECContent
from tests.utils import BaseTestCase, ec
from urllib import quote_plus


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
        self.blob_client = BlobClient()
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

    def _generate_fullpath(self, account, container_name, path, version):
        return ['{0}/{1}/{2}/{3}'.format(quote_plus(account),
                                         quote_plus(container_name),
                                         quote_plus(path),
                                         version)]

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
            "oio_version": "4.0",
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
                         self._generate_fullpath(self.account,
                                                 self.container_name,
                                                 "tox.ini",
                                                 meta['version']))
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
            "oio_version": "4.0",
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
                         self._generate_fullpath(self.account,
                                                 self.container_name,
                                                 "tox.ini",
                                                 meta['version']))
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
            "oio_version": "4.0",
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
                     container_name=None):
        old_content = self.content_factory.new(self.container_id, path,
                                               len(data), stgpol,
                                               account=account,
                                               container_name=container_name)
        old_content.create(BytesIO(data))
        return self.content_factory.get(self.container_id,
                                        old_content.content_id)

    def _test_change_policy(self, data_size, old_policy, new_policy):
        data = random_data(data_size)
        obj_type = {
            self.stgpol: PlainContent,
            self.stgpol_twocopies: PlainContent,
            self.stgpol_threecopies: PlainContent,
            self.stgpol_ec: ECContent
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

        downloaded_data = "".join(new_content.fetch())

        self.assertEqual(downloaded_data, data)

    @ec
    def test_change_content_0_byte_policy_single_to_ec(self):
        self._test_change_policy(0, self.stgpol, self.stgpol_ec)

    @ec
    def test_change_content_0_byte_policy_ec_to_twocopies(self):
        self._test_change_policy(0, self.stgpol_ec, self.stgpol_twocopies)

    @ec
    def test_change_content_1_byte_policy_single_to_ec(self):
        self._test_change_policy(1, self.stgpol, self.stgpol_ec)

    @ec
    def test_change_content_chunksize_bytes_policy_twocopies_to_ec(self):
        self._test_change_policy(
            self.chunk_size, self.stgpol_twocopies, self.stgpol_ec)

    @ec
    def test_change_content_2xchunksize_bytes_policy_threecopies_to_ec(self):
        self._test_change_policy(
            self.chunk_size * 2, self.stgpol_threecopies, self.stgpol_ec)

    @ec
    def test_change_content_1_byte_policy_ec_to_threecopies(self):
        self._test_change_policy(
            1, self.stgpol_ec, self.stgpol_threecopies)

    @ec
    def test_change_content_chunksize_bytes_policy_ec_to_twocopies(self):
        self._test_change_policy(
            self.chunk_size, self.stgpol_ec, self.stgpol_twocopies)

    @ec
    def test_change_content_2xchunksize_bytes_policy_ec_to_single(self):
        self._test_change_policy(
            self.chunk_size * 2, self.stgpol_ec, self.stgpol)

    def test_change_content_0_byte_policy_twocopies_to_threecopies(self):
        self._test_change_policy(
            0, self.stgpol_twocopies, self.stgpol_threecopies)

    def test_change_content_chunksize_bytes_policy_single_to_twocopies(self):
        self._test_change_policy(
            self.chunk_size, self.stgpol, self.stgpol_twocopies)

    def test_change_content_2xchunksize_bytes_policy_3copies_to_single(self):
        self._test_change_policy(
            self.chunk_size * 2, self.stgpol_threecopies, self.stgpol)

    def test_change_content_with_same_policy(self):
        data = random_data(10)
        old_content = self._new_content(self.stgpol_twocopies, data)
        changed_content = self.content_factory.change_policy(
            old_content.container_id, old_content.content_id,
            self.stgpol_twocopies)
        self.assertEqual(old_content.content_id, changed_content.content_id)

    def test_change_policy_unknown_content(self):
        self.assertRaises(ContentNotFound, self.content_factory.change_policy,
                          self.container_id, "1234", self.stgpol)

    def test_change_policy_unknown_storage_policy(self):
        data = random_data(10)
        old_content = self._new_content(self.stgpol_twocopies, data)
        self.assertRaises(ClientException, self.content_factory.change_policy,
                          self.container_id, old_content.content_id, "UnKnOwN")

    def _test_move_chunk(self, policy):
        data = random_data(self.chunk_size)
        content = self._new_content(policy, data)

        chunk_id = content.chunks.filter(metapos=0)[0].id
        chunk_url = content.chunks.filter(metapos=0)[0].url
        chunk_meta, chunk_stream = self.blob_client.chunk_get(chunk_url)
        chunk_hash = md5_stream(chunk_stream)
        new_chunk = content.move_chunk(chunk_id)

        content_updated = self.content_factory.get(self.container_id,
                                                   content.content_id)

        hosts = []
        for c in content_updated.chunks.filter(metapos=0):
            self.assertThat(hosts, Not(Contains(c.host)))
            self.assertNotEquals(c.id, chunk_id)
            hosts.append(c.host)

        new_chunk_meta, new_chunk_stream = self.blob_client.chunk_get(
            new_chunk["url"])
        new_chunk_hash = md5_stream(new_chunk_stream)

        self.assertEqual(new_chunk_hash, chunk_hash)

        del chunk_meta["chunk_id"]
        del new_chunk_meta["chunk_id"]
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
        strange_paths = [
                "Annual report.txt",
                "foo+bar=foobar.txt",
                "100%_bug_free.c",
                "forward/slash/allowed",
                "I\\put\\backslashes\\and$dollar$signs$in$file$names",
                "Je suis tombé sur la tête, mais ça va bien.",
                "%s%f%u%d%%",
                "{1},{0},{3}",
                "carriage\rreturn",
                "line\nfeed",
                "ta\tbu\tla\ttion",
                "controlchars",
                "//azeaze\\//azeaz\\//azea"
                ]
        answers = dict()
        for cname in strange_paths:
            content = self._new_content(self.stgpol, "nobody cares", cname)
            answers[cname] = content

        _, listing = self.container_client.content_list(self.account,
                                                        self.container_name)
        obj_set = {k["name"].encode("utf8", "ignore")
                   for k in listing["objects"]}
        try:
            # Ensure the saved path is the one we gave the object
            for cname in answers:
                self.assertEqual(cname, answers[cname].path)
                full_path = self._generate_fullpath(self.account,
                                                    self.container_name,
                                                    cname,
                                                    answers[cname].version)
                self.assertEqual(answers[cname].full_path, full_path)
            # Ensure all objects appear in listing
            for cname in strange_paths:
                self.assertIn(cname, obj_set)

        finally:
            # Cleanup
            for cname in answers:
                try:
                    content.delete()
                except:
                    pass
