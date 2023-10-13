# Copyright (C) 2018-2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2023 OVH SAS
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

import string
import os
from mock import MagicMock as Mock, patch

from oio.blob.client import BlobClient
from oio.blob.utils import CHUNK_XATTR_KEYS, read_chunk_metadata
from oio.common.constants import CHUNK_XATTR_CONTENT_FULLPATH_PREFIX
from oio.common.easy_value import true_value
from oio.common.exceptions import FaultyChunk
from oio.common.fullpath import encode_fullpath
from oio.common.utils import cid_from_name, get_hasher, paths_gen, request_id
from oio.crawler.rawx.chunk_wrapper import ChunkWrapper
from oio.crawler.rawx.filters.indexer import Indexer
from oio.event.evob import EventTypes

from tests.functional.blob import random_chunk_id, random_buffer
from tests.functional.crawler.rawx.utils import FilterApp, create_chunk_env
from tests.utils import BaseTestCase, random_id, random_str


def enc(my_str):
    return my_str.encode("utf-8")


class TestBlobIndexer(BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super(TestBlobIndexer, cls).setUpClass()
        # Prevent the chunks' rebuilds by the crawlers
        cls._service("oio-crawler.target", "stop", wait=3)

    @classmethod
    def tearDownClass(cls):
        cls._service("oio-crawler.target", "start", wait=1)
        super(TestBlobIndexer, cls).tearDownClass()

    def setUp(self):
        super(TestBlobIndexer, self).setUp()
        self.rdir_client = self.rdir
        self.blob_client = BlobClient(self.conf, watchdog=self.watchdog)
        _, self.rawx_path, rawx_addr, _ = self.get_service_url("rawx")
        services = self.conscience.all_services("rawx")
        self.rawx_id = None
        for rawx in services:
            if rawx_addr == rawx["addr"]:
                self.rawx_id = rawx["tags"].get("tag.service_id", None)
        if self.rawx_id is None:
            self.rawx_id = rawx_addr
        app = FilterApp
        app.app_env["volume_path"] = self.rawx_path
        app.app_env["volume_id"] = self.rawx_id
        app.app_env["watchdog"] = self.watchdog
        self.indexer = Indexer(app=app, conf=self.conf)
        # clear rawx/rdir
        chunk_files = paths_gen(self.rawx_path)
        for chunk_file in chunk_files:
            os.remove(chunk_file)
        self.rdir_client.admin_clear(self.rawx_id, clear_all=True)
        self.beanstalkd0.drain_tube("oio-preserved")

    def _put_chunk(self):
        account = "blob-indexer-" + random_str(6)
        container = "blob-indexer-" + random_str(6)
        cid = cid_from_name(account, container)
        content_path = "blob-indexer-" + random_str(6)
        content_version = 1234567890
        content_id = random_id(32)
        fullpath = encode_fullpath(
            account, container, content_path, content_version, content_id
        )
        chunk_id = random_chunk_id()
        data = random_buffer(string.printable, 100).encode("utf-8")
        chunk_checksum = get_hasher("blake3")
        chunk_checksum.update(data)
        hex_checksum = chunk_checksum.hexdigest()
        meta = {
            "full_path": fullpath,
            "container_id": cid,
            "content_path": content_path,
            "version": content_version,
            "id": content_id,
            "chunk_method": "ec/algo=liberasurecode_rs_vand,k=6,m=3,cca=blake3",
            "policy": "TESTPOLICY",
            "chunk_hash": hex_checksum.upper(),
            "chunk_pos": 0,
            "metachunk_hash": hex_checksum,
            "metachunk_size": 1024,
        }
        reqid = request_id()
        self.blob_client.chunk_put(
            "http://" + self.rawx_id + "/" + chunk_id, meta, data, reqid=reqid
        )
        # ensure chunk event have been processed
        self.wait_for_event("oio-preserved", reqid=reqid, types=(EventTypes.CHUNK_NEW,))
        return (
            account,
            container,
            cid,
            content_path,
            content_version,
            content_id,
            chunk_id,
        )

    def _delete_chunk(self, chunk_id):
        reqid = request_id()
        self.blob_client.chunk_delete(
            "http://" + self.rawx_id + "/" + chunk_id, reqid=reqid
        )
        # ensure chunk event have been processed
        self.wait_for_event(
            "oio-preserved", reqid=reqid, types=(EventTypes.CHUNK_DELETED,)
        )

    def _link_chunk(self, target_chunk_id):
        account = "blob-indexer-" + random_str(6)
        container = "blob-indexer-" + random_str(6)
        cid = cid_from_name(account, container)
        content_path = "blob-indexer-" + random_str(6)
        content_version = 1234567890
        content_id = random_id(32)
        fullpath = encode_fullpath(
            account, container, content_path, content_version, content_id
        )
        reqid = request_id()
        _, link = self.blob_client.chunk_link(
            "http://" + self.rawx_id + "/" + target_chunk_id,
            None,
            fullpath,
            reqid=reqid,
        )
        chunk_id = link.split("/")[-1]
        # ensure chunk event have been processed
        self.wait_for_event("oio-preserved", reqid=reqid, types=(EventTypes.CHUNK_NEW,))
        return (
            account,
            container,
            cid,
            content_path,
            content_version,
            content_id,
            chunk_id,
        )

    def _chunk_path(self, chunk_id):
        return self.rawx_path + "/" + chunk_id[:3] + "/" + chunk_id

    def _index_pass(self, reset_stats=False, callback=None):
        """Simulates crawl_volume() from oio.crawler.rawx.crawler
        but only calls the process() function of BlobIndexer
        """
        paths = paths_gen(self.rawx_path)
        if reset_stats:
            # pylint: disable=protected-access
            self.indexer._reset_filter_stats()
        for path in paths:
            chunk_id = path.rsplit("/", 1)[-1]
            chunk_env = create_chunk_env(chunk_id, path)
            self.indexer.process(chunk_env, callback)

    def test_indexer(self):
        chunks = list(self.rdir_client.chunk_fetch(self.rawx_id))
        previous_nb_chunk = len(chunks)

        (
            _,
            _,
            expected_cid,
            _,
            _,
            expected_content_id,
            expected_chunk_id,
        ) = self._put_chunk()

        chunks = list(self.rdir_client.chunk_fetch(self.rawx_id))
        self.assertEqual(previous_nb_chunk + 1, len(chunks))
        cid, chunk_id, descr = chunks[0]
        self.assertEqual(expected_cid, cid)
        self.assertEqual(expected_content_id, descr["content_id"])
        self.assertEqual(expected_chunk_id, chunk_id)

        self.rdir_client.admin_clear(self.rawx_id, clear_all=True)
        self._index_pass()
        self.assertEqual(1, self.indexer.successes)
        self.assertEqual(0, self.indexer.errors)

        chunks = self.rdir_client.chunk_fetch(self.rawx_id)
        chunks = list(chunks)
        self.assertEqual(previous_nb_chunk + 1, len(chunks))
        cid, chunk_id, descr = chunks[0]
        self.assertEqual(expected_cid, cid)
        self.assertEqual(expected_content_id, descr["content_id"])
        self.assertEqual(expected_chunk_id, chunk_id)

        self._delete_chunk(expected_chunk_id)
        chunks = self.rdir_client.chunk_fetch(self.rawx_id)
        chunks = list(chunks)
        self.assertEqual(previous_nb_chunk, len(chunks))

    def test_indexer_with_linked_chunk(self):
        if not true_value(self.conf.get("shallow_copy")):
            self.skipTest("Shallow copy disabled")
        (
            _,
            _,
            expected_cid,
            _,
            _,
            expected_content_id,
            expected_chunk_id,
        ) = self._put_chunk()

        chunks = self.rdir_client.chunk_fetch(self.rawx_id)
        chunks = list(chunks)
        self.assertEqual(1, len(chunks))
        cid, chunk_id, descr = chunks[0]
        self.assertEqual(expected_cid, cid)
        self.assertEqual(expected_content_id, descr["content_id"])
        self.assertEqual(expected_chunk_id, chunk_id)

        self.rdir_client.admin_clear(self.rawx_id, clear_all=True)
        self._index_pass()
        self.assertEqual(1, self.indexer.successes)
        self.assertEqual(0, self.indexer.errors)

        chunks = self.rdir_client.chunk_fetch(self.rawx_id)
        chunks = list(chunks)
        self.assertEqual(1, len(chunks))
        cid, chunk_id, descr = chunks[0]
        self.assertEqual(expected_cid, cid)
        self.assertEqual(expected_content_id, descr["content_id"])
        self.assertEqual(expected_chunk_id, chunk_id)

        _, _, linked_cid, _, _, linked_content_id, linked_chunk_id = self._link_chunk(
            expected_chunk_id
        )

        self.rdir_client.admin_clear(self.rawx_id, clear_all=True)
        self._index_pass(reset_stats=True)
        self.assertEqual(2, self.indexer.successes)
        self.assertEqual(0, self.indexer.errors)

        chunks = self.rdir_client.chunk_fetch(self.rawx_id)
        chunks = list(chunks)
        self.assertEqual(2, len(chunks))
        self.assertNotEqual(chunks[0][2], chunks[1][2])
        for chunk in chunks:
            cid, chunk_id, descr = chunk
            if chunk_id == expected_chunk_id:
                self.assertEqual(expected_cid, cid)
                self.assertEqual(expected_content_id, descr["content_id"])
            else:
                self.assertEqual(linked_cid, cid)
                self.assertEqual(linked_content_id, descr["content_id"])
                self.assertEqual(linked_chunk_id, chunk_id)

        self._delete_chunk(expected_chunk_id)
        chunks = self.rdir_client.chunk_fetch(self.rawx_id)
        chunks = list(chunks)
        self.assertEqual(1, len(chunks))
        cid, chunk_id, descr = chunks[0]
        self.assertEqual(linked_cid, cid)
        self.assertEqual(linked_content_id, descr["content_id"])
        self.assertEqual(linked_chunk_id, chunk_id)

        self._delete_chunk(linked_chunk_id)
        chunks = self.rdir_client.chunk_fetch(self.rawx_id)
        chunks = list(chunks)
        self.assertEqual(0, len(chunks))

    def _write_chunk(self, rawx_path, alias="toto", suffix=""):
        cname = "blob-indexer-" + random_str(6)
        container_id = cid_from_name(self.account, cname)
        content_id = random_id(32)
        chunk_id = random_id(64)

        chunk_dir = "%s/%s" % (rawx_path, chunk_id[0:3])
        if not os.path.isdir(chunk_dir):
            os.makedirs(chunk_dir)

        chunk_path = "%s/%s%s" % (chunk_dir, chunk_id, suffix)
        with open(chunk_path, "wb") as chunk_file:
            chunk_file.write(b"toto")

        # pylint: disable=no-member
        os.setxattr(chunk_path, "user." + CHUNK_XATTR_KEYS["chunk_hash"], 32 * b"0")
        os.setxattr(chunk_path, "user." + CHUNK_XATTR_KEYS["chunk_pos"], b"0")
        os.setxattr(chunk_path, "user." + CHUNK_XATTR_KEYS["chunk_size"], b"4")
        os.setxattr(
            chunk_path, "user." + CHUNK_XATTR_KEYS["content_policy"], b"TESTPOLICY"
        )
        os.setxattr(
            chunk_path,
            "user." + CHUNK_XATTR_KEYS["content_chunkmethod"],
            b"plain/nb_copy=3",
        )
        fullpath = encode_fullpath(self.account, cname, alias, 1, content_id)
        os.setxattr(
            chunk_path,
            "user.%s%s" % (CHUNK_XATTR_CONTENT_FULLPATH_PREFIX, chunk_id),
            enc(fullpath),
        )

        return chunk_path, container_id, chunk_id

    def _rdir_get(self, rawx_addr, container_id, chunk_id):
        data = self.rdir_client.chunk_fetch(rawx_addr)
        key = (container_id, chunk_id)
        for i_container, i_chunk, i_value in data:
            if (i_container, i_chunk) == key:
                return i_value
        return None

    def _test_index_chunk(self, alias="toto"):
        # create a fake chunk
        chunk_path, container_id, chunk_id = self._write_chunk(self.rawx_path, alias)

        chunk_env = create_chunk_env(chunk_id, chunk_path)

        with patch(
            "oio.crawler.rawx.filters.indexer.time.time", Mock(return_value=1234)
        ):
            self.indexer.update_index(ChunkWrapper(chunk_env))

        # check rdir
        check_value = self._rdir_get(self.rawx_id, container_id, chunk_id)

        self.assertIsNotNone(check_value)

        self.assertEqual(check_value["mtime"], 1234)

        # index a chunk already indexed
        with patch(
            "oio.crawler.rawx.filters.indexer.time.time", Mock(return_value=4567)
        ):
            self.indexer.update_index(ChunkWrapper(chunk_env))

        # check rdir
        check_value = self._rdir_get(self.rawx_id, container_id, chunk_id)

        self.assertIsNotNone(check_value)

        self.assertEqual(check_value["mtime"], 4567)

    def test_index_chunk(self):
        return self._test_index_chunk()

    def test_index_unicode_chunk(self):
        return self._test_index_chunk('a%%%s%d%xàç"\r\n{0}€ 1+1=2/\\$\t_')

    def test_index_chunk_missing_xattr(self):
        # create a fake chunk
        chunk_path, _, chunk_id = self._write_chunk(self.rawx_path)

        # remove mandatory xattr
        # pylint: disable=no-member
        os.removexattr(chunk_path, "user." + CHUNK_XATTR_KEYS["chunk_pos"])

        with open(chunk_path, "rb") as chunk_file:
            self.assertRaises(FaultyChunk, read_chunk_metadata, chunk_file, chunk_id)
        os.remove(chunk_path)
