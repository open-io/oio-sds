# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2025 OVH SAS
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
from urllib.parse import urlparse

from oio import ObjectStorageApi
from oio.common import exceptions
from oio.common.storage_method import STORAGE_METHODS
from oio.common.utils import cid_from_name
from oio.event.evob import EventTypes
from tests.functional.cli import CliTestCase
from tests.utils import random_str


class ItemRebuildTest(CliTestCase):
    """Functional tests for item to rebuild/repair."""

    @classmethod
    def setUpClass(cls):
        super(ItemRebuildTest, cls).setUpClass()
        cls.api = ObjectStorageApi(cls._cls_ns, endpoint=cls._cls_uri)
        # Prevent the chunks' rebuilds by the rdir crawlers
        cls._service("oio-crawler.target", "stop", wait=3)

    @classmethod
    def tearDownClass(cls):
        cls._service("oio-crawler.target", "start", wait=1)
        super(ItemRebuildTest, cls).tearDownClass()

    def setUp(self):
        super(ItemRebuildTest, self).setUp()
        self.rawx_services = None

        self.container = "item_rebuild_container" + random_str(4)
        self.obj_name = "item_rebuild_obj_" + random_str(4)
        self.clean_later(self.container, self.account)

    def tearDown(self):
        for acct, ct in self._containers_to_clean:
            try:
                self.storage.container_flush(acct, ct)
                self.storage.container_delete(acct, ct)
            except Exception as exc:
                self.logger.info("Failed to clean container %s", exc)
        super().tearDown()

    def _wait_events(self, account, container, obj_name):
        self.wait_for_kafka_event(
            fields={"account": account, "user": container, "path": obj_name},
            types=(EventTypes.CONTENT_NEW,),
        )
        self.wait_for_kafka_event(
            fields={"account": account, "user": container},
            types=(EventTypes.CONTAINER_STATE,),
        )

    def create_object(self, account, container, obj_name, policy=None):
        self.api.object_create(
            account,
            container,
            obj_name=obj_name,
            data="test_item_rebuild",
            policy=policy,
        )
        obj_meta, obj_chunks = self.api.object_locate(account, container, obj_name)
        self._wait_events(account, container, obj_name)
        self.clean_later(container, account)
        return obj_meta, obj_chunks

    def test_chunk_rebuild(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        stg_met = STORAGE_METHODS.load(obj_meta["chunk_method"])
        if stg_met.expected_chunks <= stg_met.min_chunks_to_read:
            self.skipTest("")

        expected_items = list()
        expected_items.append("account account=%s OK" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s OK"
            % (self.account, self.container, cid)
        )

        # Delete first chunk
        missing_chunk = random.choice(obj_chunks)
        self.api.blob_client.chunk_delete(missing_chunk["url"])
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s error"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        for chunk in obj_chunks:
            if chunk["url"] == missing_chunk["url"]:
                status = "error"
            else:
                status = "OK"
            expected_items.append("chunk chunk=%s %s" % (chunk["url"], status))

        second_obj = "item_rebuild_second_obj_" + random_str(4)
        second_obj_meta, second_obj_chunks = self.create_object(
            self.account, self.container, second_obj
        )

        # Delete first chunk
        second_missing_chunk = random.choice(second_obj_chunks)
        self.api.blob_client.chunk_delete(second_missing_chunk["url"])
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s error"
            % (
                self.account,
                self.container,
                cid,
                second_obj,
                second_obj_meta["id"],
                second_obj_meta["version"],
            )
        )
        for chunk in second_obj_chunks:
            if chunk["url"] == second_missing_chunk["url"]:
                status = "error"
            else:
                status = "OK"
            expected_items.append("chunk chunk=%s %s" % (chunk["url"], status))

        # Check with missing chunks
        _, chunks_to_repair_file = mkstemp()
        opts = self.get_format_opts(fields=["Type", "Item", "Status"])
        output = self.openio_admin(
            '--oio-account %s container check %s --output-for-chunk-rebuild "%s" %s'
            % (self.account, self.container, chunks_to_repair_file, opts),
            expected_returncode=1,
        )
        self.assert_list_output(expected_items, output)

        expected_items = list()
        expected_items.append(
            "%s|%s|%s|%s|%s|%s OK"
            % (
                self.ns,
                cid,
                obj_meta["id"],
                obj_meta["name"],
                str(obj_meta["version"]),
                missing_chunk["url"],
            )
        )
        expected_items.append(
            "%s|%s|%s|%s|%s|%s OK"
            % (
                self.ns,
                cid,
                second_obj_meta["id"],
                second_obj_meta["name"],
                str(second_obj_meta["version"]),
                second_missing_chunk["url"],
            )
        )

        # Rebuild missing chunks
        opts = self.get_format_opts(fields=["Chunk", "Status"])
        output = self.openio_admin(
            '--oio-account %s chunk rebuild --input-file "%s" %s'
            % (self.account, chunks_to_repair_file, opts)
        )
        self.assert_list_output(expected_items, output)

    def test_object_repair_from_shard(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        stg_met = STORAGE_METHODS.load(obj_meta["chunk_method"])
        if stg_met.expected_chunks <= stg_met.min_chunks_to_read:
            self.skipTest("Needs EC or replication")

        # Create some other objects
        for i in range(3):
            self.api.object_create(
                self.account, self.container, obj_name=f"~{i}", data="test_item_rebuild"
            )
        # Split the container into 2 shards
        test_shards = [
            {"index": 0, "lower": "", "upper": "~1"},
            {"index": 1, "lower": "~1", "upper": ""},
        ]
        new_shards = self.container_sharding.format_shards(test_shards, are_new=True)
        modified = self.container_sharding.replace_shard(
            self.account, self.container, new_shards, enable=True
        )
        self.assertTrue(modified)

        # Find the name of the shard our test object is in
        shards = list(self.container_sharding.show_shards(self.account, self.container))
        shard_account, shard_container = self.storage.resolve_cid(shards[0]["cid"])

        # Delete first chunk
        missing_chunk = random.choice(obj_chunks)
        self.api.blob_client.chunk_delete(missing_chunk["url"])

        # Repair
        opts = self.get_format_opts("json")
        output = self.openio_admin(
            f"object repair -a {shard_account} {shard_container} {self.obj_name} "
            f"{opts}",
            expected_returncode=0,
        )
        repaired = self.json_loads(output)
        self.assertEqual(len(repaired), 1)

        # Ensure all chunks are joinable
        _, obj_chunks_after = self.api.object_locate(
            shard_account, shard_container, self.obj_name, chunk_info=True
        )
        for chunk in obj_chunks_after:
            self.assertFalse(chunk.get("error", False))

    def _register_chunk(self, chunk, obj_meta):
        payload = {
            "type": "chunk",
            "id": chunk["url"],
            "hash": chunk["hash"],
            "size": chunk["size"],
            "content": obj_meta["id"],
            "pos": chunk["pos"],
        }
        self.api.container.container_raw_insert(
            payload,
            self.account,
            self.container,
            path=obj_meta["name"],
            version=obj_meta["version"],
        )

    def test_object_repair_too_many_chunks_EC(self):
        try:
            obj_meta, obj_chunks = self.create_object(
                self.account,
                self.container,
                self.obj_name,
                policy="EC",
            )
        except exceptions.ServiceBusy as err:
            if "did not find enough services" in str(err):
                self.skipTest("Needs EC")
            raise

        # Copy the 1st chunk on the same rawx as the 2nd chunk
        src_url_p = urlparse(obj_chunks[0]["url"])
        dst_url_p = urlparse(obj_chunks[1]["url"])
        dst_url_str = f"http://{dst_url_p.netloc}/{src_url_p.path}"
        self.api.blob_client.chunk_copy(obj_chunks[0]["url"], dst_url_str)
        dst_chunk = obj_chunks[0].copy()
        dst_chunk["url"] = dst_url_str
        self._register_chunk(dst_chunk, obj_meta)

        # Run object repair
        opts = self.get_format_opts("json")
        output = self.openio_admin(
            f"object repair -a {self.account} {self.container} {self.obj_name} {opts}",
            expected_returncode=0,
        )
        repaired = self.json_loads(output)
        self.assertEqual(len(repaired), 1)

        # Check chunks
        obj_meta_after, obj_chunks_after = self.api.object_locate(
            self.account,
            self.container,
            obj_meta["name"],
        )
        self.assertEqual(len(obj_meta), len(obj_meta_after))
        self.assertEqual(len(obj_chunks), len(obj_chunks_after))
