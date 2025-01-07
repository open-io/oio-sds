# Copyright (C) 2023-2024 OVH SAS
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

import os
import random
import sqlite3
import time
from os.path import exists, isfile, islink, join
from urllib.parse import urlparse

from oio.common.constants import CHUNK_HEADERS, M2_PROP_OBJECTS
from oio.common.green import get_watchdog
from oio.common.utils import cid_from_name, request_id
from oio.content.factory import ContentFactory
from oio.crawler.meta2.filters.verify_chunk_placement import (
    VerifyChunkPlacement,
)
from oio.crawler.meta2.meta2db import Meta2DB
from oio.directory.admin import AdminClient
from oio.event.evob import EventTypes
from tests.utils import BaseTestCase, random_str


class App(object):
    def __init__(self, app_env):
        self.app_env = app_env

    def __call__(self, env, cb):
        self.env = env
        self.cb = cb

    def get_stats(self):
        return dict()

    def reset_stats(self):
        pass


class TestVerifyChunkPlacement(BaseTestCase):
    """
    Test to verify verifyChunkPlacement of meta2 crawler
    """

    @classmethod
    def setUpClass(cls):
        super(TestVerifyChunkPlacement, cls).setUpClass()
        # Prevent the sharding/shrinking by the meta2 crawlers
        # Prevent the improver to move the misplaced chunks
        cls._service("oio-crawler.target", "stop", wait=3)

    @classmethod
    def tearDownClass(cls):
        # Restart services stopped above
        cls._service("oio-crawler.target", "start", wait=1)
        super(TestVerifyChunkPlacement, cls).tearDownClass()

    def setUp(self):
        super(TestVerifyChunkPlacement, self).setUp()
        self.app_env = dict()
        self.api = self.app_env["api"] = self.storage
        self.admin_client = AdminClient(
            self.conf, logger=self.logger, pool_manager=self.api.container.pool_manager
        )
        self.app_env["watchdog"] = get_watchdog(called_from_main_application=True)
        self.app = App(self.app_env)
        self.conscience_client = self.api.conscience
        self.content_factory = ContentFactory(
            self.conf, logger=self.logger, watchdog=self.app_env["watchdog"]
        )
        self.reqid = request_id()
        self.rawx_srv_list = self.conscience_client.all_services(
            service_type="rawx",
            reqid=self.reqid,
        )
        self.nb_rawx = len(self.conf["services"]["rawx"])
        self.containers = list()

    def tearDown(self):
        try:
            for container in self.containers:
                self.api.container_flush(self.account, container)
                self.api.container_delete(self.account, container, force=True)
        except Exception:
            self.logger.warning("Failed to clean root %s", container)
        return super().tearDown()

    def func_cb(self, status, msg):
        """
        Call back function used only on these tests
        """
        print(
            "Verify chunks placement into meta2 db failed due to error %s, %s",
            status,
            msg,
        )

    def _get_meta2db_env(self, cname=None, cid=None):
        cid = cid or cid_from_name(self.account, cname)
        status = self.admin_client.election_status(
            "meta2", account=self.account, reference=cname
        )
        volume_id = status.get("master", "")
        volume_path = None
        for srv in self.conscience.all_services("meta2"):
            if volume_id in (srv["addr"], srv["tags"].get("tag.service_id")):
                volume_path = srv["tags"]["tag.vol"]
                break
        else:
            self.fail("Unable to find the volume path")
        meta2db = Meta2DB(self.app_env, dict())
        meta2db.real_path = "/".join((volume_path, cid[:3], cid + ".1.meta2"))
        meta2db.volume_id = volume_id
        meta2db.cid = cid
        meta2db.seq = 1
        return meta2db.env

    def _create(self, container, path, policy=None):
        chunks, _, _ = self.api.object_create(
            self.account,
            container,
            obj_name=path,
            data=b"chunk",
            policy=policy,
            reqid=self.reqid,
        )
        self.wait_for_kafka_event(
            reqid=self.reqid,
            timeout=5.0,
            types=(EventTypes.CHUNK_NEW,),
        )
        return chunks

    def _verify_links(
        self, test_chunks, verifychunkplacement, policy, is_already_created=False
    ):
        link_created = []
        srv_ids = {srv["id"]: srv["tags"]["tag.vol"] for srv in self.rawx_srv_list}
        for test_chunk in test_chunks:
            rawx_srv_id = urlparse(test_chunk["url"]).netloc
            server_constraints = verifychunkplacement.policy_data[policy][2][2]
            chunk_test_path = srv_ids[rawx_srv_id]
            chunk_test_id = urlparse(test_chunk["url"]).path[1:]
            misplaced_chunk_dir = "non_optimal_placement"
            symlink_folder = join(
                chunk_test_path, misplaced_chunk_dir, chunk_test_id[:3]
            )
            if exists(symlink_folder):
                symlinks = [
                    link for link in os.listdir(symlink_folder) if chunk_test_id in link
                ]
                if len(symlinks) != 0:
                    chunk_symlink_path = join(
                        symlink_folder,
                        symlinks[0],
                    )
                    link_created.append(islink(chunk_symlink_path))
        diff = max(0, len(test_chunks) - server_constraints)
        self.assertEqual(diff, link_created.count(True))
        if is_already_created:
            # symlink already created at object creation
            self.assertEqual(verifychunkplacement.created_symlinks, 0)
        else:
            self.assertEqual(verifychunkplacement.created_symlinks, diff)

    def _add_objects(self, cname, number_of_obj, pattern_name="content", policy=None):
        created = []
        for i in range(number_of_obj):
            file_name = str(i) + pattern_name
            self.api.object_create(
                self.account,
                cname,
                obj_name=file_name,
                data="data",
                policy=policy,
                chunk_checksum_algo=None,
            )
            created.append(file_name)
        return created

    def _generate_meta2db(self, nb_obj):
        """
        Generate a large meta2 db to use when testing the verify chunk placement
        meta2 crawler filter
        """
        cname = self._create_container()
        obj_created = self._add_objects(
            cname=cname, number_of_obj=nb_obj, policy="JUSTENOUGH"
        )
        # Get the meta2 db
        meta2db_env = self._get_meta2db_env(cname)
        return cname, obj_created, meta2db_env

    def _compute_meta2_db_size(self, container):
        container_result = self.api.container_get_properties(
            self.account, container, admin_mode=True
        )
        page_count = int(container_result["system"]["stats.page_count"])
        page_size = int(container_result["system"]["stats.page_size"])
        meta2_db_size = page_count * page_size
        print(
            "Meta2 database size: %d bytes, page count: %d, page size: %d."
            % (meta2_db_size, page_count, page_size)
        )
        return meta2_db_size

    def _create_container(self):
        # With full repli environment sometimes we get the error below
        # [ServiceBusy('META1 error: Query error: found only 0 services matching
        # the criteria: no service polled from [meta2], 0/3 services polled,
        # 0 known services, # 0 services in slot, min_dist=1,
        # strict_location_constraint=0.0.0.0')]
        # That is why we added a time to make sure meta2 services are available
        # Passed the timeout the test will fail
        self.wait_for_score(("meta2",), timeout=5.0)
        cname = f"test_meta2_crawler_{time.time()}"
        iscreated = self.api.container_create(self.account, cname)
        self.assertTrue(iscreated)
        self.containers.append(cname)
        return cname

    def _remove_symlinks(self, chunks, chunk=None):
        if chunk is None:
            chunk = random.choice(chunks)
        chunk_ip_addr = urlparse(chunk["real_url"]).netloc.split(":")[0]
        # Choose the chunks that are on the same server as the chunk selected
        chunks_test = [c for c in chunks if chunk_ip_addr in c["real_url"]]

        for chunk_test in chunks_test:
            chunk_test_path = [
                srv["tags"]["tag.vol"]
                for srv in self.rawx_srv_list
                if srv["id"] == urlparse(chunk_test["url"]).netloc
            ][0]
            chunk_test_id = urlparse(chunk_test["url"]).path[1:]
            misplaced_chunk_dir = "non_optimal_placement"
            symlink_folder = join(
                chunk_test_path, misplaced_chunk_dir, chunk_test_id[:3]
            )
            if exists(symlink_folder):
                symlinks = [
                    file for file in os.listdir(symlink_folder) if chunk_test_id in file
                ]
                if len(symlinks) != 0:
                    path_link = join(
                        symlink_folder,
                        symlinks[0],
                    )
                    if islink(path_link):
                        # Remove the link created at the creation of the object
                        os.remove(path_link)
                        # Set the misplaced chunk header to False
                        headers = {CHUNK_HEADERS["non_optimal_placement"]: False}
                        self.api.blob_client.chunk_post(
                            url=chunk_test["url"], headers=headers
                        )
        return chunks_test

    def _check_shards(self, new_shards, test_shards, shards_content):
        # check shards
        for index, shard in enumerate(new_shards):
            resp = self.api.container.container_get_properties(cid=shard["cid"])
            found_object_in_shard = int(resp["system"][M2_PROP_OBJECTS])
            self.assertEqual(found_object_in_shard, len(shards_content[index]))

            lower = resp["system"]["sys.m2.sharding.lower"]
            upper = resp["system"]["sys.m2.sharding.upper"]

            # lower & upper contain < & > chars, remove them
            self.assertEqual(lower[1:], test_shards[index]["lower"])
            self.assertEqual(upper[1:], test_shards[index]["upper"])

            # check object names in each shard
            _, listing = self.api.container.content_list(cid=shard["cid"])

            list_objects = list()
            for obj in listing["objects"]:
                list_objects.append(obj["name"])
                self.assertIn(obj["name"], shards_content[index])

            # check order
            sorted_objects = sorted(list_objects)
            self.assertListEqual(sorted_objects, list_objects)

    def test_filter_on_sharded_meta2db(self):
        """
        Test on sharded meta2 database
        """
        if self.nb_rawx < 9:
            self.skipTest("need at least 9 rawx to run")
        cname = self._create_container()
        chunks_test = list()
        # Create the two objects to test with
        obj1_name = "content_0"
        chunks_1 = self._create(cname, obj1_name, policy="JUSTENOUGH")
        chunks_test.append(self._remove_symlinks(chunks=chunks_1))
        obj2_name = "content_1"
        chunks_2 = self._create(cname, obj2_name, policy="JUSTENOUGH")
        chunks_test.append(self._remove_symlinks(chunks=chunks_2))
        test_shards = [
            {"index": 0, "lower": "", "upper": "content_0."},
            {"index": 1, "lower": "content_0.", "upper": ""},
        ]
        new_shards = self.container_sharding.format_shards(test_shards, are_new=True)
        # With full repli environment sometimes we get the error below
        # [ServiceBusy('META1 error: Query error: found only 0 services matching
        # the criteria: no service polled from [meta2], 0/3 services polled,
        # 0 known services, # 0 services in slot, min_dist=1,
        # strict_location_constraint=0.0.0.0')]
        # That is why we added a time to make sure meta2 services are available
        # Passed the timeout the test will fail
        self.wait_for_score(("meta2",), timeout=5.0)
        modified = self.container_sharding.replace_shard(
            self.account, cname, new_shards, enable=True
        )
        self.assertTrue(modified)
        # check shards
        show_shards = self.container_sharding.show_shards(self.account, cname)
        shards_content = [{"content_0"}, {"content_1"}]
        self._check_shards(show_shards, test_shards, shards_content)
        for index, shard in enumerate(show_shards):
            meta2db_env = self._get_meta2db_env(cid=shard["cid"])
            self.app.app_env["volume_id"] = meta2db_env["volume_id"]
            # Initialize the meta2 crawler filter to test
            verifychunkplacement = VerifyChunkPlacement(app=self.app, conf=self.conf)
            verifychunkplacement.process(meta2db_env, self.func_cb)
            self.assertEqual(verifychunkplacement.successes, 1)
            self.assertTrue(isfile(meta2db_env["path"]))
            self.assertFalse(
                isfile(meta2db_env["path"] + "." + verifychunkplacement.suffix)
            )
            self._verify_links(
                chunks_test[index], verifychunkplacement, policy="JUSTENOUGH"
            )

        # Delete container created from the sharding
        for shard in show_shards:
            self.api.container.container_flush(cid=shard["cid"])
            self.api.container.container_delete(cid=shard["cid"])

    def test_filter_on_larger_meta2db(self):
        """
        Test on larger meta2 database
        """
        if self.nb_rawx < 9:
            self.skipTest("need at least 9 rawx to run")
        start_obj_creation = time.time()
        cname, obj_created, meta2db_env = self._generate_meta2db(100)
        nb_obj = len(obj_created)
        end_obj_creation = time.time()
        diff = end_obj_creation - start_obj_creation or 1
        print(
            "Creating %d objects took %fs seconds, %f objects per second."
            % (nb_obj, diff, nb_obj / diff)
        )
        start = time.time()
        self.app.app_env["volume_id"] = meta2db_env["volume_id"]
        # Initialize the meta2 crawler filter to test
        verifychunkplacement = VerifyChunkPlacement(app=self.app, conf=self.conf)
        verifychunkplacement.process(meta2db_env, self.func_cb)
        end = time.time()
        diff = end - start or 1
        print(
            "Verifying chunks took %fs seconds, %f object per second."
            % (diff, nb_obj / diff)
        )
        self.assertEqual(verifychunkplacement.successes, 1)
        self.assertTrue(isfile(meta2db_env["path"]))
        self.assertFalse(
            isfile(meta2db_env["path"] + "." + verifychunkplacement.suffix)
        )
        self._compute_meta2_db_size(cname)
        end_test = time.time()
        print("The test took %s s " % str(end_test - start_obj_creation))

    def test_meta2_check_with_chunk_already_tagged_as_misplaced(self):
        """
        Check if the chunk misplaced are detected and are tagged by
        the verificationChunkPlacement filter of meta2 crawler
        """
        if self.nb_rawx < 9:
            self.skipTest("need at least 9 rawx to run")
        cname = self._create_container()
        # Create the object to test with
        object_name = "m_chunk-" + random_str(8)
        chunks = self._create(cname, object_name, policy="JUSTENOUGH")
        # After object creation, misplaced tag are added on te chunks
        # if the placement is not optimal
        chunk = random.choice(chunks)
        chunk_ip_addr = urlparse(chunk["real_url"]).netloc.split(":")[0]
        # Get the meta2 db
        meta2db_env = self._get_meta2db_env(cname)
        self.app.app_env["volume_id"] = meta2db_env["volume_id"]
        # Initialize the meta2 crawler filter to test
        verifychunkplacement = VerifyChunkPlacement(app=self.app, conf=self.conf)
        verifychunkplacement.process(
            meta2db_env,
            self.func_cb,
        )
        self.assertEqual(verifychunkplacement.successes, 1)
        self.assertTrue(isfile(meta2db_env["path"]))
        self.assertFalse(
            isfile(meta2db_env["path"] + "." + verifychunkplacement.suffix)
        )
        # Choose the chunks that are on the same server as the chunk selected
        chunks_test = [c for c in chunks if chunk_ip_addr in c["real_url"]]
        self._verify_links(
            chunks_test,
            verifychunkplacement,
            policy="JUSTENOUGH",
            is_already_created=True,
        )

    def test_meta2_check_if_tag_misplaced_is_added(self):
        """
        Check if verifyChunkPlacement filter of placement checker crawler
        adds misplaced tag on chunk misplaced like it should
        """
        if self.nb_rawx < 9:
            self.skipTest("need at least 9 rawx to run")
        cname = self._create_container()
        # Create the object to test with
        object_name = "m_chunk-" + random_str(8)
        chunks = self._create(cname, object_name, policy="JUSTENOUGH")
        # After object creation, misplaced tag are added on te chunks
        # if the placement is not optimal
        chunks_test = self._remove_symlinks(chunks)

        # Get the meta2 db
        meta2db_env = self._get_meta2db_env(cname)
        self.app.app_env["volume_id"] = meta2db_env["volume_id"]
        # Initialize the meta2 crawler filter to test
        verifychunkplacement = VerifyChunkPlacement(app=self.app, conf=self.conf)
        verifychunkplacement.process(meta2db_env, self.func_cb)
        self.assertEqual(verifychunkplacement.successes, 1)
        self.assertTrue(isfile(meta2db_env["path"]))
        self.assertFalse(
            isfile(meta2db_env["path"] + "." + verifychunkplacement.suffix)
        )
        self._verify_links(
            chunks_test,
            verifychunkplacement,
            policy="JUSTENOUGH",
        )

    def test_get_all_chunks(self):
        """
        Test the method that fetch all the chunks referenced in the meta2 db
        """
        if self.nb_rawx < 9:
            self.skipTest("need at least 9 rawx to run")
        cname = self._create_container()
        # Create the object to test with
        object_name = "m_chunk-" + random_str(8)
        chunks = self._create(cname, object_name, policy="JUSTENOUGH")
        chunks_ids = {chunk["url"].split("/", 3)[2]: chunk["pos"] for chunk in chunks}
        # Get the meta2 db
        meta2db_env = self._get_meta2db_env(cname)
        self.app.app_env["volume_id"] = meta2db_env["volume_id"]
        # Initialize the meta2 crawler filter to test
        verifychunkplacement = VerifyChunkPlacement(app=self.app, conf=self.conf)

        params = {
            "service_type": "meta2",
            "cid": meta2db_env["cid"],
            "svc_from": meta2db_env["volume_id"],
            "suffix": verifychunkplacement.suffix,
        }
        try:
            # Request a local copy of the meta2 database
            verifychunkplacement.admin_client.copy_base_local(**params)
            meta2db_copy_path = meta2db_env["path"] + "." + verifychunkplacement.suffix
            cursor = None
            with sqlite3.connect(meta2db_copy_path) as connection:
                cursor = connection.cursor()
                chunks_data = verifychunkplacement._get_all_chunks(meta2db_cur=cursor)
                counter = 0
                for chunk in chunks_data:
                    rawx_srv_id = chunk[0]
                    chunk_pos = chunk[1]
                    self.assertTrue(rawx_srv_id in chunks_ids)
                    self.assertTrue(chunks_ids[rawx_srv_id] == chunk_pos)
                    counter += 1
                self.assertEqual(counter, len(chunks))
                params = {
                    "service_type": "meta2",
                    "cid": meta2db_env["cid"],
                    "service_id": meta2db_env["volume_id"],
                    "suffix": verifychunkplacement.suffix,
                }
                verifychunkplacement.admin_client.remove_base(**params)

        finally:
            if cursor:
                # Close the cursor of the meta2 database local copy
                cursor.close()

    def test_rebuild_deleted_raw_in_meta2(self):
        """
        Test if a chunk deleted in meta2 database is rebuilt by the crawler
        """
        if self.nb_rawx < 9:
            self.skipTest("need at least 9 rawx to run")
        # Create container
        cname = self._create_container()
        # Create the object to test with
        object_name = "m_chunk-" + random_str(8)
        data = random_str(1024 * 1024 * 4)
        chunks, _, _, obj_meta = self.api.object_create_ext(
            account=self.account,
            container=cname,
            obj_name=object_name,
            data=data,
            policy="JUSTENOUGH",
        )
        self.wait_for_kafka_event(
            reqid=self.reqid,
            timeout=5.0,
            types=(EventTypes.CHUNK_NEW,),
        )

        # Select chunk to remove in meta2
        chunks_to_remove = []
        chunks_to_remove.append(chunks[0])
        for chunk in chunks_to_remove:
            chunk["id"] = chunk["url"]
            chunk["content"] = obj_meta["id"]
            chunk["type"] = "chunk"
        self.api.container.container_raw_delete(
            self.account,
            cname,
            data=chunks_to_remove,
            path=obj_meta["name"],
            version=obj_meta["version"],
        )
        _, chunks_loc = self.api.object_locate(
            self.account,
            cname,
            object_name,
            obj_meta["version"],
        )
        # self._remove_symlinks(chunks, chunks_to_remove[0])
        self.assertEqual(len(chunks_loc), len(chunks) - 1)
        # # Get the meta2 db
        meta2db_env = self._get_meta2db_env(cname)
        self.app.app_env["volume_id"] = meta2db_env["volume_id"]
        # Initialize the meta2 crawler filter to test
        verifychunkplacement = VerifyChunkPlacement(app=self.app, conf=self.conf)
        verifychunkplacement.process(meta2db_env, self.func_cb)
        self.assertEqual(verifychunkplacement.successes, 1)
        _, chunks_loc = self.api.object_locate(
            self.account,
            cname,
            object_name,
            obj_meta["version"],
        )
        if verifychunkplacement.rebuilt_chunks > 0:
            self.assertEqual(verifychunkplacement.rebuilt_chunks, 1)
            self.assertEqual(len(chunks_loc), len(chunks))
        else:
            # Sometime we get a service busy exception
            self.assertEqual(verifychunkplacement.failed_rebuild, 1)
            self.assertEqual(len(chunks_loc), len(chunks) - 1)
        self.assertTrue(isfile(meta2db_env["path"]))
        self.assertFalse(
            isfile(meta2db_env["path"] + "." + verifychunkplacement.suffix)
        )
