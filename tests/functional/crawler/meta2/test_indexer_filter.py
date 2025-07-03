# Copyright (C) 2024-2025 OVH SAS
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

import os.path
import random
import time

from oio.common.constants import M2_PROP_ACCOUNT_NAME, M2_PROP_CONTAINER_NAME
from oio.common.exceptions import NoSuchContainer
from oio.common.statsd import get_statsd
from oio.common.utils import cid_from_name, request_id
from oio.crawler.meta2.filters.indexer import Indexer
from oio.crawler.meta2.meta2db import Meta2DB
from oio.event.evob import EventTypes
from tests.utils import BaseTestCase


class App(object):
    def __init__(self, app_env):
        self.app_env = app_env

    def __call__(self, env, cb):
        self.env = env
        self.cb = cb

    def get_stats(self):
        return {}

    def reset_stats(self):
        pass


class TestIndexer(BaseTestCase):
    DELETE_DELAY: float | None = None
    REMOVE_ORPHANS = False

    @classmethod
    def setUpClass(cls):
        super(TestIndexer, cls).setUpClass()
        # Prevent the sharding/shrinking by the meta2 crawlers
        cls._service("oio-crawler.target", "stop", wait=3)

    @classmethod
    def tearDownClass(cls):
        cls._service("oio-crawler.target", "start", wait=1)
        super(TestIndexer, cls).tearDownClass()

    def setUp(self):
        super().setUp()
        self.cname = f"test_meta2_crawler_{time.time()}"
        self.app_env = {}
        self.app_env["api"] = self.storage
        self.conf["check_orphan"] = True
        self.conf["remove_orphan"] = self.__class__.REMOVE_ORPHANS
        self.conf["delete_delay"] = self.__class__.DELETE_DELAY or Indexer.DELETE_DELAY
        self.app_env["statsd_client"] = get_statsd(
            conf={"statsd_prefix": "test-meta2-indexer"}
        )
        self.indexer = None

    def _create_indexer(self, volume_path):
        self.app_env["volume_path"] = volume_path
        self.indexer = Indexer(App(self.app_env), self.conf, logger=self.logger)

    def tearDown(self):
        try:
            self.storage.container_delete(self.account, self.cname)
        except NoSuchContainer:
            pass
        return super().tearDown()

    def _get_meta2db(self, cname, cid=None):
        cid = cid or cid_from_name(self.account, cname)
        dir_data = self.storage.directory.list(cid=cid, service_type="meta2")
        volume_id = dir_data["srv"][0]["host"]
        volume_path = None
        for srv in self.conscience.all_services("meta2"):
            if volume_id in (srv["addr"], srv["tags"].get("tag.service_id")):
                volume_path = srv["tags"]["tag.vol"]
                break
        else:
            self.fail("Unable to find the volume path")
        meta2db = Meta2DB(self.app_env, {})
        meta2db.real_path = "/".join((volume_path, cid[:3], cid + ".1.meta2"))
        meta2db.volume_id = volume_id
        meta2db.cid = cid
        meta2db.seq = 1
        return meta2db, [srv["host"] for srv in dir_data["srv"]], volume_path

    def test_index_existing_container(self):
        def _cb(status, _msg):
            self.assertEqual(200, status)

        reqid = request_id()
        created = self.storage.container_create(self.account, self.cname, reqid=reqid)
        self.assertTrue(created)
        meta2db, _, volume_path = self._get_meta2db(self.cname)
        self._create_indexer(volume_path)
        self.wait_for_kafka_event(
            fields={"account": self.account, "user": self.cname},
            types=(EventTypes.ACCOUNT_SERVICES,),
            reqid=reqid,
        )
        rdir_hosts = self.indexer.rdir_client._get_resolved_rdir_hosts(
            meta2db.volume_id
        )
        for rdir_host in rdir_hosts:
            # Search all associated rdir in case some didn't get the information
            rdir_info = self.indexer.rdir_client.meta2_search(
                meta2db.volume_id,
                account=self.account,
                container=self.cname,
                rdir_hosts=[rdir_host],
            )
            if rdir_info:
                ctime = rdir_info[0]["mtime"]
                break
        else:
            self.fail("No rdir with the container ID")

        # Wait 1 second to see the mtime update (which is in seconds)
        time.sleep(1)

        self.indexer.process(meta2db.env, _cb)
        filter_stats = self.indexer.get_stats()[self.indexer.NAME]
        for key, value in filter_stats.items():
            if key == "successes":
                self.assertEqual(1, value)
            else:
                self.assertEqual(0, value)
        mtime = 0
        for rdir_host in rdir_hosts:
            # Search all associated rdir in case some didn't get the information
            rdir_info = self.indexer.rdir_client.meta2_search(
                meta2db.volume_id,
                account=self.account,
                container=self.cname,
                rdir_hosts=[rdir_host],
            )
            if rdir_info:
                mtime = max(mtime, rdir_info[0]["mtime"])
        self.assertGreater(mtime, ctime)

    def _check_orphan_filter_stats(self, filter_stats, file_exists=True):
        for key, value in filter_stats.items():
            if key == "orphans":
                self.assertEqual(value, 1)
            elif key == "removed":
                if (
                    self.__class__.REMOVE_ORPHANS
                    and self.indexer.delete_delay < 1.0
                    and file_exists
                ):
                    expected = 1
                else:
                    expected = 0
                self.assertEqual(value, expected, f"{key}={value}")
            else:
                self.assertEqual(value, 0, f"{key}={value}")

    def test_index_non_existing_container(self):
        def _cb(status, msg):
            self.assertEqual(status, 200, msg)

        meta2_conf = random.choice(self.conf["services"]["meta2"])
        meta2_id = meta2_conf.get("service_id", meta2_conf["addr"])
        meta2_path = meta2_conf["path"]

        cid = cid_from_name(self.account, self.cname)
        meta2db = Meta2DB(self.app_env, {})
        meta2db.real_path = "/".join((meta2_path, cid[:3], cid + ".1.meta2"))
        meta2db.volume_id = meta2_id
        meta2db.cid = cid
        meta2db.seq = 1
        meta2db.system = {
            M2_PROP_ACCOUNT_NAME: self.account,
            M2_PROP_CONTAINER_NAME: self.cname,
        }

        self._create_indexer(meta2_path)
        self.indexer.process(meta2db.env, _cb)
        filter_stats = self.indexer.get_stats()[self.indexer.NAME]
        self._check_orphan_filter_stats(filter_stats, file_exists=False)

    def test_index_with_orphan_database(self):
        def _cb(status, msg):
            self.assertEqual(status, 200, msg)

        reqid = request_id()
        created = self.storage.container_create(self.account, self.cname, reqid=reqid)
        self.assertTrue(created)
        meta2db, peers, volume_path = self._get_meta2db(self.cname)
        orther_meta2 = [
            srv.get("service_id", srv["addr"])
            for srv in self.conf["services"]["meta2"]
            if srv.get("service_id", srv["addr"]) not in peers
        ]
        if not orther_meta2:
            self.skipTest("No other meta2 available")
        self._create_indexer(volume_path)
        meta2_id = random.choice(orther_meta2)
        self.wait_for_kafka_event(
            fields={"account": self.account, "user": self.cname},
            types=(EventTypes.ACCOUNT_SERVICES,),
            reqid=reqid,
        )
        true_meta2_id = meta2db.volume_id
        meta2db.volume_id = meta2_id
        rdir_hosts = self.indexer.rdir_client._get_resolved_rdir_hosts(true_meta2_id)
        for rdir_host in rdir_hosts:
            # Search all associated rdir in case some didn't get the information
            rdir_info = self.indexer.rdir_client.meta2_search(
                true_meta2_id,
                account=self.account,
                container=self.cname,
                rdir_hosts=[rdir_host],
            )
            if rdir_info:
                ctime = rdir_info[0]["mtime"]
                break
        else:
            self.fail("No rdir with the container ID")

        # Wait 1 second to see the mtime update (which is in seconds)
        time.sleep(1)

        self.indexer.process(meta2db.env, _cb)
        filter_stats = self.indexer.get_stats()[self.indexer.NAME]
        self._check_orphan_filter_stats(filter_stats)

        mtime = 0
        for rdir_host in rdir_hosts:
            # Search all associated rdir in case some didn't get the information
            rdir_info = self.indexer.rdir_client.meta2_search(
                true_meta2_id,
                account=self.account,
                container=self.cname,
                rdir_hosts=[rdir_host],
            )
            if rdir_info:
                mtime = max(mtime, rdir_info[0]["mtime"])
        # No update
        self.assertEqual(mtime, ctime)

        # Check orphans have been kept or removed (depending on configuration)
        if self.__class__.REMOVE_ORPHANS and self.indexer.delete_delay < 1.0:
            self.assertFalse(os.path.exists(meta2db.real_path))
            orphan_path = os.path.join(
                self.indexer.orphans_dir, os.path.basename(meta2db.real_path)
            )
            self.assertTrue(os.path.exists(orphan_path))
        else:
            self.assertTrue(os.path.exists(meta2db.real_path))


class TestIndexerRemoveOrphans(TestIndexer):
    """
    Test "indexer" filter of oio-meta2-crawler with "remove_orphan" parameter set.
    """

    REMOVE_ORPHANS = True


class TestIndexerRemoveOrphansShortDelay(TestIndexer):
    """
    Test "indexer" filter of oio-meta2-crawler with "remove_orphan" parameter set
    and a really short delete_delay.
    """

    DELETE_DELAY = 0.1
    REMOVE_ORPHANS = True
