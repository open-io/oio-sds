# Copyright (C) 2021-2024 OVH SAS
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

import math
import random
import time

from oio.common.constants import (
    M2_PROP_SHARDING_STATE,
    M2_PROP_SHARDING_TIMESTAMP,
    NEW_SHARD_STATE_APPLYING_SAVED_WRITES,
    NEW_SHARD_STATE_CLEANED_UP,
    NEW_SHARD_STATE_CLEANING_UP,
    EXISTING_SHARD_STATE_LOCKED,
)
from oio.common.utils import cid_from_name
from oio.common.statsd import get_statsd
from oio.container.sharding import ContainerSharding
from oio.crawler.meta2.filters.auto_sharding import (
    SHRINKING_COEF_LAST_SHARD,
    AutomaticSharding,
)
from oio.crawler.meta2.meta2db import Meta2DB
from tests.utils import BaseTestCase


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


class TestAutoSharding(BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super(TestAutoSharding, cls).setUpClass()
        # Prevent the sharding/shrinking by the meta2 crawlers
        cls._service("oio-crawler.target", "stop", wait=3)

    @classmethod
    def tearDownClass(cls):
        cls._service("oio-crawler.target", "start", wait=1)
        super(TestAutoSharding, cls).tearDownClass()

    def setUp(self):
        super(TestAutoSharding, self).setUp()
        self.cname = f"test_meta2_crawler_{time.time()}"
        self.container_sharding = ContainerSharding(self.conf)
        self.app_env = dict()
        self.app_env["api"] = self.storage
        self.conf["sharding_db_size"] = 1048576  # 1MB
        self.conf["sharding_strategy"] = "shard-with-partition"
        self.conf["sharding_partition"] = [50, 50]
        self.conf["sharding_threshold"] = 1
        self.conf["shrinking_db_size"] = 262144  # 256KB
        self.app_env["statsd_client"] = get_statsd(
            conf={"statsd_prefix": "test-auto-sharding"}
        )
        self.auto_sharding = AutomaticSharding(App(self.app_env), self.conf)
        created = self.storage.container_create(self.account, self.cname)
        self.assertTrue(created)

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
        meta2db = Meta2DB(self.app_env, dict())
        meta2db.real_path = "/".join((volume_path, cid[:3], cid + ".1.meta2"))
        meta2db.volume_id = volume_id
        meta2db.cid = cid
        meta2db.seq = 1
        return meta2db

    def _find_and_replace(self, cname):
        new_shards = self.container_sharding.find_shards(
            self.account,
            cname,
            strategy="shard-with-partition",
            strategy_params={"threshold": 1},
        )
        modified = self.container_sharding.replace_shard(
            self.account, cname, new_shards, enable=True
        )
        self.assertTrue(modified)
        shards = list(self.container_sharding.show_shards(self.account, cname))
        self.assertEqual(2, len(shards))
        return shards

    def test_nothing_todo(self):
        def _cb(status, _msg):
            self.assertEqual(200, status)

        meta2db = self._get_meta2db(self.cname)
        self.auto_sharding.process(meta2db.env, _cb)
        filter_stats = self.auto_sharding.get_stats()[self.auto_sharding.NAME]
        for key, value in filter_stats.items():
            if key == "skipped":
                self.assertEqual(1, value)
            else:
                self.assertEqual(0, value)

        shards = list(self.container_sharding.show_shards(self.account, self.cname))
        self.assertEqual(0, len(shards))

    def test_sharding_root(self):
        def _cb(status, _msg):
            self.assertEqual(200, status)

        for i in range(2):
            self.storage.object_create(
                self.account, self.cname, obj_name=f"obj-{i}", data=b"data"
            )

        meta2db = self._get_meta2db(self.cname)
        # Simulate a large size to trigger sharding
        meta2db.file_status["st_size"] = meta2db.file_status["st_size"] * 1024
        self.auto_sharding.process(meta2db.env, _cb)
        filter_stats = self.auto_sharding.get_stats()[self.auto_sharding.NAME]
        for key, value in filter_stats.items():
            if key == "sharding_successes":
                self.assertEqual(1, value)
            else:
                self.assertEqual(0, value)

        shards = list(self.container_sharding.show_shards(self.account, self.cname))
        self.assertEqual(2, len(shards))

    def test_sharding_shard(self):
        def _cb(status, _msg):
            self.assertEqual(200, status)

        for i in range(4):
            self.storage.object_create(
                self.account, self.cname, obj_name=f"obj-{i}", data=b"data"
            )
        shards = self._find_and_replace(self.cname)
        shard_cid = random.choice(shards)["cid"]

        meta2db = self._get_meta2db(None, cid=shard_cid)
        # Simulate a large size to trigger sharding
        meta2db.file_status["st_size"] = meta2db.file_status["st_size"] * 1024
        self.auto_sharding.process(meta2db.env, _cb)
        filter_stats = self.auto_sharding.get_stats()[self.auto_sharding.NAME]
        for key, value in filter_stats.items():
            if key == "sharding_successes":
                self.assertEqual(1, value)
            else:
                self.assertEqual(0, value)

        shards = list(self.container_sharding.show_shards(self.account, self.cname))
        self.assertEqual(3, len(shards))

    def test_sharding_empty_container(self):
        def _cb(status, _msg):
            self.assertEqual(200, status)

        meta2db = self._get_meta2db(self.cname)
        # Simulate a large size to trigger sharding
        meta2db.file_status["st_size"] = meta2db.file_status["st_size"] * 1024
        self.auto_sharding.process(meta2db.env, _cb)
        filter_stats = self.auto_sharding.get_stats()[self.auto_sharding.NAME]
        for key, value in filter_stats.items():
            if key == "sharding_no_change":
                self.assertEqual(1, value)
            else:
                self.assertEqual(0, value)

    def test_shrinking(self):
        def _cb(status, _msg):
            self.assertEqual(200, status)

        for i in range(2):
            self.storage.object_create(
                self.account, self.cname, obj_name=f"obj-{i}", data=b"data"
            )
        shards = self._find_and_replace(self.cname)

        # 2 shards
        shard_cid = random.choice(shards)["cid"]
        meta2db = self._get_meta2db(None, cid=shard_cid)
        # Simulate a large size to not trigger shrinking
        meta2db.file_status["st_size"] = self.conf["shrinking_db_size"] + 1
        self.auto_sharding.process(meta2db.env, _cb)
        filter_stats = self.auto_sharding.get_stats()[self.auto_sharding.NAME]
        for key, value in filter_stats.items():
            if key == "skipped":
                self.assertEqual(1, value)
            else:
                self.assertEqual(0, value)
        new_shards = list(self.container_sharding.show_shards(self.account, self.cname))
        self.assertListEqual(shards, new_shards)
        shards = new_shards

        # 2 small shards
        self.auto_sharding.reset_stats()
        meta2db = self._get_meta2db(None, cid=shard_cid)
        self.auto_sharding.process(meta2db.env, _cb)
        filter_stats = self.auto_sharding.get_stats()[self.auto_sharding.NAME]
        for key, value in filter_stats.items():
            if key == "shrinking_successes":
                self.assertEqual(1, value)
            else:
                self.assertEqual(0, value)
        shards = list(self.container_sharding.show_shards(self.account, self.cname))
        self.assertEqual(1, len(shards))

        # Last shard
        shard_cid = shards[0]["cid"]
        self.auto_sharding.reset_stats()
        meta2db = self._get_meta2db(None, cid=shard_cid)
        # Simulate a large size to trigger sharding (last shard is too big)
        meta2db.file_status["st_size"] = int(
            math.ceil(self.conf["shrinking_db_size"] * SHRINKING_COEF_LAST_SHARD)
        )
        self.auto_sharding.process(meta2db.env, _cb)
        filter_stats = self.auto_sharding.get_stats()[self.auto_sharding.NAME]
        for key, value in filter_stats.items():
            if key == "sharding_successes":
                self.assertEqual(1, value)
            else:
                self.assertEqual(0, value)
        shards = list(self.container_sharding.show_shards(self.account, self.cname))
        self.assertEqual(2, len(shards))

        # 2 small shards (again)
        shard_cid = random.choice(shards)["cid"]
        self.auto_sharding.reset_stats()
        meta2db = self._get_meta2db(None, cid=shard_cid)
        self.auto_sharding.process(meta2db.env, _cb)
        filter_stats = self.auto_sharding.get_stats()[self.auto_sharding.NAME]
        for key, value in filter_stats.items():
            if key == "shrinking_successes":
                self.assertEqual(1, value)
            else:
                self.assertEqual(0, value)
        shards = list(self.container_sharding.show_shards(self.account, self.cname))
        self.assertEqual(1, len(shards))

        # Last shard
        shard_cid = shards[0]["cid"]
        self.auto_sharding.reset_stats()
        meta2db = self._get_meta2db(None, cid=shard_cid)
        # Simulate a large size to trigger shrinking (last shard is "small")
        meta2db.file_status["st_size"] = (
            int(math.ceil(self.conf["shrinking_db_size"] * SHRINKING_COEF_LAST_SHARD))
            - 1
        )
        self.auto_sharding.process(meta2db.env, _cb)
        filter_stats = self.auto_sharding.get_stats()[self.auto_sharding.NAME]
        for key, value in filter_stats.items():
            if key == "shrinking_successes":
                self.assertEqual(1, value)
            else:
                self.assertEqual(0, value)
        shards = list(self.container_sharding.show_shards(self.account, self.cname))
        self.assertEqual(0, len(shards))

    def test_cleaning_root(self):
        def _cb(status, _msg):
            self.assertEqual(200, status)

        for i in range(2):
            self.storage.object_create(
                self.account, self.cname, obj_name=f"obj-{i}", data=b"data"
            )
        self._find_and_replace(self.cname)
        # Simulate an unfinished cleaning
        meta = self.storage.container_get_properties(self.account, self.cname)
        current_timestamp = int(meta["system"][M2_PROP_SHARDING_TIMESTAMP])
        old_timestamp = current_timestamp - (1000 * 1000000)
        self.storage.container_set_properties(
            self.account,
            self.cname,
            system={
                M2_PROP_SHARDING_STATE: str(NEW_SHARD_STATE_CLEANING_UP),
                M2_PROP_SHARDING_TIMESTAMP: str(old_timestamp),
            },
        )

        meta2db = self._get_meta2db(self.cname)
        self.auto_sharding.process(meta2db.env, _cb)
        filter_stats = self.auto_sharding.get_stats()[self.auto_sharding.NAME]
        for key, value in filter_stats.items():
            if key in ("skipped", "cleaning_successes"):
                self.assertEqual(1, value)
            else:
                self.assertEqual(0, value)

        shards = list(self.container_sharding.show_shards(self.account, self.cname))
        self.assertEqual(2, len(shards))
        meta = self.storage.container_get_properties(self.account, self.cname)
        self.assertEqual(
            NEW_SHARD_STATE_CLEANED_UP, int(meta["system"][M2_PROP_SHARDING_STATE])
        )
        self.assertGreater(
            int(meta["system"][M2_PROP_SHARDING_TIMESTAMP]), current_timestamp
        )

    def test_cleaning_and_shrinking_shard(self):
        def _cb(status, _msg):
            self.assertEqual(200, status)

        for i in range(2):
            self.storage.object_create(
                self.account, self.cname, obj_name=f"obj-{i}", data=b"data"
            )
        shards = self._find_and_replace(self.cname)
        shard_cid = random.choice(shards)["cid"]
        # Simulate an unfinished cleaning
        meta = self.storage.container_get_properties(None, None, cid=shard_cid)
        current_timestamp = int(meta["system"][M2_PROP_SHARDING_TIMESTAMP])
        old_timestamp = current_timestamp - (1000 * 1000000)
        self.storage.container_set_properties(
            None,
            None,
            cid=shard_cid,
            system={
                M2_PROP_SHARDING_STATE: str(NEW_SHARD_STATE_CLEANING_UP),
                M2_PROP_SHARDING_TIMESTAMP: str(old_timestamp),
            },
        )

        # First pass, cleaning in progress, the cleaning must be done
        meta2db = self._get_meta2db(None, cid=shard_cid)
        self.auto_sharding.process(meta2db.env, _cb)
        filter_stats = self.auto_sharding.get_stats()[self.auto_sharding.NAME]
        for key, value in filter_stats.items():
            if key in ("skipped", "cleaning_successes"):
                self.assertEqual(1, value)
            else:
                self.assertEqual(0, value)
        shards = list(self.container_sharding.show_shards(self.account, self.cname))
        self.assertEqual(2, len(shards))
        self.auto_sharding.reset_stats()

        # Second pass, no sharding/cleaning in progress, the shrinking can be done
        meta2db = self._get_meta2db(None, cid=shard_cid)
        self.auto_sharding.process(meta2db.env, _cb)
        filter_stats = self.auto_sharding.get_stats()[self.auto_sharding.NAME]
        print(filter_stats)
        for key, value in filter_stats.items():
            if key in ("shrinking_successes",):
                self.assertEqual(1, value)
            else:
                self.assertEqual(0, value)
        shards = list(self.container_sharding.show_shards(self.account, self.cname))
        self.assertEqual(1, len(shards))

    def test_recent_unfinished_cleaning(self):
        def _cb(status, _msg):
            self.assertEqual(200, status)

        for i in range(2):
            self.storage.object_create(
                self.account, self.cname, obj_name=f"obj-{i}", data=b"data"
            )
        shards = self._find_and_replace(self.cname)
        shard_cid = random.choice(shards)["cid"]
        # Simulate a recent unfinished cleaning
        meta = self.storage.container_get_properties(None, None, cid=shard_cid)
        current_timestamp = int(meta["system"][M2_PROP_SHARDING_TIMESTAMP])
        self.storage.container_set_properties(
            None,
            None,
            cid=shard_cid,
            system={M2_PROP_SHARDING_STATE: str(NEW_SHARD_STATE_CLEANING_UP)},
        )

        meta2db = self._get_meta2db(None, cid=shard_cid)
        self.auto_sharding.process(meta2db.env, _cb)
        filter_stats = self.auto_sharding.get_stats()[self.auto_sharding.NAME]
        for key, value in filter_stats.items():
            if key == "sharding_in_progress":
                self.assertEqual(1, value)
            else:
                self.assertEqual(0, value)

        shards = list(self.container_sharding.show_shards(self.account, self.cname))
        self.assertEqual(2, len(shards))
        meta = self.storage.container_get_properties(None, None, cid=shard_cid)
        self.assertEqual(
            NEW_SHARD_STATE_CLEANING_UP, int(meta["system"][M2_PROP_SHARDING_STATE])
        )
        self.assertEqual(
            current_timestamp, int(meta["system"][M2_PROP_SHARDING_TIMESTAMP])
        )

    def _test_possible_orphan_shard(self, sharding_state):
        def _cb(status, _msg):
            self.assertEqual(200, status)

        for i in range(2):
            self.storage.object_create(
                self.account, self.cname, obj_name=f"obj-{i}", data=b"data"
            )
        shards = self._find_and_replace(self.cname)
        shard_cid = random.choice(shards)["cid"]
        # Simulate an unfinished sharding
        meta = self.storage.container_get_properties(None, None, cid=shard_cid)
        current_timestamp = int(meta["system"][M2_PROP_SHARDING_TIMESTAMP])
        old_timestamp = current_timestamp - (1000 * 1000000)
        self.storage.container_set_properties(
            None,
            None,
            cid=shard_cid,
            system={
                M2_PROP_SHARDING_STATE: str(sharding_state),
                M2_PROP_SHARDING_TIMESTAMP: str(old_timestamp),
            },
        )

        meta2db = self._get_meta2db(None, cid=shard_cid)
        self.auto_sharding.process(meta2db.env, _cb)
        filter_stats = self.auto_sharding.get_stats()[self.auto_sharding.NAME]
        for key, value in filter_stats.items():
            if key in ("sharding_in_progress", "possible_orphan_shards"):
                self.assertEqual(1, value)
            else:
                self.assertEqual(0, value)

        shards = list(self.container_sharding.show_shards(self.account, self.cname))
        self.assertEqual(2, len(shards))
        meta = self.storage.container_get_properties(None, None, cid=shard_cid)
        self.assertEqual(sharding_state, int(meta["system"][M2_PROP_SHARDING_STATE]))
        self.assertEqual(old_timestamp, int(meta["system"][M2_PROP_SHARDING_TIMESTAMP]))

    def test_possible_orphan_shard_with_new_shard_applyings_saved_writes(self):
        self._test_possible_orphan_shard(NEW_SHARD_STATE_APPLYING_SAVED_WRITES)

    def test_possible_orphan_shard_with_locked_shard(self):
        self._test_possible_orphan_shard(EXISTING_SHARD_STATE_LOCKED)

    def test_not_found(self):
        def _cb(status, _msg):
            self.assertEqual(404, status)

        meta2db = self._get_meta2db(self.cname)
        self.storage.container_delete(self.account, self.cname)
        self.auto_sharding.process(meta2db.env, _cb)
        filter_stats = self.auto_sharding.get_stats()[self.auto_sharding.NAME]
        for _, value in filter_stats.items():
            self.assertEqual(0, value)
