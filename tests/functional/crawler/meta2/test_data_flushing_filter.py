# -*- coding: utf-8 -*-

# Copyright (C) 2021-2026 OVH SAS
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

from time import time as now
from unittest.mock import patch

from oio.common.constants import (
    DRAINING_STATE_DONE,
    DRAINING_STATE_IN_PROGRESS,
    FLUSHING_STATE_DONE,
    FLUSHING_STATE_IN_PROGRESS,
    M2_PROP_DRAINING_STATE,
    M2_PROP_DRAINING_TIMESTAMP,
    M2_PROP_FLUSHING_STATE,
    M2_PROP_FLUSHING_TIMESTAMP,
    M2_PROP_OBJECTS,
    M2_PROP_SHARDING_LOWER,
)
from oio.common.kafka_http import KafkaClusterHealth
from oio.common.utils import cid_from_name, request_id
from oio.crawler.meta2.filters.draining import Draining
from oio.crawler.meta2.filters.flushing import Flushing
from oio.event.evob import EventTypes
from tests.utils import BaseTestCase, random_str


def fake_cb(_status, _msg):
    pass


class FilterApp(object):
    def __init__(self, app_env):
        self.app_env = app_env

    def __call__(self, env, cb):
        self.env = env
        self.cb = cb

    def get_stats(self):
        return dict()

    def reset_stats(self):
        pass


NEEDED = 1  # Hardcoded because used in default values


class DataFlushingFilter:
    TYPE = "data_flushing"
    CLASS_FILTER = None
    EVENT_EXPECTED = None
    STATE_IN_PROGRESS = None
    STATE_DONE = None
    M2_PROP_STATE = None
    M2_PROP_TIMESTAMP = None

    @classmethod
    def setUpClass(cls):
        super(DataFlushingFilter, cls).setUpClass()
        cls._service_group("crawler", "stop", wait=3)

    @classmethod
    def tearDownClass(cls):
        cls._service_group("crawler", "start", wait=1)
        super(DataFlushingFilter, cls).tearDownClass()

    def setUp(self):
        super(DataFlushingFilter, self).setUp()
        self.shards_account = ".shards_%s" % self.account
        self.use_sharding = False
        self.cname = "ct-%d" % int(now())
        self.created = []
        self.containers = []

        self.app_env = dict()
        self.app_env["api"] = self.storage
        self.app = FilterApp(self.app_env)

        created = self.storage.container_create(self.account, self.cname)
        self.assertTrue(created)

        self.expected_successes = 0
        self.expected_skipped = 0
        self.expected_errors = 0

    def tearDown(self):
        try:
            # delete objects
            self.storage.object_delete_many(self.account, self.cname, objs=self.created)
            # FIXME temporary cleaning, this should be handled by deleting
            # root container
            self.wait_for_kafka_event(types=(EventTypes.CONTAINER_STATE,))
            if self.use_sharding:
                resp = self.storage.account.container_list(self.shards_account)
                for cont in resp["listing"]:
                    # delete sharded account
                    self.storage.container_flush(
                        account=self.shards_account, container=cont[0]
                    )
                    self.storage.container_delete(
                        account=self.shards_account, container=cont[0]
                    )
            self.storage.container_delete(self.account, self.cname, force=True)
        except Exception:
            self.logger.warning("Exception during cleaning %s", self.shards_account)
        super(DataFlushingFilter, self).tearDown()

    def _get_meta2db_env(self, cid):
        dir_data = self.storage.directory.list(cid=cid, service_type="meta2")
        volume_id = dir_data["srv"][0]["host"]
        volume_path = None
        for srv in self.conscience.all_services("meta2"):
            if volume_id in (srv["addr"], srv["tags"].get("tag.service_id")):
                volume_path = srv["tags"]["tag.vol"]
                break
        else:
            self.fail("Unable to find the volume path")

        meta2db_env = {}
        meta2db_env["path"] = "/".join((volume_path, cid[:3], cid + ".1.meta2"))
        meta2db_env["volume_id"] = volume_id
        meta2db_env["cid"] = cid
        meta2db_env["seq"] = 1

        return meta2db_env

    def _add_objects(self, cname, number_of_obj, pattern_name="content"):
        for _ in range(number_of_obj):
            file_name = random_str(8) + pattern_name
            reqid = request_id()
            self.storage.object_create(
                self.account,
                cname,
                obj_name=file_name,
                data="data",
                chunk_checksum_algo=None,
                reqid=reqid,
            )
            self.created.append(file_name)
        # Wait for the event from the last object created
        self.wait_for_kafka_event(
            types=(EventTypes.CONTENT_NEW,),
            fields={"path": file_name},
            reqid=reqid,
        )

    def _set_flag(self, flag=NEEDED):
        system = {
            self.M2_PROP_STATE: str(flag),
            self.M2_PROP_TIMESTAMP: str(round(now() * 1000000)),
        }
        output = self.storage.container_set_properties(
            self.account, self.cname, system=system, propagate_to_shards=True
        )
        self.assertEqual(b"", output)

    def _process_data_flush(
        self,
        nb_objects=0,
        meta2db_env=None,
        callback=fake_cb,
        nb_passes=1,
        limit=None,
        limit_per_pass=None,
        cid=None,
        out_of_range_objects=None,
    ):
        if out_of_range_objects is None:
            out_of_range_objects = []
        if not meta2db_env:
            cid = cid or cid_from_name(self.account, self.cname)
        else:
            cid = meta2db_env["cid"]

        conf = self.conf.copy()
        conf["kafka_cluster_health_metrics_endpoints"] = "http://redpanda-metrics"
        if limit:
            conf[f"{self.TYPE}_limit"] = limit
        if limit_per_pass:
            conf[f"{self.TYPE}_limit_per_pass"] = limit_per_pass
        data_flush = self.CLASS_FILTER(app=self.app, conf=conf)

        # pylint: disable=protected-access
        if self.expected_successes >= 1:
            # Get all chunk urls of the container
            resp = self.storage.object_list(None, None, cid=cid)
            self.assertEqual(
                nb_objects + len(out_of_range_objects), len(resp["objects"])
            )
            chunk_urls = []
            for object_ in resp["objects"]:
                _, chunks = self.storage.object_locate(
                    None, None, object_["name"], cid=cid
                )
                if object_["name"] not in out_of_range_objects:
                    for chunk in chunks:
                        chunk_urls.append((chunk["url"], object_["id"]))

        # Process the data flush
        if not meta2db_env:
            meta2db_env = self._get_meta2db_env(cid)
        with patch.object(KafkaClusterHealth, "check", return_value=None):
            for _ in range(nb_passes):
                data_flush.process(meta2db_env, callback)
                meta2db_env.pop("admin_table")
        self.assertEqual(self.expected_successes, data_flush.successes)
        self.assertEqual(self.expected_skipped, data_flush.skipped)
        self.assertEqual(self.expected_errors, data_flush.errors)

        if self.expected_successes >= 1:
            # All chunks should have received a "deletion" event
            deleted_chunks = []
            for _, content in chunk_urls:
                event = self.wait_for_kafka_event(
                    types=(self.EVENT_EXPECTED,),
                    fields={"content": content},
                )
                self.assertIsNotNone(event)
                for event_data in event.data:
                    if event_data.get("type") == "chunks":
                        evt_chunk_url = event_data.get("id")
                        self.logger.debug("Drain event for %s received", evt_chunk_url)
                        if evt_chunk_url not in deleted_chunks:
                            deleted_chunks.append(evt_chunk_url)
            self.assertEqual(len(deleted_chunks), len(chunk_urls))
            # Check if the out-of-range objects are not deleted
            for obj_name in out_of_range_objects:
                _, chunks = self.storage.object_locate(None, None, obj_name, cid=cid)
                self.assertGreater(len(chunks), 0)

            props = self.storage.container_get_properties(None, None, cid=cid)
            self.assertEqual(self.STATE_DONE, int(props["system"][self.M2_PROP_STATE]))

    def test_data_flush_container(self):
        nb_obj_to_add = 10
        self.expected_successes = 1
        self.expected_skipped = 0
        self.expected_errors = 0

        self._add_objects(self.cname, nb_obj_to_add)
        self._set_flag()
        self._process_data_flush(nb_obj_to_add)

        # "Done" flag done should have been set, nothing should be done anymore
        self.expected_successes = 0
        self.expected_skipped = 1
        self.expected_errors = 0
        self._process_data_flush()

    def test_data_flush_without_flag(self):
        """
        In this test, the flag is not set in the meta2, the crawler should skip this
        meta2.
        """
        nb_obj_to_add = 10
        self.expected_successes = 0
        self.expected_skipped = 1
        self.expected_errors = 0

        self._add_objects(self.cname, nb_obj_to_add)
        self._process_data_flush(nb_obj_to_add)

    def test_data_flush_with_bad_flag(self):
        """
        In this test, the flag is incorrect, the crawler should skip this meta2.
        """
        nb_obj_to_add = 10
        self.expected_successes = 0
        self.expected_skipped = 1
        self.expected_errors = 0

        self._add_objects(self.cname, nb_obj_to_add)
        self._set_flag(flag=self.STATE_IN_PROGRESS + 1)
        self._process_data_flush(nb_obj_to_add)

    def test_data_flush_bad_meta2(self):
        """
        In this test, the meta2 path is not correct, the crawler should
        return an error in the stats.
        """

        def _cb(status, _msg):
            self.assertEqual(500, status)

        nb_obj_to_add = 10
        self.expected_successes = 0
        self.expected_skipped = 0
        self.expected_errors = 1

        self._add_objects(self.cname, nb_obj_to_add)
        cid = cid_from_name(self.account, self.cname)
        meta2db_env = self._get_meta2db_env(cid)
        meta2db_env["path"] = "%s-wrong" % meta2db_env["path"]
        self.assertRaises(
            FileNotFoundError,
            self._process_data_flush,
            nb_obj_to_add,
            meta2db_env=meta2db_env,
            callback=_cb,
        )

    def test_data_flush_multiple_passes(self):
        """
        In this test, the conf gonna be tweaked to simulate a data flush in
        multiple passes.
        """
        nb_obj_to_add = 100
        nb_passes = 4
        # Test with <nb_passes> + 1 to expect 1 skip
        self.expected_successes = 3
        self.expected_skipped = 1
        self.expected_errors = 0

        self._add_objects(self.cname, nb_obj_to_add)
        self._set_flag()
        self._process_data_flush(
            nb_obj_to_add, nb_passes=nb_passes, limit=5, limit_per_pass=42
        )

    def test_data_flush_on_shards(self):
        nb_obj_to_add = 4

        self._add_objects(self.cname, nb_obj_to_add)

        # Make sharding (split in 2)
        params = {"partition": "50,50", "threshold": 4}
        shards = self.container_sharding.find_shards(
            self.account,
            self.cname,
            strategy="shard-with-partition",
            strategy_params=params,
        )
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, shards, enable=True, reqid="testingisdoubting"
        )
        self.assertTrue(modified)

        self._set_flag()

        show_shards = self.container_sharding.show_shards(self.account, self.cname)
        self.expected_successes = 1
        self.expected_skipped = 0
        self.expected_errors = 0
        for shard in show_shards:
            self._process_data_flush(2, cid=shard["cid"])


class TestDrainingFilter(DataFlushingFilter, BaseTestCase):
    TYPE = "drain"
    CLASS_FILTER = Draining
    EVENT_EXPECTED = EventTypes.CONTENT_DRAINED
    STATE_IN_PROGRESS = DRAINING_STATE_IN_PROGRESS
    STATE_DONE = DRAINING_STATE_DONE
    M2_PROP_STATE = M2_PROP_DRAINING_STATE
    M2_PROP_TIMESTAMP = M2_PROP_DRAINING_TIMESTAMP

    def test_drain_on_shard_containing_out_of_range_objects(self):
        nb_obj_to_add = 8
        self._add_objects(self.cname, nb_obj_to_add)
        self.created.sort()
        # Make sharding (split in 2)
        params = {"partition": "50,50", "threshold": 1}
        shards = self.container_sharding.find_shards(
            self.account,
            self.cname,
            strategy="shard-with-partition",
            strategy_params=params,
        )
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, shards, enable=True, reqid="testingisdoubting"
        )
        self.assertTrue(modified)

        self._set_flag()

        show_shards = self.container_sharding.show_shards(self.account, self.cname)
        shard_id = next(show_shards)["cid"]

        self.storage.container_set_properties(
            None,
            None,
            cid=shard_id,
            system={
                M2_PROP_SHARDING_LOWER: ">" + self.created[1],
                M2_PROP_OBJECTS: "2",
            },
        )

        self.expected_successes = 1
        self.expected_skipped = 0
        self.expected_errors = 0
        self._process_data_flush(2, cid=shard_id, out_of_range_objects=self.created[:2])


class TestFlushFilter(DataFlushingFilter, BaseTestCase):
    TYPE = "flush"
    CLASS_FILTER = Flushing
    EVENT_EXPECTED = EventTypes.CONTENT_DELETED
    STATE_IN_PROGRESS = FLUSHING_STATE_IN_PROGRESS
    STATE_DONE = FLUSHING_STATE_DONE
    M2_PROP_STATE = M2_PROP_FLUSHING_STATE
    M2_PROP_TIMESTAMP = M2_PROP_FLUSHING_TIMESTAMP
