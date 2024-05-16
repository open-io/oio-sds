# Copyright (C) 2024 OVH SAS
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
import time
from tests.utils import BaseTestCase, random_str
from oio.common.constants import M2_PROP_VERSIONING_POLICY
from oio.common.utils import cid_from_name, request_id
from oio.crawler.lifecycle.filters.lifecycle import Lifecycle as Lifecycle_filter
from oio.directory.admin import AdminClient
from oio.event.evob import EventTypes

from oio.common.kafka import DEFAULT_ENDPOINT, DEFAULT_LIFECYCLE_TOPIC, KafkaConsumer
from oio.container.lifecycle import LIFECYCLE_PROPERTY_KEY


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


lifecycle_conf = """
    {"Rules":
        {
            "rule-1":
            {
                "Status":"Disabled",
                "Filter":{"Prefix": "documents/"},
                "Transitions": [{
                    "Days": 0,
                    "StorageClass": "STANDARD_IA"
                }]
            },
            "rule-2":
            {
                "Status":"Enabled",
                "Filter":{"Prefix": "doc"},
                "Expiration": {
                    "Days": 0
                }
            }
        }
    }"""

lifecycle_conf_disabled = """
    {"Rules":
        {
            "rule-1":
            {
                "Status":"Disabled",
                "Filter":{"Prefix": "documents/"},
                "Transitions": [{
                    "Days": 1,
                    "StorageClass": "STANDARD_IA"
                }],
                "NoncurrentVersionExpiration": {
                    "NoncurrentDays": 20
                }
            },
            "rule-2":
            {
                "Status":"Disabled",
                "Filter":{"Prefix": "documents"},
                "Expiration": {
                    "Days": 10
                }
            }
        }
    }"""


lifecycle_conf_transition = """
    {"Rules":
        {
            "rule-3":
            {
                "Status":"Enabled",
                "Filter":{"Prefix": "documents/"},
                "Transitions": [{
                    "Days": 0,
                    "StorageClass": "STANDARD_IA"
                }]
            }
        }
    }"""


class TestLifecycleFilter(BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super(TestLifecycleFilter, cls).setUpClass()
        cls._service("oio-crawler.target", "stop", wait=3)

        group_id = "default-crawler-lifecycle"
        cls._cls_kafka_consumer = KafkaConsumer(
            DEFAULT_ENDPOINT,
            [DEFAULT_LIFECYCLE_TOPIC],
            group_id,
            logger=cls._cls_logger,
            app_conf=cls._cls_conf,
            kafka_conf={
                "enable.auto.commit": True,
                "auto.offset.reset": "latest",
            },
        )

    @classmethod
    def tearDownClass(cls):
        cls._service("oio-crawler.target", "start", wait=1)
        super(TestLifecycleFilter, cls).tearDownClass()

    def setUp(self):
        super(TestLifecycleFilter, self).setUp()
        self.cname = "lifecycle-%d" % int(time.time())
        self.created = []
        self.containers = []

        self.now_suffix = time.strftime("%Y-%m-%d")

        self.admin_client = AdminClient(
            self.conf,
            logger=self.logger,
            pool_manager=self.storage.container.pool_manager,
        )

        created = self.storage.container_create(self.account, self.cname)
        self.assertTrue(created)

        self.expected_successes = 0
        self.expected_errors = 0

        self.meta2db_env = self._get_meta2db_env()
        self.meta2db_env["api"] = self.storage
        self.app = FilterApp(self.meta2db_env)

        self.budget_per_container = 3
        self.lifecycle_batch_size = 2
        self.conf["budget_per_container"] = self.budget_per_container
        self.conf["lifecycle_batch_size"] = self.lifecycle_batch_size

    def tearDown(self):
        try:
            # delete objects
            self.storage.object_delete_many(self.account, self.cname, objs=self.created)
            # FIXME temporary cleaning, this should be handled by deleting
            # root container
            # self.wait_for_kafka_event(types=(EventTypes.CONTAINER_STATE,))
            self.storage.container_delete(self.account, self.cname, force=True)
        except Exception:
            self.logger.warning("Exception during cleaning %s", self.account)
        super(TestLifecycleFilter, self).tearDown()

    def _get_meta2db_env(self, cid=None):
        cid = cid or cid_from_name(self.account, self.cname)

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

    def _make_local_copy(self, meta2db_env=None):
        params = {
            "service_type": "meta2",
            "cid": meta2db_env["cid"],
            "svc_from": meta2db_env["volume_id"],
            "suffix": f"lifecycle-{self.now_suffix}",
        }

        # Request a local copy of the meta2 database
        self.admin_client.copy_base_local(**params)

    def _make_symbolic_link(self, meta2db_env):
        path_segs = (meta2db_env["path"]).rsplit("/", 2)
        local_dir = "/".join([path_segs[0], "local_lifecycle"])
        prefix = "lifecycle"
        src = ".".join([meta2db_env["path"], f"lifecycle-{self.now_suffix}"])
        copy_name = ".".join([prefix, path_segs[2], f"lifecycle-{self.now_suffix}"])
        dst = "/".join([local_dir, copy_name])

        if not os.path.isdir(local_dir):
            os.makedirs(local_dir, exist_ok=True)
        os.symlink(src, dst)

    def _add_objects(self, cname, number_of_obj, pattern_name="content"):
        for _ in range(number_of_obj):
            file_name = "documents/" + random_str(8) + pattern_name
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

    def _set_lifecycle_prop(self, lc_conf):
        props = {
            LIFECYCLE_PROPERTY_KEY: lc_conf,
        }
        output = self.storage.container_set_properties(
            self.account,
            self.cname,
            properties=props,
        )
        self.assertEqual(b"", output)

    def _process(
        self,
        nb_objects=0,
        meta2db_env=None,
        callback=fake_cb,
        nb_passes=1,
        cid=None,
        out_of_range_objects=None,
        expected_events=None,
    ):
        if out_of_range_objects is None:
            out_of_range_objects = []
        if not meta2db_env:
            meta2db_env = self._get_meta2db_env()
        cid = meta2db_env["cid"]
        conf = self.conf.copy()

        conf["bypass_days_dates"] = True

        lifecycle = Lifecycle_filter(app=self.app, conf=conf)

        # pylint: disable=protected-access
        if self.expected_successes >= 1:
            # Get all chunk urls of the container
            resp = self.storage.object_list(None, None, cid=cid)
            self.assertEqual(
                nb_objects + len(out_of_range_objects), len(resp["objects"])
            )

        # Process the lifecycle
        for _ in range(nb_passes):
            lifecycle.process(meta2db_env, callback)

        self.assertEqual(self.expected_successes, lifecycle.successes)
        self.assertEqual(self.expected_errors, lifecycle.errors)

        self.assertEqual(self.count_disabled_rules, lifecycle.count_disabled_rules)
        i = 0
        while i < expected_events:
            event = self.wait_for_kafka_event(
                types=(EventTypes.LIFECYCLE_ACTION,),
            )
            self.assertIsNotNone(event)
            i += 1

    def test_basic(self):
        nb_obj_to_add = 4
        self.expected_successes = 1
        self.expected_errors = 0
        self.count_disabled_rules = 1
        self._set_lifecycle_prop(lifecycle_conf)
        self._add_objects(self.cname, nb_obj_to_add)
        self._make_local_copy(self.meta2db_env)
        self._make_symbolic_link(self.meta2db_env)
        time.sleep(2)
        self._process(
            nb_obj_to_add, meta2db_env=self.meta2db_env, expected_events=nb_obj_to_add
        )

    def test_disabled_rules(self):
        nb_obj_to_add = 4
        self.expected_successes = 1
        self.expected_errors = 0
        self.count_disabled_rules = 2
        self._set_lifecycle_prop(lifecycle_conf_disabled)
        self._add_objects(self.cname, nb_obj_to_add)
        self._make_local_copy(self.meta2db_env)
        self._make_symbolic_link(self.meta2db_env)
        time.sleep(2)
        self._process(nb_obj_to_add, meta2db_env=self.meta2db_env, expected_events=0)

    def test_offset(self):
        nb_obj_to_add = 5
        self.expected_successes = 1
        self.expected_errors = 0
        self.count_disabled_rules = 1
        self._set_lifecycle_prop(lifecycle_conf)
        self._add_objects(self.cname, nb_obj_to_add)
        self._make_local_copy(self.meta2db_env)
        self._make_symbolic_link(self.meta2db_env)
        time.sleep(2)
        # First pass makes 2 requests with batch_size = 2
        # Then breaks as nb of matches > self.budget_per_container
        self._process(nb_obj_to_add, meta2db_env=self.meta2db_env, expected_events=4)
        time.sleep(2)
        # Next pass finds only one remainingn match
        self._process(nb_obj_to_add, meta2db_env=self.meta2db_env, expected_events=1)

    def test_transition(self):
        nb_obj_to_add = 4
        self.expected_successes = 1
        self.expected_errors = 0
        self.count_disabled_rules = 0

        self._set_lifecycle_prop(lifecycle_conf_transition)
        self._add_objects(self.cname, nb_obj_to_add)
        self._make_local_copy(self.meta2db_env)
        self._make_symbolic_link(self.meta2db_env)
        time.sleep(2)
        self._process(
            nb_obj_to_add, meta2db_env=self.meta2db_env, expected_events=nb_obj_to_add
        )


class TestLifecycleFilterVersioned(TestLifecycleFilter):
    def setUp(self):
        super(TestLifecycleFilterVersioned, self).setUp()

        self.storage.container_set_properties(
            self.account, self.cname, system={M2_PROP_VERSIONING_POLICY: "-1"}
        )
