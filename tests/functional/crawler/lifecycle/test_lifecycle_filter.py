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

import json
import time
from tests.utils import BaseTestCase, random_str
from oio.common.constants import LIFECYCLE_PROPERTY_KEY, M2_PROP_VERSIONING_POLICY
from oio.common.kafka import DEFAULT_LIFECYCLE_TOPIC
from oio.common.utils import cid_from_name, request_id
from oio.crawler.meta2.filters.lifecycle import Lifecycle as Lifecycle_filter
from oio.directory.admin import AdminClient
from oio.event.evob import EventTypes


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


lifecycle_conf = {
    "Rules": {
        "0": {
            "ID": "rule-id1",
            "Status": "Disabled",
            "Filter": {"Prefix": "documents/"},
            "Transition": {
                "0": {"Days": 0, "StorageClass": "STANDARD_IA"},
                "__time_type": "Days",
            },
        },
        "1": {
            "ID": "rule-id2",
            "Status": "Enabled",
            "Filter": {"Prefix": "doc"},
            "Expiration": {
                "0": {"Days": 0},
                "__time_type": "Days",
            },
        },
    },
    "_schema_version": 1,
    "_expiration_rules": {"days": ["1-0"], "date": []},
    "_transition_rules": {"days": [], "date": []},
    "_delete_marker_rules": [],
    "_abort_mpu_rules": [],
    "_non_current_expiration_rules": [],
    "_non_current_transition_rules": [],
}


lifecycle_conf_disabled = {
    "Rules": {
        "0": {
            "ID": "rule-id1",
            "Status": "Disabled",
            "Filter": {"Prefix": "documents/"},
            "Transition": {
                "0": {"Days": 0, "StorageClass": "STANDARD_IA"},
                "__time_type": "Days",
            },
        },
        "1": {
            "ID": "rule-id2",
            "Status": "Disabled",
            "Filter": {"Prefix": "doc"},
            "Expiration": {"0": {"Days": 0}, "__time_type": "Days"},
        },
    },
    "_schema_version": 1,
    "_expiration_rules": {"days": [], "date": []},
    "_transition_rules": {"days": [], "date": []},
    "_delete_marker_rules": [],
    "_abort_mpu_rules": [],
    "_non_current_expiration_rules": [],
    "_non_current_transition_rules": [],
}


lifecycle_conf_transition = {
    "Rules": {
        "0": {
            "ID": "id",
            "Status": "Enabled",
            "Filter": {"Prefix": "documents/"},
            "Transition": {
                "0": {"Days": 0, "StorageClass": "STANDARD_IA"},
                "__time_type": "Days",
            },
        }
    },
    "_schema_version": 1,
    "_expiration_rules": {"days": [], "date": []},
    "_transition_rules": {"days": ["0-0"], "date": []},
    "_delete_marker_rules": [],
    "_abort_mpu_rules": [],
    "_non_current_expiration_rules": [],
    "_non_current_transition_rules": [],
}


lifecycle_conf_abort_incmplete_mpu = {
    "Rules": {
        "0": {
            "ID": "rule-2",
            "Status": "Enabled",
            "Filter": {"Prefix": "documents/"},
            "AbortIncompleteMultipartUpload": {"0": {"DaysAfterInitiation": 0}},
        }
    },
    "_schema_version": 1,
    "_expiration_rules": {"days": [], "date": []},
    "_transition_rules": {"days": [], "date": []},
    "_delete_marker_rules": [],
    "_abort_mpu_rules": ["0-0"],
    "_non_current_expiration_rules": [],
    "_non_current_transition_rules": [],
}

lifecycle_conf_2_rules = {
    "Rules": {
        "0": {
            "ID": "rule1",
            "Status": "Enabled",
            "Filter": {"Prefix": "doc"},
            "Expiration": {"0": {"Days": 0}, "__time_type": "Days"},
        },
        "1": {
            "ID": "rule-2",
            "Status": "Enabled",
            "Filter": {"Prefix": "documents/"},
            "Expiration": {"1": {"Days": 0}, "__time_type": "Days"},
        },
    },
    "_schema_version": 1,
    "_expiration_rules": {"days": ["1-1", "0-0"], "date": []},
    "_transition_rules": {"days": [], "date": []},
    "_delete_marker_rules": [],
    "_abort_mpu_rules": [],
    "_non_current_expiration_rules": [],
    "_non_current_transition_rules": [],
}

lifecycle_conf_non_current_and_exp = {
    "Rules": {
        "0": {
            "ID": "rule-1",
            "Status": "Enabled",
            "Filter": {"Prefix": "doc"},
            "Expiration": {"0": {"Days": 1}, "__time_type": "Days"},
        },
        "1": {
            "ID": "rule-2",
            "Status": "Enabled",
            "Filter": {"Prefix": "documents/"},
            "NoncurrentVersionExpiration": {
                "1": {"NoncurrentDays": 0, "NewerNoncurrentVersions": 1},
                "__time_type": "NoncurrentDays",
            },
        },
    },
    "_schema_version": 1,
    "_expiration_rules": {"days": ["0-0"], "date": []},
    "_transition_rules": {"days": [], "date": []},
    "_delete_marker_rules": [],
    "_abort_mpu_rules": [],
    "_non_current_expiration_rules": ["1-1"],
    "_non_current_transition_rules": [],
}

lifecycle_conf_non_current_trs_and_exp = {
    "Rules": {
        "0": {
            "ID": "rule-1",
            "Status": "Enabled",
            "Filter": {"Prefix": "doc"},
            "Expiration": {"0": {"Days": 0}, "__time_type": "Days"},
        },
        "1": {
            "ID": "rule-2",
            "Status": "Enabled",
            "Filter": {"Prefix": "documents/"},
            "NoncurrentVersionTransition": {
                "1": {
                    "NoncurrentDays": 0,
                    "NewerNoncurrentVersions": 1,
                    "StorageClass": "STANDARD_IA",
                },
                "__time_type": "NoncurrentDays",
            },
        },
    },
    "_schema_version": 1,
    "_expiration_rules": {"days": ["0-0"], "date": []},
    "_transition_rules": {"days": [], "date": []},
    "_delete_marker_rules": [],
    "_abort_mpu_rules": [],
    "_non_current_expiration_rules": [],
    "_non_current_transition_rules": ["1-1"],
}

lifecycle_conf_mix_expdeletemarker_expiration = {
    "Rules": {
        "0": {
            "ID": "id1",
            "Status": "Enabled",
            "Filter": {"Prefix": "doc"},
            "Expiration": {
                "0": {"ExpiredObjectDeleteMarker": "true"},
            },
        },
        "1": {
            "ID": "id2",
            "Status": "Enabled",
            "Filter": {"Prefix": "doc"},
            "Expiration": {"1": {"Days": 0}, "__time_type": "Days"},
        },
    },
    "_schema_version": 1,
    "_expiration_rules": {"days": ["1-1"], "date": []},
    "_transition_rules": {"days": [], "date": []},
    "_delete_marker_rules": ["0-0"],
    "_abort_mpu_rules": [],
    "_non_current_expiration_rules": [],
    "_non_current_transition_rules": [],
}

lifecycle_conf_mix_expdeletemarker_noncurrexp = {
    "Rules": {
        "0": {
            "ID": "id1",
            "Status": "Enabled",
            "Filter": {"Prefix": "doc"},
            "Expiration": {
                "0": {"ExpiredObjectDeleteMarker": "true"},
            },
        },
        "1": {
            "ID": "rule-2",
            "Status": "Enabled",
            "Filter": {"Prefix": "documents/"},
            "NoncurrentVersionExpiration": {
                "1": {"NoncurrentDays": 0, "NewerNoncurrentVersions": 1},
                "__time_type": "NoncurrentDays",
            },
        },
    },
    "_schema_version": 1,
    "_expiration_rules": {"days": [], "date": []},
    "_transition_rules": {"days": [], "date": []},
    "_delete_marker_rules": ["0-0"],
    "_abort_mpu_rules": [],
    "_non_current_expiration_rules": ["1-1"],
    "_non_current_transition_rules": [],
}

lifecycle_conf_mix_exp_expdeletemarker_noncurrexp = {
    "Rules": {
        "0": {
            "ID": "id1",
            "Status": "Enabled",
            "Filter": {"Prefix": "doc"},
            "Expiration": {
                "0": {"ExpiredObjectDeleteMarker": "true"},
            },
        },
        "1": {
            "ID": "id2",
            "Status": "Enabled",
            "Filter": {"Prefix": "doc"},
            "Expiration": {"1": {"Days": 0}, "__time_type": "Days"},
        },
        "2": {
            "ID": "id3",
            "Status": "Enabled",
            "Filter": {"Prefix": "documents/"},
            "NoncurrentVersionExpiration": {
                "1": {"NoncurrentDays": 0, "NewerNoncurrentVersions": 1},
                "__time_type": "NoncurrentDays",
            },
        },
    },
    "_schema_version": 1,
    "_expiration_rules": {"days": ["1-1"], "date": []},
    "_transition_rules": {"days": [], "date": []},
    "_delete_marker_rules": ["0-0"],
    "_abort_mpu_rules": [],
    "_non_current_expiration_rules": ["2-1"],
    "_non_current_transition_rules": [],
}

lifecycle_conf_shard_budget = {
    "Rules": {
        "0": {
            "ID": "id2",
            "Status": "Enabled",
            "Filter": {"Prefix": ""},
            "Expiration": {"0": {"Days": 0}, "__time_type": "Days"},
        }
    },
    "_schema_version": 1,
    "_expiration_rules": {"days": ["0-0"], "date": []},
    "_transition_rules": {"days": [], "date": []},
    "_delete_marker_rules": [],
    "_abort_mpu_rules": [],
    "_non_current_expiration_rules": [],
    "_non_current_transition_rules": [],
}


class TestLifecycleFilter(BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super(TestLifecycleFilter, cls).setUpClass()
        cls._service("oio-crawler.target", "stop", wait=3)

        cls._cls_lifecycle_consumer = cls._register_consumer(
            topic=DEFAULT_LIFECYCLE_TOPIC
        )

    @classmethod
    def tearDownClass(cls):
        cls._service("oio-crawler.target", "start", wait=1)
        super(TestLifecycleFilter, cls).tearDownClass()

    def setUp(self):
        super(TestLifecycleFilter, self).setUp()
        self.cname = f"lifecycle-{int(time.time())}"
        self.created = []
        self.containers = []

        self.now_suffix = time.time()

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
        self.lifecycle_batch_size = 10
        self.conf["budget_per_container"] = self.budget_per_container
        self.conf["lifecycle_batch_size"] = self.lifecycle_batch_size

        self.conf["lifecycle_configuration_backup_account"] = "AUTH_demo"
        self.conf["lifecycle_configuration_backup_bucket"] = "lc-bucket"

        self.force_delete = False

    def tearDown(self):
        try:
            if self.force_delete:
                # delete objects
                self.storage.object_delete_many(
                    self.account, self.cname, objs=self.created
                )
                # FIXME temporary cleaning, this should be handled by deleting
                # root container
                self.storage.container_delete(self.account, self.cname, force=True)
        except Exception:
            self.logger.warning("Exception during cleaning %s", self.account)
        super(TestLifecycleFilter, self).tearDown()

    def _get_meta2db_env(self, account=None, cname=None, cid=None):
        cid = cid or cid_from_name(account or self.account, cname or self.cname)
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

    def _add_suffix(self, meta2db_env=None):
        suffix = f"Lifecycle-{self.now_suffix}.runid-{self.now_suffix}"
        if meta2db_env:
            meta2db_env["suffix"] = suffix
        return suffix

    def _make_local_copy(self, meta2db_env=None):
        suffix = self._add_suffix(meta2db_env)
        params = {
            "service_type": "meta2",
            "cid": meta2db_env["cid"],
            "svc_from": meta2db_env["volume_id"],
            "suffix": suffix,
        }
        if meta2db_env:
            meta2db_env["suffix"] = suffix
        # Request a local copy of the meta2 database
        self.admin_client.copy_base_local(**params)

    def _store_config(self, lifecycle_config):
        if isinstance(lifecycle_config, dict):
            lifecycle_config = json.dumps(lifecycle_config)

        self.storage.object_create(
            self.conf["lifecycle_configuration_backup_account"],
            self.conf["lifecycle_configuration_backup_bucket"],
            obj_name=f"{self.account}/{self.cname}/lifecycle-config",
            data=lifecycle_config,
        )

    def _add_objects(
        self,
        cname,
        number_of_obj,
        properties=None,
        nb_versions=1,
        prefix="documents/",
        pattern_name="content",
    ):
        for _ in range(number_of_obj):
            file_name = prefix + random_str(8) + pattern_name
            reqid = request_id()
            for _ in range(nb_versions):
                self.storage.object_create(
                    self.account,
                    cname,
                    obj_name=file_name,
                    data="data",
                    chunk_checksum_algo=None,
                    reqid=reqid,
                )
                self.created.append(file_name)

                if properties is not None:
                    for k, v in properties.items():
                        self.storage.object_set_properties(
                            self.account,
                            cname,
                            file_name,
                            {k: v},
                        )

    def _set_lifecycle_prop(self, lc_conf):
        if isinstance(lc_conf, dict):
            lc_conf = json.dumps(lc_conf)

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
        meta2db_env=None,
        callback=fake_cb,
        nb_passes=1,
        expected_events=0,
    ):
        if not meta2db_env:
            meta2db_env = self._get_meta2db_env()
        conf = self.conf.copy()

        conf["bypass_days_dates"] = True
        conf["redis_sentinel_name"] = "oio"
        conf["redis_host"] = "127.0.0.1:6379"

        lifecycle = Lifecycle_filter(app=self.app, conf=conf)

        # Process the lifecycle
        for _ in range(nb_passes):
            lifecycle._process(meta2db_env, callback)

        self.assertEqual(self.expected_successes, lifecycle.successes)
        self.assertEqual(self.expected_errors, lifecycle.errors)

        for i in range(expected_events):
            event = self.wait_for_kafka_event(
                types=(EventTypes.LIFECYCLE_ACTION,),
                kafka_consumer=self._cls_lifecycle_consumer,
            )
            self.assertIsNotNone(event, f"Event {i}/{expected_events} not received")


class TestLifecycleFilterNonVersioned(TestLifecycleFilter):
    def test_basic(self):
        nb_obj_to_add = 4
        self.expected_successes = 1
        self.expected_errors = 0
        self.count_disabled_rules = 1
        self._set_lifecycle_prop(lifecycle_conf)
        self._add_objects(self.cname, nb_obj_to_add)
        self._make_local_copy(self.meta2db_env)
        self._store_config(lifecycle_conf)
        time.sleep(2)
        self._process(meta2db_env=self.meta2db_env, expected_events=nb_obj_to_add)

    def test_disabled_rules(self):
        nb_obj_to_add = 4
        self.expected_successes = 1
        self.expected_errors = 0
        self.count_disabled_rules = 2
        self._set_lifecycle_prop(lifecycle_conf_disabled)
        self._add_objects(self.cname, nb_obj_to_add)
        self._make_local_copy(self.meta2db_env)
        self._store_config(lifecycle_conf_disabled)
        time.sleep(2)
        self._process(meta2db_env=self.meta2db_env, expected_events=0)

    def test_offset(self):
        nb_obj_to_add = 5
        self.expected_successes = 1
        self.expected_errors = 0
        self.count_disabled_rules = 1
        self._set_lifecycle_prop(lifecycle_conf)
        self._add_objects(self.cname, nb_obj_to_add)
        self._make_local_copy(self.meta2db_env)
        self._store_config(lifecycle_conf)
        time.sleep(2)
        self.lifecycle_batch_size = 2

        # First pass makes 2 requests with batch_size = 2
        # Then breaks as nb of matches > self.budget_per_container
        self._process(meta2db_env=self.meta2db_env, expected_events=4)
        time.sleep(1)
        # Next pass finds only one remaining match
        self._process(meta2db_env=self.meta2db_env, expected_events=1)

    def _test_transition(self):
        """TODO enable test for transitions"""
        nb_obj_to_add = 4
        self.expected_successes = 1
        self.expected_errors = 0
        self.count_disabled_rules = 0
        self._set_lifecycle_prop(lifecycle_conf_transition)
        self._add_objects(self.cname, nb_obj_to_add)
        self._make_local_copy(self.meta2db_env)
        self._store_config(lifecycle_conf_transition)
        time.sleep(2)
        self._process(meta2db_env=self.meta2db_env, expected_events=nb_obj_to_add)

    def test_several_rules(self):
        nb_obj_to_add = 4
        self.expected_successes = 1
        self.expected_errors = 0
        self.count_disabled_rules = 0
        self.budget_per_container = 1000
        self._set_lifecycle_prop(lifecycle_conf_2_rules)
        self._add_objects(self.cname, nb_obj_to_add)
        self._make_local_copy(self.meta2db_env)
        self._store_config(lifecycle_conf_2_rules)
        time.sleep(2)
        self._process(meta2db_env=self.meta2db_env, expected_events=nb_obj_to_add)


class TestLifecycleFilterVersioned(TestLifecycleFilterNonVersioned):
    def setUp(self):
        super(TestLifecycleFilterVersioned, self).setUp()

        self.storage.container_set_properties(
            self.account, self.cname, system={M2_PROP_VERSIONING_POLICY: "-1"}
        )

    def test_delete_marker(self):
        nb_obj_to_add = 1
        self.expected_successes = 1
        self.expected_errors = 0
        self.count_disabled_rules = 1
        self.budget_per_container = 1000
        self._set_lifecycle_prop(lifecycle_conf)
        self._add_objects(self.cname, nb_obj_to_add)
        self._make_local_copy(self.meta2db_env)
        self._store_config(lifecycle_conf)
        time.sleep(1)
        # run first time => insert delete mar
        self._process(meta2db_env=self.meta2db_env, expected_events=nb_obj_to_add)
        # run second time , no delete marker
        self.expected_successes = 0
        self.count_disabled_rules = 0
        self._process(meta2db_env=self.meta2db_env, expected_events=0)

    def test_non_current_exp(self):
        nb_obj_to_add = 1
        self.expected_successes = 1
        self.expected_errors = 0
        self.count_disabled_rules = 0
        self.budget_per_container = 1000
        self._set_lifecycle_prop(lifecycle_conf_non_current_and_exp)
        self._add_objects(self.cname, nb_obj_to_add, nb_versions=3)
        self._make_local_copy(self.meta2db_env)
        self._store_config(lifecycle_conf_non_current_and_exp)
        time.sleep(1)
        self._process(meta2db_env=self.meta2db_env, expected_events=1)

    def test_non_current_trs(self):
        nb_obj_to_add = 1
        self.expected_successes = 1
        self.expected_errors = 0
        self.count_disabled_rules = 0
        self.budget_per_container = 1000
        self._set_lifecycle_prop(lifecycle_conf_non_current_trs_and_exp)
        self._add_objects(self.cname, nb_obj_to_add, nb_versions=3)
        self._make_local_copy(self.meta2db_env)
        self._store_config(lifecycle_conf_non_current_trs_and_exp)
        time.sleep(1)
        self._process(meta2db_env=self.meta2db_env, expected_events=2)

    # Mix tests
    def test_delete_marker_exists(self):
        """
        Create Objects, add delete markers, check that no event is sent as
        objects are marked before and delete marker is not the only version
        """
        nb_obj_to_add = 2
        self.expected_successes = 1
        self.expected_errors = 0
        self.budget_per_container = 1000
        self._set_lifecycle_prop(lifecycle_conf_mix_expdeletemarker_expiration)
        self._add_objects(self.cname, nb_obj_to_add, nb_versions=1)

        # insert delete marker
        for name in self.created:
            self.storage.object_delete(self.account, self.cname, name)

        self._make_local_copy(self.meta2db_env)
        self._store_config(lifecycle_conf_mix_expdeletemarker_expiration)
        time.sleep(2)
        self._process(meta2db_env=self.meta2db_env, expected_events=0)

    def test_mix_expiration_expdeletemarker(self):
        """
        One object with no delete marker =>insert delete marker
            (match expiration rule)
        One object with only delete marker => expired delete marker
            (match expired delete marker)
        One object with delete marker and a previous version => no action
        """
        nb_obj_to_add = 3
        self.expected_successes = 1
        self.expected_errors = 0
        self.budget_per_container = 1000
        self._set_lifecycle_prop(lifecycle_conf_mix_expdeletemarker_expiration)
        self._add_objects(self.cname, nb_obj_to_add, nb_versions=1)

        for i, name in enumerate(self.created):
            if i == 0:
                pass
            elif i == 1:
                # inset delete marker
                self.storage.object_delete(self.account, self.cname, name)
            else:
                # insert delete marker then remove previous version
                self.storage.object_delete(self.account, self.cname, name)
                objects = self.storage.object_list(
                    self.account, self.cname, prefix=name, deleted=True, versions=True
                )
                self.storage.object_delete(
                    self.account,
                    self.cname,
                    name,
                    version=objects["objects"][1]["version"],
                )
        self._make_local_copy(self.meta2db_env)
        self._store_config(lifecycle_conf_mix_expdeletemarker_expiration)
        time.sleep(2)
        self._process(meta2db_env=self.meta2db_env, expected_events=2)

    def test_mix_noncurrentexpiration_expdeletemarker(self):
        """
        One object with several versions => match noncurrent action
        One object with only delete marker => expired delete marker
            (match expired delete marker)
        """
        self.expected_successes = 1
        self.expected_errors = 0
        self.budget_per_container = 1000
        self._set_lifecycle_prop(lifecycle_conf_mix_expdeletemarker_noncurrexp)
        self._add_objects(self.cname, 1, nb_versions=1)
        self._add_objects(self.cname, 1, nb_versions=3)

        for i, name in enumerate(self.created):
            if i == 0:
                # insert delete marker then remove previous version
                self.storage.object_delete(self.account, self.cname, name)
                objects = self.storage.object_list(
                    self.account, self.cname, prefix=name, deleted=True, versions=True
                )
                self.storage.object_delete(
                    self.account,
                    self.cname,
                    name,
                    version=objects["objects"][1]["version"],
                )
        self._make_local_copy(self.meta2db_env)
        self._store_config(lifecycle_conf_mix_expdeletemarker_noncurrexp)
        time.sleep(2)
        self._process(meta2db_env=self.meta2db_env, expected_events=2)

    def test_mix_expiration_noncurrentexpiration_expdeletemarker(self):
        """
        One object with no delete marker =>insert delete marker
            (match expiration rule)
        One object with only delete marker => expired delete marker
            (match expired delete marker)
        One object several versions => match both expiration and non current
        """
        nb_obj_to_add = 3
        self.expected_successes = 1
        self.expected_errors = 0
        self.budget_per_container = 1000
        self._set_lifecycle_prop(lifecycle_conf_mix_exp_expdeletemarker_noncurrexp)
        self._add_objects(self.cname, nb_obj_to_add, nb_versions=1)

        for i, name in enumerate(self.created):
            if i == 0:
                pass
            elif i == 1:
                # inset delete marker
                self.storage.object_delete(self.account, self.cname, name)
            else:
                # insert delete marker then remove previous version
                self.storage.object_delete(self.account, self.cname, name)
                objects = self.storage.object_list(
                    self.account, self.cname, prefix=name, deleted=True, versions=True
                )
                self.storage.object_delete(
                    self.account,
                    self.cname,
                    name,
                    version=objects["objects"][1]["version"],
                )
        self._make_local_copy(self.meta2db_env)
        self._store_config(lifecycle_conf_mix_exp_expdeletemarker_noncurrexp)
        time.sleep(2)
        self._process(meta2db_env=self.meta2db_env, expected_events=2)


class TestLifecycleFilterMpu(TestLifecycleFilter):
    def setUp(self):
        super(TestLifecycleFilterMpu, self).setUp()
        self.seg_container = self.cname + "+segments"
        self._create_container_segments()
        self.meta2db_env = self._get_meta2db_env(cname=self.seg_container)

    def _create_container_segments(self):
        self.storage.container_create(
            self.account,
            self.seg_container,
        )

    def test_abort_mpu(self):
        nb_obj_to_add = 4
        self.expected_successes = 1
        self.expected_errors = 0
        self.count_disabled_rules = 0
        self._set_lifecycle_prop(lifecycle_conf_abort_incmplete_mpu)
        incomplete_mpu_property = {"x-object-sysmeta-s3api-has-content-type": "no"}
        self._add_objects(
            self.seg_container, nb_obj_to_add, properties=incomplete_mpu_property
        )
        self._make_local_copy(self.meta2db_env)
        self._store_config(lifecycle_conf_abort_incmplete_mpu)
        time.sleep(2)
        self._process(meta2db_env=self.meta2db_env, expected_events=nb_obj_to_add)


class TestLifecycleFilterShards(TestLifecycleFilter):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Prevent the sharding/shrinking by the meta2 crawlers
        cls._service("oio-crawler.target", "stop", wait=3)

    @classmethod
    def tearDownClass(cls):
        cls._service("oio-crawler.target", "start", wait=1)
        super().tearDownClass()

    def _shard_container(self):
        test_shards = [
            {"index": 0, "lower": "", "upper": "end"},
            {"index": 1, "lower": "end", "upper": ""},
        ]
        new_shards = self.container_sharding.format_shards(test_shards, are_new=True)
        self.container_sharding.replace_shard(
            self.account, self.cname, new_shards, enable=True
        )
        # check shards
        show_shards = self.container_sharding.show_shards(self.account, self.cname)
        show_shards = list(show_shards)
        return show_shards

    def test_shards(self):
        nb_obj_to_add = 4
        self.expected_successes = 1
        self.expected_errors = 0
        self.count_disabled_rules = 1
        self._set_lifecycle_prop(lifecycle_conf)
        self._add_objects(self.cname, nb_obj_to_add, prefix="doc/")
        self._store_config(lifecycle_conf)

        self._add_objects(self.cname, nb_obj_to_add, prefix="var/")
        # Shard container into 2 shards
        shards = self._shard_container()
        for index, el in enumerate(shards):
            cid = el.get("cid")
            self.meta2db_env = self._get_meta2db_env(cid=cid)

            self._make_local_copy(self.meta2db_env)
            time.sleep(2)

            # nb_obj_to_add on first shard and zero on next and it is outside prefix
            nb_objects = nb_obj_to_add if index == 0 else 0
            self._process(meta2db_env=self.meta2db_env, expected_events=nb_objects)

    def test_budget_per_bucket(self):
        nb_obj_to_add = 20
        self.expected_successes = 1
        self.count_disabled_rules = 1
        self._set_lifecycle_prop(lifecycle_conf_shard_budget)
        self._add_objects(self.cname, nb_obj_to_add, prefix="doc")
        self._store_config(lifecycle_conf_shard_budget)

        self._add_objects(self.cname, nb_obj_to_add, prefix="var")

        self.conf["lifecycle_batch_size"] = 2

        self.conf["budget_per_bucket"] = 8
        self.conf["budget_per_container"] = 4
        # Shard container into 2 shards
        shards = self._shard_container()
        for el in shards:
            cid = el.get("cid")
            self.meta2db_env = self._get_meta2db_env(cid=cid)
            self._make_local_copy(self.meta2db_env)
            time.sleep(2)

            self._process(meta2db_env=self.meta2db_env, expected_events=4)

        # Make a second pass and check that no event is sent
        # as budget is reached
        self.expected_successes = 0
        for el in shards:
            cid = el.get("cid")
            self.meta2db_env = self._get_meta2db_env(cid=cid)
            self._add_suffix(self.meta2db_env)
            # expected_events is 0 as we reached bucket budget
            self._process(meta2db_env=self.meta2db_env, expected_events=0)
