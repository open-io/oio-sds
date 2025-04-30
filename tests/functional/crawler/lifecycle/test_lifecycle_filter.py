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
import json
import os
import time
from datetime import datetime
from enum import Enum
from unittest.mock import patch

from oio.common.constants import (
    ACL_PROPERTY_KEY,
    LIFECYCLE_USER_AGENT,
    LOGGING_PROPERTY_KEY,
    M2_PROP_BUCKET_NAME,
    M2_PROP_LIFECYCLE_CUSTOM_BUDGET,
    M2_PROP_LIFECYCLE_TIME_BYPASS,
    M2_PROP_VERSIONING_POLICY,
    TAGGING_KEY,
)
from oio.common.exceptions import NoSuchObject
from oio.common.kafka import (
    DEFAULT_LIFECYCLE_RESTORE_TOPIC,
    DEFAULT_LIFECYCLE_TOPIC,
    KafkaSender,
)
from oio.common.utils import cid_from_name
from oio.crawler.meta2.filters.lifecycle import Lifecycle
from oio.event.evob import EventTypes
from tests.utils import BaseTestCase, random_str

INTERNAL_ACCOUNT = "internal"
INTERNAL_BUCKET = "internal_lifecycle"
BUCKET_LOGGING = {
    "Bucket": "test2",
    "Prefix": "Logs/",
    "Grant": [],
}
BUCKET_ACL = {
    "Owner": "demo:demo",
    "Grant": [
        {
            "Permission": "FULL_CONTROL",
            "Grantee": "demo:demo",
        },
    ],
}


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


class ExpectedAction(str, Enum):
    DELETE = "delete"
    DELETE_MARKER = "delete_marker"
    MOVE = "move"


class Expectation:
    def __init__(
        self, rule_id, action, key, version, extra_fields=None, chunks=None, parts=None
    ):
        self.rule_id = rule_id
        self.action = action
        self.key = key
        self.version = version
        self.extra_fields = extra_fields or {}
        self.chunks = chunks or []
        self.parts = parts or []

    def __str__(self):
        return (
            f"Expect(rule_id={self.rule_id} action={self.action} object={self.key}"
            f" version={self.version})"
        )


class TestLifecycleCrawler(BaseTestCase):
    TIME_FACTOR = 43200  # 1 day =>  2 seconds
    DEFAULT_STATS = {
        "successes": 0,
        "errors": 0,
        "skipped": 0,
        "bucket_budget_reached": 0,
        "container_budget_reached": 0,
        "total_events": 0,
        "total_abortmpu": 0,
        "total_delete": 0,
        "total_transition": 0,
    }

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._service("oio-crawler.target", "stop", wait=3)
        cls._cls_lifecycle_consumer = cls._register_consumer(
            topic=DEFAULT_LIFECYCLE_TOPIC
        )
        cls._cls_lifecycle_restore_consumer = cls._register_consumer(
            topic=DEFAULT_LIFECYCLE_RESTORE_TOPIC
        )

        cls._cls_producer = KafkaSender(
            cls._cls_conf["kafka_endpoints"], cls._cls_logger
        )

    @classmethod
    def tearDownClass(cls):
        cls._service("oio-crawler.target", "start", wait=2)
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        self.use_sharding = False
        self.account = "test_lifecycle"
        self.container = "lifecycle-" + random_str(4)
        self.container_segment = f"{self.container}+segments"
        system = {
            M2_PROP_BUCKET_NAME: self.container,
            M2_PROP_LIFECYCLE_TIME_BYPASS: "1",
        }
        properties = {
            ACL_PROPERTY_KEY: json.dumps(BUCKET_ACL, separators=(",", ":")),
            LOGGING_PROPERTY_KEY: json.dumps(BUCKET_LOGGING, separators=(",", ":")),
        }
        self.local_copies = []
        self.containers_to_process = []
        # Create containers
        for container in (self.container, self.container_segment):
            self.storage.container_create(
                self.account, container, properties=properties, system=system
            )
            self.containers_to_process.append((self.account, container))
            self.clean_later(container)

        self.expectations = []
        self.metrics_by_passes = []

        self.filter_conf = {
            **self.conf,
            "redis_host": "127.0.0.1:6379",
            "time_factor": self.TIME_FACTOR,
            "shorten_days_dates_factor": self.TIME_FACTOR,
            "broker_endpoint": self._cls_conf["kafka_endpoints"],
            "lifecycle_configuration_backup_account": "foo",
            "lifecycle_configuration_backup_bucket": "bar",
            "storage_class.STANDARD": "EC21, ANY-E93, TWOCOPIES, THREECOPIES",
            "storage_class.STANDARD_IA": "SINGLE",
        }

        self.app_env = {}
        self.app_env["api"] = self.storage
        self.app = FilterApp(self.app_env)
        self.run_id = f"runid_{random_str(4)}"

        self.wait_for_score(("meta2",), score_threshold=2)

    def tearDown(self):
        for db_copy in self.local_copies:
            try:
                os.remove(db_copy)
            except Exception as exc:
                self.logger.error(
                    "Failed to remove local copy %s, reason: %s", db_copy, exc
                )
        super().tearDown()

    def _wait_n_days(self, days):
        wait = days * 86400 / self.TIME_FACTOR
        time.sleep(wait)

    def _enable_versioning(self):
        self.storage.container_set_properties(
            self.account, self.container, system={M2_PROP_VERSIONING_POLICY: "-1"}
        )

    def __build_tagset(self, tags):
        tags = [f"<Tag><Key>{k}</Key><Value>{v}</Value></Tag>" for k, v in tags.items()]
        return (
            '<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            f"</TagSet>{''.join(tags)}</TagSet>"
            "</Tagging>"
        )

    @property
    def _expected_metrics_for_test(self):
        return self.metrics_by_passes

    def _create_mpu(self, obj_name, nb_parts=1, size=1):
        upload_id = random_str(48)
        # Create manifest
        chunks, _, _, obj_meta = self.storage.object_create_ext(
            account=self.account,
            container=self.container,
            obj_name=obj_name,
            data=b"m" * size,
            properties={
                "x-static-large-object": "True",
                "x-object-sysmeta-s3api-upload-id": upload_id,
            },
            policy="TWOCOPIES",
        )
        chunks = [c for c in chunks]
        part_size = size // nb_parts
        parts = []
        for i in range(1, nb_parts + 1):
            obj = f"{obj_name}/{upload_id}/{i}"
            chunks_part, _, _, part_meta = self.storage.object_create_ext(
                account=self.account,
                container=self.container_segment,
                obj_name=obj,
                data=b"a" * part_size,
                policy="TWOCOPIES",
            )
            chunks.extend(chunks_part)
            parts.append((obj, part_meta["version"]))

        return chunks, obj_meta, parts

    def _create_objects_for_rule(
        self,
        rule_id,
        container=None,
        count=1,
        prefix="",
        objects=None,
        versions=1,
        tags=None,
        size=128001,
        mpu=False,
        properties=None,
        extras_fields=None,
        action=None,
    ):
        properties = properties or {}
        if tags:
            properties = {
                TAGGING_KEY: self.__build_tagset(tags),
            }
        if container is None:
            container = self.container

        def generator():
            if objects is None:
                for _ in range(count):
                    yield f"{prefix}test-object-{random_str(6)}"
            else:
                for name, _version in objects:
                    yield name

        created_objects = []
        for obj_name in generator():
            for _ in range(versions):
                parts = None
                if mpu:
                    chunks, meta, parts = self._create_mpu(obj_name, size=size)
                else:
                    chunks, _, _, meta = self.storage.object_create_ext(
                        self.account,
                        container,
                        obj_name=obj_name,
                        data=b"a" * size,
                        properties=properties,
                        policy="TWOCOPIES",
                    )
                if rule_id:
                    self.expectations.append(
                        Expectation(
                            rule_id,
                            action,
                            obj_name,
                            meta["version"],
                            extra_fields=extras_fields,
                            chunks=chunks,
                            parts=parts,
                        )
                    )
            created_objects.append((obj_name, meta["version"]))
        return created_objects

    def _delete_objects_for_rule(self, rule_id, objects, extra_fields=None):
        deletions = []
        for obj_name, obj_version in objects:
            is_delete_marker, version_id = self.storage.object_delete(
                self.account,
                self.container,
                obj_name,
                version=obj_version,
            )
            if rule_id:
                self.expectations.append(
                    Expectation(
                        rule_id,
                        "",
                        obj_name,
                        version_id,
                        extra_fields=extra_fields,
                    )
                )
            deletions.append((is_delete_marker, version_id))

    def _make_local_copy(
        self, meta2db_env, timestamp=None, create_copy=True, prefix="Lifecycle"
    ):
        if timestamp is None:
            timestamp = time.time()
        suffix = f"{prefix}-{self.run_id}-{timestamp}"
        params = {
            "service_type": "meta2",
            "cid": meta2db_env["cid"],
            "svc_from": meta2db_env["volume_id"],
            "suffix": suffix,
        }
        if meta2db_env:
            meta2db_env["suffix"] = suffix
            meta2db_env["path"] = f"{meta2db_env['path']}.{suffix}"
        if create_copy:
            # Request a local copy of the meta2 database
            self.admin.copy_base_local(**params)
            self.local_copies.append(meta2db_env["path"])

    def _get_meta2db_env(self, cid):
        services = self.conscience.all_services("meta2")
        volumes = {
            s["id"]: s["tags"]["tag.vol"] for s in services if "tag.vol" in s["tags"]
        }
        status = self.admin.election_status("meta2", cid=cid)
        master = status.get("master")
        return {
            "path": "/".join((volumes[master], cid[:3], cid + ".1.meta2")),
            "volume_id": master,
            "cid": cid,
            "seq": 1,
        }

    def _ensure_no_more_event(self):
        event = self.wait_for_kafka_event(
            kafka_consumer=self._cls_lifecycle_consumer,
            types=[EventTypes.LIFECYCLE_ACTION],
            timeout=2.0,
        )
        rule_id = ""
        if event:
            rule_id = event.data.get("rule_id", "")

        self.assertIsNone(
            event,
            f"Some extra events produced for rule: '{rule_id}'",
        )

    def _validate_metrics(self, current_pass):
        stats = self.lifecycle_filter._get_filter_stats()
        if current_pass >= len(self._expected_metrics_for_test):
            self.fail(f"No expected stats for pass {current_pass}")
        for key, value in self._expected_metrics_for_test[current_pass].items():
            self.assertIn(key, stats)
            if value != stats[key]:
                self.logger.warning(
                    "Stat '%s' does not match in pass %s: expected %s but got %s",
                    key,
                    current_pass,
                    value,
                    stats[key],
                )
        for key, value in self._expected_metrics_for_test[current_pass].items():
            self.assertEqual(
                value, stats[key], f"Stat '{key}' does not match in pass {current_pass}"
            )

    def _trigger_sharding(self):
        for container in (self.container, self.container_segment):
            shards = self.shard_container(container)
            self.containers_to_process.extend(shards)

    def _run_scenario(
        self, configuration, cb, filter_conf=None, passes=1, prefix="Lifecycle"
    ):
        # Trigger Sharding if activated
        if self.use_sharding:
            self._trigger_sharding()
        timestamp = time.time()
        with patch(
            "oio.crawler.meta2.filters.lifecycle.Lifecycle._retrieve_lifecycle_config"
        ) as mock_retrieve_config:
            # Install custom configuration
            mock_retrieve_config.return_value = configuration
            for current_pass in range(passes):
                # One pass per container
                filter_conf = filter_conf or {}
                filter_conf = {
                    **self.filter_conf,
                    **filter_conf,
                }
                self.lifecycle_filter = Lifecycle(
                    app=self.app, conf=filter_conf, logger=self.logger
                )
                for account, container in self.containers_to_process:
                    cid = cid_from_name(account, container)
                    env = self._get_meta2db_env(cid)
                    self._make_local_copy(
                        env,
                        timestamp=timestamp,
                        create_copy=current_pass == 0,
                        prefix=prefix,
                    )
                    self.lifecycle_filter._process(env, cb)
                self._validate_metrics(current_pass)
            # Validation
            for i, expect in enumerate(self.expectations, start=1):
                event = self.wait_for_kafka_event(
                    kafka_consumer=self._cls_lifecycle_consumer,
                    types=[EventTypes.LIFECYCLE_ACTION],
                    data_fields={
                        "object": expect.key,
                        "rule_id": expect.rule_id,
                        "run_id": self.run_id,
                        **expect.extra_fields,
                    },
                    timeout=60.0,
                )
                self.assertIsNotNone(
                    event,
                    f"({i}/{len(self.expectations)}) Event not found for: {expect}",
                )
                self.assertIsNotNone(event.event_key)
                self.assertTrue(isinstance(event.event_key, bytes))
                self.assertEqual(event.url["id"], event.event_key.decode("utf-8"))
                # Validate access logging info are present
                self.assertIn("has_bucket_logging", event.data)
                self.assertTrue(event.data["has_bucket_logging"])
                self.assertIn("bucket_owner", event.data)
                self.assertEqual(event.data["bucket_owner"], "demo:demo")
                if expect.action == ExpectedAction.DELETE:
                    self._validate_delete_action(expect)
                elif expect.action == ExpectedAction.DELETE_MARKER:
                    self._validate_delete_marker_action(expect)

                # Ensure event is processed (same event fromoio-preserved)
                event = self.wait_for_kafka_event(
                    types=[EventTypes.LIFECYCLE_ACTION],
                    data_fields={
                        "object": expect.key,
                        "rule_id": expect.rule_id,
                        "run_id": self.run_id,
                        **expect.extra_fields,
                    },
                )
                self.assertIsNotNone(
                    event,
                    f"({i}/{len(self.expectations)}) Event not found for: {expect}",
                )

            self._ensure_no_more_event()

    def _validate_delete_action(self, expect):
        # Ensure object had been deleted
        event = self.wait_for_kafka_event(
            types=(EventTypes.CONTENT_DELETED,),
            origin=LIFECYCLE_USER_AGENT,
            fields={
                "path": expect.key,
                "version": expect.version,
            },
        )
        self.assertIsNotNone(
            event,
            f"Expecting delete event for object {expect.key} {expect.version}",
        )

        # Ensure object is not accessible anymore
        self.assertRaises(
            NoSuchObject,
            self.storage.object_get_properties,
            self.account,
            self.container,
            expect.key,
            version=expect.version,
        )

        # Ensure chunks are still present
        for chunk in expect.chunks:
            self.assertIsNotNone(
                self.storage.blob_client.chunk_head(chunk.get("real_url", chunk["url"]))
            )

        # Ensure parts had been removed
        for part_name, part_version in expect.parts:
            self.assertRaises(
                NoSuchObject,
                self.storage.object_get_properties,
                self.account,
                self.container_segment,
                part_name,
                version=part_version,
            )

    def _validate_delete_marker_action(self, expect):
        # Ensure a delete marker had been added
        props = self.storage.object_get_properties(
            self.account,
            self.container,
            expect.key,
        )
        self.assertIn("deleted", props)
        self.assertTrue(props["deleted"])

        # Ensure previous version still exist
        self.storage.object_get_properties(
            self.account,
            self.container,
            expect.key,
            version=expect.version,
        )

    def test_not_empty_filter(self):
        def callback(status, _msg):
            self.assertEqual(500, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"Tags": [{"Key": "key1", "Value": "value1"}]},
                    "Expiration": {
                        "0": {"Days": 2},
                        "__time_type": "Days",
                    },
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

        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 0,
                "errors": 2,
            },
        )

        self._create_objects_for_rule(None, prefix="doc/", count=10)
        self._create_objects_for_rule(None, prefix="foo/", count=10)
        self._wait_n_days(4)
        self._run_scenario(configuration, callback)

    def test_wrong_tags(self):
        def callback(status, _msg):
            self.assertEqual(500, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"Tag": [{"key1": "value1"}]},
                    "Expiration": {
                        "0": {"Days": 2},
                        "__time_type": "Days",
                    },
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

        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 0,
                "errors": 2,
            },
        )

        self._create_objects_for_rule(None, prefix="doc/", count=10)
        self._create_objects_for_rule(None, prefix="foo/", count=10)
        self._wait_n_days(4)
        self._run_scenario(configuration, callback)

    def test_disabled_time_bypass(self):
        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "doc/"},
                    "Expiration": {
                        "0": {"Days": 2},
                        "__time_type": "Days",
                    },
                },
                "1": {
                    "ID": "rule-2",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "foo/"},
                    "Expiration": {
                        "1": {"Days": 10},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": ["0-0", "1-1"], "date": []},
            "_transition_rules": {"days": [], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }

        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
            },
        )

        self.storage.container_set_properties(
            self.account,
            self.container,
            system={
                M2_PROP_LIFECYCLE_TIME_BYPASS: "0",
            },
        )
        self._create_objects_for_rule(None, prefix="doc/", count=10)
        self._create_objects_for_rule(None, prefix="foo/", count=10)
        self._wait_n_days(4)
        self._run_scenario(configuration, callback)

    def test_wrong_container(self):
        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "doc/"},
                    "Expiration": {
                        "0": {"Days": 2},
                        "__time_type": "Days",
                    },
                },
                "1": {
                    "ID": "rule-2",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "foo/"},
                    "Expiration": {
                        "1": {"Days": 10},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": ["0-0", "1-1"], "date": []},
            "_transition_rules": {"days": [], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }

        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "skipped": 2,
            },
        )

        self._create_objects_for_rule(None, prefix="doc/", count=10)
        self._create_objects_for_rule(None, prefix="foo/", count=10)
        self._wait_n_days(4)
        self._run_scenario(configuration, callback, prefix="Wrong")

    def test_expiration(self):
        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "doc/"},
                    "Expiration": {
                        "0": {"Days": 2},
                        "__time_type": "Days",
                    },
                },
                "1": {
                    "ID": "rule-2",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "foo/"},
                    "Expiration": {
                        "1": {"Days": 10},
                        "__time_type": "Days",
                    },
                },
                "2": {
                    "ID": "rule-3",
                    "Status": "Enabled",
                    "Filter": {"Prefix": " OR 1=1 "},
                    "Expiration": {
                        "2": {"Days": 2},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": ["0-0", "2-2", "1-1"], "date": []},
            "_transition_rules": {"days": [], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "total_events": 10,
                "total_delete": 10,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 2,
            },
        )
        self._create_objects_for_rule(
            "rule-1", prefix="doc/", count=10, action=ExpectedAction.DELETE
        )
        self._create_objects_for_rule(None, prefix="foo/", count=10)
        self._create_objects_for_rule(None, prefix="bar/", count=10)
        self._wait_n_days(4)
        self._run_scenario(configuration, callback, passes=2)

    def test_expiration_mpu(self):
        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "doc/"},
                    "Expiration": {
                        "0": {"Days": 2},
                        "__time_type": "Days",
                    },
                },
                "1": {
                    "ID": "rule-2",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "foo/"},
                    "Expiration": {
                        "1": {"Days": 10},
                        "__time_type": "Days",
                    },
                },
                "2": {
                    "ID": "rule-3",
                    "Status": "Enabled",
                    "Filter": {"Prefix": " OR 1=1 "},
                    "Expiration": {
                        "2": {"Days": 2},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": ["0-0", "2-2", "1-1"], "date": []},
            "_transition_rules": {"days": [], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "total_events": 10,
                "total_delete": 10,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 2,
            },
        )
        self._create_objects_for_rule(
            "rule-1", prefix="doc/", count=10, action=ExpectedAction.DELETE, mpu=True
        )
        self._create_objects_for_rule(None, prefix="foo/", count=10, mpu=True)
        self._create_objects_for_rule(None, prefix="bar/", count=10, mpu=True)
        self._wait_n_days(4)
        self._run_scenario(configuration, callback, passes=2)

    def test_expiration_no_filter(self):
        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {},
                    "Expiration": {
                        "0": {"Days": 2},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {
                "days": [
                    "0-0",
                ],
                "date": [],
            },
            "_transition_rules": {"days": [], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "total_events": 20,
                "total_delete": 20,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 2,
            },
        )
        self._create_objects_for_rule(
            "rule-1", prefix="doc/", count=10, action=ExpectedAction.DELETE
        )
        self._create_objects_for_rule(
            "rule-1", prefix="foo/", count=10, action=ExpectedAction.DELETE
        )
        self._wait_n_days(4)
        self._run_scenario(configuration, callback, passes=2)

    def test_expiration_tagging(self):
        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {
                        "Tag": [
                            {"Key": "key1", "Value": "value1"},
                            {"Key": "key2", "Value": "value2"},
                        ]
                    },
                    "Expiration": {
                        "0": {"Days": 2},
                        "__time_type": "Days",
                    },
                },
                "1": {
                    "ID": "rule-2",
                    "Status": "Enabled",
                    "Filter": {"Tag": [{"Key": "key3", "Value": "value3"}]},
                    "Expiration": {
                        "1": {"Days": 2},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": ["0-0", "1-1"], "date": []},
            "_transition_rules": {"days": [], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "total_events": 20,
                "total_delete": 20,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 2,
            },
        )
        self._create_objects_for_rule(
            "rule-1",
            prefix="doc1/",
            count=10,
            tags={"key1": "value1", "key2": "value2"},
            action=ExpectedAction.DELETE,
        )
        self._create_objects_for_rule(
            "rule-2",
            prefix="doc2/",
            count=10,
            tags={"key3": "value3"},
            action=ExpectedAction.DELETE,
        )
        self._create_objects_for_rule(
            None, prefix="foo/", count=10, tags={"key1": "value1"}
        )
        self._wait_n_days(4)
        self._run_scenario(configuration, callback, passes=2)

    def test_expiration_tagging_versioned(self):
        self._enable_versioning()

        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {
                        "Tag": [
                            {"Key": "key1", "Value": "value1"},
                            {"Key": "key2", "Value": "value2"},
                        ]
                    },
                    "Expiration": {
                        "0": {"Days": 2},
                        "__time_type": "Days",
                    },
                },
                "1": {
                    "ID": "rule-2",
                    "Status": "Enabled",
                    "Filter": {"Tag": [{"Key": "key3", "Value": "value3"}]},
                    "Expiration": {
                        "1": {"Days": 2},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": ["0-0", "1-1"], "date": []},
            "_transition_rules": {"days": [], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "total_events": 20,
                "total_delete": 20,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 2,
            },
        )
        self._create_objects_for_rule(
            "rule-1",
            prefix="doc1/",
            count=10,
            tags={"key1": "value1", "key2": "value2"},
            extras_fields={"add_delete_marker": 1},
            action=ExpectedAction.DELETE_MARKER,
        )
        self._create_objects_for_rule(
            "rule-2",
            prefix="doc2/",
            count=10,
            tags={"key3": "value3"},
            extras_fields={"add_delete_marker": 1},
            action=ExpectedAction.DELETE_MARKER,
        )
        self._create_objects_for_rule(
            None, prefix="foo/", count=10, tags={"key1": "value1"}
        )
        self._wait_n_days(4)
        self._run_scenario(configuration, callback, passes=2)

    def test_expiration_less_than(self):
        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"ObjectSizeLessThan": 10},
                    "Expiration": {
                        "0": {"Days": 2},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": ["0-0"], "date": []},
            "_transition_rules": {"days": [], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "total_events": 10,
                "total_delete": 10,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 2,
            },
        )
        self._create_objects_for_rule(
            "rule-1", prefix="doc/", count=10, size=8, action=ExpectedAction.DELETE
        )
        self._create_objects_for_rule(None, prefix="doc/", count=10, size=20)
        self._wait_n_days(4)
        self._run_scenario(configuration, callback, passes=2)

    def test_expiration_less_than_versioned(self):
        self._enable_versioning()

        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"ObjectSizeLessThan": 10},
                    "Expiration": {
                        "0": {"Days": 2},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": ["0-0"], "date": []},
            "_transition_rules": {"days": [], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "total_events": 10,
                "total_delete": 10,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 2,
            },
        )
        self._create_objects_for_rule(
            "rule-1",
            prefix="doc/",
            count=10,
            size=8,
            extras_fields={"add_delete_marker": 1},
            action=ExpectedAction.DELETE_MARKER,
        )
        self._create_objects_for_rule(None, prefix="doc/", count=10, size=20)
        self._wait_n_days(4)
        self._run_scenario(configuration, callback, passes=2)

    def test_expiration_greater_than(self):
        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"ObjectSizeGreaterThan": 10},
                    "Expiration": {
                        "0": {"Days": 2},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": ["0-0"], "date": []},
            "_transition_rules": {"days": [], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "total_events": 10,
                "total_delete": 10,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 2,
            },
        )
        self._create_objects_for_rule(
            "rule-1",
            prefix="doc/",
            count=10,
            size=18,
            action=ExpectedAction.DELETE,
        )
        self._create_objects_for_rule(None, prefix="doc/", count=10, size=8)
        self._wait_n_days(4)
        self._run_scenario(configuration, callback, passes=2)

    def test_expiration_greater_than_versioned(self):
        self._enable_versioning()

        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"ObjectSizeGreaterThan": 10},
                    "Expiration": {
                        "0": {"Days": 2},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": ["0-0"], "date": []},
            "_transition_rules": {"days": [], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "total_events": 10,
                "total_delete": 10,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 2,
            },
        )
        self._create_objects_for_rule(
            "rule-1",
            prefix="doc/",
            count=10,
            size=18,
            extras_fields={"add_delete_marker": 1},
            action=ExpectedAction.DELETE_MARKER,
        )
        self._create_objects_for_rule(None, prefix="doc/", count=10, size=8)
        self._wait_n_days(4)
        self._run_scenario(configuration, callback, passes=2)

    def test_expiration_all_filters(self):
        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {
                        "ObjectSizeLessThan": 20,
                        "ObjectSizeGreaterThan": 10,
                        "Tag": [{"Key": "key1", "Value": "value1"}],
                        "Prefix": "doc/",
                    },
                    "Expiration": {
                        "0": {"Days": 2},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": ["0-0"], "date": []},
            "_transition_rules": {"days": [], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "total_events": 10,
                "total_delete": 10,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 2,
            },
        )
        # Match all criteria
        self._create_objects_for_rule(
            "rule-1",
            prefix="doc/",
            count=10,
            size=18,
            tags={"key1": "value1"},
            action=ExpectedAction.DELETE,
        )
        # Match all criteria but one
        self._create_objects_for_rule(None, prefix="doc/", count=10, size=18)
        self._create_objects_for_rule(
            None, prefix="doc/", count=10, size=28, tags={"key1": "value1"}
        )
        self._create_objects_for_rule(
            None, prefix="doc/", count=10, size=8, tags={"key1": "value1"}
        )
        self._create_objects_for_rule(
            None, prefix="foo/", count=10, size=18, tags={"key1": "value1"}
        )
        self._wait_n_days(4)
        self._run_scenario(configuration, callback, passes=2)

    def test_expiration_all_filters_versioned(self):
        self._enable_versioning()

        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {
                        "ObjectSizeLessThan": 20,
                        "ObjectSizeGreaterThan": 10,
                        "Tag": [{"Key": "key1", "Value": "value1"}],
                        "Prefix": "doc/",
                    },
                    "Expiration": {
                        "0": {"Days": 2},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": ["0-0"], "date": []},
            "_transition_rules": {"days": [], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "total_events": 10,
                "total_delete": 10,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 2,
            },
        )
        # Match all criteria
        self._create_objects_for_rule(
            "rule-1",
            prefix="doc/",
            count=10,
            size=18,
            tags={"key1": "value1"},
            extras_fields={"add_delete_marker": 1},
            action=ExpectedAction.DELETE_MARKER,
        )
        # Match all criteria but one
        self._create_objects_for_rule(None, prefix="doc/", count=10, size=18)
        self._create_objects_for_rule(
            None, prefix="doc/", count=10, size=28, tags={"key1": "value1"}
        )
        self._create_objects_for_rule(
            None, prefix="doc/", count=10, size=8, tags={"key1": "value1"}
        )
        self._create_objects_for_rule(
            None, prefix="foo/", count=10, size=18, tags={"key1": "value1"}
        )
        self._wait_n_days(4)
        self._run_scenario(configuration, callback, passes=2)

    def test_expiration_multiple_passes(self):
        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "doc/"},
                    "Expiration": {
                        "0": {"Days": 2},
                        "__time_type": "Days",
                    },
                },
                "1": {
                    "ID": "rule-2",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "foo/"},
                    "Expiration": {
                        "1": {"Days": 12},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": ["0-0", "1-1"], "date": []},
            "_transition_rules": {"days": [], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "container_budget_reached": 1,
                "total_events": 20,
                "total_delete": 20,
            },
            {
                **self.DEFAULT_STATS,
                "successes": 1,
                "processed": 1,
                "container_budget_reached": 1,
                "total_events": 20,
                "total_delete": 20,
            },
            {
                **self.DEFAULT_STATS,
                "successes": 1,
                "processed": 1,
                "container_budget_reached": 1,
                "total_events": 20,
                "total_delete": 20,
            },
        )
        self._create_objects_for_rule(
            "rule-1", prefix="doc/a", count=60, action=ExpectedAction.DELETE
        )
        self._create_objects_for_rule(None, prefix="doc/z", count=40)
        self._create_objects_for_rule(None, prefix="foo/", count=100)
        self._wait_n_days(3)
        # Only the two first passes should generate events
        self._run_scenario(
            configuration,
            callback,
            filter_conf={"container_budget_per_pass": 20},
            passes=3,
        )

    def test_bucket_budget_reached(self):
        # self._enable_versioning()

        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "doc/"},
                    "Expiration": {
                        "0": {"Days": 2},
                        "__time_type": "Days",
                    },
                },
                "1": {
                    "ID": "rule-2",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "foo/"},
                    "Expiration": {
                        "1": {"Days": 2},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": ["0-0", "1-1"], "date": []},
            "_transition_rules": {"days": [], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "container_budget_reached": 1,
                "total_events": 5,
                "total_delete": 5,
            },
            {
                **self.DEFAULT_STATS,
                "successes": 1,
                "processed": 1,
                "container_budget_reached": 1,
                "total_events": 5,
                "total_delete": 5,
            },
            {
                **self.DEFAULT_STATS,
                "successes": 1,
                "processed": 1,
                "container_budget_reached": 1,
                "total_events": 5,
                "total_delete": 5,
            },
            {
                **self.DEFAULT_STATS,
                "successes": 1,
                "processed": 1,
                "container_budget_reached": 1,
                "total_events": 5,
                "total_delete": 5,
            },
            {
                **self.DEFAULT_STATS,
                "successes": 1,
                "processed": 1,
                "container_budget_reached": 1,
                "total_events": 5,
                "total_delete": 5,
            },
            {
                **self.DEFAULT_STATS,
                "successes": 1,
                "processed": 1,
                "bucket_budget_reached": 1,
            },
        )

        self._create_objects_for_rule(
            "rule-1", prefix="doc/a/", count=10, action=ExpectedAction.DELETE
        )
        self._create_objects_for_rule(
            "rule-1", prefix="doc/b/", count=5, action=ExpectedAction.DELETE
        )
        self._create_objects_for_rule(
            "rule-1", prefix="doc/c/", count=5, action=ExpectedAction.DELETE
        )
        self._create_objects_for_rule(
            "rule-1", prefix="doc/z/", count=5, action=ExpectedAction.DELETE
        )
        self._create_objects_for_rule(None, prefix="foo/", count=5)
        self._wait_n_days(3)
        self._run_scenario(
            configuration,
            callback,
            filter_conf={"budget_per_bucket": 25, "container_budget_per_pass": 5},
            passes=6,
        )

    def test_non_current_budget_reached(self):
        self._enable_versioning()

        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "doc/"},
                    "NoncurrentVersionExpiration": {
                        "0": {"NoncurrentDays": 2, "NewerNoncurrentVersions": 100},
                        "__time_type": "Days",
                    },
                },
                "1": {
                    "ID": "rule-2",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "foo/"},
                    "NoncurrentVersionExpiration": {
                        "1": {"NoncurrentDays": 2, "NewerNoncurrentVersions": 100},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": [], "date": []},
            "_transition_rules": {"days": [], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": ["0-0", "1-1"],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "container_budget_reached": 1,
                "total_events": 5,
                "total_delete": 5,
            },
            {
                **self.DEFAULT_STATS,
                "successes": 1,
                "processed": 1,
                "container_budget_reached": 1,
                "total_events": 5,
                "total_delete": 5,
            },
            {
                **self.DEFAULT_STATS,
                "successes": 1,
                "processed": 1,
                "container_budget_reached": 1,
                "total_events": 5,
                "total_delete": 5,
            },
            {
                **self.DEFAULT_STATS,
                "successes": 1,
                "processed": 1,
                "container_budget_reached": 1,
                "total_events": 5,
                "total_delete": 5,
            },
            {
                **self.DEFAULT_STATS,
                "successes": 1,
                "processed": 1,
                "container_budget_reached": 1,
                "total_events": 5,
                "total_delete": 5,
            },
            {
                **self.DEFAULT_STATS,
                "successes": 1,
                "processed": 1,
                "bucket_budget_reached": 1,
            },
        )
        objects = self._create_objects_for_rule(
            "rule-1",
            prefix="doc/a/",
            count=10,
            versions=1,
            action=ExpectedAction.DELETE,
        )
        self._create_objects_for_rule(None, objects=objects, versions=101)
        objects = self._create_objects_for_rule(
            "rule-1", prefix="doc/b/", count=5, versions=1, action=ExpectedAction.DELETE
        )
        self._create_objects_for_rule(None, objects=objects, versions=101)
        objects = self._create_objects_for_rule(
            "rule-1", prefix="doc/c/", count=5, versions=1, action=ExpectedAction.DELETE
        )
        self._create_objects_for_rule(None, objects=objects, versions=101)
        objects = self._create_objects_for_rule(
            "rule-1", prefix="doc/z/", count=5, versions=1, action=ExpectedAction.DELETE
        )
        self._create_objects_for_rule(None, objects=objects, versions=101)

        self._create_objects_for_rule(None, prefix="foo/", count=5, versions=102)
        self._wait_n_days(3)
        self._run_scenario(
            configuration,
            callback,
            filter_conf={"budget_per_bucket": 25, "container_budget_per_pass": 5},
            passes=6,
        )

    def test_override_bucket_budget_larger(self):
        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "doc/1.0"},
                    "Expiration": {
                        "0": {"Days": 2},
                        "__time_type": "Days",
                    },
                },
                "1": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "doc/1.2"},
                    "Expiration": {
                        "1": {"Days": 2},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": ["0-0", "1-1"], "date": []},
            "_transition_rules": {"days": [], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "container_budget_reached": 1,
                "successes": 2,
                "total_events": 7,
                "total_delete": 7,
            },
            {
                **self.DEFAULT_STATS,
                "bucket_budget_reached": 1,
                "processed": 1,
                "successes": 1,
                "total_events": 3,
                "total_delete": 3,
            },
        )

        self.storage.container_set_properties(
            self.account,
            self.container,
            system={
                M2_PROP_LIFECYCLE_CUSTOM_BUDGET: "10",
            },
        )

        self._create_objects_for_rule(
            "rule-1", prefix="doc/1.0", count=7, action=ExpectedAction.DELETE
        )
        self._create_objects_for_rule(None, prefix="doc/1.1", count=3)
        self._create_objects_for_rule(
            "rule-1", prefix="doc/1.2", count=3, action=ExpectedAction.DELETE
        )
        self._create_objects_for_rule(None, prefix="foo/", count=7)
        self._wait_n_days(4)
        self._run_scenario(
            configuration,
            callback,
            passes=2,
            filter_conf={"budget_per_bucket": 3, "container_budget_per_pass": 7},
        )

    def test_override_bucket_budget_smaller(self):
        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "doc/1.0"},
                    "Expiration": {
                        "0": {"Days": 2},
                        "__time_type": "Days",
                    },
                },
                "1": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "doc/1.2"},
                    "Expiration": {
                        "1": {"Days": 2},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": ["0-0", "1-1"], "date": []},
            "_transition_rules": {"days": [], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "container_budget_reached": 1,
                "successes": 2,
                "total_events": 7,
                "total_delete": 7,
            },
            {
                **self.DEFAULT_STATS,
                "bucket_budget_reached": 1,
                "processed": 1,
                "successes": 1,
                "total_events": 3,
                "total_delete": 3,
            },
        )
        self.storage.container_set_properties(
            self.account,
            self.container,
            system={
                M2_PROP_LIFECYCLE_CUSTOM_BUDGET: "10",
            },
        )

        self._create_objects_for_rule(
            "rule-1", prefix="doc/1.0", count=7, action=ExpectedAction.DELETE
        )
        self._create_objects_for_rule(None, prefix="doc/1.1", count=3)
        self._create_objects_for_rule(
            "rule-1", prefix="doc/1.2", count=3, action=ExpectedAction.DELETE
        )
        self._create_objects_for_rule(None, prefix="foo/", count=7)
        self._wait_n_days(4)
        self._run_scenario(
            configuration,
            callback,
            passes=2,
            filter_conf={"budget_per_bucket": 20, "container_budget_per_pass": 7},
        )

    def test_expiration_versioned(self):
        self._enable_versioning()

        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "doc/"},
                    "Expiration": {
                        "0": {"Days": 2},
                        "__time_type": "Days",
                    },
                },
                "1": {
                    "ID": "rule-2",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "foo/"},
                    "Expiration": {
                        "1": {"Days": 6},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": ["0-0", "1-1"], "date": []},
            "_transition_rules": {"days": [], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "total_events": 10,
                "total_delete": 10,
            },
        )
        self._create_objects_for_rule(
            "rule-1",
            prefix="doc/",
            count=10,
            extras_fields={"add_delete_marker": 1},
        )
        self._create_objects_for_rule(None, prefix="foo/", count=10)
        self._wait_n_days(3)
        self._run_scenario(configuration, callback)

    def test_non_current_expiration_versioned_multiple_passes(self):
        self._enable_versioning()

        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "doc/"},
                    "NoncurrentVersionExpiration": {
                        "0": {"NoncurrentDays": 2, "NewerNoncurrentVersions": 2},
                        "__time_type": "NoncurrentDays",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": [], "date": []},
            "_transition_rules": {"days": [], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": ["0-0"],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "container_budget_reached": 1,
                "total_events": 3,
                "total_delete": 3,
            },
            {
                **self.DEFAULT_STATS,
                "successes": 1,
                "processed": 1,
                "total_events": 1,
                "total_delete": 1,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 2,
            },
        )
        objects = self._create_objects_for_rule(
            "rule-1", prefix="doc/", count=1, versions=4, action=ExpectedAction.DELETE
        )
        self._create_objects_for_rule(None, objects=objects, versions=3)
        self._wait_n_days(3)
        self._run_scenario(
            configuration,
            callback,
            filter_conf={"container_budget_per_pass": 3},
            passes=3,
        )

    def test_non_current_expiration_versioned(self):
        self._enable_versioning()

        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "doc/"},
                    "NoncurrentVersionExpiration": {
                        "0": {"NoncurrentDays": 2, "NewerNoncurrentVersions": 5},
                        "__time_type": "NoncurrentDays",
                    },
                },
                "1": {
                    "ID": "rule-2",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "foo/"},
                    "NoncurrentVersionExpiration": {
                        "1": {"NoncurrentDays": 2, "NewerNoncurrentVersions": 1},
                        "__time_type": "NoncurrentDays",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": [], "date": []},
            "_transition_rules": {"days": [], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": ["0-0", "1-1"],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "total_events": 150,
                "total_delete": 150,
            },
        )
        objects = self._create_objects_for_rule(
            "rule-1", prefix="doc/", count=10, versions=5, action=ExpectedAction.DELETE
        )
        self._create_objects_for_rule(None, objects=objects, versions=5)
        self._wait_n_days(3)
        self._create_objects_for_rule(None, objects=objects, versions=1)

        objects = self._create_objects_for_rule(
            "rule-2", prefix="foo/", count=10, versions=10, action=ExpectedAction.DELETE
        )
        self._create_objects_for_rule(None, objects=objects, versions=1)
        self._wait_n_days(3)
        self._create_objects_for_rule(None, objects=objects, versions=1)
        self._run_scenario(configuration, callback)

    def test_expiration_non_current_since(self):
        self._enable_versioning()

        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "doc/"},
                    "NoncurrentVersionExpiration": {
                        "0": {"NoncurrentDays": 3},
                        "__time_type": "NoncurrentDays",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": [], "date": []},
            "_transition_rules": {"days": [], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": ["0-0"],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "total_events": 10,
                "total_delete": 10,
            },
        )
        objects = self._create_objects_for_rule(
            "rule-1", prefix="doc/", count=10, versions=1, action=ExpectedAction.DELETE
        )
        self._create_objects_for_rule(None, objects=objects, versions=1)
        self._wait_n_days(3)
        self._create_objects_for_rule(None, objects=objects, versions=1)
        self._wait_n_days(1)
        self._run_scenario(configuration, callback)

    def test_expiration_last_version_is_delete_marker(self):
        self._enable_versioning()

        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "doc/"},
                    "Expiration": {
                        "0": {"Days": 1},
                        "__time_type": "Days",
                    },
                },
                "1": {
                    "ID": "rule-2",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "foo/"},
                    "Expiration": {
                        "1": {"Days": 1},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": ["0-0", "1-1"], "date": []},
            "_transition_rules": {"days": [], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "total_events": 10,
                "total_delete": 10,
            },
        )
        objects = self._create_objects_for_rule(None, prefix="doc/", count=10)
        # Create delete marker
        self._delete_objects_for_rule(None, [(o, None) for o, _ in objects])
        objects = self._create_objects_for_rule(None, prefix="doc/", count=10)
        # Create delete marker
        self._delete_objects_for_rule(None, [(o, None) for o, _ in objects])
        objects = self._create_objects_for_rule(
            "rule-2",
            prefix="foo/",
            count=10,
            action=ExpectedAction.DELETE_MARKER,
            extras_fields={"add_delete_marker": 1},
        )
        objects = self._create_objects_for_rule(None, prefix="bar/", count=10)
        # Create delete marker
        self._delete_objects_for_rule(None, [(o, None) for o, _ in objects])
        self._wait_n_days(3)
        self._run_scenario(configuration, callback)

    def test_expiration_delete_marker(self):
        self._enable_versioning()

        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "doc/"},
                    "Expiration": {
                        "0": {"ExpiredObjectDeleteMarker": True},
                        "__time_type": None,
                    },
                },
                "1": {
                    "ID": "rule-2",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "foo/"},
                    "Expiration": {
                        "1": {"ExpiredObjectDeleteMarker": True},
                        "__time_type": None,
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": [], "date": []},
            "_transition_rules": {"days": [], "date": []},
            "_delete_marker_rules": ["0-0", "1-1"],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "total_events": 10,
                "total_delete": 10,
            },
        )
        objects = self._create_objects_for_rule(None, prefix="doc/", count=10)
        # Create delete marker
        self._delete_objects_for_rule(None, [(o, None) for o, _ in objects])
        # Delete previous versions
        self._delete_objects_for_rule("rule-1", objects)
        objects = self._create_objects_for_rule(None, prefix="doc/", count=10)
        # Create delete marker
        self._delete_objects_for_rule(None, [(o, None) for o, _ in objects])
        objects = self._create_objects_for_rule(None, prefix="foo/", count=10)
        self._delete_objects_for_rule(None, [(o, None) for o, _ in objects])
        objects = self._create_objects_for_rule(None, prefix="bar/", count=10)
        # Create delete marker
        self._delete_objects_for_rule(None, [(o, None) for o, _ in objects])
        # Delete previous versions
        self._delete_objects_for_rule(None, objects)
        self._wait_n_days(3)
        self._run_scenario(configuration, callback)

    def test_abort_mpu(self):
        self._enable_versioning()

        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "doc/"},
                    "AbortIncompleteMultipartUpload": {
                        "0": {"DaysAfterInitiation": 2},
                    },
                },
                "1": {
                    "ID": "rule-2",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "foo/"},
                    "AbortIncompleteMultipartUpload": {
                        "1": {"DaysAfterInitiation": 15},
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": [], "date": []},
            "_transition_rules": {"days": [], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": ["0-0", "1-1"],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "total_events": 10,
                "total_abortmpu": 10,
            },
        )
        mpus = self._create_objects_for_rule(
            "rule-1",
            count=10,
            prefix="doc/",
            container=self.container_segment,
            properties={"x-object-sysmeta-s3api-has-content-type": "no"},
        )
        mpu_parts = [(f"{mpu}/{i}", None) for mpu, _ in mpus for i in range(20)]
        self._create_objects_for_rule(
            None, objects=mpu_parts, container=self.container_segment
        )
        # Create similar object name on root container
        self._create_objects_for_rule(None, objects=mpus)

        mpus = self._create_objects_for_rule(
            None,
            count=10,
            prefix="foo/",
            container=self.container_segment,
            properties={"x-object-sysmeta-s3api-has-content-type": "no"},
        )
        mpu_parts = [(f"{mpu}/{i}", None) for mpu, _ in mpus for i in range(20)]
        self._create_objects_for_rule(
            None, objects=mpu_parts, container=self.container_segment
        )
        self._wait_n_days(3)
        self._run_scenario(configuration, callback)

    def test_expiration_restore(self):
        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "doc/"},
                    "Expiration": {
                        "0": {"Days": 2},
                        "__time_type": "Days",
                    },
                },
                "1": {
                    "ID": "rule-2",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "foo/"},
                    "Expiration": {
                        "1": {"Days": 10},
                        "__time_type": "Days",
                    },
                },
                "2": {
                    "ID": "rule-3",
                    "Status": "Enabled",
                    "Filter": {"Prefix": " OR 1=1 "},
                    "Expiration": {
                        "2": {"Days": 2},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": ["0-0", "2-2", "1-1"], "date": []},
            "_transition_rules": {"days": [], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "total_events": 20,
                "total_delete": 20,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 2,
            },
        )
        self._create_objects_for_rule(
            "rule-1",
            prefix="doc/",
            tags={"key3": "value3"},
            count=10,
            action=ExpectedAction.DELETE,
        )
        self._create_objects_for_rule(
            "rule-1",
            prefix="doc/",
            tags={"key3": "value3"},
            count=10,
            action=ExpectedAction.DELETE,
            mpu=True,
        )
        self._create_objects_for_rule(None, prefix="foo/", count=10)
        self._create_objects_for_rule(None, prefix="bar/", count=10)
        self._wait_n_days(4)
        self._run_scenario(configuration, callback, passes=2)

        day = datetime.now().strftime("%Y-%m-%d")

        prefix = f"/backup/{self.container}_{day}_"
        resp = self.storage.object_list(
            INTERNAL_ACCOUNT, INTERNAL_BUCKET, prefix=prefix
        )

        # Clear events as the restoration events are delete one that should already
        # been processed.
        self.clear_events()

        produced_events = 0
        for obj in resp.get("objects", []):
            _, stream = self.storage.object_fetch(
                INTERNAL_ACCOUNT, INTERNAL_BUCKET, obj["name"]
            )
            content = b"".join(stream).decode("utf-8")
            for line in content.split("\n"):
                if not line:
                    continue
                data = json.loads(line)
                self._cls_producer.send(
                    DEFAULT_LIFECYCLE_RESTORE_TOPIC, data, flush=True
                )
                produced_events += 1

        delete_expectations = [
            e for e in self.expectations if e.action == ExpectedAction.DELETE
        ]
        expected_events = sum(1 + len(e.parts) for e in delete_expectations)
        self.assertEqual(expected_events, produced_events)

        for i, expect in enumerate(delete_expectations, start=1):
            evt = self.wait_for_kafka_event(
                types=(EventTypes.CONTENT_DELETED,),
                origin=LIFECYCLE_USER_AGENT,
                fields={
                    "path": expect.key,
                    "version": expect.version,
                },
                timeout=5.0,
            )
            self.assertIsNotNone(
                evt,
                f"({i}/{len(self.expectations)}) Event missing",
            )

        for expect in delete_expectations:
            # Check if object is restored
            _, _ = self.storage.object_fetch(
                self.account,
                self.container,
                expect.key,
                version=expect.version,
            )

    def test_transition(self):
        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "doc/"},
                    "Transition": {
                        "0": {"Days": 2, "StorageClass": "STANDARD_IA"},
                        "__time_type": "Days",
                    },
                },
                "1": {
                    "ID": "rule-2",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "foo/"},
                    "Transition": {
                        "1": {"Days": 10, "StorageClass": "STANDARD_IA"},
                        "__time_type": "Days",
                    },
                },
                "2": {
                    "ID": "rule-3",
                    "Status": "Enabled",
                    "Filter": {"Prefix": " OR 1=1 "},
                    "Transition": {
                        "2": {"Days": 2, "StorageClass": "STANDARD_IA"},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": [], "date": []},
            "_transition_rules": {"days": ["0-0", "2-2", "1-1"], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "total_events": 10,
                "total_transition": 10,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 2,
            },
        )
        self._create_objects_for_rule("rule-1", prefix="doc/", count=10)
        self._create_objects_for_rule(None, prefix="foo/", count=10)
        self._create_objects_for_rule(None, prefix="bar/", count=10)
        self._wait_n_days(4)
        self._run_scenario(configuration, callback, passes=2)

    def test_transition_mpu(self):
        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "doc/"},
                    "Transition": {
                        "0": {"Days": 2, "StorageClass": "STANDARD_IA"},
                        "__time_type": "Days",
                    },
                },
                "1": {
                    "ID": "rule-2",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "foo/"},
                    "Transition": {
                        "1": {"Days": 10, "StorageClass": "STANDARD_IA"},
                        "__time_type": "Days",
                    },
                },
                "2": {
                    "ID": "rule-3",
                    "Status": "Enabled",
                    "Filter": {"Prefix": " OR 1=1 "},
                    "Transition": {
                        "2": {"Days": 2, "StorageClass": "STANDARD_IA"},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": [], "date": []},
            "_transition_rules": {"days": ["0-0", "2-2", "1-1"], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "total_events": 10,
                "total_transition": 10,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 2,
            },
        )
        self._create_objects_for_rule("rule-1", prefix="doc/", count=10, mpu=True)
        self._create_objects_for_rule(None, prefix="foo/", count=10, mpu=True)
        self._create_objects_for_rule(None, prefix="bar/", count=10, mpu=True)
        self._wait_n_days(4)
        self._run_scenario(configuration, callback, passes=2)

    def test_transition_not_allowed(self):
        """Transition is not allowed by default for objects with size less than 128K"""

        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "doc/"},
                    "Transition": {
                        "0": {"Days": 2, "StorageClass": "STANDARD_IA"},
                        "__time_type": "Days",
                    },
                },
                "1": {
                    "ID": "rule-2",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "foo/"},
                    "Transition": {
                        "1": {"Days": 10, "StorageClass": "STANDARD_IA"},
                        "__time_type": "Days",
                    },
                },
                "2": {
                    "ID": "rule-3",
                    "Status": "Enabled",
                    "Filter": {"Prefix": " OR 1=1 "},
                    "Transition": {
                        "2": {"Days": 2, "StorageClass": "STANDARD_IA"},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": [], "date": []},
            "_transition_rules": {"days": ["0-0", "2-2", "1-1"], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "total_events": 0,
                "total_transition": 0,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 2,
            },
        )
        self._create_objects_for_rule(None, prefix="doc/", count=10, size=10)
        self._create_objects_for_rule(None, prefix="foo/", count=10)
        self._create_objects_for_rule(None, prefix="bar/", count=10)
        self._wait_n_days(4)
        self._run_scenario(configuration, callback, passes=2)

    def test_transition_no_filter(self):
        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {},
                    "Transition": {
                        "0": {"Days": 2, "StorageClass": "STANDARD_IA"},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {
                "days": [],
                "date": [],
            },
            "_transition_rules": {"days": ["0-0"], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "total_events": 20,
                "total_transition": 20,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 2,
            },
        )
        self._create_objects_for_rule("rule-1", prefix="doc/", count=10)
        self._create_objects_for_rule("rule-1", prefix="foo/", count=10)
        self._wait_n_days(4)
        self._run_scenario(configuration, callback, passes=2)

    def test_transition_tagging(self):
        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {
                        "Tag": [
                            {"Key": "key1", "Value": "value1"},
                            {"Key": "key2", "Value": "value2"},
                        ]
                    },
                    "Transition": {
                        "0": {"Days": 2, "StorageClass": "STANDARD_IA"},
                        "__time_type": "Days",
                    },
                },
                "1": {
                    "ID": "rule-2",
                    "Status": "Enabled",
                    "Filter": {"Tag": [{"Key": "key3", "Value": "value3"}]},
                    "Transition": {
                        "1": {"Days": 2, "StorageClass": "STANDARD_IA"},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": [], "date": []},
            "_transition_rules": {"days": ["0-0", "1-1"], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "total_events": 20,
                "total_transition": 20,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 2,
            },
        )

        self._create_objects_for_rule(
            "rule-1",
            prefix="doc1/",
            count=10,
            tags={"key1": "value1", "key2": "value2"},
        )
        self._create_objects_for_rule(
            "rule-2", prefix="doc2/", count=10, tags={"key3": "value3"}
        )
        self._create_objects_for_rule(
            None, prefix="foo/", count=10, tags={"key1": "value1"}
        )
        self._wait_n_days(4)
        self._run_scenario(configuration, callback, passes=2)

    def test_transition_less_than(self):
        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"ObjectSizeLessThan": 10},
                    "Transition": {
                        "0": {"Days": 2, "StorageClass": "STANDARD_IA"},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": [], "date": []},
            "_transition_rules": {"days": ["0-0"], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "total_events": 10,
                "total_transition": 10,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 2,
            },
        )
        self._create_objects_for_rule("rule-1", prefix="doc/", count=10, size=8)
        self._create_objects_for_rule(None, prefix="doc/", count=10, size=20)
        self._wait_n_days(4)
        self._run_scenario(configuration, callback, passes=2)

    def test_transition_greater_than(self):
        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"ObjectSizeGreaterThan": 10},
                    "Transition": {
                        "0": {"Days": 2, "StorageClass": "STANDARD_IA"},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": [], "date": []},
            "_transition_rules": {"days": ["0-0"], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "total_events": 10,
                "total_transition": 10,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 2,
            },
        )
        self._create_objects_for_rule("rule-1", prefix="doc/", count=10, size=18)
        self._create_objects_for_rule(None, prefix="doc/", count=10, size=8)
        self._wait_n_days(4)
        self._run_scenario(configuration, callback, passes=2)

    def test_transition_all_filters(self):
        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {
                        "ObjectSizeLessThan": 20,
                        "ObjectSizeGreaterThan": 10,
                        "Tag": [{"Key": "key1", "Value": "value1"}],
                        "Prefix": "doc/",
                    },
                    "Transition": {
                        "0": {"Days": 2, "StorageClass": "STANDARD_IA"},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": [], "date": []},
            "_transition_rules": {"days": ["0-0"], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "total_events": 10,
                "total_transition": 10,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 2,
            },
        )
        # Match all criteria
        self._create_objects_for_rule(
            "rule-1", prefix="doc/", count=10, size=18, tags={"key1": "value1"}
        )
        # Match all criteria but one
        self._create_objects_for_rule(None, prefix="doc/", count=10, size=18)
        self._create_objects_for_rule(
            None, prefix="doc/", count=10, size=28, tags={"key1": "value1"}
        )
        self._create_objects_for_rule(
            None, prefix="doc/", count=10, size=8, tags={"key1": "value1"}
        )
        self._create_objects_for_rule(
            None, prefix="foo/", count=10, size=18, tags={"key1": "value1"}
        )
        self._wait_n_days(4)
        self._run_scenario(configuration, callback, passes=2)

    def test_transition_multiple_passes(self):
        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "doc/"},
                    "Transition": {
                        "0": {"Days": 2, "StorageClass": "STANDARD_IA"},
                        "__time_type": "Days",
                    },
                },
                "1": {
                    "ID": "rule-2",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "foo/"},
                    "Transition": {
                        "1": {"Days": 20, "StorageClass": "STANDARD_IA"},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": [], "date": []},
            "_transition_rules": {"days": ["0-0", "1-1"], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "container_budget_reached": 1,
                "total_events": 20,
                "total_transition": 20,
            },
            {
                **self.DEFAULT_STATS,
                "successes": 1,
                "processed": 1,
                "container_budget_reached": 1,
                "total_events": 20,
                "total_transition": 20,
            },
            {
                **self.DEFAULT_STATS,
                "successes": 1,
                "processed": 1,
                "container_budget_reached": 1,
                "total_events": 20,
                "total_transition": 20,
            },
        )
        self._create_objects_for_rule("rule-1", prefix="doc/a", count=60)
        self._create_objects_for_rule(None, prefix="doc/z", count=40)
        self._create_objects_for_rule(None, prefix="foo/", count=100)
        self._wait_n_days(3)
        # Only the two first passes should generate events
        self._run_scenario(
            configuration,
            callback,
            filter_conf={"container_budget_per_pass": 20},
            passes=3,
        )

    def test_transition_versioned(self):
        self._enable_versioning()

        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "doc/"},
                    "Transition": {
                        "0": {"Days": 2, "StorageClass": "STANDARD_IA"},
                        "__time_type": "Days",
                    },
                },
                "1": {
                    "ID": "rule-2",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "foo/"},
                    "Transition": {
                        "1": {"Days": 6, "StorageClass": "STANDARD_IA"},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": [], "date": []},
            "_transition_rules": {"days": ["0-0", "1-1"], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "total_events": 10,
                "total_transition": 10,
            },
        )
        self._create_objects_for_rule(
            "rule-1",
            prefix="doc/",
            count=10,
        )
        self._create_objects_for_rule(None, prefix="foo/", count=10)
        self._wait_n_days(3)
        self._run_scenario(configuration, callback)

    def test_non_current_transition_versioned_multiple_passes(self):
        self._enable_versioning()

        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "doc/"},
                    "NoncurrentVersionTransition": {
                        "0": {
                            "NoncurrentDays": 2,
                            "NewerNoncurrentVersions": 2,
                            "StorageClass": "STANDARD_IA",
                        },
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": [], "date": []},
            "_transition_rules": {"days": [], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": ["0-0"],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "container_budget_reached": 1,
                "total_events": 3,
                "total_transition": 3,
            },
            {
                **self.DEFAULT_STATS,
                "successes": 1,
                "processed": 1,
                "total_events": 1,
                "total_transition": 1,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 2,
            },
        )
        objects = self._create_objects_for_rule(
            "rule-1", prefix="doc/", count=1, versions=4
        )
        self._create_objects_for_rule(None, objects=objects, versions=3)
        self._wait_n_days(3)
        self._run_scenario(
            configuration,
            callback,
            filter_conf={"container_budget_per_pass": 3},
            passes=3,
        )

    def test_non_current_transition_versioned(self):
        self._enable_versioning()

        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "doc/"},
                    "NoncurrentVersionTransition": {
                        "0": {
                            "NoncurrentDays": 2,
                            "NewerNoncurrentVersions": 5,
                            "StorageClass": "STANDARD_IA",
                        },
                        "__time_type": "Days",
                    },
                },
                "1": {
                    "ID": "rule-2",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "foo/"},
                    "NoncurrentVersionTransition": {
                        "1": {
                            "NoncurrentDays": 2,
                            "NewerNoncurrentVersions": 1,
                            "StorageClass": "STANDARD_IA",
                        },
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": [], "date": []},
            "_transition_rules": {"days": [], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": ["0-0", "1-1"],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "total_events": 150,
                "total_transition": 150,
            },
        )
        objects = self._create_objects_for_rule(
            "rule-1", prefix="doc/", count=10, versions=5
        )
        self._create_objects_for_rule(None, objects=objects, versions=5)
        self._wait_n_days(3)
        self._create_objects_for_rule(None, objects=objects, versions=1)

        objects = self._create_objects_for_rule(
            "rule-2", prefix="foo/", count=10, versions=10
        )
        self._create_objects_for_rule(None, objects=objects, versions=1)
        self._wait_n_days(5)
        self._create_objects_for_rule(None, objects=objects, versions=1)
        self._run_scenario(configuration, callback)

    def test_transition_non_current_since(self):
        self._enable_versioning()

        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "doc/"},
                    "NoncurrentVersionTransition": {
                        "0": {
                            "NoncurrentDays": 2,
                            "StorageClass": "STANDARD_IA",
                        },
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": [], "date": []},
            "_transition_rules": {"days": [], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": ["0-0"],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "total_events": 10,
                "total_transition": 10,
            },
        )
        objects = self._create_objects_for_rule(
            "rule-1", prefix="doc/", count=10, versions=1
        )
        self._create_objects_for_rule(None, objects=objects, versions=1)
        self._wait_n_days(3)
        self._create_objects_for_rule(None, objects=objects, versions=1)
        self._wait_n_days(1)
        self._run_scenario(configuration, callback)

    def test_transition_expiration(self):
        """expiration takes priority over transition"""

        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "doc/"},
                    "Transition": {
                        "0": {"Days": 2, "StorageClass": "STANDARD_IA"},
                        "__time_type": "Days",
                    },
                },
                "1": {
                    "ID": "rule-2",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "doc/"},
                    "Expiration": {
                        "1": {"Days": 2},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": ["1-1"], "date": []},
            "_transition_rules": {"days": ["0-0"], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "total_events": 10,
                "total_delete": 10,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 2,
            },
        )
        self._create_objects_for_rule("rule-2", prefix="doc/", count=10)
        self._wait_n_days(3)
        self._run_scenario(configuration, callback, passes=2)

    def test_transition_delete_marker(self):
        """transition takes priority over delete marker"""

        self._enable_versioning()

        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "doc/"},
                    "Transition": {
                        "0": {"Days": 2, "StorageClass": "STANDARD_IA"},
                        "__time_type": "Days",
                    },
                },
                "1": {
                    "ID": "rule-2",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "doc/"},
                    "Expiration": {
                        "1": {"Days": 2},
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": ["1-1"], "date": []},
            "_transition_rules": {"days": ["0-0"], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": [],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "total_events": 10,
                "total_transition": 10,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 2,
            },
        )
        self._create_objects_for_rule("rule-1", prefix="doc/", count=10)
        self._wait_n_days(3)
        self._run_scenario(configuration, callback, passes=2)

    def test_transition_non_current_not_allowed(self):
        self._enable_versioning()

        def callback(status, _msg):
            self.assertEqual(200, status)

        configuration = {
            "Rules": {
                "0": {
                    "ID": "rule-1",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "doc/"},
                    "NoncurrentVersionTransition": {
                        "0": {
                            "NoncurrentDays": 2,
                            "StorageClass": "STANDARD",
                        },
                        "__time_type": "Days",
                    },
                },
            },
            "_schema_version": 1,
            "_expiration_rules": {"days": [], "date": []},
            "_transition_rules": {"days": [], "date": []},
            "_delete_marker_rules": [],
            "_abort_mpu_rules": [],
            "_non_current_expiration_rules": [],
            "_non_current_transition_rules": ["0-0"],
        }
        self.metrics_by_passes = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "total_events": 0,
                "total_transition": 0,
            },
        )
        objects = self._create_objects_for_rule(
            "rule-1", prefix="doc/", count=10, versions=1
        )
        self._create_objects_for_rule(None, objects=objects, versions=1)
        self._wait_n_days(3)
        self._create_objects_for_rule(None, objects=objects, versions=1)
        self._wait_n_days(1)
        # No event expected as storage class is same
        self.expectations = []
        self._run_scenario(configuration, callback)


class TestLifecycleCrawlerWithSharding(TestLifecycleCrawler):

    def setUp(self):
        super().setUp()
        self.use_sharding = True
        self.metrics_by_passes_with_sharding = []

    @property
    def _expected_metrics_for_test(self):
        return self.metrics_by_passes_with_sharding

    def test_not_empty_filter(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 0,
                "errors": 4,
            },
        )
        super().test_not_empty_filter()

    def test_wrong_tags(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 0,
                "errors": 4,
            },
        )
        super().test_wrong_tags()

    def test_disabled_time_bypass(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
            },
        )
        super().test_disabled_time_bypass()

    def test_bucket_budget_reached(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
                "container_budget_reached": 2,
                "total_events": 10,
                "total_delete": 10,
            },
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "processed": 2,
                "container_budget_reached": 2,
                "total_events": 10,
                "total_delete": 10,
            },
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "processed": 2,
                "bucket_budget_reached": 1,
                "container_budget_reached": 1,
                "total_events": 5,
                "total_delete": 5,
            },
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "processed": 2,
                "bucket_budget_reached": 2,
            },
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "processed": 2,
                "bucket_budget_reached": 2,
            },
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "processed": 2,
                "bucket_budget_reached": 2,
            },
        )
        super().test_bucket_budget_reached()

    def test_wrong_container(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "skipped": 4,
            },
        )
        super().test_wrong_container()

    def test_expiration(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
                "total_events": 10,
                "total_delete": 10,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 4,
            },
        )
        super().test_expiration()

    def test_expiration_mpu(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 6,
                "total_events": 10,
                "total_delete": 10,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 6,
            },
        )
        super().test_expiration_mpu()

    def test_expiration_no_filter(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
                "total_events": 20,
                "total_delete": 20,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 4,
            },
        )
        super().test_expiration_no_filter()

    def test_expiration_tagging(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
                "total_events": 20,
                "total_delete": 20,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 4,
            },
        )
        super().test_expiration_tagging()

    def test_expiration_tagging_versioned(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
                "total_events": 20,
                "total_delete": 20,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 4,
            },
        )
        super().test_expiration_tagging_versioned()

    def test_expiration_less_than(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
                "total_events": 10,
                "total_delete": 10,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 4,
            },
        )
        super().test_expiration_less_than()

    def test_expiration_less_than_versioned(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
                "total_events": 10,
                "total_delete": 10,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 4,
            },
        )
        super().test_expiration_less_than_versioned()

    def test_expiration_greater_than(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
                "total_events": 10,
                "total_delete": 10,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 4,
            },
        )
        super().test_expiration_greater_than()

    def test_expiration_greater_than_versioned(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
                "total_events": 10,
                "total_delete": 10,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 4,
            },
        )
        super().test_expiration_greater_than_versioned()

    def test_expiration_all_filters(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
                "total_events": 10,
                "total_delete": 10,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 4,
            },
        )
        super().test_expiration_all_filters()

    def test_expiration_all_filters_versioned(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
                "total_events": 10,
                "total_delete": 10,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 4,
            },
        )
        super().test_expiration_all_filters_versioned()

    def test_expiration_last_version_is_delete_marker(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
                "total_events": 10,
                "total_delete": 10,
            },
        )
        super().test_expiration_last_version_is_delete_marker()

    def test_expiration_delete_marker(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
                "total_events": 10,
                "total_delete": 10,
            },
        )
        super().test_expiration_delete_marker()

    def test_abort_mpu(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 6,
                "total_events": 10,
                "total_abortmpu": 10,
            },
        )
        super().test_abort_mpu()

    def test_expiration_multiple_passes(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
                "container_budget_reached": 1,
                "total_events": 20,
                "total_delete": 20,
            },
            {
                **self.DEFAULT_STATS,
                "successes": 1,
                "processed": 3,
                "container_budget_reached": 1,
                "total_events": 20,
                "total_delete": 20,
            },
            {
                **self.DEFAULT_STATS,
                "successes": 1,
                "processed": 3,
                "container_budget_reached": 1,
                "total_events": 20,
                "total_delete": 20,
            },
        )
        super().test_expiration_multiple_passes()

    def test_non_current_budget_reached(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
                "container_budget_reached": 2,
                "total_events": 10,
                "total_delete": 10,
            },
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "processed": 2,
                "container_budget_reached": 2,
                "total_events": 10,
                "total_delete": 10,
            },
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "processed": 2,
                "bucket_budget_reached": 1,
                "container_budget_reached": 1,
                "total_events": 5,
                "total_delete": 5,
            },
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "processed": 2,
                "bucket_budget_reached": 2,
            },
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "processed": 2,
                "bucket_budget_reached": 2,
            },
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "processed": 2,
                "bucket_budget_reached": 2,
            },
        )
        super().test_non_current_budget_reached()

    def test_override_bucket_budget_larger(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "container_budget_reached": 1,
                "bucket_budget_reached": 1,
                "successes": 4,
                "total_events": 10,
                "total_delete": 10,
            },
            {
                **self.DEFAULT_STATS,
                "bucket_budget_reached": 2,
                "processed": 2,
                "successes": 2,
                "total_events": 0,
                "total_delete": 0,
            },
        )
        super().test_override_bucket_budget_larger()

    def test_override_bucket_budget_smaller(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "bucket_budget_reached": 1,
                "container_budget_reached": 1,
                "successes": 4,
                "total_events": 10,
                "total_delete": 10,
            },
            {
                **self.DEFAULT_STATS,
                "bucket_budget_reached": 2,
                "processed": 2,
                "successes": 2,
                "total_events": 0,
                "total_delete": 0,
            },
        )
        super().test_override_bucket_budget_smaller()

    def test_expiration_versioned(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
                "total_events": 10,
                "total_delete": 10,
            },
        )
        super().test_expiration_versioned()

    def test_non_current_expiration_versioned(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
                "total_events": 150,
                "total_delete": 150,
            },
        )
        super().test_non_current_expiration_versioned()

    def test_non_current_expiration_versioned_multiple_passes(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "container_budget_reached": 1,
                "total_events": 3,
                "total_delete": 3,
            },
            {
                **self.DEFAULT_STATS,
                "successes": 1,
                "processed": 1,
                "total_events": 1,
                "total_delete": 1,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 2,
            },
        )

        super().test_non_current_expiration_versioned_multiple_passes()

    def test_expiration_non_current_since(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
                "total_events": 10,
                "total_delete": 10,
            },
        )
        super().test_expiration_non_current_since()

    def test_expiration_restore(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 6,
                "total_events": 20,
                "total_delete": 20,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 6,
            },
        )
        super().test_expiration_restore()

    def test_transition(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
                "total_events": 10,
                "total_transition": 10,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 4,
            },
        )
        super().test_transition()

    def test_transition_mpu(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 6,
                "total_events": 10,
                "total_transition": 10,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 6,
            },
        )
        super().test_transition_mpu()

    def test_transition_not_allowed(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
                "total_events": 0,
                "total_transition": 0,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 4,
            },
        )
        super().test_transition_not_allowed()

    def test_transition_no_filter(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
                "total_events": 20,
                "total_transition": 20,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 4,
            },
        )
        super().test_transition_no_filter()

    def test_transition_tagging(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
                "total_events": 20,
                "total_transition": 20,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 4,
            },
        )
        super().test_transition_tagging()

    def test_transition_less_than(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
                "total_events": 10,
                "total_transition": 10,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 4,
            },
        )
        super().test_transition_less_than()

    def test_transition_greater_than(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
                "total_events": 10,
                "total_transition": 10,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 4,
            },
        )
        super().test_transition_greater_than()

    def test_transition_all_filters(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
                "total_events": 10,
                "total_transition": 10,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 4,
            },
        )
        super().test_transition_all_filters()

    def test_transition_delete_marker(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
                "total_events": 10,
                "total_transition": 10,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 4,
            },
        )
        super().test_transition_delete_marker()

    def test_transition_multiple_passes(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
                "container_budget_reached": 1,
                "total_events": 20,
                "total_transition": 20,
            },
            {
                **self.DEFAULT_STATS,
                "successes": 1,
                "processed": 3,
                "container_budget_reached": 1,
                "total_events": 20,
                "total_transition": 20,
            },
            {
                **self.DEFAULT_STATS,
                "successes": 1,
                "processed": 3,
                "container_budget_reached": 1,
                "total_events": 20,
                "total_transition": 20,
            },
        )
        super().test_transition_multiple_passes()

    def test_transition_versioned(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
                "total_events": 10,
                "total_transition": 10,
            },
        )
        super().test_transition_versioned()

    def test_non_current_transition_versioned(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
                "total_events": 150,
                "total_transition": 150,
            },
        )
        super().test_non_current_transition_versioned()

    def test_non_current_transition_versioned_multiple_passes(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 2,
                "container_budget_reached": 1,
                "total_events": 3,
                "total_transition": 3,
            },
            {
                **self.DEFAULT_STATS,
                "successes": 1,
                "processed": 1,
                "total_events": 1,
                "total_transition": 1,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 2,
            },
        )

        super().test_non_current_transition_versioned_multiple_passes()

    def test_transition_non_current_since(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
                "total_events": 10,
                "total_transition": 10,
            },
        )
        super().test_transition_non_current_since()

    def test_transition_expiration(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
                "total_events": 10,
                "total_delete": 10,
            },
            {
                **self.DEFAULT_STATS,
                "processed": 4,
            },
        )
        super().test_transition_expiration()

    def test_transition_non_current_not_allowed(self):
        self.metrics_by_passes_with_sharding = (
            {
                **self.DEFAULT_STATS,
                "successes": 4,
                "total_events": 0,
                "total_transition": 0,
            },
        )
        super().test_transition_non_current_not_allowed()
