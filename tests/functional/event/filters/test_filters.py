# -*- coding: utf-8 -*-

# Copyright (C) 2017-2020 OpenIO SAS, as part of OpenIO SDS
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

import time
from datetime import datetime, timezone
from urllib.parse import quote

from mock import patch

from oio.blob.rebuilder import BlobRebuilder
from oio.common.exceptions import ServiceBusy
from oio.common.statsd import get_statsd
from oio.event.evob import Event
from oio.event.filters.lifecycle_actions import LifecycleActionContext, LifecycleActions
from oio.event.filters.notify import KafkaNotifyFilter
from tests.utils import BaseTestCase, random_str, strange_paths


class _App(object):
    app_env = {
        "statsd_client": get_statsd(),
    }

    def __init__(self, env, cb):
        self.env = env
        self.cb = cb


class TestContentRebuildFilter(BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super(TestContentRebuildFilter, cls).setUpClass()
        # Prevent the sharding/shrinking by the meta2 crawlers
        cls._service("oio-crawler.target", "stop", wait=3)

    @classmethod
    def tearDownClass(cls):
        cls._service("oio-crawler.target", "start", wait=1)
        super(TestContentRebuildFilter, cls).tearDownClass()

    def setUp(self):
        super(TestContentRebuildFilter, self).setUp()
        self.container = "TestContentRebuildFilter%f" % time.time()
        self.ref = self.container
        self.container_client = self.storage.container
        self.container_client.container_create(self.account, self.container)
        syst = self.container_client.container_get_properties(
            self.account, self.container
        )["system"]
        self.container_id = syst["sys.name"].split(".", 1)[0]
        self.conf["queue_url"] = self.ns_conf["event-agent"]
        self.conf["topic"] = BlobRebuilder.DEFAULT_WORKER_TUBE
        self.notify_filter = KafkaNotifyFilter(
            app=_App, conf=self.conf, endpoint=self.ns_conf["event-agent"]
        )
        self.wait_for_score(("rawx", "meta2"), score_threshold=10, timeout=5.0)
        self.objects_created = []

    def tearDown(self):
        for obj in self.objects_created:
            try:
                self.storage.object_delete(self.account, self.container, obj)
            except Exception as exc:
                print(f"Failed to delete {self.account}/{self.container}/{obj}: {exc}")
        try:
            self.storage.container_delete(self.account, self.container)
        except Exception as exc:
            print(f"Failed to delete {self.account}/{self.container}: {exc}")
        super().tearDown()

    def _create_event(self, obj_meta, present_chunks, missing_chunks):
        event = {}
        event["when"] = time.time()
        event["event"] = "storage.content.broken"
        event["data"] = {
            "present_chunks": present_chunks,
            "missing_chunks": missing_chunks,
        }
        event["url"] = {
            "ns": self.ns,
            "account": self.account,
            "user": self.container,
            "id": self.container_id,
            "content": obj_meta["id"],
            "path": obj_meta["name"],
            "version": obj_meta["version"],
        }
        return event

    def _was_created_before(self, url, time_point):
        chunk_md = self.storage.blob_client.chunk_head(url)
        print(
            "chunk_mtime: %f, rebuild_time: %f" % (chunk_md["chunk_mtime"], time_point)
        )
        return chunk_md["chunk_mtime"] <= time_point

    def _is_chunks_created(self, previous, after, pos_created, time_point):
        created = list(after)
        for cr in after:
            if self._was_created_before(cr["url"], time_point):
                # The chunk was there before: it has not been created
                created.remove(cr)
        if len(created) != len(pos_created):
            print(
                "The number of newly created chunks is not as expected: %d vs %d"
                % (len(created), len(pos_created))
            )
            return False
        for cr in created:
            if cr["pos"] in pos_created:
                created.remove(cr)
            else:
                # The position of one of the new chunks is not as expected
                return False
        return True

    def _rebuild(self):
        self.wait_until_empty("oio-rebuild", "event-agent-rebuild")
        time.sleep(2)

    def _remove_chunks(self, obj_meta, chunks):
        if not chunks:
            return
        for chunk in chunks:
            chunk["id"] = chunk["url"]
            chunk["content"] = obj_meta["id"]
            chunk["type"] = "chunk"
        self.container_client.container_raw_delete(
            self.account,
            self.container,
            data=chunks,
            path=obj_meta["name"],
            version=obj_meta["version"],
        )
        try:
            self.storage.blob_client.chunk_delete_many(chunks)
        except Exception:
            pass

    def _check_rebuild(self, obj_meta, chunks, chunks_to_remove, chunk_created=True):
        start = time.time()
        self._remove_chunks(obj_meta, chunks_to_remove)
        time.sleep(1)  # Need to sleep 1s, because mtime has 1s precision
        missing_pos = [chunk["pos"] for chunk in chunks_to_remove]
        event = self._create_event(obj_meta, chunks, missing_pos)
        self.notify_filter.process(event, None)
        self._rebuild()
        _, after = self.storage.object_locate(
            account=self.account,
            container=self.container,
            obj=obj_meta["name"],
            version=obj_meta["version"],
        )
        self.assertIs(
            chunk_created, self._is_chunks_created(chunks, after, missing_pos, start)
        )

    def test_nothing_missing(self):
        content_name = "test_nothing_missing"
        chunks, _, _, obj_meta = self.storage.object_create_ext(
            account=self.account,
            container=self.container,
            obj_name=content_name,
            data="test",
            policy="THREECOPIES",
        )
        self.objects_created.append(content_name)

        chunks_to_remove = []
        for chunk in chunks:
            chunk.pop("score", None)

        self._check_rebuild(obj_meta, chunks, chunks_to_remove, chunk_created=True)

    def test_missing_1_chunk(self):
        content_name = "test_missing_1_chunk"
        chunks, _, _, obj_meta = self.storage.object_create_ext(
            account=self.account,
            container=self.container,
            obj_name=content_name,
            data="test",
            policy="THREECOPIES",
        )
        self.objects_created.append(content_name)

        chunks_to_remove = []
        chunks_to_remove.append(chunks.pop(0))
        for chunk in chunks:
            chunk.pop("score", None)

        self._check_rebuild(obj_meta, chunks, chunks_to_remove)

    def test_missing_last_chunk(self):
        content_name = "test_missing_last_chunk"
        data = random_str(1024 * 1024 * 4)
        chunks, _, _, obj_meta = self.storage.object_create_ext(
            account=self.account,
            container=self.container,
            obj_name=content_name,
            data=data,
            policy="THREECOPIES",
        )
        self.objects_created.append(content_name)

        chunks_to_remove = []
        chunks_to_remove.append(chunks.pop(-1))
        for chunk in chunks:
            chunk.pop("score", None)

        self._check_rebuild(obj_meta, chunks, chunks_to_remove)

    def test_missing_2_chunks(self):
        content_name = "test_missing_2_chunks"
        chunks, _, _, obj_meta = self.storage.object_create_ext(
            account=self.account,
            container=self.container,
            obj_name=content_name,
            data="test",
            policy="THREECOPIES",
        )
        self.objects_created.append(content_name)

        chunks_to_remove = []
        for i in range(0, 2):
            chunks_to_remove.append(chunks.pop(0))
        for chunk in chunks:
            chunk.pop("score", None)

        self._check_rebuild(obj_meta, chunks, chunks_to_remove)

    def test_missing_all_chunks(self):
        content_name = "test_missing_all_chunks"
        chunks, _, _, obj_meta = self.storage.object_create_ext(
            account=self.account,
            container=self.container,
            obj_name=content_name,
            data="test",
            policy="SINGLE",
        )
        self.objects_created.append(content_name)

        chunks_to_remove = []
        chunks_to_remove.append(chunks.pop(0))
        for chunk in chunks:
            chunk.pop("score", None)

        self.assertRaises(
            ServiceBusy,
            self._check_rebuild,
            obj_meta,
            chunks,
            chunks_to_remove,
            chunk_created=False,
        )

    def test_missing_all_chunks_of_a_pos(self):
        content_name = "test_missing_2_chunks"
        chunks, _, _, obj_meta = self.storage.object_create_ext(
            account=self.account,
            container=self.container,
            obj_name=content_name,
            data="test",
            policy="THREECOPIES",
        )
        self.objects_created.append(content_name)

        chunks_to_remove = []
        for i in range(0, 3):
            chunks_to_remove.append(chunks.pop(0))

        for chunk in chunks:
            chunk.pop("score", None)

        self.assertRaises(
            ServiceBusy,
            self._check_rebuild,
            obj_meta,
            chunks,
            chunks_to_remove,
            chunk_created=False,
        )

    def test_missing_multiple_chunks(self):
        content_name = "test_missing_multiple_chunks"
        data = random_str(1024 * 1024 * 4)
        chunks, _, _, obj_meta = self.storage.object_create_ext(
            account=self.account,
            container=self.container,
            obj_name=content_name,
            data=data,
            policy="THREECOPIES",
        )
        self.objects_created.append(content_name)

        chunks_to_remove = []
        chunks_to_remove.append(chunks.pop(9))
        chunks_to_remove.append(chunks.pop(6))
        chunks_to_remove.append(chunks.pop(4))
        chunks_to_remove.append(chunks.pop(0))
        for chunk in chunks:
            chunk.pop("score", None)

        self._check_rebuild(obj_meta, chunks, chunks_to_remove)

    def test_missing_1_chunk_ec(self):
        if len(self.conf["services"]["rawx"]) < 9:
            self.skipTest("Not enough rawx. EC tests needs at least 9 rawx to run")
        content_name = "test_missing_1_chunk_ec"
        chunks, _, _, obj_meta = self.storage.object_create_ext(
            account=self.account,
            container=self.container,
            obj_name=content_name,
            data="test",
            policy="EC",
        )
        self.objects_created.append(content_name)

        chunks_to_remove = []
        chunks_to_remove.append(chunks.pop(0))
        for chunk in chunks:
            chunk.pop("score", None)

        self._check_rebuild(obj_meta, chunks, chunks_to_remove)

    def test_missing_m_chunk_ec(self):
        if len(self.conf["services"]["rawx"]) < 9:
            self.skipTest("Not enough rawx. EC tests needs at least 9 rawx to run")
        content_name = "test_missing_m_chunk_ec"
        chunks, _, _, obj_meta = self.storage.object_create_ext(
            account=self.account,
            container=self.container,
            obj_name=content_name,
            data="test",
            policy="EC",
        )
        self.objects_created.append(content_name)

        chunks_to_remove = []
        for i in range(0, 3):
            chunks_to_remove.append(chunks.pop(0))
        for chunk in chunks:
            chunk.pop("score", None)

        self._check_rebuild(obj_meta, chunks, chunks_to_remove)

    def test_missing_m_chunk_ec_2(self):
        if len(self.conf["services"]["rawx"]) < 9:
            self.skipTest("Not enough rawx. EC tests needs at least 9 rawx to run")
        content_name = "test_missing_m_chunk_ec"
        chunks, _, _, obj_meta = self.storage.object_create_ext(
            account=self.account,
            container=self.container,
            obj_name=content_name,
            data="test",
            policy="EC",
        )
        self.objects_created.append(content_name)

        chunks_to_remove = []
        chunks_to_remove.append(chunks.pop(0))
        chunks_to_remove.append(chunks.pop(3))
        chunks_to_remove.append(chunks.pop(5))
        for chunk in chunks:
            chunk.pop("score", None)

        self._check_rebuild(obj_meta, chunks, chunks_to_remove)

    def test_missing_m1_chunk_ec(self):
        if len(self.conf["services"]["rawx"]) < 9:
            self.skipTest("Not enough rawx. EC tests needs at least 9 rawx to run")
        content_name = "test_missing_m1_chunk_ec"
        chunks, _, _, obj_meta = self.storage.object_create_ext(
            account=self.account,
            container=self.container,
            obj_name=content_name,
            data="test",
            policy="EC",
        )
        self.objects_created.append(content_name)

        chunks_to_remove = []
        chunks_to_remove.append(chunks.pop(0))
        chunks_to_remove.append(chunks.pop(0))
        chunks_to_remove.append(chunks.pop(0))
        chunks_to_remove.append(chunks.pop(0))
        for chunk in chunks:
            chunk.pop("score", None)

        self._check_rebuild(obj_meta, chunks, chunks_to_remove, chunk_created=False)


class TestKafkaNotifyFilter(BaseTestCase):
    def setUp(self):
        super(TestKafkaNotifyFilter, self).setUp()
        self.queue_url = self.ns_conf["event-agent"].replace("kafka://", "")
        self.conf["queue_url"] = self.ns_conf["event-agent"]
        self.conf["topic"] = BlobRebuilder.DEFAULT_WORKER_TUBE
        self.conf["exclude"] = []
        self.notify_filter = KafkaNotifyFilter(
            app=_App, conf=self.conf, endpoint=self.conf["queue_url"]
        )

    def test_parsing(self):
        expected = {
            "account": [],
            "account2": ["container"],
            "account3": ["container1", "container2"],
        }
        actual = self.notify_filter._parse_exclude(
            "account,account2/container,account3/container1,account3/container2"
        )
        self.assertDictEqual(expected, actual)

    def test_filtering(self):
        # Simple test
        self.notify_filter.exclude = self.notify_filter._parse_exclude(
            [quote("account"), "account2/container"]
        )
        self.assertFalse(self.notify_filter._should_notify("account", random_str(16)))
        self.assertFalse(self.notify_filter._should_notify("account2", "container"))

        # account that should not be replicated
        strange_account = [quote(x, "") for x in strange_paths]
        self.notify_filter.exclude = self.notify_filter._parse_exclude(strange_account)
        for x in strange_paths:
            self.assertFalse(self.notify_filter._should_notify(x, random_str(16)))

        # random account should be replicated
        self.assertTrue(
            self.notify_filter._should_notify(random_str(16), random_str(16))
        )


class TestLifecycleAccessLoggerFilter(BaseTestCase):
    class EchoLogger:
        def __init__(self):
            self.lines = []

        def info(self, msg):
            self.lines.append(msg)

    def setUp(self):
        super().setUp()
        self.conf["log_prefix"] = "lifecycle_access-"
        self.conf["redis_host"] = "127.0.0.1:4000"
        self.queue_url = self.ns_conf["event-agent"].replace("kafka://", "")
        self.filter = LifecycleActions(app=_App, conf=self.conf)

    def test_should_log(self):
        # Empty event
        event = LifecycleActionContext(Event({}))
        self.assertFalse(self.filter._should_log(event))
        event = LifecycleActionContext(Event({"data": {}}))
        self.assertFalse(self.filter._should_log(event))
        event = LifecycleActionContext(Event({"data": {"has_bucket_logging": False}}))
        self.assertFalse(self.filter._should_log(event))
        event = LifecycleActionContext(Event({"data": {"has_bucket_logging": True}}))
        self.assertFalse(self.filter._should_log(event))
        event = LifecycleActionContext(
            Event({"data": {"has_bucket_logging": True, "bucket": None}})
        )
        self.assertFalse(self.filter._should_log(event))
        event = LifecycleActionContext(
            Event({"data": {"has_bucket_logging": True, "bucket": ""}})
        )
        self.assertFalse(self.filter._should_log(event))
        event = LifecycleActionContext(
            Event({"data": {"has_bucket_logging": False, "bucket": "foobar"}})
        )
        self.assertFalse(self.filter._should_log(event))
        event = LifecycleActionContext(
            Event({"data": {"has_bucket_logging": True, "bucket": "foobar"}})
        )
        self.assertTrue(self.filter._should_log(event))

    def test_log_event(self):
        # Missing action
        context = LifecycleActionContext(
            Event(
                {
                    "url": {},
                    "data": {
                        "bucket": "foo",
                        "has_bucket_logging": True,
                    },
                }
            )
        )
        self.assertRaises(ValueError, self.filter._log_event, context)

        with patch("oio.event.filters.lifecycle_actions.datetime") as mock_fmt:
            mock_fmt.now.return_value = datetime.fromtimestamp(
                1727682407.0962443, tz=timezone.utc
            )

            # Invalid action
            context = LifecycleActionContext(
                Event(
                    {
                        "url": {},
                        "data": {
                            "action": "INVALID",
                            "bucket": "foo",
                            "has_bucket_logging": True,
                        },
                    }
                )
            )
            self.assertRaises(ValueError, self.filter._log_event, context)

            tests = (
                ("Expiration", False, "S3.EXPIRE.OBJECT", 123),
                ("Expiration", True, "S3.CREATE.DELETEMARKER", 123),
                ("NoncurrentVersionExpiration", False, "S3.EXPIRE.OBJECT", 123),
                ("NoncurrentVersionExpiration", True, "S3.CREATE.DELETEMARKER", 123),
                ("AbortIncompleteMultipartUpload", False, "S3.DELETE.UPLOAD", 123),
                ("Transition", False, "S3.TRANSITION_SIA.OBJECT", 123),
                ("NoncurrentVersionTransition", False, "S3.TRANSITION_SIA.OBJECT", 123),
            )

            for action, marker, s3action, obj_size in tests:
                # Expiration delete marker action
                context = LifecycleActionContext(
                    Event(
                        {
                            "url": {},
                            "request_id": "req-1",
                            "data": {
                                "action": action,
                                "bucket": "foo",
                                "has_bucket_logging": True,
                                "bucket_owner": "my_owner",
                                "add_delete_marker": marker,
                                "object": "test/bar🔥",
                                "version": 123456789,
                                "storage_class": "STANDARD_IA",
                            },
                        }
                    )
                )
                context.size = obj_size
                with patch("logging.Logger.info") as mock_logger:
                    self.filter._log_event(context)
                    mock_logger.assert_called_once_with(
                        "lifecycle_access-foo: my_owner foo "
                        f"[30/Sep/2024:07:46:47 +0000] - OVHcloudS3 req-1 {s3action} "
                        f'test/bar%25F0%259F%2594%25A5 "-" - - - {obj_size} '
                        '- - "-" "-" 123.456789 - - - - - - -'
                    )
