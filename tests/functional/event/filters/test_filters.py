# -*- coding: utf-8 -*-

# Copyright (C) 2017-2020 OpenIO SAS, as part of OpenIO SDS
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

import time
from random import choice
from urllib.parse import quote

from oio.account.client import AccountClient
from oio.blob.rebuilder import BlobRebuilder
from oio.common.constants import BUCKET_PROP_REPLI_ENABLED
from oio.event.beanstalk import Beanstalk
from oio.event.filters.notify import NotifyFilter
from oio.event.filters.replicate import ReplicateFilter
from tests.utils import BaseTestCase, random_str, strange_paths


class _App(object):
    app_env = {}

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
        self.gridconf = {"namespace": self.ns}
        self.container = "TestContentRebuildFilter%f" % time.time()
        self.ref = self.container
        self.container_client = self.storage.container
        self.container_client.container_create(self.account, self.container)
        syst = self.container_client.container_get_properties(
            self.account, self.container
        )["system"]
        self.container_id = syst["sys.name"].split(".", 1)[0]
        queue_addr = choice(self.conf["services"]["beanstalkd"])["addr"]
        self.queue_url = queue_addr
        self.conf["queue_url"] = "beanstalk://" + self.queue_url
        self.conf["tube"] = BlobRebuilder.DEFAULT_BEANSTALKD_WORKER_TUBE
        self.notify_filter = NotifyFilter(app=_App, conf=self.conf)
        bt = Beanstalk.from_url(self.conf["queue_url"])
        bt.drain_tube(BlobRebuilder.DEFAULT_BEANSTALKD_WORKER_TUBE, timeout=0.5)
        bt.close()
        self.wait_for_score(("rawx", "meta2"), score_threshold=10, timeout=5.0)
        self.objects_created = list()

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

    def _rebuild(self, event, job_id=0):
        bt = Beanstalk.from_url(self.conf["queue_url"])
        bt.wait_until_empty(BlobRebuilder.DEFAULT_BEANSTALKD_WORKER_TUBE, timeout=0.5)
        bt.close()
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
        self._rebuild(event)
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

        self._check_rebuild(obj_meta, chunks, chunks_to_remove, chunk_created=False)

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

        self._check_rebuild(obj_meta, chunks, chunks_to_remove, chunk_created=False)

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


class TestNotifyFilterBase(BaseTestCase):
    def setUp(self):
        super(TestNotifyFilterBase, self).setUp()
        queue_addr = choice(self.conf["services"]["beanstalkd"])["addr"]
        self.queue_url = queue_addr
        self.conf["queue_url"] = "beanstalk://" + self.queue_url
        self.conf["tube"] = "oio-repli"
        self.conf["exclude"] = []
        self.notify_filter = self.filter_class(app=_App, conf=self.conf)

    def tearDown(self):
        super(TestNotifyFilterBase, self).tearDown()


class TestNotifyFilter(TestNotifyFilterBase):
    filter_class = NotifyFilter

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


class TestReplicateFilter(TestNotifyFilterBase):
    """
    Test the "replicate" filter, forwarding object or container events to
    the "replicator" service.
    """

    filter_class = ReplicateFilter

    def setUp(self):
        super(TestReplicateFilter, self).setUp()
        self.notify_filter.check_account = True

    @classmethod
    def setUpClass(cls):
        super(TestReplicateFilter, cls).setUpClass()
        cls.account_client = AccountClient({"namespace": cls._cls_ns})
        _App.app_env["account_client"] = cls.account_client

    def test_replication_always_enabled(self):
        # Disable the account check
        self.notify_filter.check_account = False
        bname = "repli" + random_str(4)
        self.storage.bucket.bucket_create(bname, self.account)
        now = time.time()
        # Disable replication for this bucket
        self.storage.bucket.bucket_update(
            bname, {BUCKET_PROP_REPLI_ENABLED: "false"}, None, account=self.account
        )
        self.storage.account.container_update(
            self.account, bname, now, 0, 0, bucket=bname
        )
        # Replication is disabled for this bucket,
        # but the filter won't do the check,
        # and forward the event anyway.
        self.assertTrue(self.notify_filter._should_notify(self.account, bname))

    def test_replication_enabled(self):
        bname = "repli" + random_str(4)
        self.storage.bucket.bucket_create(bname, self.account)
        now = time.time()
        self.storage.bucket.bucket_update(
            bname, {BUCKET_PROP_REPLI_ENABLED: "true"}, None, account=self.account
        )
        self.storage.account.container_update(
            self.account, bname, now, 0, 0, bucket=bname
        )
        self.assertTrue(self.notify_filter._should_notify(self.account, bname))

    def test_replication_disabled(self):
        bname = "repli" + random_str(4)
        self.storage.bucket.bucket_create(bname, self.account)
        now = time.time()
        self.storage.bucket.bucket_update(
            bname, {BUCKET_PROP_REPLI_ENABLED: "false"}, None, account=self.account
        )
        self.storage.account.container_update(
            self.account, bname, now, 0, 0, bucket=bname
        )
        self.assertFalse(self.notify_filter._should_notify(self.account, bname))
