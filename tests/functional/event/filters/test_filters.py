# -*- coding: utf-8 -*-
# Copyright (C) 2017 OpenIO, original work as part of
# OpenIO Software Defined Storage
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
from oio.common.exceptions import MissingData, UnrecoverableContent
from oio.event.filters.content_rebuild import ContentRebuildFilter
from tests.utils import BaseTestCase, random_str
from testtools.testcase import ExpectedException
from oio.container.client import ContainerClient
import time
from oio.api.object_storage import ObjectStorageAPI


class _App(object):

    def __init__(self, env, cb):
        self.env = env
        self.cb = cb


class TestContentBrokenFilter(BaseTestCase):
    def setUp(self):
        super(TestContentBrokenFilter, self).setUp()
        self.namespace = self.conf['namespace']
        self.gridconf = {"namespace": self.namespace}
        self.container = "TestContentBrokenFilter%f" % time.time()
        self.ref = self.container
        self.container_client = ContainerClient(self.conf)
        self.container_client.container_create(acct=self.account,
                                               ref=self.container)
        uri = self.container_client._make_uri('container/show')
        params = self.container_client._make_params(self.account,
                                                    self.container)
        resp, _ = self.container_client._request('GET', uri, params=params)
        self.container_id = resp.headers['x-oio-container-meta-sys-name'][:-2]
        self.object_storage_api = ObjectStorageAPI(namespace=self.namespace)
        self.stgpol = "SINGLE"
        self.content_rebuild_filter = ContentRebuildFilter(app=_App,
                                                           conf=self.conf)

    def _create_event(self, content_name, present_chunks, missing_chunks):
        event = {}
        event["when"] = time.time()
        event["event"] = "storage.content.broken"
        event["data"] = {"present_chunks": present_chunks,
                         "missing_chunks": missing_chunks}
        event["url"] = {"ns": self.namespace, "account": self.account,
                        "user": self.container, "path": content_name,
                        "id": self.container_id}
        return event

    def _is_chunks_created(self, previous, after, pos_created):
        remain = list(after)
        for p in previous:
            for r in remain:
                if p["url"] == r["url"]:
                    remain.remove(r)
                    break
        for r in remain:
            if r["pos"] in pos_created:
                remain.remove(r)
            else:
                return False
        return True

    def test_nothing_missing(self):
        content_name = "test_nothing_missing"
        self.object_storage_api.object_create(account=self.account,
                                              container=self.container,
                                              data="test",
                                              policy="THREECOPIES",
                                              obj_name=content_name)
        _, chunks = self.object_storage_api.object_analyze(
                          container=self.container, obj=content_name,
                          account=self.account)
        for c in chunks:
            c.pop('score', None)
            c['id'] = c.pop('url')

        missing_pos = []
        event = self._create_event(content_name, chunks, missing_pos)
        with ExpectedException(MissingData):
            self.content_rebuild_filter.process(env=event, cb=None)

    def test_missing_1_chunk(self):
        content_name = "test_missing_1_chunk"
        self.object_storage_api.object_create(account=self.account,
                                              container=self.container,
                                              data="test",
                                              policy="THREECOPIES",
                                              obj_name=content_name
                                              )
        _, chunks = self.object_storage_api.object_analyze(
                        container=self.container, obj=content_name,
                        account=self.account)
        previous = list(chunks)
        chunks.pop(0)
        for c in chunks:
            c.pop('score', None)
            c['id'] = c.pop('url')

        missing_pos = ["0"]
        event = self._create_event(content_name, chunks, missing_pos)
        self.content_rebuild_filter.process(env=event, cb=None)
        _, after = self.object_storage_api.object_analyze(
                        container=self.container, obj=content_name,
                        account=self.account)
        self.assertIs(True, self._is_chunks_created(previous,
                                                    after,
                                                    missing_pos))

    def test_missing_last_chunk(self):
        content_name = "test_missing_1_chunk_frim_multiple_chunks_content"
        data = random_str(1024 * 1024 * 4)
        self.object_storage_api.object_create(account=self.account,
                                              container=self.container,
                                              data=data,
                                              policy="THREECOPIES",
                                              obj_name=content_name
                                              )
        _, chunks = self.object_storage_api.object_analyze(
                        container=self.container, obj=content_name,
                        account=self.account)
        previous = list(chunks)
        chunks.pop(0)
        for c in chunks:
            c.pop('score', None)
            c['id'] = c.pop('url')

        missing_pos = ["3"]
        event = self._create_event(content_name, chunks, missing_pos)
        self.content_rebuild_filter.process(env=event, cb=None)
        _, after = self.object_storage_api.object_analyze(
                        container=self.container, obj=content_name,
                        account=self.account)
        self.assertIs(True, self._is_chunks_created(previous,
                                                    after,
                                                    missing_pos))

    def test_missing_2_chunks(self):
        content_name = "test_missing_2_chunks"
        self.object_storage_api.object_create(account=self.account,
                                              container=self.container,
                                              data="test",
                                              policy="THREECOPIES",
                                              obj_name=content_name
                                              )
        _, chunks = self.object_storage_api.object_analyze(
                        container=self.container, obj=content_name,
                        account=self.account)
        previous = list(chunks)
        chunks.pop(0)
        chunks.pop(0)
        for c in chunks:
            c.pop('score', None)
            c['id'] = c.pop('url')

        missing_pos = ["0", "0"]
        event = self._create_event(content_name, chunks, missing_pos)
        self.content_rebuild_filter.process(env=event, cb=None)
        _, after = self.object_storage_api.object_analyze(
                        container=self.container, obj=content_name,
                        account=self.account)
        self.assertIs(True, self._is_chunks_created(previous,
                                                    after,
                                                    missing_pos))

    def test_missing_all_chunks(self):
        content_name = "test_missing_all_chunks"
        self.object_storage_api.object_create(account=self.account,
                                              container=self.container,
                                              data="test",
                                              policy="SINGLE",
                                              obj_name=content_name
                                              )
        _, chunks = self.object_storage_api.object_analyze(
                        container=self.container, obj=content_name,
                        account=self.account)
        chunks.pop(0)
        for c in chunks:
            c.pop('score', None)
            c['id'] = c.pop('url')

        missing_pos = ["0"]
        event = self._create_event(content_name, chunks, missing_pos)
        with ExpectedException(UnrecoverableContent):
            self.content_rebuild_filter.process(env=event, cb=None)

    def test_missing_all_chunks_of_a_pos(self):
        content_name = "test_missing_2_chunks"
        self.object_storage_api.object_create(account=self.account,
                                              container=self.container,
                                              data="test",
                                              policy="THREECOPIES",
                                              obj_name=content_name
                                              )
        _, chunks = self.object_storage_api.object_analyze(
                        container=self.container, obj=content_name,
                        account=self.account)
        chunks.pop(0)
        chunks.pop(0)
        chunks.pop(0)
        for c in chunks:
            c.pop('score', None)
            c['id'] = c.pop('url')

        missing_pos = ["0"]
        event = self._create_event(content_name, chunks, missing_pos)
        with ExpectedException(UnrecoverableContent):
            self.content_rebuild_filter.process(env=event, cb=None)

    def test_missing_multiple_chunks(self):
        content_name = "test_missing_multiple_chunks"
        data = random_str(1024 * 1024 * 4)
        self.object_storage_api.object_create(account=self.account,
                                              container=self.container,
                                              data=data,
                                              policy="THREECOPIES",
                                              obj_name=content_name)
        _, chunks = self.object_storage_api.object_analyze(
                        container=self.container, obj=content_name,
                        account=self.account)
        previous = list(chunks)
        chunks.pop(9)
        chunks.pop(6)
        chunks.pop(4)
        chunks.pop(0)
        for c in chunks:
            c.pop('score', None)
            c['id'] = c.pop('url')

        missing_pos = ["0", "1", "2", "3"]
        event = self._create_event(content_name, chunks, missing_pos)
        self.content_rebuild_filter.process(env=event, cb=None)
        _, after = self.object_storage_api.object_analyze(
                        container=self.container, obj=content_name,
                        account=self.account)
        self.assertIs(True, self._is_chunks_created(previous,
                                                    after,
                                                    missing_pos))

    def test_missing_1_chunk_ec(self):
        if len(self.conf['services']['rawx']) < 9:
            self.skipTest("Not enough rawx. "
                          "EC tests needs at least 9 rawx to run")
        content_name = "test_missing_1_chunk_ec"
        self.object_storage_api.object_create(account=self.account,
                                              container=self.container,
                                              data="test",
                                              policy="EC",
                                              obj_name=content_name
                                              )
        _, chunks = self.object_storage_api.object_analyze(
                        container=self.container, obj=content_name,
                        account=self.account)
        previous = list(chunks)
        chunks.pop(0)
        for c in chunks:
            c.pop('score', None)
            c['id'] = c.pop('url')

        missing_pos = ["0.1"]
        event = self._create_event(content_name, chunks, missing_pos)
        self.content_rebuild_filter.process(env=event, cb=None)
        _, after = self.object_storage_api.object_analyze(
                        container=self.container, obj=content_name,
                        account=self.account)
        self.assertIs(True, self._is_chunks_created(previous,
                                                    after,
                                                    missing_pos))

    def test_missing_m_chunk_ec(self):
        if len(self.conf['services']['rawx']) < 9:
            self.skipTest("Not enough rawx. "
                          "EC tests needs at least 9 rawx to run")
        content_name = "test_missing_m_chunk_ec"
        self.object_storage_api.object_create(account=self.account,
                                              container=self.container,
                                              data="test",
                                              policy="EC",
                                              obj_name=content_name)
        _, chunks = self.object_storage_api.object_analyze(
                        container=self.container, obj=content_name,
                        account=self.account)
        previous = list(chunks)
        chunks.pop(0)
        chunks.pop(0)
        chunks.pop(0)
        for c in chunks:
            c.pop('score', None)
            c['id'] = c.pop('url')

        missing_pos = ["0.1", "0.2", "0.3"]
        event = self._create_event(content_name, chunks, missing_pos)
        self.content_rebuild_filter.process(env=event, cb=None)

        _, after = self.object_storage_api.object_analyze(
                        container=self.container, obj=content_name,
                        account=self.account)

        self.assertIs(True, self._is_chunks_created(previous,
                                                    after,
                                                    missing_pos))

    def test_missing_m_chunk_ec_2(self):
        if len(self.conf['services']['rawx']) < 9:
            self.skipTest("Not enough rawx. "
                          "EC tests needs at least 9 rawx to run")
        content_name = "test_missing_m_chunk_ec"
        self.object_storage_api.object_create(account=self.account,
                                              container=self.container,
                                              data="test",
                                              policy="EC",
                                              obj_name=content_name)
        _, chunks = self.object_storage_api.object_analyze(
                        container=self.container, obj=content_name,
                        account=self.account)
        previous = list(chunks)
        chunks.pop(0)
        chunks.pop(3)
        chunks.pop(5)
        for c in chunks:
            c.pop('score', None)
            c['id'] = c.pop('url')

        missing_pos = ["0.1", "0.5", "0.8"]
        event = self._create_event(content_name, chunks, missing_pos)
        self.content_rebuild_filter.process(env=event, cb=None)

        _, after = self.object_storage_api.object_analyze(
                        container=self.container, obj=content_name,
                        account=self.account)

        self.assertIs(True, self._is_chunks_created(previous,
                                                    after,
                                                    missing_pos))

    def test_missing_m1_chunk_ec(self):
        if len(self.conf['services']['rawx']) < 9:
            self.skipTest("Not enough rawx. "
                          "EC tests needs at least 9 rawx to run")
        content_name = "test_missing_m1_chunk_ec"
        self.object_storage_api.object_create(account=self.account,
                                              container=self.container,
                                              data="test",
                                              policy="EC",
                                              obj_name=content_name)
        _, chunks = self.object_storage_api.object_analyze(
                        container=self.container, obj=content_name,
                        account=self.account)
        chunks.pop(0)
        chunks.pop(0)
        chunks.pop(0)
        chunks.pop(0)
        for c in chunks:
            c.pop('score', None)
            c['id'] = c.pop('url')

        event = self._create_event(content_name, chunks, ["0.1", "0.2", "0.3",
                                                          "0.4"])
        with ExpectedException(UnrecoverableContent):
            self.content_rebuild_filter.process(env=event, cb=None)
