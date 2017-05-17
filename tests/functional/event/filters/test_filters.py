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
import json
import time
import subprocess
from oio import ObjectStorageApi
from oio.container.client import ContainerClient
from oio.event.filters.content_rebuild import ContentRebuildFilter
from tests.utils import BaseTestCase, random_str
from oio.event.beanstalk import Beanstalk


class _App(object):
    app_env = dict()

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
        self.object_storage_api = ObjectStorageApi(namespace=self.namespace)
        self.stgpol = "SINGLE"
        self.content_rebuild_filter = ContentRebuildFilter(app=_App,
                                                           conf=self.conf)
        queue_url = self.conf.get('queue_url', 'tcp://127.0.0.1:11300')
        self.tube = self.conf.get('tube', 'rebuild')
        self.beanstalk = Beanstalk.from_url(queue_url)
        self.beanstalk.use(self.tube)

    def _create_event(self, content_name, present_chunks, missing_chunks,
                      content_id):
        event = {}
        event["when"] = time.time()
        event["event"] = "storage.content.broken"
        event["data"] = {"present_chunks": present_chunks,
                         "missing_chunks": missing_chunks}
        event["url"] = {"ns": self.namespace, "account": self.account,
                        "user": self.container, "path": content_name,
                        "id": self.container_id, "content": content_id}
        return event

    def _is_chunks_created(self, previous, after, pos_created):
        remain = list(after)
        for p in previous:
            for r in remain:
                if p["url"] == r["url"]:
                    remain.remove(r)
                    break
        if len(remain) != len(pos_created):
            return False
        for r in remain:
            if r["pos"] in pos_created:
                remain.remove(r)
            else:
                return False
        return True

    def _rebuild(self, event, job_id=0):
        self.blob_rebuilder = subprocess.Popen(
                    ['oio-blob-rebuilder', self.namespace,
                     '--beanstalkd=127.0.0.1:11300'])
        time.sleep(3)
        self.blob_rebuilder.kill()

    def _remove_chunks(self, chunks, content_id):
        uri = self.object_storage_api._make_uri('container/raw_delete')
        params = self.object_storage_api._make_params(self.account,
                                                      self.container)
        if not chunks:
            return
        for c in chunks:
            c['id'] = c['url']
            c['content'] = content_id
            c['type'] = 'chunk'
        data = json.dumps(chunks)
        resp, _ = self.object_storage_api._request('POST', uri, params=params,
                                                   data=data)
        self.assertEqual(204, resp.status_code)

    def _check_rebuild(self, content_name, chunks, missing_pos, meta,
                       chunks_to_remove, chunk_created=True):
        self._remove_chunks(chunks_to_remove, meta['id'])
        event = self._create_event(content_name, chunks, missing_pos,
                                   meta['id'])
        self.content_rebuild_filter.process(env=event, cb=None)
        self._rebuild(event)
        _, after = self.object_storage_api.object_analyze(
                        container=self.container, obj=content_name,
                        account=self.account)
        self.assertIs(chunk_created, self._is_chunks_created(chunks,
                                                             after,
                                                             missing_pos))

    def test_nothing_missing(self):
        content_name = "test_nothing_missing"
        self.object_storage_api.object_create(account=self.account,
                                              container=self.container,
                                              data="test",
                                              policy="THREECOPIES",
                                              obj_name=content_name)

        meta, chunks = self.object_storage_api.object_analyze(
                          container=self.container, obj=content_name,
                          account=self.account)
        chunks_to_remove = []
        for c in chunks:
            c.pop('score', None)

        missing_pos = []
        self._check_rebuild(content_name, chunks, missing_pos, meta,
                            chunks_to_remove, chunk_created=True)

    def test_missing_1_chunk(self):
        content_name = "test_missing_1_chunk"
        self.object_storage_api.object_create(account=self.account,
                                              container=self.container,
                                              data="test",
                                              policy="THREECOPIES",
                                              obj_name=content_name
                                              )
        meta, chunks = self.object_storage_api.object_analyze(
                        container=self.container, obj=content_name,
                        account=self.account)
        chunks_to_remove = []
        chunks_to_remove.append(chunks.pop(0))
        for c in chunks:
            c.pop('score', None)

        missing_pos = ["0"]
        self._check_rebuild(content_name, chunks, missing_pos, meta,
                            chunks_to_remove)

    def test_missing_last_chunk(self):
        content_name = "test_missing_last_chunk"
        data = random_str(1024 * 1024 * 4)
        self.object_storage_api.object_create(account=self.account,
                                              container=self.container,
                                              data=data,
                                              policy="THREECOPIES",
                                              obj_name=content_name
                                              )
        meta, chunks = self.object_storage_api.object_analyze(
                        container=self.container, obj=content_name,
                        account=self.account)
        chunks_to_remove = []
        chunks_to_remove.append(chunks.pop(0))
        for c in chunks:
            c.pop('score', None)

        missing_pos = ["3"]
        self._check_rebuild(content_name, chunks, missing_pos, meta,
                            chunks_to_remove)

    def test_missing_2_chunks(self):
        content_name = "test_missing_2_chunks"
        self.object_storage_api.object_create(account=self.account,
                                              container=self.container,
                                              data="test",
                                              policy="THREECOPIES",
                                              obj_name=content_name
                                              )
        meta, chunks = self.object_storage_api.object_analyze(
                        container=self.container, obj=content_name,
                        account=self.account)
        chunks_to_remove = []
        for i in range(0, 2):
            chunks_to_remove.append(chunks.pop(0))
        for c in chunks:
            c.pop('score', None)

        missing_pos = ["0", "0"]
        self._check_rebuild(content_name, chunks, missing_pos, meta,
                            chunks_to_remove)

    def test_missing_all_chunks(self):
        content_name = "test_missing_all_chunks"
        self.object_storage_api.object_create(account=self.account,
                                              container=self.container,
                                              data="test",
                                              policy="SINGLE",
                                              obj_name=content_name
                                              )
        meta, chunks = self.object_storage_api.object_analyze(
                        container=self.container, obj=content_name,
                        account=self.account)
        chunks_to_remove = []
        chunks_to_remove.append(chunks.pop(0))
        for c in chunks:
            c.pop('score', None)

        missing_pos = ["0"]
        self._check_rebuild(content_name, chunks, missing_pos, meta,
                            chunks_to_remove, chunk_created=False)

    def test_missing_all_chunks_of_a_pos(self):
        content_name = "test_missing_2_chunks"
        self.object_storage_api.object_create(account=self.account,
                                              container=self.container,
                                              data="test",
                                              policy="THREECOPIES",
                                              obj_name=content_name
                                              )
        meta, chunks = self.object_storage_api.object_analyze(
                        container=self.container, obj=content_name,
                        account=self.account)
        chunks_to_remove = []
        for i in range(0, 3):
            chunks_to_remove.append(chunks.pop(0))

        for c in chunks:
            c.pop('score', None)

        missing_pos = ["0"]
        self._check_rebuild(content_name, chunks, missing_pos, meta,
                            chunks_to_remove, chunk_created=False)

    def test_missing_multiple_chunks(self):
        content_name = "test_missing_multiple_chunks"
        data = random_str(1024 * 1024 * 4)
        self.object_storage_api.object_create(account=self.account,
                                              container=self.container,
                                              data=data,
                                              policy="THREECOPIES",
                                              obj_name=content_name)
        meta, chunks = self.object_storage_api.object_analyze(
                        container=self.container, obj=content_name,
                        account=self.account)
        chunks_to_remove = []
        chunks_to_remove.append(chunks.pop(9))
        chunks_to_remove.append(chunks.pop(6))
        chunks_to_remove.append(chunks.pop(4))
        chunks_to_remove.append(chunks.pop(0))
        for c in chunks:
            c.pop('score', None)

        missing_pos = ["0", "1", "2", "3"]
        self._check_rebuild(content_name, chunks, missing_pos, meta,
                            chunks_to_remove)

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
        meta, chunks = self.object_storage_api.object_analyze(
                        container=self.container, obj=content_name,
                        account=self.account)
        chunks_to_remove = []
        chunks_to_remove.append(chunks.pop(0))
        for c in chunks:
            c.pop('score', None)

        missing_pos = ["0.1"]
        self._check_rebuild(content_name, chunks, missing_pos, meta,
                            chunks_to_remove)

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
        meta, chunks = self.object_storage_api.object_analyze(
                        container=self.container, obj=content_name,
                        account=self.account)
        chunks_to_remove = []
        for i in range(0, 3):
            chunks_to_remove.append(chunks.pop(0))
        for c in chunks:
            c.pop('score', None)

        missing_pos = ["0.1", "0.2", "0.3"]
        self._check_rebuild(content_name, chunks, missing_pos, meta,
                            chunks_to_remove)

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
        meta, chunks = self.object_storage_api.object_analyze(
                        container=self.container, obj=content_name,
                        account=self.account)
        chunks_to_remove = []
        chunks_to_remove.append(chunks.pop(0))
        chunks_to_remove.append(chunks.pop(3))
        chunks_to_remove.append(chunks.pop(5))
        for c in chunks:
            c.pop('score', None)

        missing_pos = ["0.1", "0.5", "0.8"]
        self._check_rebuild(content_name, chunks, missing_pos, meta,
                            chunks_to_remove)

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
        meta, chunks = self.object_storage_api.object_analyze(
                        container=self.container, obj=content_name,
                        account=self.account)
        chunks_to_remove = []
        chunks_to_remove.append(chunks.pop(0))
        chunks_to_remove.append(chunks.pop(0))
        chunks_to_remove.append(chunks.pop(0))
        chunks_to_remove.append(chunks.pop(0))
        for c in chunks:
            c.pop('score', None)

        missing_pos = ["0.1", "0.2", "0.3", "0.4"]
        self._check_rebuild(content_name, chunks, missing_pos, meta,
                            chunks_to_remove, chunk_created=False)
