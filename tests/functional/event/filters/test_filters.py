# -*- coding: utf-8 -*-

# Copyright (C) 2017-2017 OpenIO SAS, as part of OpenIO SDS
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
import subprocess
from random import choice
from oio.api.object_storage import ObjectStorageApi
from oio.container.client import ContainerClient
from oio.event.filters.notify import NotifyFilter
from tests.utils import BaseTestCase, random_str
from oio.rebuilder.blob_rebuilder import DEFAULT_REBUILDER_TUBE


class _App(object):
    app_env = dict()

    def __init__(self, env, cb):
        self.env = env
        self.cb = cb


class TestContentRebuildFilter(BaseTestCase):

    def setUp(self):
        super(TestContentRebuildFilter, self).setUp()
        self.namespace = self.conf['namespace']
        self.gridconf = {"namespace": self.namespace}
        self.container = "TestContentRebuildFilter%f" % time.time()
        self.ref = self.container
        self.container_client = ContainerClient(self.conf)
        self.container_client.container_create(self.account, self.container)
        syst = self.container_client.container_get_properties(
                self.account, self.container)['system']
        self.container_id = syst['sys.name'].split('.', 1)[0]
        self.object_storage_api = ObjectStorageApi(namespace=self.namespace)
        queue_addr = choice(self.conf['services']['beanstalkd'])['addr']
        self.queue_url = 'beanstalk://' + queue_addr
        self.conf['queue_url'] = self.queue_url
        self.conf['tube'] = DEFAULT_REBUILDER_TUBE
        self.notify_filter = NotifyFilter(app=_App, conf=self.conf)

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
                     '--beanstalkd=' + self.queue_url])
        time.sleep(3)
        self.blob_rebuilder.kill()

    def _remove_chunks(self, chunks, content_id):
        if not chunks:
            return
        for chunk in chunks:
            chunk['id'] = chunk['url']
            chunk['content'] = content_id
            chunk['type'] = 'chunk'
        self.container_client.container_raw_delete(
            self.account, self.container, data=chunks)

    def _check_rebuild(self, content_name, chunks, missing_pos, meta,
                       chunks_to_remove, chunk_created=True):
        self._remove_chunks(chunks_to_remove, meta['id'])
        event = self._create_event(content_name, chunks, missing_pos,
                                   meta['id'])
        self.notify_filter.process(env=event, cb=None)
        self._rebuild(event)
        _, after = self.object_storage_api.object_locate(
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

        meta, chunks = self.object_storage_api.object_locate(
                          container=self.container, obj=content_name,
                          account=self.account)
        chunks_to_remove = []
        for chunk in chunks:
            chunk.pop('score', None)

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
        meta, chunks = self.object_storage_api.object_locate(
                        container=self.container, obj=content_name,
                        account=self.account)
        chunks_to_remove = []
        chunks_to_remove.append(chunks.pop(0))
        for chunk in chunks:
            chunk.pop('score', None)

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
        meta, chunks = self.object_storage_api.object_locate(
                        container=self.container, obj=content_name,
                        account=self.account)
        chunks_to_remove = []
        chunks_to_remove.append(chunks.pop(0))
        for chunk in chunks:
            chunk.pop('score', None)

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
        meta, chunks = self.object_storage_api.object_locate(
                        container=self.container, obj=content_name,
                        account=self.account)
        chunks_to_remove = []
        for i in range(0, 2):
            chunks_to_remove.append(chunks.pop(0))
        for chunk in chunks:
            chunk.pop('score', None)

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
        meta, chunks = self.object_storage_api.object_locate(
                        container=self.container, obj=content_name,
                        account=self.account)
        chunks_to_remove = []
        chunks_to_remove.append(chunks.pop(0))
        for chunk in chunks:
            chunk.pop('score', None)

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
        meta, chunks = self.object_storage_api.object_locate(
                        container=self.container, obj=content_name,
                        account=self.account)
        chunks_to_remove = []
        for i in range(0, 3):
            chunks_to_remove.append(chunks.pop(0))

        for chunk in chunks:
            chunk.pop('score', None)

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
        meta, chunks = self.object_storage_api.object_locate(
                        container=self.container, obj=content_name,
                        account=self.account)
        chunks_to_remove = []
        chunks_to_remove.append(chunks.pop(9))
        chunks_to_remove.append(chunks.pop(6))
        chunks_to_remove.append(chunks.pop(4))
        chunks_to_remove.append(chunks.pop(0))
        for chunk in chunks:
            chunk.pop('score', None)

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
        meta, chunks = self.object_storage_api.object_locate(
                        container=self.container, obj=content_name,
                        account=self.account)
        chunks_to_remove = []
        chunks_to_remove.append(chunks.pop(0))
        for chunk in chunks:
            chunk.pop('score', None)

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
        meta, chunks = self.object_storage_api.object_locate(
                        container=self.container, obj=content_name,
                        account=self.account)
        chunks_to_remove = []
        for i in range(0, 3):
            chunks_to_remove.append(chunks.pop(0))
        for chunk in chunks:
            chunk.pop('score', None)

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
        meta, chunks = self.object_storage_api.object_locate(
                        container=self.container, obj=content_name,
                        account=self.account)
        chunks_to_remove = []
        chunks_to_remove.append(chunks.pop(0))
        chunks_to_remove.append(chunks.pop(3))
        chunks_to_remove.append(chunks.pop(5))
        for chunk in chunks:
            chunk.pop('score', None)

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
        meta, chunks = self.object_storage_api.object_locate(
                        container=self.container, obj=content_name,
                        account=self.account)
        chunks_to_remove = []
        chunks_to_remove.append(chunks.pop(0))
        chunks_to_remove.append(chunks.pop(0))
        chunks_to_remove.append(chunks.pop(0))
        chunks_to_remove.append(chunks.pop(0))
        for chunk in chunks:
            chunk.pop('score', None)

        missing_pos = ["0.1", "0.2", "0.3", "0.4"]
        self._check_rebuild(content_name, chunks, missing_pos, meta,
                            chunks_to_remove, chunk_created=False)
