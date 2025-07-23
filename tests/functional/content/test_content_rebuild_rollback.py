# Copyright (C) 2025 OVH SAS
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
from copy import copy
from io import BytesIO

from oio.common.exceptions import ClientException
from oio.common.utils import cid_from_name, request_id
from oio.container.client import ContainerClient
from oio.content.ec import ECContent
from oio.content.factory import ContentFactory
from oio.content.plain import PlainContent
from oio.event.evob import EventTypes
from tests.utils import BaseTestCase, random_data, random_str


class RebuildRollbackTestCase(BaseTestCase):
    __test__ = False
    CONTENT_CLASS = ""
    STGPOL = ""

    def setUp(self):
        super(RebuildRollbackTestCase, self).setUp()
        self.account = self.conf["account"]
        self.chunk_size = self.conf["chunk_size"]
        self.gridconf = {"namespace": self.ns}
        self.content_factory = ContentFactory(
            self.gridconf, logger=self.logger, watchdog=self.watchdog
        )
        self.container_client = ContainerClient(self.gridconf, logger=self.logger)
        self.blob_client = self.content_factory.blob_client
        self.container_name = "%s-%f" % (self.__class__.__name__, time.time())
        self.container_client.container_create(
            account=self.account, reference=self.container_name
        )
        self.clean_later(self.container_name, self.account)
        self.container_id = cid_from_name(self.account, self.container_name).upper()
        self.content = "%s-%s" % (self.__class__.__name__, random_str(4))
        self.data_field = "chunk_id"
        self.size = self.conf["chunk_size"]
        self.reqid = None
        self.add_service_id = False

    def _new_content(self):
        data = random_data(self.size)
        content = self.content_factory.new(
            self.container_id, self.content, len(data), self.STGPOL
        )
        self.assertEqual(type(content), self.CONTENT_CLASS)
        content.create(BytesIO(data))
        return content

    def _remove_chunks(self, content, chunks):
        obj_meta = content.metadata
        if not chunks:
            return
        for chunk in chunks:
            chunk["id"] = chunk["url"]
            chunk["content"] = obj_meta["id"]
            chunk["type"] = "chunk"
        self.container_client.container_raw_delete(
            self.account,
            self.container_name,
            data=chunks,
            path=obj_meta["name"],
            version=obj_meta["version"],
        )
        try:
            self.blob_client.chunk_delete_many(chunks)
        except Exception:
            pass

    def _check_events(self, chunk_pos):
        event_new = self.wait_for_event(
            reqid=self.reqid,
            timeout=5,
            types=(EventTypes.CHUNK_NEW,),
            data_fields={"chunk_position": chunk_pos},
        )
        self.assertIsNotNone(event_new)
        event_deleted = self.wait_for_event(
            reqid=self.reqid,
            timeout=5,
            types=(EventTypes.CHUNK_DELETED,),
            data_fields={self.data_field: event_new.data[self.data_field]},
        )
        self.assertIsNotNone(event_deleted)
        # Check the chunk delete comes as rollback of the chunk creation
        self.assertGreater(event_deleted.when, event_new.when)

    def _test_handle_raw_registration_error(
        self,
        err_status_code=None,
        func=None,
        use_chunk_id=True,
        check_content=True,
    ):
        """
        Test that when an unrecoverable error occurs during chunk registration,
        a rollback is performed to delete the previously created chunk.
        """
        content = self._new_content()
        chunks = copy(content.chunks.chunks)
        chunk_to_rebuild = chunks.pop(0)
        chunk_id = None
        if use_chunk_id:
            chunk_id = chunk_to_rebuild.id
        chunk_host = None
        if self.add_service_id:
            chunk_host = chunk_to_rebuild.host
        chunk_pos = chunk_to_rebuild.pos
        self._remove_chunks(content, [chunk_to_rebuild._data])

        def raise_client_exception(*args, **kwargs):
            raise ClientException(
                http_status=err_status_code, status=err_status_code, message="error"
            )

        if err_status_code:
            if chunk_id:
                content.container_client.container_raw_update = raise_client_exception
            else:
                content.container_client.container_raw_insert = raise_client_exception
        if func:

            def _custom_raw_action(*args, **kwargs):
                # run the function before calling raw registration
                func()
                if chunk_id:
                    return content.container_client.container_raw_update(
                        *args, **kwargs
                    )
                else:
                    return content.container_client.container_raw_insert(
                        *args, **kwargs
                    )

            if chunk_id:
                content.container_client.container_raw_update = _custom_raw_action
            else:
                content.container_client.container_raw_insert = _custom_raw_action
        with self.assertRaises(ClientException):
            content.rebuild_chunk(
                container_id=self.container_id,
                content_id=content.content_id,
                chunk_id=chunk_id,
                chunk_pos=chunk_pos,
                path=content.path,
                reqid=self.reqid,
                service_id=chunk_host,
            )
        self._check_events(chunk_pos)
        if check_content:
            self._check_content(
                content.content_id,
                content.path,
                content.version,
                chunk_id=chunk_id,
                chunk_pos=chunk_pos,
                service_id=chunk_host,
            )

    def test_handle_raw_update_error_400(self, err_status_code=400):
        """Test bad request handle while registering raw"""
        self._test_handle_raw_registration_error(err_status_code)

    def test_handle_raw_add_error_400(self, err_status_code=400):
        """Test bad request handle while registering raw"""
        self._test_handle_raw_registration_error(err_status_code, use_chunk_id=False)

    def test_handle_raw_update_error_420(self):
        """Test bean not found handle while registering raw"""
        self._test_handle_raw_registration_error()

    def test_handle_raw_add_error_420(self):
        """Test bean not found handle while registering raw"""
        self._test_handle_raw_registration_error(use_chunk_id=False)

    def test_handle_raw_update_error_421(self, err_status_code=421):
        """Test bean already exists handle while registering raw"""
        self._test_handle_raw_registration_error(err_status_code)

    def test_handle_raw_add_error_421(self, err_status_code=421):
        """Test bean already exists handle while registering raw"""
        self._test_handle_raw_registration_error(err_status_code, use_chunk_id=False)

    def _test_handle_raw_action_error_431(self, use_chunk_id=True):
        """Test container not found handle while registering raw"""

        def _custom_func(*args, **kwargs):
            self.container_client.container_flush(self.account, self.container_name)
            self.container_client.container_delete(self.account, self.container_name)
            self.wait_for_kafka_event(
                types=[EventTypes.CONTAINER_DELETED],
                fields={"user": self.container_name},
            )

        self._test_handle_raw_registration_error(
            func=_custom_func,
            use_chunk_id=use_chunk_id,
            check_content=False,
        )

    def test_handle_raw_update_error_431(self):
        """Test container not found handle while registering raw"""
        self._test_handle_raw_action_error_431()

    def test_handle_raw_add_error_431(self):
        """Test container not found handle while registering raw"""
        self._test_handle_raw_action_error_431(use_chunk_id=False)

    def test_handle_raw_update_error_500(self, err_status_code=500):
        """Test internal error handle while registering raw"""
        self._test_handle_raw_registration_error(err_status_code)

    def test_handle_raw_add_error_500(self, err_status_code=500):
        """Test internal error handle while registering raw"""
        self._test_handle_raw_registration_error(err_status_code, use_chunk_id=False)

    def test_handle_raw_update_error_511(self, err_status_code=511):
        """Test corrupted db error handle while registering raw"""
        self._test_handle_raw_registration_error(err_status_code)

    def test_handle_raw_add_error_511(self, err_status_code=511):
        """Test corrupted db error handle while registering raw"""
        self._test_handle_raw_registration_error(err_status_code, use_chunk_id=False)


class TestECContentRebuildRollback(RebuildRollbackTestCase):
    __test__ = True
    CONTENT_CLASS = ECContent
    STGPOL = "EC"

    def setUp(self):
        super(TestECContentRebuildRollback, self).setUp()
        if len(self.conf["services"]["rawx"]) < 12:
            self.skipTest("Not enough rawx. EC tests needs at least 12 rawx to run")
        self.size = 1024 * 1024 + 320
        self.reqid = request_id("ec-rebuild-test-")

    def _check_content(
        self, content_id, path, version, chunk_id=None, chunk_pos=None, **kwargs
    ):
        content = self.content_factory.get_by_path_and_version(
            container_id=self.container_id,
            content_id=content_id,
            path=path,
            version=version,
        )
        # Check that the chunk has not been rebuilt
        self.assertEqual(
            len(content.chunks), content.storage_method.expected_chunks - 1
        )
        chunk_ids = [c.id for c in content.chunks]
        self.assertNotIn(chunk_id, chunk_ids)
        chunk_positions = [c.pos for c in content.chunks]
        self.assertNotIn(chunk_pos, chunk_positions)


class TestPlainContentRebuildRollback(RebuildRollbackTestCase):
    __test__ = True
    CONTENT_CLASS = PlainContent
    STGPOL = "THREECOPIES"

    def setUp(self):
        super(TestPlainContentRebuildRollback, self).setUp()
        if len(self.conf["services"]["rawx"]) < 4:
            self.skipTest("Plain tests needs more than 3 rawx to run")
        self.data_field = "volume_service_id"
        self.reqid = request_id("plain-rebuild-test-")
        self.add_service_id = True

    def _check_content(self, content_id, path, version, service_id=None, **kwargs):
        content = self.content_factory.get_by_path_and_version(
            container_id=self.container_id,
            content_id=content_id,
            path=path,
            version=version,
        )
        # Check that the chunk has not been rebuilt
        self.assertEqual(
            len(content.chunks), content.storage_method.expected_chunks - 1
        )
        chunk_hosts = [c.host for c in content.chunks]
        self.assertNotIn(service_id, chunk_hosts)

    def test_handle_raw_add_error_420(self):
        # This case is not possible because any copy can be used for rebuild
        # when a specific chunk ID is not specified.
        self.skipTest("Not relevant")
