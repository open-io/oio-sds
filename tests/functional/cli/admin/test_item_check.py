# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2024 OVH SAS
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
import random
import time

from subprocess import CalledProcessError

from oio import ObjectStorageApi
from oio.common.autocontainer import HashedContainerBuilder
from oio.common.utils import cid_from_name, request_id
from oio.event.evob import EventTypes
from tests.functional.cli import CliTestCase, CommandFailed
from tests.utils import random_str


class ItemCheckTest(CliTestCase):
    """Functional tests for item to check."""

    FLAT_BITS = 5
    OBJECTS_CREATED = []

    @classmethod
    def setUpClass(cls):
        super(ItemCheckTest, cls).setUpClass()
        cls.check_opts = cls.get_format_opts(fields=("Type", "Item", "Status"))
        cls.api = ObjectStorageApi(cls._cls_ns, endpoint=cls._cls_uri)
        cls.autocontainer = HashedContainerBuilder(bits=cls.FLAT_BITS)
        # Prevent the chunks' rebuilds or moves by the crawlers
        cls._service("oio-crawler.target", "stop", wait=3)

    @classmethod
    def tearDownClass(cls):
        accounts = set()
        conts = set()
        for acct, cont, obj, vers in cls.OBJECTS_CREATED:
            try:
                cls.api.object_delete(acct, cont, obj, version=vers)
                conts.add((acct, cont))
            except Exception as exc:
                print(f"Failed to delete {acct}/{cont}/{obj}: {exc}")
        for acct, cont in conts:
            try:
                cls.api.container_delete(acct, cont)
            except Exception as exc:
                print(f"Failed to delete {acct}/{cont}: {exc}")
            accounts.add(acct)
        for acct in accounts:
            try:
                cls.api.account_flush(acct)
                cls.api.account_delete(acct)
            except Exception as exc:
                print(f"Failed to delete {acct}: {exc}")
        cls._service("oio-crawler.target", "start", wait=1)
        super(ItemCheckTest, cls).tearDownClass()

    def setUp(self):
        super(ItemCheckTest, self).setUp()
        self.rawx_services = None

        self.account = "item_check_account_" + random_str(4)
        self.container = "item_check_container" + random_str(4)
        self.obj_name = "item_check_obj_" + random_str(4)

        self.beanstalkd0.drain_tube("oio-preserved")
        self.api.account_create(self.account)

        self.limit_listings = 0

    def _wait_for_events(self, chunks, reqid):
        for _ in range(2 + len(chunks)):
            self.wait_for_event(
                "oio-preserved",
                reqid=reqid,
                types=(
                    EventTypes.CHUNK_NEW,
                    EventTypes.CONTENT_NEW,
                    EventTypes.CONTAINER_STATE,
                ),
            )

    def _wait_for_chunk_indexation(self, chunk_url, timeout=10.0):
        _, rawx_service, chunk_id = chunk_url.rsplit("/", 2)
        deadline = time.monotonic() + timeout
        while (
            not self.rdir.chunk_search(rawx_service, chunk_id)
            and time.monotonic() < deadline
        ):
            self.logger.info("Waiting for chunk %s to be indexed in rdir", chunk_url)
            time.sleep(1.0)

    def create_object(self, account, container, obj_name):
        reqid = request_id(self.__class__.__name__)
        obj_chunks, _, _, obj_meta = self.api.object_create_ext(
            account, container, obj_name=obj_name, data="test_item_check", reqid=reqid
        )
        self._wait_for_events(obj_chunks, reqid)
        self.__class__.OBJECTS_CREATED.append(
            (account, container, obj_name, obj_meta["version"])
        )
        return obj_meta, obj_chunks

    def create_object_auto(self, account, obj_name):
        reqid = request_id(self.__class__.__name__)
        container = self.autocontainer(obj_name)
        obj_chunks, _, _, obj_meta = self.api.object_create_ext(
            account, container, obj_name=obj_name, data="test_item_check", reqid=reqid
        )
        self._wait_for_events(obj_chunks, reqid)
        self.__class__.OBJECTS_CREATED.append(
            (account, container, obj_name, obj_meta["version"])
        )
        return container, obj_meta, obj_chunks

    def corrupt_chunk(self, chunk):
        _, service_id, chunk_id = chunk.rsplit("/", 2)
        if self.rawx_services is None:
            self.rawx_services = self.conscience.all_services("rawx")
        for rawx_service in self.rawx_services:
            tags = rawx_service["tags"]
            rawx_service_id = tags.get("tag.service_id", None)
            if rawx_service_id is None:
                rawx_service_id = rawx_service["addr"]
            if rawx_service_id != service_id:
                continue
            rawx_service_path = tags.get("tag.vol", None)
            break
        else:
            self.fail("No service matches with the chunk %s" % chunk)
        chunk_id = chunk_id.upper()
        chunk_path = rawx_service_path + "/" + chunk_id[:3] + "/" + chunk_id
        with open(chunk_path, "wb") as fp:
            fp.write(b"chunk is dead")

    def test_account_check(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        expected_items = list()
        expected_items.append("account account=%s OK" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s OK"
            % (self.account, self.container, cid)
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        for chunk in obj_chunks:
            expected_items.append("chunk chunk=%s OK" % (chunk["url"]))

        # Check all items
        output = self.openio_admin(
            "account check %s %s" % (self.account, self.check_opts)
        )
        self.assert_list_output(expected_items, output)

        output = self.openio_admin(
            "--oio-account %s account check %s" % (self.account, self.check_opts)
        )
        self.assert_list_output(expected_items, output)

    def test_account_with_depth(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        expected_items = list()

        # Check part of items
        expected_items.append("account account=%s OK" % self.account)
        output = self.openio_admin(
            "account check %s --depth 0 %s" % (self.account, self.check_opts)
        )
        self.assert_list_output(expected_items, output)

        expected_items.append(
            "container account=%s, container=%s, cid=%s OK"
            % (self.account, self.container, cid)
        )
        output = self.openio_admin(
            "account check %s --depth 1 %s" % (self.account, self.check_opts)
        )
        self.assert_list_output(expected_items, output)

        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        output = self.openio_admin(
            "account check %s --depth 2 %s" % (self.account, self.check_opts)
        )
        self.assert_list_output(expected_items, output)

        for chunk in obj_chunks:
            expected_items.append("chunk chunk=%s OK" % (chunk["url"]))
        output = self.openio_admin(
            "account check %s --depth 3 %s" % (self.account, self.check_opts)
        )
        self.assert_list_output(expected_items, output)

        output = self.openio_admin(
            "account check %s --depth 4 %s" % (self.account, self.check_opts)
        )
        self.assert_list_output(expected_items, output)

    def test_account_check_with_checksum(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        expected_items = list()
        expected_items.append("account account=%s OK" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s OK"
            % (self.account, self.container, cid)
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        for chunk in obj_chunks:
            expected_items.append("chunk chunk=%s OK" % (chunk["url"]))

        # Check with checksum
        output = self.openio_admin(
            "account check %s --checksum %s" % (self.account, self.check_opts)
        )
        self.assert_list_output(expected_items, output)

        # Corrupt the chunk
        corrupted_chunk = random.choice(obj_chunks)
        self.corrupt_chunk(corrupted_chunk["url"])

        # Check without checksum
        output = self.openio_admin(
            "account check %s %s" % (self.account, self.check_opts)
        )
        self.assert_list_output(expected_items, output)

        expected_items.remove("chunk chunk=%s OK" % (corrupted_chunk["url"]))
        expected_items.append("chunk chunk=%s error" % (corrupted_chunk["url"]))
        expected_items.remove(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s error"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )

        # Check with checksum
        output = self.openio_admin(
            "account check %s --checksum %s" % (self.account, self.check_opts),
            expected_returncode=1,
        )
        self.assert_list_output(expected_items, output)

    def test_account_check_with_missing_chunk(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        missing_chunk = random.choice(obj_chunks)

        expected_items = list()
        expected_items.append("account account=%s OK" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s OK"
            % (self.account, self.container, cid)
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s error"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        for chunk in obj_chunks:
            if chunk["url"] == missing_chunk["url"]:
                status = "error"
            else:
                status = "OK"
            expected_items.append("chunk chunk=%s %s" % (chunk["url"], status))

        # Delete chunk
        self.api.blob_client.chunk_delete(missing_chunk["url"])

        # Check with missing chunk
        output = self.openio_admin(
            "account check %s %s" % (self.account, self.check_opts),
            expected_returncode=1,
        )
        self.assert_list_output(expected_items, output)

    def test_account_check_with_missing_container(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        missing_container = "item_check_missing_container_" + random_str(4)

        expected_items = list()
        expected_items.append("account account=%s OK" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s OK"
            % (self.account, self.container, cid)
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        for chunk in obj_chunks:
            expected_items.append("chunk chunk=%s OK" % (chunk["url"]))
        cid = cid_from_name(self.account, missing_container)
        expected_items.append(
            "container account=%s, container=%s, cid=%s error"
            % (self.account, missing_container, cid)
        )

        # Create a container only in account service
        self.api.account.container_update(
            self.account, missing_container, time.time(), 0, 0
        )

        # Check with missing container
        output = self.openio_admin(
            "account check %s %s" % (self.account, self.check_opts),
            expected_returncode=1,
        )
        self.assert_list_output(expected_items, output)

    def test_account_check_with_missing_account(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        missing_account = "item_check_missing_account_" + random_str(4)

        expected_items = list()
        expected_items.append("account account=%s error" % missing_account)

        # Check with missing account
        output = self.openio_admin(
            "account check %s %s" % (missing_account, self.check_opts),
            expected_returncode=1,
        )
        self.assert_list_output(expected_items, output)

        expected_items.append("account account=%s OK" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s OK"
            % (self.account, self.container, cid)
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        for chunk in obj_chunks:
            expected_items.append("chunk chunk=%s OK" % (chunk["url"]))

        output = self.openio_admin(
            "account check %s %s %s" % (self.account, missing_account, self.check_opts),
            expected_returncode=1,
        )
        self.assert_list_output(expected_items, output)

    def test_account_check_with_multiple_accounts(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        second_account = "item_check_second_account_" + random_str(4)

        expected_items = list()
        expected_items.append("account account=%s OK" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s OK"
            % (self.account, self.container, cid)
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        for chunk in obj_chunks:
            expected_items.append("chunk chunk=%s OK" % (chunk["url"]))

        # Create a second account
        self.api.account_create(second_account)

        # Check only the first account
        output = self.openio_admin(
            "account check %s %s" % (self.account, self.check_opts)
        )
        self.assert_list_output(expected_items, output)

        # Check two accounts
        expected_items.append("account account=%s OK" % second_account)
        output = self.openio_admin(
            "account check %s %s %s" % (self.account, second_account, self.check_opts)
        )
        self.assert_list_output(expected_items, output)
        self.api.account_delete(second_account)

    def test_container_check(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        expected_items = list()
        expected_items.append("account account=%s OK" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s OK"
            % (self.account, self.container, cid)
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        for chunk in obj_chunks:
            expected_items.append("chunk chunk=%s OK" % (chunk["url"]))

        # Check all items
        output = self.openio_admin(
            "--oio-account %s container check %s %s"
            % (self.account, self.container, self.check_opts)
        )
        self.assert_list_output(expected_items, output)

    def test_container_check_with_cid(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        expected_items = list()
        expected_items.append("account account=%s OK" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s OK"
            % (self.account, self.container, cid)
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        for chunk in obj_chunks:
            expected_items.append("chunk chunk=%s OK" % (chunk["url"]))

        # Check all items
        output = self.openio_admin(
            "container check %s --cid %s" % (cid, self.check_opts)
        )
        self.assert_list_output(expected_items, output)

    def test_container_with_depth(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        expected_items = list()

        # Check part of items
        expected_items.append("account account=%s OK" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s OK"
            % (self.account, self.container, cid)
        )
        output = self.openio_admin(
            "--oio-account %s container check %s --depth 0 %s"
            % (self.account, self.container, self.check_opts)
        )
        self.assert_list_output(expected_items, output)

        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        output = self.openio_admin(
            "--oio-account %s container check %s --depth 1 %s"
            % (self.account, self.container, self.check_opts)
        )
        self.assert_list_output(expected_items, output)

        for chunk in obj_chunks:
            expected_items.append("chunk chunk=%s OK" % (chunk["url"]))
        output = self.openio_admin(
            "--oio-account %s container check %s --depth 2 %s"
            % (self.account, self.container, self.check_opts)
        )
        self.assert_list_output(expected_items, output)

        output = self.openio_admin(
            "--oio-account %s container check %s --depth 3 %s"
            % (self.account, self.container, self.check_opts)
        )
        self.assert_list_output(expected_items, output)

        output = self.openio_admin(
            "--oio-account %s container check %s --depth 4 %s"
            % (self.account, self.container, self.check_opts)
        )
        self.assert_list_output(expected_items, output)

    def test_container_check_with_checksum(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        expected_items = list()
        expected_items.append("account account=%s OK" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s OK"
            % (self.account, self.container, cid)
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        for chunk in obj_chunks:
            expected_items.append("chunk chunk=%s OK" % (chunk["url"]))

        # Check with checksum
        output = self.openio_admin(
            "--oio-account %s container check %s --checksum %s"
            % (self.account, self.container, self.check_opts)
        )
        self.assert_list_output(expected_items, output)

        # Corrupt the chunk
        corrupted_chunk = random.choice(obj_chunks)
        self.corrupt_chunk(corrupted_chunk["url"])

        # Check without checksum
        output = self.openio_admin(
            "--oio-account %s container check %s %s"
            % (self.account, self.container, self.check_opts)
        )
        self.assert_list_output(expected_items, output)

        expected_items.remove("chunk chunk=%s OK" % (corrupted_chunk["url"]))
        expected_items.append("chunk chunk=%s error" % (corrupted_chunk["url"]))
        expected_items.remove(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s error"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )

        # Check with checksum
        output = self.openio_admin(
            "--oio-account %s container check %s --checksum %s"
            % (self.account, self.container, self.check_opts),
            expected_returncode=1,
        )
        self.assert_list_output(expected_items, output)

    def test_container_check_with_missing_chunk(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        missing_chunk = random.choice(obj_chunks)

        expected_items = list()
        expected_items.append("account account=%s OK" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s OK"
            % (self.account, self.container, cid)
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s error"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        for chunk in obj_chunks:
            if chunk["url"] == missing_chunk["url"]:
                status = "error"
            else:
                status = "OK"
            expected_items.append("chunk chunk=%s %s" % (chunk["url"], status))

        # Delete chunk
        self.api.blob_client.chunk_delete(missing_chunk["url"])

        # Check with missing chunk
        output = self.openio_admin(
            "--oio-account %s container check %s %s"
            % (self.account, self.container, self.check_opts),
            expected_returncode=1,
        )
        self.assert_list_output(expected_items, output)

    def test_container_check_with_missing_container(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )

        missing_container = "item_check_missing_container_" + random_str(4)
        cid = cid_from_name(self.account, missing_container)

        expected_items = list()
        expected_items.append("account account=%s OK" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s error"
            % (self.account, missing_container, cid)
        )

        # Check with missing container
        output = self.openio_admin(
            "--oio-account %s container check %s %s"
            % (self.account, missing_container, self.check_opts),
            expected_returncode=1,
        )
        self.assert_list_output(expected_items, output)

        # Create a container only in account service
        self.api.account.container_update(
            self.account, missing_container, time.time(), 0, 0
        )

        # Check with missing container
        output = self.openio_admin(
            "--oio-account %s container check %s %s"
            % (self.account, missing_container, self.check_opts),
            expected_returncode=1,
        )
        self.assert_list_output(expected_items, output)

        cid = cid_from_name(self.account, self.container)
        expected_items.append(
            "container account=%s, container=%s, cid=%s OK"
            % (self.account, self.container, cid)
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        for chunk in obj_chunks:
            expected_items.append("chunk chunk=%s OK" % (chunk["url"]))

        output = self.openio_admin(
            "--oio-account %s container check %s %s %s"
            % (self.account, self.container, missing_container, self.check_opts),
            expected_returncode=1,
        )
        self.assert_list_output(expected_items, output)

    def test_container_check_with_missing_account(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        expected_items = list()
        expected_items.append("account account=%s error" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s error"
            % (self.account, self.container, cid)
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        for chunk in obj_chunks:
            expected_items.append("chunk chunk=%s OK" % (chunk["url"]))

        # Remove account
        self.api.account_flush(self.account)
        self.api.account_delete(self.account)

        # Check with missing account
        output = self.openio_admin(
            "--oio-account %s container check %s %s"
            % (self.account, self.container, self.check_opts),
            expected_returncode=1,
        )
        self.assert_list_output(expected_items, output)

    def test_container_check_with_multiple_containers(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        second_container = "item_check_second_container_" + random_str(4)

        expected_items = list()
        expected_items.append("account account=%s OK" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s OK"
            % (self.account, self.container, cid)
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        for chunk in obj_chunks:
            expected_items.append("chunk chunk=%s OK" % (chunk["url"]))

        # Create a second container
        self.api.container_create(self.account, second_container)

        # Check only the first container
        output = self.openio_admin(
            "--oio-account %s container check %s %s"
            % (self.account, self.container, self.check_opts)
        )
        self.assert_list_output(expected_items, output)

        # Check two containers
        cid = cid_from_name(self.account, second_container)
        expected_items.append(
            "container account=%s, container=%s, cid=%s OK"
            % (self.account, second_container, cid)
        )
        output = self.openio_admin(
            "--oio-account %s container check %s %s %s"
            % (self.account, self.container, second_container, self.check_opts)
        )
        self.assert_list_output(expected_items, output)

    def test_object_check(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        expected_items = list()
        expected_items.append("account account=%s OK" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s OK"
            % (self.account, self.container, cid)
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        for chunk in obj_chunks:
            expected_items.append("chunk chunk=%s OK" % (chunk["url"]))

        # Check all items
        output = self.openio_admin(
            "--oio-account %s object check --limit-listings %d %s %s %s "
            % (
                self.account,
                self.limit_listings,
                self.container,
                self.obj_name,
                self.check_opts,
            )
        )
        self.assert_list_output(expected_items, output)

    def test_object_check_with_cid(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        expected_items = list()
        expected_items.append("account account=%s OK" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s OK"
            % (self.account, self.container, cid)
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        for chunk in obj_chunks:
            expected_items.append("chunk chunk=%s OK" % (chunk["url"]))

        # Check all items
        output = self.openio_admin(
            "object check --limit-listings %d --cid %s %s %s"
            % (self.limit_listings, cid, self.obj_name, self.check_opts)
        )
        self.assert_list_output(expected_items, output)

    def test_object_check_with_object_version(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        expected_items = list()
        expected_items.append("account account=%s OK" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s OK"
            % (self.account, self.container, cid)
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        for chunk in obj_chunks:
            expected_items.append("chunk chunk=%s OK" % (chunk["url"]))

        # Check all items
        output = self.openio_admin(
            "--oio-account %s object check --limit-listings %d %s %s "
            "--object-version %s %s"
            % (
                self.account,
                self.limit_listings,
                self.container,
                self.obj_name,
                obj_meta["version"],
                self.check_opts,
            )
        )
        self.assert_list_output(expected_items, output)

        # Enable versioning
        system = dict()
        system["sys.m2.policy.version"] = "-1"
        self.api.container_set_properties(self.account, self.container, system=system)

        # Create a second version of the object
        second_version_meta, second_version_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )

        # Check first version
        output = self.openio_admin(
            "--oio-account %s object check --limit-listings %d %s %s "
            "--object-version %s %s"
            % (
                self.account,
                self.limit_listings,
                self.container,
                self.obj_name,
                obj_meta["version"],
                self.check_opts,
            )
        )
        self.assert_list_output(expected_items, output)

        expected_items = list()
        expected_items.append("account account=%s OK" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s OK"
            % (self.account, self.container, cid)
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                second_version_meta["id"],
                second_version_meta["version"],
            )
        )
        for chunk in second_version_chunks:
            expected_items.append("chunk chunk=%s OK" % (chunk["url"]))

        # Check second version
        output = self.openio_admin(
            "--oio-account %s object check --limit-listings %d %s %s "
            "--object-version %s %s"
            % (
                self.account,
                self.limit_listings,
                self.container,
                self.obj_name,
                second_version_meta["version"],
                self.check_opts,
            )
        )
        self.assert_list_output(expected_items, output)

        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        for chunk in obj_chunks:
            expected_items.append("chunk chunk=%s OK" % (chunk["url"]))

        # Check all versions
        output = self.openio_admin(
            "--oio-account %s object check --limit-listings %d %s %s %s"
            % (
                self.account,
                self.limit_listings,
                self.container,
                self.obj_name,
                self.check_opts,
            )
        )

        self.assert_list_output(expected_items, output)

    def test_object_check_with_auto(self):
        self.container, obj_meta, obj_chunks = self.create_object_auto(
            self.account, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        expected_items = list()
        expected_items.append("account account=%s OK" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s OK"
            % (self.account, self.container, cid)
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        for chunk in obj_chunks:
            expected_items.append("chunk chunk=%s OK" % (chunk["url"]))

        # Check all items
        output = self.openio_admin(
            "--oio-account %s object check --limit-listings %d %s"
            " --auto --flat-bits %d %s"
            % (
                self.account,
                self.limit_listings,
                self.obj_name,
                self.FLAT_BITS,
                self.check_opts,
            )
        )
        self.assert_list_output(expected_items, output)

    def test_object_with_depth(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        expected_items = list()

        # Check part of items
        expected_items.append("account account=%s OK" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s OK"
            % (self.account, self.container, cid)
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        output = self.openio_admin(
            "--oio-account %s object check --limit-listings %d %s %s --depth 0 %s"
            % (
                self.account,
                self.limit_listings,
                self.container,
                self.obj_name,
                self.check_opts,
            )
        )
        self.assert_list_output(expected_items, output)

        for chunk in obj_chunks:
            expected_items.append("chunk chunk=%s OK" % (chunk["url"]))
        output = self.openio_admin(
            "--oio-account %s object check --limit-listings %d %s %s --depth 1 %s"
            % (
                self.account,
                self.limit_listings,
                self.container,
                self.obj_name,
                self.check_opts,
            )
        )
        self.assert_list_output(expected_items, output)

        output = self.openio_admin(
            "--oio-account %s object check --limit-listings %d %s %s --depth 2 %s"
            % (
                self.account,
                self.limit_listings,
                self.container,
                self.obj_name,
                self.check_opts,
            )
        )
        self.assert_list_output(expected_items, output)

        output = self.openio_admin(
            "--oio-account %s object check --limit-listings %d %s %s --depth 3 %s"
            % (
                self.account,
                self.limit_listings,
                self.container,
                self.obj_name,
                self.check_opts,
            )
        )
        self.assert_list_output(expected_items, output)

        output = self.openio_admin(
            "--oio-account %s object check --limit-listings %d %s %s --depth 4 %s"
            % (
                self.account,
                self.limit_listings,
                self.container,
                self.obj_name,
                self.check_opts,
            )
        )
        self.assert_list_output(expected_items, output)

    def test_object_check_with_checksum(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        expected_items = list()
        expected_items.append("account account=%s OK" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s OK"
            % (self.account, self.container, cid)
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        for chunk in obj_chunks:
            expected_items.append("chunk chunk=%s OK" % (chunk["url"]))

        # Check with checksum
        output = self.openio_admin(
            "--oio-account %s object check --limit-listings %d %s %s --checksum %s"
            % (
                self.account,
                self.limit_listings,
                self.container,
                self.obj_name,
                self.check_opts,
            )
        )
        self.assert_list_output(expected_items, output)

        # Corrupt the chunk
        corrupted_chunk = random.choice(obj_chunks)
        self.corrupt_chunk(corrupted_chunk["url"])

        # Check without checksum
        output = self.openio_admin(
            "--oio-account %s object check --limit-listings %d %s %s %s"
            % (
                self.account,
                self.limit_listings,
                self.container,
                self.obj_name,
                self.check_opts,
            )
        )
        self.assert_list_output(expected_items, output)

        expected_items.remove("chunk chunk=%s OK" % (corrupted_chunk["url"]))
        expected_items.append("chunk chunk=%s error" % (corrupted_chunk["url"]))
        expected_items.remove(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s error"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )

        # Check with checksum
        output = self.openio_admin(
            "--oio-account %s object check --limit-listings %d %s %s --checksum %s"
            % (
                self.account,
                self.limit_listings,
                self.container,
                self.obj_name,
                self.check_opts,
            ),
            expected_returncode=1,
        )
        self.assert_list_output(expected_items, output)

    def test_object_check_with_missing_chunk(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        missing_chunk = random.choice(obj_chunks)

        expected_items = list()
        expected_items.append("account account=%s OK" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s OK"
            % (self.account, self.container, cid)
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s error"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        for chunk in obj_chunks:
            if chunk["url"] == missing_chunk["url"]:
                status = "error"
            else:
                status = "OK"
            expected_items.append("chunk chunk=%s %s" % (chunk["url"], status))

        # Delete chunk
        self.api.blob_client.chunk_delete(missing_chunk["url"])

        # Check with missing chunk
        output = self.openio_admin(
            "--oio-account %s object check --limit-listings %d %s %s %s"
            % (
                self.account,
                self.limit_listings,
                self.container,
                self.obj_name,
                self.check_opts,
            ),
            expected_returncode=1,
        )
        self.assert_list_output(expected_items, output)

    def test_object_check_with_missing_object(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        missing_obj = "item_check_missing_obj_" + random_str(4)

        expected_items = list()
        expected_items.append("account account=%s OK" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s OK"
            % (self.account, self.container, cid)
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s error"
            % (self.account, self.container, cid, missing_obj)
        )

        # Check with missing object
        output = self.openio_admin(
            "--oio-account %s object check --limit-listings %d %s %s %s"
            % (
                self.account,
                self.limit_listings,
                self.container,
                missing_obj,
                self.check_opts,
            ),
            expected_returncode=1,
        )
        self.assert_list_output(expected_items, output)

        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        for chunk in obj_chunks:
            expected_items.append("chunk chunk=%s OK" % (chunk["url"]))

        output = self.openio_admin(
            "--oio-account %s object check --limit-listings %d %s %s %s %s"
            % (
                self.account,
                self.limit_listings,
                self.container,
                self.obj_name,
                missing_obj,
                self.check_opts,
            ),
            expected_returncode=1,
        )
        self.assert_list_output(expected_items, output)

    def test_object_check_with_missing_container(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        expected_items = list()
        expected_items.append("account account=%s OK" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s error"
            % (self.account, self.container, cid)
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        for chunk in obj_chunks:
            expected_items.append("chunk chunk=%s OK" % (chunk["url"]))

        # Remove container in account service
        self.api.account_flush(self.account)

        # Check with missing container
        output = self.openio_admin(
            "--oio-account %s object check --limit-listings %d %s %s %s"
            % (
                self.account,
                self.limit_listings,
                self.container,
                self.obj_name,
                self.check_opts,
            ),
            expected_returncode=1,
        )
        self.assert_list_output(expected_items, output)

    def test_object_check_with_missing_account(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        expected_items = list()
        expected_items.append("account account=%s error" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s error"
            % (self.account, self.container, cid)
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        for chunk in obj_chunks:
            expected_items.append("chunk chunk=%s OK" % (chunk["url"]))

        # Remove account
        self.api.account_flush(self.account)
        self.api.account_delete(self.account)

        # Check with missing account
        output = self.openio_admin(
            "--oio-account %s object check --limit-listings %d %s %s %s"
            % (
                self.account,
                self.limit_listings,
                self.container,
                self.obj_name,
                self.check_opts,
            ),
            expected_returncode=1,
        )
        self.assert_list_output(expected_items, output)

    def test_object_check_with_multiple_objects(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        second_obj = "item_check_second_obj_" + random_str(4)

        expected_items = list()
        expected_items.append("account account=%s OK" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s OK"
            % (self.account, self.container, cid)
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        for chunk in obj_chunks:
            expected_items.append("chunk chunk=%s OK" % (chunk["url"]))

        # Create a second object
        second_obj_meta, second_obj_chunks = self.create_object(
            self.account, self.container, second_obj
        )

        # Check only the first object
        output = self.openio_admin(
            "--oio-account %s object check --limit-listings %d %s %s %s"
            % (
                self.account,
                self.limit_listings,
                self.container,
                self.obj_name,
                self.check_opts,
            )
        )
        self.assert_list_output(expected_items, output)

        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                second_obj,
                second_obj_meta["id"],
                second_obj_meta["version"],
            )
        )
        for chunk in second_obj_chunks:
            expected_items.append("chunk chunk=%s OK" % (chunk["url"]))

        # Check two objects
        output = self.openio_admin(
            "--oio-account %s object check --limit-listings %d %s %s %s %s"
            % (
                self.account,
                self.limit_listings,
                self.container,
                self.obj_name,
                second_obj,
                self.check_opts,
            )
        )
        self.assert_list_output(expected_items, output)

    def test_chunk_check(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        chunk = random.choice(obj_chunks)

        expected_items = list()
        expected_items.append("account account=%s OK" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s OK"
            % (self.account, self.container, cid)
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        expected_items.append("chunk chunk=%s OK" % (chunk["url"]))

        # Check all items
        output = self.openio_admin(
            "chunk check %s %s" % (chunk["url"], self.check_opts)
        )
        self.assert_list_output(expected_items, output)

    def test_chunk_check_with_checksum(self):
        self.maxDiff = 1024
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        chunk = random.choice(obj_chunks)

        expected_items = list()
        expected_items.append("account account=%s OK" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s OK"
            % (self.account, self.container, cid)
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        expected_items.append("chunk chunk=%s OK" % (chunk["url"]))

        self._wait_for_chunk_indexation(chunk["url"])

        # Check with checksum
        output = self.openio_admin(
            "chunk check %s --checksum %s" % (chunk["url"], self.check_opts)
        )
        self.assert_list_output(expected_items, output)

        # Corrupt the chunk
        self.corrupt_chunk(chunk["url"])

        # Check without checksum
        output = self.openio_admin(
            "chunk check %s %s" % (chunk["url"], self.check_opts)
        )
        self.assert_list_output(expected_items, output)

        expected_items.remove("chunk chunk=%s OK" % (chunk["url"]))
        expected_items.append("chunk chunk=%s error" % (chunk["url"]))

        # Check with checksum
        output = self.openio_admin(
            "chunk check %s --checksum %s" % (chunk["url"], self.check_opts),
            expected_returncode=1,
        )
        self.assert_list_output(expected_items, output)

    def test_chunk_check_with_missing_chunk(self):
        self.maxDiff = 1024
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        missing_chunk = random.choice(obj_chunks)

        expected_items = []
        expected_items.append(f"account account={self.account} OK None")
        expected_items.append(
            f"container account={self.account}, container={self.container}, cid={cid}"
            " OK None"
        )
        expected_items.append(
            f"object account={self.account}, container={self.container}, cid={cid}, "
            f"obj={self.obj_name}, content_id={obj_meta['id']}, "
            f"version={obj_meta['version']} OK None"
        )

        self._wait_for_chunk_indexation(missing_chunk["url"])

        # Do a check before removing the chunk
        check_opts = self.get_format_opts()
        expected_items.append(f"chunk chunk={missing_chunk['url']} OK None")
        output = self.openio_admin(
            f"chunk check {missing_chunk['url']} {check_opts}",
            expected_returncode=0,
        )
        self.assert_list_output(expected_items, output)

        # Stop treating the events
        self._service("oio-event.target", "stop", wait=8)
        # Verify the event-agent is actually stopped
        self.assertRaises(
            CalledProcessError, self._service, "oio-event.target", "status", wait=0
        )

        try:
            # Delete the selected chunk
            self.api.blob_client.chunk_delete(missing_chunk["url"])

            # Verify we know about the chunk, even if we just deleted it:
            # it is still registered in rdir (we blocked the deletion event).
            expected_items[-1] = (
                f"chunk chunk={missing_chunk['url']} error "
                "Not found: n/a (HTTP 404) (STATUS Not Found)"
            )
            output = self.openio_admin(
                f"chunk check {missing_chunk['url']} {check_opts}",
                expected_returncode=1,
            )
            self.assert_list_output(expected_items, output)
        finally:
            self._service("oio-event.target", "start", wait=3)

    def test_chunk_check_with_missing_object(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        chunk = random.choice(obj_chunks)

        expected_items = list()
        expected_items.append("account account=%s OK" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s OK"
            % (self.account, self.container, cid)
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s error"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        expected_items.append("chunk chunk=%s error" % (chunk["url"]))

        # Prevent the deletion of chunks
        self._service("oio-event.target", "stop", wait=8)

        try:
            # Delete object
            self.api.object_delete(self.account, self.container, self.obj_name)

            # Check with missing object
            output = self.openio_admin(
                "chunk check %s %s" % (chunk["url"], self.check_opts),
                expected_returncode=1,
            )
            self.assert_list_output(expected_items, output)
        finally:
            self._service("oio-event.target", "start", wait=2)

    def test_chunk_check_with_missing_container(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        chunk = random.choice(obj_chunks)

        expected_items = list()
        expected_items.append("account account=%s OK" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s error"
            % (self.account, self.container, cid)
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        expected_items.append("chunk chunk=%s OK" % (chunk["url"]))

        # Remove container from account service
        self.api.account_flush(self.account)

        # Check with missing container
        output = self.openio_admin(
            "chunk check %s %s" % (chunk["url"], self.check_opts), expected_returncode=1
        )
        self.assert_list_output(expected_items, output)

    def test_chunk_check_with_missing_account(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        chunk = random.choice(obj_chunks)

        expected_items = list()
        expected_items.append("account account=%s error" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s error"
            % (self.account, self.container, cid)
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        expected_items.append("chunk chunk=%s OK" % (chunk["url"]))
        # Remove account
        self.api.account_flush(self.account)
        self.api.account_delete(self.account)

        # Check with missing account
        output = self.openio_admin(
            "chunk check %s %s" % (chunk["url"], self.check_opts), expected_returncode=1
        )
        self.assert_list_output(expected_items, output)

    def test_chunk_check_with_multiple_objects(self):
        obj_meta, obj_chunks = self.create_object(
            self.account, self.container, self.obj_name
        )
        cid = cid_from_name(self.account, self.container)

        chunk = random.choice(obj_chunks)
        second_obj = "item_check_second_obj_" + random_str(4)

        expected_items = list()
        expected_items.append("account account=%s OK" % self.account)
        expected_items.append(
            "container account=%s, container=%s, cid=%s OK"
            % (self.account, self.container, cid)
        )
        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                self.obj_name,
                obj_meta["id"],
                obj_meta["version"],
            )
        )
        expected_items.append("chunk chunk=%s OK" % (chunk["url"]))

        # Create a second object
        second_obj_meta, second_obj_chunks = self.create_object(
            self.account, self.container, second_obj
        )
        second_chunk = random.choice(second_obj_chunks)

        # Check only the first object
        output = self.openio_admin(
            "chunk check %s %s" % (chunk["url"], self.check_opts)
        )
        self.assert_list_output(expected_items, output)

        expected_items.append(
            "object account=%s, container=%s, cid=%s, obj=%s, content_id=%s, "
            "version=%s OK"
            % (
                self.account,
                self.container,
                cid,
                second_obj,
                second_obj_meta["id"],
                second_obj_meta["version"],
            )
        )
        expected_items.append("chunk chunk=%s OK" % (second_chunk["url"]))

        # Check two objects
        output = self.openio_admin(
            "chunk check %s %s %s"
            % (chunk["url"], second_chunk["url"], self.check_opts)
        )
        self.assert_list_output(expected_items, output)


class ItemCheckTestLimitListing(ItemCheckTest):
    def setUp(self):
        super(ItemCheckTestLimitListing, self).setUp()
        self.limit_listings = 2


class PeersCheckTest(CliTestCase):
    def setUp(self):
        self.container = f"peers_check_{random_str(4)}"
        self.openio(f"container create {self.container}")
        return super(PeersCheckTest, self).setUp()

    def tearDown(self):
        self.openio(f"container delete {self.container}")
        return super(PeersCheckTest, self).tearDown()

    def test_meta2_peers_valid(self):
        output = self.openio_admin(
            f"peers check meta2 {self.container} {self.get_format_opts(format_='json')}"
        )
        output = json.loads(output)

        parent_peers = sorted(output["peers"]["parent"])
        expected_output = {
            "agree_with_majority": {
                "parent": True,
                "meta2": {sid: True for sid in parent_peers},
                "majority": True,
            },
            "peers": {
                "parent": parent_peers,
                "meta2": {sid: parent_peers for sid in parent_peers},
                "majority": parent_peers,
            },
        }
        self.assertDictEqual(expected_output, output)

    def _recover_commandfailed(self, func, *args):
        try:
            func(*args)
        except CommandFailed as cf:
            self.stdout = cf.stdout
            self.stderr = cf.stderr
            self.rc = cf.returncode
            raise

    def _test_meta2_peers_with_bad_parent_peers(self, copy_base=True):
        self.maxDiff = None

        # Fetch current meta2 links in meta1 database
        data_dir = self.storage.directory.list(self.account_from_env(), self.container)
        old_parent_peers = []
        for d in data_dir["srv"]:
            if d["type"] == "meta2":
                old_parent_peers.append(d["host"])
        old_parent_peers.sort()

        # Select a meta2 service not yet used
        remaining_services = [
            service.get("service_id", service["addr"])
            for service in self.conf["services"]["meta2"]
            if service.get("service_id", service["addr"]) not in old_parent_peers
        ]
        if not remaining_services:
            self.skipTest("Not enough meta2 service")
        bad_service_id = random.choice(remaining_services)
        tmp_old_parent_peers = list(old_parent_peers)
        new_parent_peers = []
        for _ in range(len(old_parent_peers) - 1):
            sid = random.choice(tmp_old_parent_peers)
            tmp_old_parent_peers.remove(sid)
            new_parent_peers.append(sid)
        new_parent_peers.append(bad_service_id)
        new_parent_peers.sort()

        try:
            if copy_base:
                # Copy meta2 database
                self.admin.copy_base_from(
                    service_type="meta2",
                    account=self.account_from_env(),
                    reference=self.container,
                    svc_from=old_parent_peers[0],
                    svc_to=bad_service_id,
                )

            # Update meta2 links in meta1 database
            self.storage.directory.force(
                self.account_from_env(),
                self.container,
                service_type="meta2",
                replace=True,
                services={
                    "host": ",".join(new_parent_peers),
                    "type": "meta2",
                    "args": "",
                    "seq": 1,
                },
            )

            self.assertRaises(
                CommandFailed,
                self._recover_commandfailed,
                self.openio_admin,
                f"peers check meta2 {self.container} "
                f"{self.get_format_opts(format_='json')}",
            )
            self.assertEqual(1, self.rc)
            output = json.loads(self.stdout)

            expected_output = {
                "agree_with_majority": {
                    "parent": False,
                    "meta2": {sid: True for sid in old_parent_peers},
                    "majority": True,
                },
                "peers": {
                    "parent": new_parent_peers,
                    "meta2": {sid: old_parent_peers for sid in old_parent_peers},
                    "majority": old_parent_peers,
                },
            }
            if copy_base:
                expected_output["agree_with_majority"]["meta2"][bad_service_id] = True
                expected_output["peers"]["meta2"][bad_service_id] = old_parent_peers
            else:
                expected_output["agree_with_majority"]["meta2"][bad_service_id] = False
                expected_output["peers"]["meta2"][bad_service_id] = None
            self.assertDictEqual(expected_output, output)
        finally:
            try:
                self.storage.directory.force(
                    self.account_from_env(),
                    self.container,
                    service_type="meta2",
                    replace=True,
                    services={
                        "host": ",".join(old_parent_peers),
                        "type": "meta2",
                        "args": "",
                        "seq": 1,
                    },
                )
            except Exception as exc:
                self.logger.error("Failed to change meta2 links: %s", exc)

            if copy_base:
                try:
                    self.admin.remove_base(
                        service_type="meta2",
                        account=self.account_from_env(),
                        reference=self.container,
                        service_id=bad_service_id,
                    )
                except Exception as exc:
                    self.logger.error("Failed to delete meta2 database: %s", exc)

    def test_meta2_peers_with_bad_parent_peers_and_copy(self):
        self._test_meta2_peers_with_bad_parent_peers()

    def test_meta2_peers_with_bad_parent_peers_and_no_copy(self):
        self._test_meta2_peers_with_bad_parent_peers(copy_base=False)
