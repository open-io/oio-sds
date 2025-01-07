# -*- coding: utf-8 -*-
# Copyright (C) 2016-2020 OpenIO SAS, as part of OpenIO SDS
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

import re
import tempfile
import uuid

from oio.common.utils import cid_from_name, request_id
from oio.event.evob import EventTypes
from tests.functional.cli import CliTestCase, CommandFailed
from tests.utils import random_str


class ContainerTest(CliTestCase):
    """Functional tests for containers."""

    NAME = uuid.uuid4().hex

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        opts = cls.get_format_opts(fields=("Name",))
        output = cls.openio("container create " + cls.NAME + opts)
        cls.CID = cid_from_name(cls.account_from_env(), cls.NAME)
        cls.assertOutput(cls.NAME + "\n", output)

    @classmethod
    def tearDownClass(cls):
        output = cls.openio("container delete " + cls.NAME)
        cls.assertOutput("", output)
        super().tearDownClass()

    def setUp(self):
        super(ContainerTest, self).setUp()

    def _test_container_show(self, with_cid=False, extra_counters=False):
        opts = self.get_format_opts("json")
        cid_opt = ""
        extra_opt = ""
        name = self.NAME
        if with_cid:
            cid_opt = "--cid "
            name = self.CID
        if extra_counters:
            extra_opt = "--extra-counters "
        output = self.openio("container show " + cid_opt + name + opts + extra_opt)
        container = self.json_loads(output)
        self.assertEqual(self.NAME, container["container"])
        if with_cid:
            self.assertIn(self.CID, container["base_name"])
        if extra_counters:
            # Check the key exist (only key in extra_counter yet)
            self.assertIn("objects_drained", container)
        else:
            self.assertNotIn("objects_drained", container)

    def test_bucket_list(self):
        cname = "mybucket-" + random_str(4).lower()
        # Create bucket
        opts = self.get_format_opts(fields=("Created",))
        output = self.openio("bucket create " + cname + opts)
        self.assertEqual("True\n", output)
        # List buckets
        opts = self.get_format_opts(fields=("Name",))
        output = self.openio("bucket list " + opts)
        self.assertIn(cname, output)

    def test_bucket_list_with_versioning(self):
        cname = "mybucket-" + random_str(4).lower()
        # Create bucket
        opts = self.get_format_opts(fields=("Created",))
        output = self.openio("bucket create " + cname + opts)
        self.assertEqual("True\n", output)
        # Create the root container
        opts = self.get_format_opts(fields=("Name",))
        output = self.openio(
            "container create --bucket-name %s %s %s" % (cname, cname, opts)
        )
        self.assertOutput(cname + "\n", output)
        # List buckets
        opts = self.get_format_opts(fields=("Name", "Versioning"))
        opts += " --prefix %s --versioning" % cname
        output = self.openio("bucket list " + opts)
        self.assertIn("Suspended", output)
        # Enable versioning on the root container
        self.openio("container set --versioning -1 %s" % cname)
        # List buckets
        output = self.openio("bucket list " + opts)
        self.assertIn("Enabled", output)

    def test_bucket_show(self):
        cname = "mybucket-" + random_str(4).lower()
        # Create bucket
        opts = self.get_format_opts(fields=("Created",))
        output = self.openio("bucket create " + cname + opts)
        self.assertEqual("True\n", output)
        # Show bucket
        opts = self.get_format_opts(fields=("account", "bytes", "objects"))
        output = self.openio("bucket show " + cname + opts)
        self.assertEqual(self.account_from_env() + "\n0\n0\n", output)
        # Delete bucket
        opts = self.get_format_opts(fields=("Deleted",))
        output = self.openio("bucket delete " + cname + opts)
        self.assertEqual("True\n", output)
        # Bucket not found (HTTP 404)
        self.assertRaises(CommandFailed, self.openio, "bucket show " + cname)

    def test_bucket_show_with_feature(self):
        cname = "mybucket-" + random_str(4).lower()
        # Create bucket
        opts = self.get_format_opts(fields=("Created",))
        output = self.openio("bucket create " + cname + opts)
        self.assertEqual("True\n", output)

        # Activate feature
        output = self.openio(
            " container set --property X-Container-Sysmeta-S3Api-Website=foo " + cname
        )
        event = self.wait_for_kafka_event(
            fields={"user": cname}, types=(EventTypes.CONTAINER_UPDATE,)
        )
        self.assertIsNotNone(event)

        opts = self.get_format_opts(
            fields=("account", "bytes", "objects", "features-details")
        )
        mtime = event.when
        output = self.openio("bucket show " + cname + opts)
        self.assertEqual(
            self.account_from_env()
            + "\n0\n{'website': [{'mtime': '"
            + str(mtime)
            + "', 'action': 'SET'}]}\n0\n",
            output,
        )

        # Activate untracked feature
        output = self.openio(
            " container set --property X-Container-Sysmeta-S3Api-Not-tracked=foo "
            + cname
        )
        event = self.wait_for_kafka_event(
            fields={"user": cname}, types=(EventTypes.CONTAINER_UPDATE,)
        )
        self.assertIsNotNone(event)

        opts = self.get_format_opts(
            fields=("account", "bytes", "objects", "features-details")
        )
        output = self.openio("bucket show " + cname + opts)
        self.assertEqual(
            self.account_from_env()
            + "\n0\n{'website': [{'mtime': '"
            + str(mtime)
            + "', 'action': 'SET'}]}\n0\n",
            output,
        )

        # Delete bucket
        opts = self.get_format_opts(fields=("Deleted",))
        output = self.openio("bucket delete " + cname + opts)
        self.assertEqual("True\n", output)
        # Bucket not found (HTTP 404)
        self.assertRaises(CommandFailed, self.openio, "bucket show " + cname)

    def test_bucket_show_with_account_refresh(self):
        account = "myaccount-" + random_str(4).lower()
        cname = "mybucket-" + random_str(4).lower()
        # Create bucket (and root container)
        opts = self.get_format_opts(fields=("Created",))
        output = self.openio(
            "--oio-account " + account + " bucket create " + cname + opts
        )
        self.assertEqual("True\n", output)
        # Show bucket
        opts = self.get_format_opts(fields=("account", "bytes", "objects"))
        output = self.openio(
            "--oio-account " + account + " bucket show " + cname + opts
        )
        self.assertEqual(account + "\n0\n0\n", output)
        # Put object
        with tempfile.NamedTemporaryFile() as file_:
            file_.write(b"test")
            file_.flush()
            output = self.openio(
                "--oio-account %s object create %s %s --name test"
                % (account, cname, file_.name)
            )
        event = self.wait_for_kafka_event(
            fields={"user": cname}, types=(EventTypes.CONTAINER_STATE,)
        )
        self.assertIsNotNone(event)
        # Show bucket
        opts = self.get_format_opts(
            fields=("account", "bytes", "containers", "objects")
        )
        output = self.openio(
            "--oio-account " + account + " bucket show " + cname + opts
        )
        self.assertEqual(account + "\n4\n1\n1\n", output)
        # Refresh account
        output = self.openio("account refresh " + account)
        self.wait_for_kafka_event(
            fields={"user": cname}, types=(EventTypes.CONTAINER_STATE,)
        )
        # show bucket
        output = self.openio(
            "--oio-account " + account + " bucket show " + cname + opts
        )
        self.assertEqual(account + "\n4\n1\n1\n", output)

    def test_bucket_refresh(self):
        cname = "mybucket-" + random_str(4).lower()
        # Create bucket (and root container)
        opts = self.get_format_opts(fields=("Created",))
        output = self.openio("bucket create " + cname + opts)
        self.assertEqual("True\n", output)
        # Put object
        with tempfile.NamedTemporaryFile() as file_:
            file_.write(b"test")
            file_.flush()
            output = self.openio(
                "object create %s %s --name test" % (cname, file_.name)
            )
        self.wait_for_kafka_event(
            fields={"user": cname}, types=(EventTypes.CONTAINER_STATE,)
        )
        # Show bucket
        opts = self.get_format_opts(
            fields=("account", "bytes", "containers", "objects")
        )
        output = self.openio("bucket show " + cname + opts)
        self.assertEqual(self.account_from_env() + "\n4\n1\n1\n", output)
        # Refresh bucket
        output = self.openio("bucket refresh " + cname)
        # Show bucket
        output = self.openio("bucket show " + cname + opts)
        self.assertEqual(self.account_from_env() + "\n4\n1\n1\n", output)

    def test_max_buckets(self):
        account = "myacocunt-" + random_str(4).lower()
        # Create bucket
        opts = self.get_format_opts(fields=("Created",))
        bname1 = "mybucket-" + random_str(4).lower()
        output = self.openio("--account " + account + " bucket create " + bname1 + opts)
        self.assertEqual("True\n", output)
        # Set max-buckets to 2
        self.openio("account set " + account + " --max-buckets 2")
        # Create second bucket
        bname2 = "mybucket-" + random_str(4).lower()
        output = self.openio("--account " + account + " bucket create " + bname2 + opts)
        self.assertEqual("True\n", output)
        # Try to create third bucket
        bname3 = "mybucket-" + random_str(4).lower()
        output = self.openio("--account " + account + " bucket create " + bname3 + opts)
        self.assertEqual("False\n", output)
        # Reset max-buckets
        self.openio("account unset " + account + " --max-buckets")
        # Try to create third bucket
        output = self.openio("--account " + account + " bucket create " + bname3 + opts)
        self.assertEqual("True\n", output)

    def test_container_show(self):
        self._test_container_show()

    def test_container_show_with_cid(self):
        self._test_container_show(with_cid=True)

    def test_container_show_extra_counter(self):
        self._test_container_show(extra_counters=True)

    def test_container_show_extra_counter_with_cid(self):
        self._test_container_show(with_cid=True, extra_counters=True)

    def _test_container_show_table(self, with_cid=False):
        opts = self.get_format_opts("table")
        cid_opt = ""
        name = self.NAME
        if with_cid:
            cid_opt = "--cid "
            name = self.CID
        output = self.openio("container show " + cid_opt + name + opts)
        regex = r"|\s*%s\s*|\s*%s\s*|"
        self.assertIsNotNone(re.match(regex % ("bytes_usage", "0B"), output))
        self.assertIsNotNone(re.match(regex % ("objects", "0"), output))

    def test_container_show_table(self):
        self._test_container_show_table()

    def test_container_show_table_with_cid(self):
        self._test_container_show_table(with_cid=True)

    def test_container_list(self):
        opts = self.get_format_opts(fields=("Name",))
        output = self.openio("container list " + opts)
        self.assertIn(self.NAME, output)

    def test_unicode_container_list(self):
        opts = self.get_format_opts(fields=("Name",)) + " -a " + self.account
        cname = "Intérêts-" + uuid.uuid4().hex
        reqid = request_id()
        self.storage.container_create(self.account, cname, reqid=reqid)
        self.wait_for_kafka_event(
            reqid=reqid,
            fields={"user": cname},
            types=(EventTypes.CONTAINER_NEW,),
        )
        output = self.openio("container list " + opts)
        self.assertIn(cname, output)

    def _test_container_refresh(self, with_cid=False):
        cid_opt = ""
        name = self.NAME
        if with_cid:
            cid_opt = "--cid "
            name = self.CID
        self.openio("container refresh " + cid_opt + name)
        opts = self.get_format_opts("json")
        output = self.openio("container list " + opts)
        containers = self.json_loads(output)
        for container in containers:
            if container["Name"] == self.NAME:
                self.assertEqual(container["Count"], 0)
                self.assertEqual(container["Bytes"], 0)
                return
        self.fail("No container %s" % self.NAME)

    def test_container_refresh(self):
        self._test_container_refresh()

    def test_container_refresh_with_cid(self):
        self._test_container_refresh(with_cid=True)

    def _test_container_snapshot(self, with_cid=False):
        self.wait_for_score(("meta2", "meta1"))
        # Please don't ask...
        try:
            self.openio("election sync meta2 " + self.NAME)
        except Exception:
            pass
        # Snapshot should reply the name of the snapshot on success
        opts = self.get_format_opts("json")
        cid_opt = ""
        cname = self.NAME
        if with_cid:
            cid_opt = "--cid "
            cname = self.CID
        output = self.openio("container snapshot " + cid_opt + cname + opts)
        output = self.json_loads(output)[0]
        self.assertEqual(output["Status"], "OK")
        # Snapshot should reply Missing container on non existent container
        self.assertRaises(
            CommandFailed, self.openio, ("container snapshot Should_not_exist" + opts)
        )
        # Use specified name
        dst_account = "acct-" + random_str(6)
        dst_container = cname + ".snapshot-" + random_str(6)
        opts += " --dst-account " + dst_account
        opts += " --dst-container " + dst_container
        output = self.openio("container snapshot " + cid_opt + cname + opts)
        output = self.json_loads(output)[0]
        self.assertEqual(output["Account"], dst_account)
        self.assertEqual(output["Container"], dst_container)
        self.assertEqual(output["Status"], "OK")
        # Snapshot should reply Container already exists when using already
        #   specified name
        self.assertRaises(
            CommandFailed, self.openio, ("container snapshot " + cid_opt + cname + opts)
        )

    def test_container_snapshot(self):
        self._test_container_snapshot()

    def test_container_snapshot_with_cid(self):
        self._test_container_snapshot(with_cid=True)

    def _test_container_purge(self, with_cid=False):
        cid_opt = ""
        name = self.NAME
        if with_cid:
            cid_opt = "--cid "
            name = self.CID
        output = self.openio("container purge " + cid_opt + name)
        self.assertEqual("", output)

    def test_container_purge(self):
        self._test_container_purge()

    def test_container_purge_with_cid(self):
        self._test_container_purge(with_cid=True)

    def _test_container_flush(self, with_cid=False):
        cid_opt = ""
        name = self.NAME
        if with_cid:
            cid_opt = "--cid "
            name = self.CID
        with tempfile.NamedTemporaryFile(delete=False) as ntf:
            ntf.write(b"test_exists")
            ntf.flush()
            obj = ntf.name
            for _ in range(10):
                obj_name = random_str(6)
                self.openio(
                    "object create " + self.NAME + " " + obj + " --name " + obj_name
                )
        output = self.openio("container flush " + cid_opt + name)
        self.assertEqual("", output)
        output = self.openio("object list " + self.NAME)
        self.assertEqual("\n", output)

    def test_container_flush(self):
        self._test_container_flush()

    def test_container_flush_with_cid(self):
        self._test_container_flush(with_cid=True)

    def _test_container_flush_quickly(self, with_cid=False):
        cid_opt = ""
        name = self.NAME
        if with_cid:
            cid_opt = "--cid "
            name = self.CID
        with tempfile.NamedTemporaryFile(delete=False) as ntf:
            ntf.write(b"test_exists")
            ntf.flush()
            obj = ntf.name
            for _ in range(10):
                obj_name = random_str(6)
                self.openio(
                    "object create "
                    + cid_opt
                    + name
                    + " "
                    + obj
                    + " --name "
                    + obj_name
                )
        output = self.openio("container flush --quickly " + cid_opt + name)
        self.assertEqual("", output)
        output = self.openio("object list " + cid_opt + name)
        self.assertEqual("\n", output)

    def test_container_flush_quickly(self):
        self._test_container_flush_quickly()

    def test_container_flush_quickly_with_cid(self):
        self._test_container_flush_quickly(with_cid=True)

    def _test_container_drain(self, with_cid=False):
        cid_opt = ""
        name = self.NAME
        if with_cid:
            cid_opt = "--cid "
            name = self.CID
        with tempfile.NamedTemporaryFile() as ntf:
            ntf.write(b"test_exists")
            ntf.flush()
            obj = ntf.name
            for _ in range(5):
                obj_name = random_str(6)
                self.openio(
                    "object create "
                    + cid_opt
                    + name
                    + " "
                    + obj
                    + " --name "
                    + obj_name
                )
        output = self.openio("container drain " + cid_opt + name)
        self.assertEqual("", output)
        # Clean container as teardown expect an empty one
        output = self.openio("container flush " + cid_opt + name)
        self.assertEqual("", output)

    def test_container_drain(self):
        self._test_container_drain()

    def test_container_drain_with_cid(self):
        self._test_container_drain(with_cid=True)

    def _test_container_set_bucket_name(self, with_cid=False):
        cid_opt = " "
        name = self.NAME
        bname = "mybucket"
        if with_cid:
            cid_opt = " --cid "
            name = self.CID
        opts = " -f json"
        output = self.openio("container show " + cid_opt + name + opts)
        output = self.json_loads(output)
        self.assertNotIn(output, "bucket")
        output = self.openio("container set --bucket-name " + bname + cid_opt + name)
        self.assertEqual("", output)
        output = self.openio("container show " + cid_opt + name + opts)
        output = self.json_loads(output)
        self.assertEqual(output["bucket"], bname)
        output = self.openio("container unset --bucket-name " + cid_opt + name)
        self.assertEqual("", output)
        output = self.openio("container show " + cid_opt + name + opts)
        output = self.json_loads(output)
        self.assertNotIn(output, "bucket")

    def test_container_set_bucket_name(self):
        self._test_container_set_bucket_name()

    def test_container_set_bucket_name_with_cid(self):
        self._test_container_set_bucket_name(with_cid=True)

    def _test_container_set_status(self, with_cid=False):
        cid_opt = ""
        name = self.NAME
        if with_cid:
            cid_opt = "--cid "
            name = self.CID
        opts = " -f json"
        output = self.openio("container show " + cid_opt + name + opts)
        output = self.json_loads(output)
        self.assertEqual(output["status"], "Enabled")
        output = self.openio("container set --status frozen " + cid_opt + name)
        self.assertEqual("", output)
        output = self.openio("container show " + cid_opt + name + opts)
        output = self.json_loads(output)
        self.assertEqual(output["status"], "Frozen")
        output = self.openio("container set --status enabled " + cid_opt + name)
        self.assertEqual("", output)
        output = self.openio("container show " + cid_opt + name + opts)
        output = self.json_loads(output)
        self.assertEqual(output["status"], "Enabled")

    def test_container_set_status(self):
        self._test_container_set_status()

    def test_container_set_status_with_cid(self):
        self._test_container_set_status(with_cid=True)

    def _test_container_set_properties(self, with_cid=False):
        cid_opt = ""
        name = self.NAME
        if with_cid:
            cid_opt = "--cid "
            name = self.CID
        opts = " -f json"

        output = self.openio(
            "container set " + cid_opt + name + " --property test1=1 --property test2=2"
        )
        self.assertEqual(output, "")
        output = self.openio("container show " + cid_opt + name + opts)
        output = self.json_loads(output)
        self.assertEqual(self.NAME, output["container"])
        self.assertEqual("1", output["meta.test1"])
        self.assertEqual("2", output["meta.test2"])

        output = self.openio("container set " + cid_opt + name + " --property test3=3")
        self.assertEqual(output, "")
        output = self.openio("container show " + cid_opt + name + opts)
        output = self.json_loads(output)
        self.assertEqual(self.NAME, output["container"])
        self.assertEqual("1", output["meta.test1"])
        self.assertEqual("2", output["meta.test2"])
        self.assertEqual("3", output["meta.test3"])

        output = self.openio(
            "container set " + cid_opt + name + " --clear --property test4=4"
        )
        self.assertEqual(output, "")
        output = self.openio("container show " + cid_opt + name + opts)
        output = self.json_loads(output)
        self.assertEqual(self.NAME, output["container"])
        self.assertNotIn("meta.test1", output)
        self.assertNotIn("meta.test2", output)
        self.assertNotIn("meta.test3", output)
        self.assertEqual("4", output["meta.test4"])

    def test_container_set_properties(self):
        self._test_container_set_properties()

    def test_container_set_properties_with_cid(self):
        self._test_container_set_properties(with_cid=True)


class TestContainerSharding(CliTestCase):
    NAME = uuid.uuid4().hex

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        opts = cls.get_format_opts(fields=("Name",))
        output = cls.openio("container create " + cls.NAME + opts)
        cls.CID = cid_from_name(cls.account_from_env(), cls.NAME)
        cls.assertOutput(cls.NAME + "\n", output)

    @classmethod
    def tearDownClass(cls):
        output = cls.openio("container delete " + cls.NAME)
        cls.assertOutput("", output)
        super().tearDownClass()

    def test_abort_no_sharding_yet(self):
        opts = self.get_format_opts(format_="json")
        output = self.openio(
            "container-sharding abort " + self.NAME + opts, expected_returncode=1
        )
        result = self.json_loads(output)
        self.assertEqual(self.NAME, result.get("container"))
        self.assertFalse(result.get("aborted"))
        self.assertFalse(result.get("drained"))
