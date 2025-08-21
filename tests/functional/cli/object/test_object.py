# Copyright (C) 2016-2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2020-2025 OVH SAS
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

import os
import tempfile
import uuid

from oio.common.constants import HTTP_CONTENT_TYPE_DELETED, M2_PROP_VERSIONING_POLICY
from oio.common.easy_value import true_value
from oio.common.utils import get_hasher
from tests.functional.cli import CliTestCase, CommandFailed
from tests.utils import random_str

HEADERS = ["Name", "Created"]
OBJ_HEADERS = ["Name", "Size", "Hash"]
CONTAINER_LIST_HEADERS = ["Name", "Bytes", "Count"]
CONTAINER_FIELDS = [
    "account",
    "base_name",
    "bytes_usage",
    "container",
    "ctime",
    "location",
    "max_versions",
    "objects",
    "sharding.state",
    "sharding.timestamp",
    "shards",
    "stats.db_size",
    "stats.freelist_count",
    "stats.journal_mode",
    "stats.page_count",
    "stats.page_size",
    "stats.space_wasted",
    "status",
    "storage_policy",
]
OBJ_FIELDS = [
    "account",
    "chunk_method",
    "container",
    "ctime",
    "hash",
    "id",
    "mime-type",
    "mtime",
    "object",
    "policy",
    "shard_hexid",
    "size",
    "target_policy",
    "version",
]


class ObjectTest(CliTestCase):
    """Functional tests for objects."""

    def setUp(self):
        super(ObjectTest, self).setUp()
        self.wait_for_score(("rawx", "meta2"), score_threshold=1, timeout=5.0)

    @classmethod
    def _get_cid_from_name(self, name):
        opts = self.get_format_opts("json")
        output = self.openio("container show " + name + opts)
        data = self.json_loads(output)
        return data["base_name"]

    def __test_obj(self, name, with_cid=False, oca="md5"):
        with tempfile.NamedTemporaryFile() as f:
            test_content = b"test content"
            f.write(test_content)
            f.flush()
            self._test_obj(f.name, test_content, name, with_cid=with_cid, oca=oca)
        self._test_many_obj(name, with_cid=with_cid)

    def test_obj(self):
        self.__test_obj(uuid.uuid4().hex)

    def test_obj_stdin(self):
        container_name = uuid.uuid4().hex
        object_name = uuid.uuid4().hex
        self._test_obj(container_name, b"test content", object_name, use_stdin=True)

    def test_obj_stdin_blake3(self):
        container_name = uuid.uuid4().hex
        object_name = uuid.uuid4().hex
        self._test_obj(
            container_name, b"test content", object_name, use_stdin=True, oca="blake3"
        )

    def test_obj_stdin_with_cid(self):
        container_name = uuid.uuid4().hex
        object_name = uuid.uuid4().hex
        self._test_obj(
            container_name, b"test content", object_name, with_cid=True, use_stdin=True
        )

    def test_obj_with_cid(self):
        self.__test_obj(uuid.uuid4().hex, with_cid=True)

    def test_obj_oca_blake3(self):
        self.__test_obj(uuid.uuid4().hex, oca="blake3")

    def test_obj_oca_blake3_with_cid(self):
        self.__test_obj(uuid.uuid4().hex, with_cid=True, oca="blake3")

    def test_obj_without_autocreate(self):
        with tempfile.NamedTemporaryFile() as f:
            test_content = b"test content"
            f.write(test_content)
            f.flush()

            self.assertRaises(
                CommandFailed,
                self.openio,
                "object create --no-autocreate " + uuid.uuid4().hex + " " + f.name,
            )

    def _test_many_obj(self, cname, with_cid=False):
        cid_opt = ""
        if with_cid:
            cname = self._get_cid_from_name(cname)
            cid_opt = "--cid "
        opts = self.get_format_opts("json")
        obj_name_exists = ""
        obj_name_also_exists = ""

        # delete 2 existent
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test_exists")
            f.flush()
            obj_file_exists = f.name
            obj_name_exists = os.path.basename(f.name)
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test_also_exists")
            f.flush()
            obj_file_also_exists = f.name
            obj_name_also_exists = os.path.basename(f.name)
        self.openio(
            "object create "
            + cid_opt
            + " "
            + cname
            + " "
            + obj_file_exists
            + " "
            + obj_file_also_exists
            + " "
            + opts
        )
        output = self.openio(
            "object delete "
            + cid_opt
            + cname
            + " "
            + obj_name_exists
            + " "
            + obj_name_also_exists
            + opts
        )
        data_json = self.json_loads(output)
        self.assertEqual(data_json[0]["Deleted"], True)
        self.assertEqual(data_json[1]["Deleted"], True)
        # delete 2 nonexistent
        output = self.openio(
            "object delete "
            + cid_opt
            + cname
            + " "
            + "should_not_exists"
            + " "
            + "should_also_not_exists"
            + opts
        )
        data_json = self.json_loads(output)
        self.assertEqual(data_json[0]["Deleted"], False)
        self.assertEqual(data_json[1]["Deleted"], False)
        # delete 1 existent 1 nonexistent
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test_exists")
            f.flush()
            obj_file_exists = f.name
            obj_name_exists = os.path.basename(f.name)
        self.openio(
            "object create " + cid_opt + " " + cname + " " + obj_file_exists + opts
        )
        output = self.openio(
            "object delete "
            + cid_opt
            + cname
            + " "
            + obj_name_exists
            + " should_not_exists"
            + opts
        )
        data_json = self.json_loads(output)
        self.assertEqual(data_json[0]["Deleted"], True)
        self.assertEqual(data_json[1]["Deleted"], False)

    def test_auto_container(self):
        with open("/etc/fstab", "rb") as source:
            test_content = source.read()
            self._test_auto_container(test_content)

    def _test_auto_container(self, test_content):
        self._test_obj("/etc/fstab", test_content, "06EE0", auto="--auto")

    def _test_obj(
        self,
        obj_file,
        test_content,
        cname,
        auto="",
        with_cid=False,
        with_tls=False,
        oca="md5",
        use_stdin=False,
    ):
        cid_opt = ""
        hasher = get_hasher(oca)
        hasher.update(test_content)
        checksum = hasher.hexdigest().upper()
        opts = self.get_format_opts("json")
        # Wait for meta2 service to be available again
        # After the set timeout the test must fail
        self.wait_for_score(("meta2",), timeout=5.0)
        self.clean_later(cname, self.account_from_env())
        output = self.openio("container create " + cname + opts)
        data = self.json_loads(output)
        self.assertEqual(len(data), 1)
        self.assert_list_fields(data, HEADERS)
        self.assertEqual(data[0]["Name"], cname)
        cname_or_cid = cname
        if with_cid:
            cname_or_cid = self._get_cid_from_name(cname)
            cid_opt = "--cid "
        # TODO ensure a clean environment before the test, and proper cleanup
        # after, so that we can check the container is properly created
        if not auto:
            self.assertTrue(data[0]["Created"])

        opts = self.get_format_opts("json")
        output = self.openio("container list" + opts)
        listing = self.json_loads(output)
        self.assert_list_fields(listing, CONTAINER_LIST_HEADERS)
        self.assertGreaterEqual(len(listing), 1)

        opts = self.get_format_opts("json")
        output = self.openio("container show " + cname + opts)
        data = self.json_loads(output)
        self.assert_show_fields(data, CONTAINER_FIELDS)

        fake_cname = cname
        if auto:
            fake_cname = "_"
        obj_name = os.path.basename(obj_file)
        opts = self.get_format_opts("json")
        if with_tls:
            opts += " --tls"
        # If object checksum algo is not the default
        if oca != "md5":
            opts += " --checksum-algo " + oca
        expected_created_objects = 2
        if not use_stdin:
            command = f"object create {auto} {fake_cname} {obj_file} {obj_file} {opts}"
            output = self.openio(command)
        else:
            command = f"object create {auto} {fake_cname} - {opts}"
            # Check stdin without specifying object name is forbidden
            self.assertRaises(CommandFailed, self.openio, command, stdin=test_content)
            command = command + " --name " + obj_name
            output = self.openio(command, stdin=test_content)
            expected_created_objects = 1

        data = self.json_loads(output)
        self.assert_list_fields(data, OBJ_HEADERS)
        self.assertEqual(len(data), expected_created_objects)
        item = data[0]
        self.assertEqual(item["Name"], obj_name)
        self.assertEqual(item["Size"], len(test_content))
        self.assertEqual(item["Hash"], checksum)

        opts = self.get_format_opts("json")
        output = self.openio("object list " + cid_opt + cname_or_cid + opts)
        listing = self.json_loads(output)
        self.assert_list_fields(listing, OBJ_HEADERS)
        self.assertEqual(len(listing), 1)  # 1 object stored
        item = data[0]
        self.assertEqual(item["Name"], obj_name)
        self.assertEqual(item["Size"], len(test_content))
        self.assertEqual(item["Hash"], checksum)

        output = self.openio("object save " + cid_opt + cname_or_cid + " " + obj_name)
        self.addCleanup(os.remove, obj_name)
        self.assertOutput("", output)

        tmp_file = f"tmp_obj_{random_str(3)}"
        opts = " --tls" if with_tls else ""
        output = self.openio(
            "object save "
            + cid_opt
            + cname_or_cid
            + " "
            + obj_name
            + " --file "
            + tmp_file
            + opts
        )
        self.addCleanup(os.remove, tmp_file)
        self.assertOutput("", output)

        opts = self.get_format_opts("json")
        output = self.openio(
            "object show " + cid_opt + cname_or_cid + " " + obj_name + opts
        )
        data = self.json_loads(output)
        self.assert_show_fields(data, OBJ_FIELDS)
        self.assertEqual(data["object"], obj_name)
        self.assertEqual(data["size"], str(len(test_content)))
        self.assertEqual(data["hash"], checksum)

        output = self.openio(
            "object delete " + cid_opt + cname_or_cid + " " + obj_name + opts
        )
        self.assertEqual(True, self.json_loads(output)[0]["Deleted"])

    def _test_drain(self, with_cid=False):
        cname = "test-drain-" + random_str(6)
        self.clean_later(cname, self.account_from_env())
        cid_opt = ""
        if with_cid:
            self.openio(" ".join(("container create", cname)))
            cname = self._get_cid_from_name(cname)
            cid_opt = "--cid"

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test_exists")
            f.flush()
            obj = f.name
            obj_name = "test-drain-" + random_str(6)
            self.openio(
                " ".join(["object create ", cid_opt, cname, obj, "--name ", obj_name])
            )
            self.openio(" ".join(["object drain ", cid_opt, cname, " ", obj_name]))

        self.assertRaises(
            CommandFailed,
            self.openio,
            " ".join(["object drain", cid_opt, cname, "should not exist"]),
        )

    def test_drain(self):
        self._test_drain()

    def test_drain_with_cid(self):
        self._test_drain(with_cid=True)

    def _test_autocontainer_object_listing(self, args="", env=None):
        obj_count = 7
        prefix = random_str(8)
        expected = []
        # TODO(FVE): find a quicker way to upload several objects
        commands = []
        for i in range(obj_count):
            obj_name = f"{prefix}_{i}"
            commands.append(
                " ".join(
                    [
                        "object create --auto /etc/fstab",
                        "--name ",
                        obj_name,
                        args,
                    ]
                )
            )
            expected.append(obj_name)
        self.openio_batch(commands, env=env)

        # Default listing
        opts = self.get_format_opts("json") + " --attempts 3"
        output = self.openio(
            "object list --auto --prefix " + prefix + " " + opts + " " + args, env=env
        )
        listing = self.json_loads(output)
        self.assertEqual(obj_count, len(listing))
        for obj in listing:
            # 4 columns
            self.assertEqual(4, len(obj))

        # Listing with properties
        output = self.openio(
            "object list --auto --properties --prefix "
            + prefix
            + " "
            + opts
            + " "
            + args,
            env=env,
        )
        listing = self.json_loads(output)
        self.assertEqual(obj_count, len(listing))
        for obj in listing:
            # 10 columns
            self.assertEqual(10, len(obj))

        # Unpaged listing
        output = self.openio(
            "object list --auto --no-paging --prefix "
            + prefix
            + " "
            + opts
            + " "
            + args,
            env=env,
        )
        listing = self.json_loads(output)
        actual = sorted(x["Name"] for x in listing)
        self.assertEqual(expected, actual)
        for obj in listing:
            # 4 columns
            self.assertEqual(4, len(obj))

        # Cleanup
        opts = self.get_format_opts("json")
        output = self.openio(
            "container list " + opts,
            env=env,
        )
        listing = self.json_loads(output)
        to_clean = [(env.get("OIO_ACCOUNT"), x["Name"]) for x in listing]
        self._containers_to_clean.extend(to_clean)

    def test_autocontainer_object_listing(self):
        self.skipTest("Deprecated")
        env = dict(os.environ)
        env["OIO_ACCOUNT"] = f"ACT_{uuid.uuid4().hex}"
        self._test_autocontainer_object_listing(env=env)

    def test_autocontainer_object_listing_other_flatns(self):
        self.skipTest("Deprecated")
        env = dict(os.environ)
        env["OIO_ACCOUNT"] = f"ACT_{uuid.uuid4().hex}"
        self._test_autocontainer_object_listing("--flat-bits 8", env=env)
        opts = self.get_format_opts("json")
        output = self.openio("container list " + opts, env=env)
        for entry in self.json_loads(output):
            self.assertEqual(len(entry["Name"]), 2)

    def _test_object_link(self, with_cid=False):
        if not true_value(self.conf.get("shallow_copy")):
            self.skipTest("Shallow copy disabled")

        cont_name = "test-object-link-" + random_str(6)
        obj_name = "test-object-link-" + random_str(6)
        lk_name = obj_name + "-link"
        cid_opt = ""

        output = self.openio("container create " + cont_name)
        self.clean_later(cont_name, self.account_from_env())
        if with_cid:
            cont_name = self._get_cid_from_name(cont_name)
            cid_opt = "--cid "

        with tempfile.NamedTemporaryFile() as myfile:
            myfile.write(b"something")
            myfile.flush()
            output = self.openio(
                "object create "
                + cid_opt
                + cont_name
                + " "
                + myfile.name
                + " --name "
                + obj_name
                + " -f json"
            )
        output = self.openio(
            "object show -f json " + cid_opt + cont_name + " " + obj_name
        )
        output = self.json_loads(output)
        self.assertEqual(output["object"], obj_name)

        output = self.openio(
            "object link " + cid_opt + cont_name + " " + obj_name + " " + lk_name
        )
        self.assertEqual(output, "")
        output = self.openio(
            "object show -f json " + cid_opt + cont_name + " " + lk_name
        )
        output = self.json_loads(output)
        self.assertEqual(output["object"], lk_name)

    def test_object_link(self):
        self._test_object_link()

    def test_object_link_with_cid(self):
        self._test_object_link(with_cid=True)

    def _test_object_set_properties(self, with_cid=False):
        cont_name = "test-prop-" + random_str(6)
        obj_name = "test-prop-" + random_str(6)
        cid_opt = ""

        output = self.openio("container create " + cont_name)
        self.clean_later(cont_name, self.account_from_env())
        if with_cid:
            cont_name = self._get_cid_from_name(cont_name)
            cid_opt = "--cid "

        with tempfile.NamedTemporaryFile() as myfile:
            myfile.write(b"something")
            myfile.flush()
            output = self.openio(
                "object create "
                + cid_opt
                + cont_name
                + " "
                + myfile.name
                + " --name "
                + obj_name
                + " -f json"
            )
        output = self.openio(
            "object show -f json " + cid_opt + cont_name + " " + obj_name
        )
        output = self.json_loads(output)
        self.assertEqual(obj_name, output["object"])

        output = self.openio(
            "object set "
            + cid_opt
            + cont_name
            + " "
            + obj_name
            + " --property test1=1 --property test2=2"
        )
        self.assertEqual(output, "")
        output = self.openio(
            "object show -f json " + cid_opt + cont_name + " " + obj_name
        )
        output = self.json_loads(output)
        self.assertEqual(obj_name, output["object"])
        self.assertEqual("1", output["meta.test1"])
        self.assertEqual("2", output["meta.test2"])

        output = self.openio(
            "object set " + cid_opt + cont_name + " " + obj_name + " --property test3=3"
        )
        self.assertEqual(output, "")
        output = self.openio(
            "object show -f json " + cid_opt + cont_name + " " + obj_name
        )
        output = self.json_loads(output)
        self.assertEqual(obj_name, output["object"])
        self.assertEqual("1", output["meta.test1"])
        self.assertEqual("2", output["meta.test2"])
        self.assertEqual("3", output["meta.test3"])

        output = self.openio(
            "object set "
            + cid_opt
            + cont_name
            + " "
            + obj_name
            + " --clear"
            + " --property test4=4"
        )
        self.assertEqual(output, "")
        output = self.openio(
            "object show -f json " + cid_opt + cont_name + " " + obj_name
        )
        output = self.json_loads(output)
        self.assertEqual(obj_name, output["object"])
        self.assertNotIn("meta.test1", output)
        self.assertNotIn("meta.test2", output)
        self.assertNotIn("meta.test3", output)
        self.assertEqual("4", output["meta.test4"])

    def test_object_set_properties(self):
        self._test_object_set_properties()

    def test_object_set_properties_with_cid(self):
        self._test_object_set_properties(with_cid=True)

    def test_object_with_tls(self):
        if not self.conf.get("use_tls"):
            self.skipTest("TLS support must enabled for RAWX")
        with tempfile.NamedTemporaryFile() as f:
            test_content = b"test content"
            f.write(test_content)
            f.flush()
            self._test_obj(f.name, test_content, "tls-" + random_str(6), with_tls=True)

    def test_object_show_delete_marker(self):
        account = self.account_from_env()
        cname = f"test-show-delete-marker-{random_str(3)}"
        sys_props = {
            M2_PROP_VERSIONING_POLICY: "-1",
        }
        self.storage.container_create(account, cname, system=sys_props)
        self.clean_later(cname, account)
        _, _, _, _obj_meta = self.storage.object_create_ext(
            account,
            cname,
            obj_name=cname,
            data=cname.encode("utf-8"),
        )
        dm_created, dm_vers = self.storage.object_delete(
            account,
            cname,
            cname,
        )
        self.assertTrue(dm_created, "No delete marker created")

        output = self.openio(f"object show -f json {cname} {cname}")
        output = self.json_loads(output)
        self.assertEqual(output["version"], dm_vers)
        self.assertEqual(output["size"], "deleted")
        self.assertEqual(output["mime-type"], HTTP_CONTENT_TYPE_DELETED)
