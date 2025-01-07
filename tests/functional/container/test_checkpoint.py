# -*- coding: utf-8 -*-

# Copyright (C) 2024 OVH SAS
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

# pylint: disable=no-member

from os import walk
from os.path import isfile, join
from unittest.mock import patch

from oio.common.exceptions import BadRequest, NoSuchAccount, NoSuchContainer, NotFound
from oio.common.utils import cid_from_name, request_id
from tests.utils import BaseTestCase, random_str


class TestCheckpointContainer(BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Prevent the sharding/shrinking by the meta2 crawlers
        cls._service("oio-crawler.target", "stop", wait=3)

    @classmethod
    def tearDownClass(cls):
        cls._service("oio-crawler.target", "start", wait=1)
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        self.api = self.storage
        self.objects = []
        self.account = f"lifecycle-acct-{random_str(4)}"
        self.container = f"lifecycle-ct-{random_str(4)}"
        self._create_container()
        self.container_base = self._get_container_base(self.container, self.account)
        self._data_dirs = self._get_data_dirs(self.container, self.account)
        # Ensure all bases are present
        # master
        entries = self._list_base_in_master(self.container_base)
        self.assertListEqual(entries, [f"{self.container_base}.meta2"])
        # slaves
        entries = self._list_base_in_slaves(self.container_base)
        self.assertListEqual(
            entries,
            [f"{self.container_base}.meta2" for _ in range(len(self._data_dirs[1]))],
        )

    def tearDown(self):
        self._delete_objects()

        try:
            shards = self.container_sharding.show_shards(self.account, self.container)
            for shard in shards:
                self.storage.container.container_delete(cid=shard["cid"])
            self.api.container_delete(self.account, self.container, force=True)
        except NoSuchContainer:
            pass
        except Exception as exc:
            self.logger.warning("Failed to clean container: %s", exc)

        try:
            self.api.account_flush(self.account)
            self.api.account_delete(self.account)
        except NoSuchAccount:
            pass
        except Exception as exc:
            self.logger.warning("Failed to clean account: %s", exc)

        super().tearDown()

    def _list_base_in_master(self, base_name=""):
        master_dir, _ = self._data_dirs
        entries = self._list_files_in_dirs([master_dir])
        if base_name:
            entries = [e for e in entries if e.startswith(base_name)]
        return entries

    def _list_base_in_slaves(self, base_name=""):
        _, slave_dirs = self._data_dirs
        entries = self._list_files_in_dirs(slave_dirs)
        if base_name:
            entries = [e for e in entries if e.startswith(base_name)]
        return entries

    def _get_container_base(self, container, account):
        props = self.api.container_get_properties(account, container)
        return props["system"]["sys.name"]

    def _create_container(self):
        created = self.api.container_create(
            self.account,
            self.container,
        )
        self.assertTrue(created)

    def _list_files_in_dirs(self, dirs, skip_journal=True):
        entries = []
        for entry in dirs:
            for root, _, files in walk(entry):
                for file in files:
                    if skip_journal and file.endswith("-journal"):
                        continue
                    path = join(root, file)
                    if isfile(path):
                        entries.append(file)
        return entries

    def _list_lifecycle_symlinks(self, cid):
        lifecycle_dir = self.conf["lifecycle_path"]
        entries = self._list_files_in_dirs([lifecycle_dir])
        return [e for e in entries if cid in e]

    def _get_data_dirs(self, container=None, account=None, cid=None):
        services = self.conscience.all_services("meta2")
        volumes = {s["id"]: s["tags"]["tag.vol"] for s in services}

        status = self.admin.election_status(
            "meta2", account=account, reference=container, cid=cid
        )
        master = status.get("master")
        slaves = status.get("slaves", [])
        return volumes.get(master), [volumes.get(s) for s in slaves]

    def test_checkpoint_existing_container(self):
        # Create container
        self.api.container.container_checkpoint(
            account=self.account, reference=self.container, prefix="my-prefix"
        )

        entries = self._list_base_in_master(self.container_base)
        self.assertEqual(len(entries), 2)
        # keep only base with suffix
        entries = [e for e in entries if not e.endswith(".meta2")]
        self.assertEqual(len(entries), 1)

        entries = self._list_base_in_slaves(self.container_base)
        self.assertEqual(len(entries), len(self._data_dirs[1]))
        # keep only base with suffix
        entries = [e for e in entries if not e.endswith(".meta2")]
        self.assertEqual(len(entries), 0)

        # Ensure the symlink is correctly created
        entries = self._list_lifecycle_symlinks(self.container_base)
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertTrue(entry.startswith("my-prefix."))

    def test_checkpoint_existing_container_with_suffix(self):
        # Create container checkpoint
        self.api.container.container_checkpoint(
            account=self.account,
            reference=self.container,
            prefix="my-prefix",
            suffix="my-suffix",
        )

        entries = self._list_base_in_master(self.container_base)
        self.assertEqual(len(entries), 2)
        # keep only base with suffix
        entries = [e for e in entries if not e.endswith(".meta2")]
        self.assertEqual(len(entries), 1)

        entries = self._list_base_in_slaves(self.container_base)
        self.assertEqual(len(entries), len(self._data_dirs[1]))
        # keep only base with suffix
        entries = [e for e in entries if not e.endswith(".meta2")]
        self.assertEqual(len(entries), 0)

        # Ensure the symlink is correctly created
        entries = self._list_lifecycle_symlinks(self.container_base)
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertTrue(entry.startswith("my-prefix."))
        self.assertTrue(entry.endswith("my-suffix"))

        # Create container with same suffix and prefix
        self.api.container.container_checkpoint(
            account=self.account,
            reference=self.container,
            prefix="my-prefix",
            suffix="my-suffix",
        )
        entries = self._list_base_in_master(self.container_base)
        self.assertEqual(len(entries), 2)
        # keep only base with suffix
        entries = [e for e in entries if not e.endswith(".meta2")]
        self.assertEqual(len(entries), 1)
        print(entries)

        # Ensure the symlink is correctly created
        entries = self._list_lifecycle_symlinks(self.container_base)
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertTrue(entry.startswith("my-prefix."))
        self.assertTrue(entry.endswith("my-suffix"))

    def test_checkpoint_invalid_container(self):
        self.assertRaises(
            NotFound,
            self.api.container.container_checkpoint,
            account=self.account,
            reference="invalid",
            prefix="my-prefix",
        )

    def test_checkpoint_invalid_account(self):
        self.assertRaises(
            NotFound,
            self.api.container.container_checkpoint,
            account="invalid",
            reference=self.container,
            prefix="my-prefix",
        )

    def test_checkpoint_missing_prefix(self):
        self.assertRaises(
            BadRequest,
            self.api.container.container_checkpoint,
            account=self.account,
            reference=self.container,
        )

    def _add_objects(
        self,
        cname,
        nb_objects,
        prefix="content",
        account=None,
        cname_root=None,
        properties=None,
    ):
        reqid = None
        if not account:
            account = self.account
        if not cname_root:
            cname_root = cname
        for i in range(nb_objects):
            obj_name = "%s_%d" % (prefix, i)
            self.objects.append(obj_name)
            reqid = request_id()
            data = obj_name.encode("utf-8")
            _, _, _, _ = self.storage.object_create_ext(
                account,
                cname,
                obj_name=obj_name,
                data=data,
                reqid=reqid,
                properties=properties,
            )

    def _delete_objects(self):
        if self.objects:
            self.storage.object_delete_many(self.account, self.container, self.objects)

    def _shard_container(self):
        test_shards = [
            {"index": 0, "lower": "", "upper": "content_0."},
            {"index": 1, "lower": "content_0.", "upper": ""},
        ]
        new_shards = self.container_sharding.format_shards(test_shards, are_new=True)
        _vacuum = self.container_sharding.admin.vacuum_base
        with patch("oio.directory.admin.AdminClient.vacuum_base", wraps=_vacuum):
            modified = self.container_sharding.replace_shard(
                self.account, self.container, new_shards, enable=True
            )
            self.assertTrue(modified)

    def test_checkpoint_sharded_container(self):
        self._add_objects(self.container, 16)

        root_cid = cid_from_name(self.account, self.container)
        cleaning = {"local": 0, "replicated_root": 0, "replicated_shard": 0}
        _request = self.container_sharding._request

        def _wrap_request(*args, **kwargs):
            if args == ("POST", "/clean"):
                if kwargs.get("params", {}).get("local") == 1:
                    cleaning["local"] = cleaning["local"] + 1
                elif root_cid == kwargs.get("params", {}).get("cid"):
                    cleaning["replicated_root"] = cleaning["replicated_root"] + 1
                else:
                    cleaning["replicated_shard"] = cleaning["replicated_shard"] + 1
            return _request(*args, **kwargs)

        with patch(
            "oio.container.sharding.ContainerSharding._request", wraps=_wrap_request
        ):
            self._shard_container()

            # Create  checkpoint on root container
            self.api.container.container_checkpoint(
                account=self.account, reference=self.container, prefix="my-prefix"
            )
            entries = self._list_base_in_master(self.container_base)
            self.assertEqual(len(entries), 2)
            entries = self._list_lifecycle_symlinks(self.container_base)
            self.assertEqual(len(entries), 1)

            shards = self.container_sharding.show_shards(self.account, self.container)
            for shard in shards:
                self.api.container.container_checkpoint(
                    cid=shard["cid"], prefix="my-prefix"
                )
                self._data_dirs = self._get_data_dirs(cid=shard["cid"])
                entries = self._list_base_in_master(shard["cid"])
                self.assertEqual(len(entries), 2)
                entries = self._list_lifecycle_symlinks(shard["cid"])
                self.assertEqual(len(entries), 1)
