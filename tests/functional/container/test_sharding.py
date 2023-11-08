# -*- coding: utf-8 -*-

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

import random
import sqlite3
import time
from unittest.mock import ANY, call, patch
from datetime import datetime, timedelta, timezone

from oio.common.constants import (
    M2_PROP_BUCKET_NAME,
    M2_PROP_DRAINING_TIMESTAMP,
    M2_PROP_OBJECTS,
    M2_PROP_SHARDING_LOWER,
    M2_PROP_SHARDING_ROOT,
    M2_PROP_SHARDING_STATE,
    M2_PROP_SHARDING_TABLES_CLEANED,
    M2_PROP_SHARDING_UPPER,
    NEW_SHARD_STATE_CLEANED_UP,
    M2_PROP_VERSIONING_POLICY,
    OIO_DB_ENABLED,
    OIO_DB_FROZEN,
)
from oio.common.exceptions import (
    DeadlineReached,
    Forbidden,
    NotFound,
    OioTimeout,
    ServiceBusy,
)
from oio.common.green import eventlet
from oio.common.utils import cid_from_name, request_id
from oio.container.sharding import ContainerSharding
from oio.event.evob import EventTypes
from tests.unit.api import FakeResponse
from tests.utils import BaseTestCase


class TestSharding(BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super(TestSharding, cls).setUpClass()
        # Prevent the sharding/shrinking by the meta2 crawlers
        cls._service("oio-crawler.target", "stop", wait=3)

    @classmethod
    def tearDownClass(cls):
        cls._service("oio-crawler.target", "start", wait=1)
        super(TestSharding, cls).tearDownClass()

    def setUp(self):
        super(TestSharding, self).setUp()
        self.cname = f"test_sharding_{time.time()}"
        self.created = {}
        self.container_sharding = ContainerSharding(self.conf)
        self.beanstalkd0.drain_tube("oio-preserved")
        self.versioning_enabled = False
        self.system = {}
        self.objects_properties = {}
        self.object_lock = False

        self.wait_for_score(("rawx", "meta2"), score_threshold=1, timeout=5.0)

    def tearDown(self):
        for cname, created in self.created.items():
            try:
                # delete objects
                if self.versioning_enabled:
                    for obj_name, versions in created.items():
                        for version, _ in versions:
                            self.storage.object_delete(
                                self.account, cname, obj_name, version=version
                            )
                else:
                    self.storage.object_delete_many(self.account, cname, objs=created)
                # FIXME temporary cleaning, this should be handled by deleting
                # root container
                shards = self.container_sharding.show_shards(self.account, cname)
                for shard in shards:
                    self.storage.container.container_delete(cid=shard["cid"])
                # FIXME(adu): Shrink the container to delete it
                # without using the 'force' option.
                self.storage.container_delete(self.account, self.cname, force=True)
            except Exception:
                self.logger.warning("Failed to cleaning root %s", cname)
        super(TestSharding, self).tearDown()

    def _create(self, cname, properties=None, bucket=None, versioning=False):
        if bucket:
            self.storage.bucket.bucket_create(bucket, self.account)
            self.system[M2_PROP_BUCKET_NAME] = bucket
        if versioning:
            self.system[M2_PROP_VERSIONING_POLICY] = "-1"
            self.versioning_enabled = True
        created = self.storage.container_create(
            self.account, cname, properties=properties, system=self.system
        )
        self.assertTrue(created)
        if self.versioning_enabled:
            self.created[cname] = {}
        else:
            self.created[cname] = set()

    def _get_object_count(self, cname):
        if self.versioning_enabled:
            count = 0
            for _, versions in self.created[cname].items():
                for _, deleted in versions:
                    if not deleted:
                        count += 1
        else:
            count = len(self.created[cname])
        return count

    def _get_byte_count(self, cname):
        if self.versioning_enabled:
            count = 0
            for obj, versions in self.created[cname].items():
                for i, (_, deleted) in enumerate(versions):
                    if not deleted:
                        count += len(obj) + 1 + len(str(i))
        else:
            count = sum((len(obj) for obj in self.created[cname]))
        return count

    def _check_bucket_stats(self, cname, bucket, account=None):
        stats = self.storage.bucket.bucket_show(bucket, account=account)
        if cname.endswith("+segments"):
            self.assertEqual(0, stats["objects"])
        else:
            self.assertEqual(self._get_object_count(cname), stats["objects"])
        self.assertEqual(self._get_byte_count(cname), stats["bytes"])

    def _add_objects(
        self,
        cname,
        nb_objects,
        prefix="content",
        bucket=None,
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
            reqid = request_id()
            data = obj_name
            if self.versioning_enabled:
                data += f"-{len(self.created[cname_root].get(obj_name, []))}"
            data = data.encode("utf-8")
            _, _, _, meta = self.storage.object_create_ext(
                account,
                cname,
                obj_name=obj_name,
                data=data,
                reqid=reqid,
                properties=properties,
            )
            if self.versioning_enabled:
                self.created[cname_root].setdefault(obj_name, []).append(
                    (meta["version"], False)
                )
            else:
                self.created[cname_root].add(obj_name)
        if bucket:
            self.wait_for_event(
                "oio-preserved", reqid=reqid, types=(EventTypes.CONTAINER_STATE,)
            )
            self._check_bucket_stats(cname_root, bucket, account=account)

    def _delete_objects(
        self, cname, nb_objects, prefix="content", bucket=None, object_lock=False
    ):
        reqid = None
        for i in range(nb_objects):
            obj_name = "%s_%d" % (prefix, i)
            reqid = request_id()
            if object_lock:
                self.assertRaises(
                    Forbidden,
                    self.storage.object_delete,
                    self.account,
                    cname,
                    obj_name,
                    reqid=reqid,
                )
            else:
                self.storage.object_delete(self.account, cname, obj_name, reqid=reqid)
                if self.versioning_enabled:
                    versions = self.created[cname].setdefault(obj_name, [])
                    versions.append((str(int(versions[-1][1]) + 1), True))
                else:
                    self.created[cname].remove(obj_name)
        if bucket:
            self.wait_for_event(
                "oio-preserved",
                reqid=reqid,
                fields={"account": self.account, "user": cname},
                types=(EventTypes.CONTAINER_STATE,),
            )
            stats = self.storage.bucket.bucket_show(cname, account=self.account)
            self.assertEqual(self._get_object_count(cname), stats["objects"])

    def _check_objects(self, cname):
        # Check the objects list
        obj_list = self.storage.object_list(self.account, cname)
        if self.versioning_enabled:
            self.assertListEqual(
                sorted(
                    [
                        obj
                        for obj, versions in self.created[cname].items()
                        if not versions[-1][1]
                    ]
                ),
                [obj["name"] for obj in obj_list["objects"]],
            )
            # Check the objects data
            for obj_name, versions in self.created[cname].items():
                for i, (version, deleted) in enumerate(versions):
                    if deleted:
                        continue
                    _, data = self.storage.object_fetch(
                        self.account, cname, obj_name, version=version
                    )
                    self.assertEqual(f"{obj_name}-{i}".encode("utf-8"), b"".join(data))
        else:
            self.assertListEqual(
                sorted(self.created[cname]),
                [obj["name"] for obj in obj_list["objects"]],
            )
            # Check the objects data
            for obj_name in self.created[cname]:
                _, data = self.storage.object_fetch(self.account, cname, obj_name)
                self.assertEqual(obj_name.encode("utf-8"), b"".join(data))

    def _check_shards_objectlock_properties(self, resp):
        pass

    def _check_cleaning(self, cid, objects_count):
        meta2db_path = self._get_meta2db_path(cid)
        with sqlite3.connect(meta2db_path) as connection:
            cursor = connection.cursor()
            try:
                aliases_count = cursor.execute(
                    "SELECT COUNT(*) FROM aliases WHERE deleted == 0"
                ).fetchall()[0][0]
                self.assertEqual(objects_count, aliases_count)
                contents_count = cursor.execute(
                    "SELECT COUNT(*) FROM contents"
                ).fetchall()[0][0]
                self.assertEqual(objects_count, contents_count)
                chunks_count = cursor.execute("SELECT COUNT(*) FROM chunks").fetchall()[
                    0
                ][0]
                self.assertEqual(
                    0, chunks_count % objects_count if objects_count else 0
                )
                properties_count = cursor.execute(
                    "SELECT COUNT(*) FROM properties"
                ).fetchall()[0][0]
                self.assertEqual(
                    0, properties_count % objects_count if objects_count else 0
                )
            finally:
                cursor.close()

    def _check_shards(self, new_shards, test_shards, shards_content):
        # check shards
        for index, shard in enumerate(new_shards):
            resp = self.storage.container.container_get_properties(cid=shard["cid"])
            self.assertEqual(
                NEW_SHARD_STATE_CLEANED_UP, int(resp["system"][M2_PROP_SHARDING_STATE])
            )
            self.assertNotIn(M2_PROP_SHARDING_TABLES_CLEANED, resp["system"])
            found_object_in_shard = int(resp["system"][M2_PROP_OBJECTS])
            self.assertEqual(found_object_in_shard, len(shards_content[index]))

            lower = resp["system"]["sys.m2.sharding.lower"]
            upper = resp["system"]["sys.m2.sharding.upper"]

            # lower & upper contain < & > chars, remove them
            self.assertEqual(lower[1:], test_shards[index]["lower"])
            self.assertEqual(upper[1:], test_shards[index]["upper"])

            self._check_shards_objectlock_properties(resp)

            # check object names in each shard
            _, listing = self.storage.container.content_list(cid=shard["cid"])

            list_objects = list()
            for obj in listing["objects"]:
                list_objects.append(obj["name"])
                self.assertIn(obj["name"], shards_content[index])

            # check order
            sorted_objects = sorted(list_objects)
            self.assertListEqual(sorted_objects, list_objects)

            # check cleaning
            self._check_cleaning(shard["cid"], len(shards_content[index]))

    def _shard_container(self):
        self._create(self.cname)
        self._add_objects(self.cname, 16)

        test_shards = [
            {"index": 0, "lower": "", "upper": "content_0."},
            {"index": 1, "lower": "content_0.", "upper": ""},
        ]
        new_shards = self.container_sharding.format_shards(test_shards, are_new=True)
        _vacuum = self.container_sharding.admin.vacuum_base
        with patch(
            "oio.directory.admin.AdminClient.vacuum_base", wraps=_vacuum
        ) as mock_vacuum:
            modified = self.container_sharding.replace_shard(
                self.account, self.cname, new_shards, enable=True
            )
            self.assertTrue(modified)
        parent_cid = cid_from_name(self.account, self.cname)
        expected_calls = [
            call(
                "meta2",
                cid=parent_cid,
                suffix=None,
                service_id=None,
                params={},
                headers=ANY,
                reqid=ANY,
            )
        ]
        for _ in range(2):
            expected_calls.append(
                call(
                    "meta2",
                    cid=parent_cid,
                    suffix=ANY,
                    service_id=ANY,
                    params={"local": 1},
                    headers=ANY,
                    reqid=ANY,
                )
            )
        mock_vacuum.assert_has_calls(expected_calls, any_order=True)
        self.assertEqual(len(expected_calls), mock_vacuum.call_count)

        # check objects
        self._check_objects(self.cname)

        # check shards
        show_shards = self.container_sharding.show_shards(self.account, self.cname)
        show_shards = list(show_shards)
        shards_content = [{"content_0"}, {f"content_{i}" for i in range(1, 16)}]
        self._check_shards(show_shards, test_shards, shards_content)

        # check root container properties
        resp = self.storage.container.container_get_properties(self.account, self.cname)
        self.assertEqual(int(resp["system"][M2_PROP_OBJECTS]), 0)
        self.assertEqual(int(resp["system"]["sys.m2.shards"]), len(test_shards))
        self.assertEqual(
            NEW_SHARD_STATE_CLEANED_UP, int(resp["system"][M2_PROP_SHARDING_STATE])
        )
        self.assertNotIn(M2_PROP_SHARDING_TABLES_CLEANED, resp["system"])
        self._check_cleaning(cid_from_name(self.account, self.cname), 0)

        return show_shards

    def _get_meta2db_path(self, cid):
        dir_data = self.storage.directory.list(cid=cid, service_type="meta2")
        volume_id = dir_data["srv"][0]["host"]
        volume_path = None
        for srv in self.conscience.all_services("meta2"):
            if volume_id in (srv["addr"], srv["tags"].get("tag.service_id")):
                volume_path = srv["tags"]["tag.vol"]
                break
        else:
            self.fail("Unable to find the volume path")
        return "/".join((volume_path, cid[:3], cid + ".1.meta2"))

    def test_shard_container(self):
        root_cid = cid_from_name(self.account, self.cname)
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
        ) as mock_request:
            self._shard_container()
        mock_request.assert_called()
        self.assertEqual(2, cleaning["local"])
        self.assertGreaterEqual(cleaning["replicated_root"], 5)
        self.assertEqual(2, cleaning["replicated_shard"])

    def test_shard_container_with_no_cleaning_during_precleaning(self):
        self.container_sharding.preclean_timeout = 0.000001
        root_cid = cid_from_name(self.account, self.cname)
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
        ) as mock_request:
            self._shard_container()
        mock_request.assert_called()
        self.assertLessEqual(cleaning["local"], 2)
        self.assertGreaterEqual(cleaning["replicated_root"], 5)
        self.assertGreater(cleaning["replicated_shard"], 5)

    def test_shard_container_with_incomplete_precleaning(self):
        self.container_sharding.preclean_timeout = 2
        _request = self.container_sharding._request
        precleaned_indexes = set()

        def _wrap_request(*args, **kwargs):
            resp, body = _request(*args, **kwargs)
            if (
                args == ("POST", "/clean")
                and kwargs.get("params", {}).get("local") == 1
            ):
                # Make it appear that the pr-cleaning
                # has not been completely carried out
                precleaned_index = kwargs.get("json", {}).get("index")
                self.assertIsNotNone(precleaned_index)
                precleaned_indexes.add(precleaned_index)
                resp.headers["x-oio-truncated"] = "true"
            return resp, body

        with patch(
            "oio.container.sharding.ContainerSharding._request", wraps=_wrap_request
        ) as mock_request:
            self._shard_container()
        mock_request.assert_called()
        self.assertEqual(2, len(precleaned_indexes))

    def test_shard_container_with_versioning(self):
        self._create(self.cname, versioning=True)
        self._add_objects(self.cname, 4)
        self._delete_objects(self.cname, 2)

        test_shards = [
            {"index": 0, "lower": "", "upper": "content_0."},
            {"index": 1, "lower": "content_0.", "upper": ""},
        ]
        new_shards = self.container_sharding.format_shards(test_shards, are_new=True)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, new_shards, enable=True
        )
        self.assertTrue(modified)

        # check objects
        self._check_objects(self.cname)

        # check shards
        show_shards = self.container_sharding.show_shards(self.account, self.cname)
        shards_content = [{"content_0"}, {"content_1", "content_2", "content_3"}]
        self._check_shards(show_shards, test_shards, shards_content)

        # check root container properties
        resp = self.storage.container.container_get_properties(self.account, self.cname)
        self.assertEqual(int(resp["system"][M2_PROP_OBJECTS]), 0)
        self.assertEqual(int(resp["system"]["sys.m2.shards"]), len(test_shards))

    def test_add_objects_to_shards(self):
        # add object that gows to first shard
        self._create(self.cname)
        self._add_objects(self.cname, 4)

        test_shards = [
            {"index": 0, "lower": "", "upper": "content_0."},
            {"index": 1, "lower": "content_0.", "upper": ""},
        ]
        new_shards = self.container_sharding.format_shards(test_shards, are_new=True)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, new_shards, enable=True
        )
        self.assertTrue(modified)

        # check objects
        self._check_objects(self.cname)

        # push 1 object in the first shard
        self._add_objects(self.cname, 1, prefix="content-bis")
        # push 1 object in the second shard
        self._add_objects(self.cname, 1, prefix="contentbis")

        # check objects
        self._check_objects(self.cname)

        # check shards
        show_shards = self.container_sharding.show_shards(self.account, self.cname)
        shards_content = [
            {"content-bis_0", "content_0"},
            {"content_1", "content_2", "content_3", "contentbis_0"},
        ]
        self._check_shards(show_shards, test_shards, shards_content)

    def test_delete_objects_from_shards(self):
        chunk_urls = []
        self._create(self.cname)
        self._add_objects(self.cname, 9)

        test_shards = [
            {"index": 0, "lower": "", "upper": "content_3"},
            {"index": 1, "lower": "content_3", "upper": ""},
        ]
        new_shards = self.container_sharding.format_shards(test_shards, are_new=True)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, new_shards, enable=True
        )
        self.assertTrue(modified)
        shards = self.container_sharding.show_shards(self.account, self.cname)
        self.assertEqual(len(list(shards)), 2)  # two shards

        # select random object
        obj_name = random.sample(self.created[self.cname], 1)[0]
        # get all chunks urls before removal
        _, chunks = self.storage.object_locate(self.account, self.cname, obj_name)
        for chunk in chunks:
            chunk_urls.append(chunk["url"])
        # remove this object
        self._delete_object(
            self.account, self.cname, obj_name, reqid="delete-from-shards"
        )

        self._check_objects(self.cname)

        if self.wait_event:
            # check that all chunk urls are matching expected ones
            event = self.wait_for_event(
                "oio-preserved",
                reqid="delete-from-shards",
                types=(EventTypes.CONTENT_DELETED,),
            )
            self.assertIsNotNone(event)
            for event_data in event.data:
                if event_data.get("type") == "chunks":
                    chunk_urls.remove(event_data.get("id"))
            self.assertEqual(0, len(chunk_urls))

    # test shards with empty container
    def test_shard_with_empty_container(self):
        self._create(self.cname)
        self._add_objects(self.cname, 4)

        test_shards = [
            {"index": 0, "lower": "", "upper": "content_5"},
            {"index": 1, "lower": "content_5", "upper": ""},
        ]
        new_shards = self.container_sharding.format_shards(test_shards, are_new=True)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, new_shards, enable=True
        )
        self.assertTrue(modified)
        show_shards = self.container_sharding.show_shards(self.account, self.cname)
        self.assertEqual(len(list(show_shards)), 2)  # two shards

        shards_content = [
            {"0content", "1content", "2content", "3content", "4content"},
            {},
        ]
        # check shards
        self._check_shards(show_shards, test_shards, shards_content)

    def test_successive_shards(self):
        self._create(self.cname)
        for i in range(5):
            self._add_objects(self.cname, 5, prefix="%d-content/" % i)

        test_shards = [
            {"index": 0, "lower": "", "upper": "2-content"},
            {"index": 1, "lower": "2-content", "upper": ""},
        ]
        new_shards = self.container_sharding.format_shards(test_shards, are_new=True)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, new_shards, enable=True
        )
        self.assertTrue(modified)
        shards = self.container_sharding.show_shards(self.account, self.cname)
        self.assertEqual(len(list(shards)), 2)

        self._check_objects(self.cname)

        index = 0
        objects_per_shard = [10, 15]
        # check shards
        for shard in shards:
            resp = self.storage.container.container_get_properties(cid=shard["cid"])
            found_object_in_shard = int(resp["system"][M2_PROP_OBJECTS])
            self.assertEqual(found_object_in_shard, objects_per_shard[index])
            index = index + 1

        # reshard
        test_shards = [
            {"index": 0, "lower": "", "upper": "2-content"},
            {"index": 1, "lower": "2-content", "upper": "3-content"},
            {"index": 2, "lower": "3-content", "upper": ""},
        ]
        new_shards = self.container_sharding.format_shards(test_shards, are_new=True)
        modified = self.container_sharding.replace_all_shards(
            self.account, self.cname, new_shards
        )
        self.assertTrue(modified)
        shards = self.container_sharding.show_shards(self.account, self.cname)
        self.assertEqual(len(list(shards)), 3)

        index = 0
        objects_per_shard = [10, 5, 10]
        # check shards
        for shard in shards:
            resp = self.storage.container.container_get_properties(cid=shard["cid"])
            found_object_in_shard = int(resp["system"][M2_PROP_OBJECTS])
            self.assertEqual(found_object_in_shard, objects_per_shard[index])
            index = index + 1

    def test_shard_and_add_delete(self):
        pool = eventlet.GreenPool(size=2)
        self._create(self.cname)
        self._add_objects(self.cname, 140)

        test_shards = [
            {"index": 0, "lower": "", "upper": "content_89"},
            {"index": 1, "lower": "content_89", "upper": ""},
        ]
        new_shards = self.container_sharding.format_shards(test_shards, are_new=True)

        pool.spawn(
            self._add_objects,
            self.cname,
            50,
            prefix="thread_add",
            properties=self.objects_properties,
        )
        pool.spawn(self._delete_objects, self.cname, 30, object_lock=self.object_lock)

        modified = self.container_sharding.replace_shard(
            self.account, self.cname, new_shards, enable=True
        )
        self.assertTrue(modified)
        shards = self.container_sharding.show_shards(self.account, self.cname)
        self.assertEqual(len(list(shards)), 2)

        pool.waitall()

        self._check_objects(self.cname)

    # threshold are applied with partition strategy
    def test_threshold(self):
        nb_obj_to_add = 10
        self._create(self.cname)
        self._add_objects(self.cname, nb_obj_to_add)

        expected_shards = [
            [
                {
                    "index": 0,
                    "lower": "",
                    "upper": "content_4",
                    "metadata": {},
                    "count": 5,
                },
                {
                    "index": 1,
                    "lower": "content_4",
                    "upper": "",
                    "metadata": {},
                    "count": 5,
                },
            ],
            [
                {
                    "index": 0,
                    "lower": "",
                    "upper": "content_4",
                    "metadata": {},
                    "count": 5,
                },
                {
                    "index": 1,
                    "lower": "content_4",
                    "upper": "",
                    "metadata": {},
                    "count": 5,
                },
            ],
            [{"index": 0, "lower": "", "upper": "", "metadata": {}, "count": 10}],
        ]

        thresholds = {nb_obj_to_add - 1, nb_obj_to_add, nb_obj_to_add + 1}
        for i, threshold in enumerate(thresholds):
            shards = self.container_sharding.find_shards(
                self.account,
                self.cname,
                strategy="shard-with-partition",
                strategy_params={"threshold": threshold},
            )

            for j, shard in enumerate(shards):
                self.assertDictEqual(shard, expected_shards[i][j])

    def test_threshold_on_shard(self):
        nb_obj_to_add = 10
        self._create(self.cname)
        self._add_objects(self.cname, nb_obj_to_add)
        test_shards = [
            {"index": 0, "lower": "", "upper": "content"},
            {"index": 1, "lower": "content", "upper": ""},
        ]
        new_shards = self.container_sharding.format_shards(test_shards, are_new=True)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, new_shards, enable=True
        )
        self.assertTrue(modified)
        shards = list(self.container_sharding.show_shards(self.account, self.cname))
        self.assertEqual(2, len(shards))
        shard_meta = self.storage.container_get_properties(
            None, None, cid=shards[1]["cid"]
        )
        shard_account = shard_meta["system"]["sys.account"]
        shard_container = shard_meta["system"]["sys.user.name"]

        expected_shards = [
            [
                {
                    "index": 0,
                    "lower": "content",
                    "upper": "content_4",
                    "metadata": {},
                    "count": 5,
                },
                {
                    "index": 1,
                    "lower": "content_4",
                    "upper": "",
                    "metadata": {},
                    "count": 5,
                },
            ],
            [
                {
                    "index": 0,
                    "lower": "content",
                    "upper": "content_4",
                    "metadata": {},
                    "count": 5,
                },
                {
                    "index": 1,
                    "lower": "content_4",
                    "upper": "",
                    "metadata": {},
                    "count": 5,
                },
            ],
            [
                {
                    "index": 0,
                    "lower": "content",
                    "upper": "",
                    "metadata": {},
                    "count": 10,
                }
            ],
        ]

        thresholds = {nb_obj_to_add - 1, nb_obj_to_add, nb_obj_to_add + 1}
        for i, threshold in enumerate(thresholds):
            shards = self.container_sharding.find_shards(
                shard_account,
                shard_container,
                strategy="shard-with-partition",
                strategy_params={"threshold": threshold},
            )

            for j, shard in enumerate(shards):
                self.assertDictEqual(shard, expected_shards[i][j])

    # partitions are applied with partition strategy
    def test_partition(self):
        nb_obj_to_add = 10
        self._create(self.cname)
        self._add_objects(self.cname, nb_obj_to_add)

        partitions = [[10, 90], [50, 50], [60, 40]]
        expected_shards = [
            [
                {
                    "index": 0,
                    "lower": "",
                    "upper": "content_0",
                    "metadata": {},
                    "count": 1,
                },
                {
                    "index": 1,
                    "lower": "content_0",
                    "upper": "",
                    "metadata": {},
                    "count": 9,
                },
            ],
            [
                {
                    "index": 0,
                    "lower": "",
                    "upper": "content_4",
                    "metadata": {},
                    "count": 5,
                },
                {
                    "index": 1,
                    "lower": "content_4",
                    "upper": "",
                    "metadata": {},
                    "count": 5,
                },
            ],
            [
                {
                    "index": 0,
                    "lower": "",
                    "upper": "content_5",
                    "metadata": {},
                    "count": 6,
                },
                {
                    "index": 1,
                    "lower": "content_5",
                    "upper": "",
                    "metadata": {},
                    "count": 4,
                },
            ],
        ]

        for i, partition in enumerate(partitions):
            shards = self.container_sharding.find_shards(
                self.account,
                self.cname,
                strategy="shard-with-partition",
                strategy_params={
                    "threshold": nb_obj_to_add - 1,
                    "partition": partition,
                },
            )

            for j, shard in enumerate(shards):
                self.assertDictEqual(shard, expected_shards[i][j])

    def test_partition_with_versioning(self):
        nb_obj_to_add = 10
        self._create(self.cname, versioning=True)
        self._add_objects(self.cname, nb_obj_to_add)
        self._delete_objects(self.cname, nb_obj_to_add // 2)

        partitions = [[10, 90], [50, 50], [60, 40]]
        expected_shards = [
            [
                {
                    "index": 0,
                    "lower": "",
                    "upper": "content_0",
                    "metadata": {},
                    "count": 1,
                },
                {
                    "index": 1,
                    "lower": "content_0",
                    "upper": "",
                    "metadata": {},
                    "count": 9,
                },
            ],
            [
                {
                    "index": 0,
                    "lower": "",
                    "upper": "content_4",
                    "metadata": {},
                    "count": 5,
                },
                {
                    "index": 1,
                    "lower": "content_4",
                    "upper": "",
                    "metadata": {},
                    "count": 5,
                },
            ],
            [
                {
                    "index": 0,
                    "lower": "",
                    "upper": "content_5",
                    "metadata": {},
                    "count": 6,
                },
                {
                    "index": 1,
                    "lower": "content_5",
                    "upper": "",
                    "metadata": {},
                    "count": 4,
                },
            ],
        ]

        for i, partition in enumerate(partitions):
            shards = self.container_sharding.find_shards(
                self.account,
                self.cname,
                strategy="shard-with-partition",
                strategy_params={
                    "threshold": nb_obj_to_add - 1,
                    "partition": partition,
                },
            )

            for j, shard in enumerate(shards):
                self.assertDictEqual(shard, expected_shards[i][j])

    def _test_account_counters_after_sharding(self, cname, bucket=None):
        if not bucket:
            bucket = cname

        # Clear the account stats
        try:
            self.storage.account.account_flush(self.account)
        except NotFound:
            pass

        # Fill a bucket
        self._create(cname, bucket=bucket)
        self._add_objects(cname, 10, bucket=bucket)
        stats = self.storage.account.account_show(self.account)
        self.assertEqual(stats["objects"], 10)

        # Split it in 2
        params = {"partition": "50,50", "threshold": 4}
        shards = self.container_sharding.find_shards(
            self.account, cname, strategy="shard-with-partition", strategy_params=params
        )
        modified = self.container_sharding.replace_shard(
            self.account, cname, shards, enable=True, reqid="testingisdoubting"
        )
        self.assertTrue(modified)

        # Wait for the update of the root and the 2 new shards
        for _ in range(3):
            self.wait_for_event(
                "oio-preserved",
                reqid="testingisdoubting",
                types=(EventTypes.CONTAINER_STATE,),
            )
        self._check_bucket_stats(cname, bucket, account=self.account)
        stats = self.storage.account.account_show(self.account)
        self.assertEqual(stats["objects"], 10)

        # Split the first shard in 2
        shards_account = f".shards_{self.account}"
        res = self.storage.container_list(shards_account, prefix=f"{cname}-")
        first = res[0][0]
        shards = self.container_sharding.find_shards(
            shards_account,
            first,
            strategy="shard-with-partition",
            strategy_params=params,
        )
        modified = self.container_sharding.replace_shard(
            shards_account, first, shards, enable=True, reqid="fixingisfailing"
        )
        self.assertTrue(modified)

        # Wait for the deletion of the parent and update of the 2 new shards
        for _ in range(3):
            self.wait_for_event(
                "oio-preserved",
                reqid="fixingisfailing",
                fields={"account": shards_account},
                types=(EventTypes.CONTAINER_DELETED, EventTypes.CONTAINER_STATE),
            )
        self._check_bucket_stats(cname, bucket, account=self.account)
        stats = self.storage.account.account_show(self.account)
        self.assertEqual(stats["objects"], 10)

        self._add_objects(cname, 1, prefix="test/", bucket=bucket)
        stats = self.storage.account.account_show(self.account)
        self.assertEqual(stats["objects"], 11)

    def test_account_counters_after_sharding(self):
        self._test_account_counters_after_sharding(self.cname)

    def test_account_counters_after_sharding_with_segments(self):
        self._test_account_counters_after_sharding(
            f"{self.cname}+segments", bucket=self.cname
        )

    def test_listing(self):
        self._create(self.cname)
        for i in range(4):
            self._add_objects(self.cname, 4, prefix="dir%d/obj" % i)
        # Split it in 2
        params = {"partition": "50,50", "threshold": 1}
        shards = self.container_sharding.find_shards(
            self.account,
            self.cname,
            strategy="shard-with-partition",
            strategy_params=params,
        )
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, shards, enable=True
        )
        self.assertTrue(modified)
        # Classic listing
        objects = self.storage.object_list(self.account, self.cname)
        self.assertListEqual([], objects["prefixes"])
        self.assertListEqual(
            sorted(self.created[self.cname]),
            [obj["name"] for obj in objects["objects"]],
        )
        self.assertFalse(objects["truncated"])
        # Listing with prefix
        objects = self.storage.object_list(self.account, self.cname, prefix="dir1/")
        self.assertListEqual([], objects["prefixes"])
        self.assertListEqual(
            ["dir1/obj_0", "dir1/obj_1", "dir1/obj_2", "dir1/obj_3"],
            [obj["name"] for obj in objects["objects"]],
        )
        self.assertFalse(objects["truncated"])
        # Listing with prefix and limit
        objects = self.storage.object_list(
            self.account, self.cname, prefix="dir3/", limit=1
        )
        self.assertListEqual([], objects["prefixes"])
        self.assertListEqual(
            ["dir3/obj_0"], [obj["name"] for obj in objects["objects"]]
        )
        self.assertTrue(objects["truncated"])
        # Listing with marker in the first shard
        objects = self.storage.object_list(
            self.account, self.cname, marker="dir1/obj_0"
        )
        self.assertListEqual([], objects["prefixes"])
        self.assertListEqual(
            [
                "dir1/obj_1",
                "dir1/obj_2",
                "dir1/obj_3",
                "dir2/obj_0",
                "dir2/obj_1",
                "dir2/obj_2",
                "dir2/obj_3",
                "dir3/obj_0",
                "dir3/obj_1",
                "dir3/obj_2",
                "dir3/obj_3",
            ],
            [obj["name"] for obj in objects["objects"]],
        )
        self.assertFalse(objects["truncated"])
        # Listing with marker in the second shard
        objects = self.storage.object_list(
            self.account, self.cname, marker="dir2/obj_2"
        )
        self.assertListEqual([], objects["prefixes"])
        self.assertListEqual(
            ["dir2/obj_3", "dir3/obj_0", "dir3/obj_1", "dir3/obj_2", "dir3/obj_3"],
            [obj["name"] for obj in objects["objects"]],
        )
        self.assertFalse(objects["truncated"])
        # Listing with marker and prefix
        objects = self.storage.object_list(
            self.account, self.cname, marker="dir2/obj_1", prefix="dir2/"
        )
        self.assertListEqual([], objects["prefixes"])
        self.assertListEqual(
            ["dir2/obj_2", "dir2/obj_3"], [obj["name"] for obj in objects["objects"]]
        )
        self.assertFalse(objects["truncated"])
        # Listing with delimiter
        objects = self.storage.object_list(self.account, self.cname, delimiter="/")
        self.assertListEqual(["dir0/", "dir1/", "dir2/", "dir3/"], objects["prefixes"])
        self.assertListEqual([], objects["objects"])
        self.assertFalse(objects["truncated"])

    def _find_and_check(self, shards, small_shard_pos, expected_pos):
        small_shard = shards[small_shard_pos]
        (
            shard,
            neighboring_shard,
        ) = self.container_sharding.find_smaller_neighboring_shard(small_shard)
        self.assertTrue(self.container_sharding._shards_equal(small_shard, shard))
        if expected_pos is None:
            self.assertIsNone(neighboring_shard)
        else:
            self.assertTrue(
                self.container_sharding._shards_equal(
                    shards[expected_pos], neighboring_shard
                )
            )
        return shard, neighboring_shard

    def test_find_smaller_neighboring_shard(self):
        self._create(self.cname)
        self._add_objects(self.cname, 10)
        # Split it in 5
        params = {"partition": "30,10,20,30,10", "threshold": 1}
        shards = self.container_sharding.find_shards(
            self.account,
            self.cname,
            strategy="shard-with-partition",
            strategy_params=params,
        )
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, shards, enable=True
        )
        self.assertTrue(modified)
        shards = list(self.container_sharding.show_shards(self.account, self.cname))
        self.assertEqual(5, len(shards))
        # First shard
        self._find_and_check(shards, 0, 1)
        # Middle shard
        self._find_and_check(shards, 2, 1)
        # Last shard
        self._find_and_check(shards, 4, 3)

    def test_find_smaller_neighboring_shard_with_the_one_and_last_shard(self):
        self._create(self.cname, bucket=self.cname)
        self._add_objects(self.cname, 4, bucket=self.cname)
        # Split it in 2
        params = {"partition": "50,50", "threshold": 1}
        shards = self.container_sharding.find_shards(
            self.account,
            self.cname,
            strategy="shard-with-partition",
            strategy_params=params,
        )
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, shards, enable=True
        )
        self.assertTrue(modified)
        shards = list(self.container_sharding.show_shards(self.account, self.cname))
        self.assertEqual(2, len(shards))
        # Go back to 1 single shard
        small_shard, neighboring_shard = self._find_and_check(shards, 0, 1)
        shards_to_merge = list()
        shards_to_merge.append(small_shard)
        if neighboring_shard is not None:
            shards_to_merge.append(neighboring_shard)
        modified = self.container_sharding.shrink_shards(shards_to_merge)
        self.assertTrue(modified)
        new_shards = list(self.container_sharding.show_shards(self.account, self.cname))
        self.assertEqual(len(shards) - 1, len(new_shards))
        # Find the root as a neighbor
        self._find_and_check(new_shards, 0, None)

    def test_find_smaller_neighboring_shard_on_unsharded_container(self):
        self._create(self.cname, bucket=self.cname)
        fake_shard = {
            "index": -1,
            "lower": "",
            "upper": "",
            "cid": cid_from_name(self.account, self.cname),
            "metadata": None,
        }
        # Try to find
        self.assertRaises(
            ValueError,
            self.container_sharding.find_smaller_neighboring_shard,
            fake_shard,
        )

    def test_find_smaller_neighboring_shard_on_root(self):
        self._create(self.cname, bucket=self.cname)
        self._add_objects(self.cname, 4, bucket=self.cname)
        # Split it in 2
        params = {"partition": "50,50", "threshold": 1}
        shards = self.container_sharding.find_shards(
            self.account,
            self.cname,
            strategy="shard-with-partition",
            strategy_params=params,
        )
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, shards, enable=True
        )
        self.assertTrue(modified)
        shards = list(self.container_sharding.show_shards(self.account, self.cname))
        self.assertEqual(2, len(shards))
        fake_shard = {
            "index": -1,
            "lower": "",
            "upper": "",
            "cid": cid_from_name(self.account, self.cname),
            "metadata": None,
        }
        # Try to find
        self.assertRaises(
            ValueError,
            self.container_sharding.find_smaller_neighboring_shard,
            fake_shard,
        )

    def test_find_smaller_neighboring_shard_on_nonexistent_container(self):
        fake_shard = {
            "index": -1,
            "lower": "",
            "upper": "",
            "cid": cid_from_name(self.account, self.cname),
            "metadata": None,
        }
        self.assertRaises(
            NotFound, self.container_sharding.find_smaller_neighboring_shard, fake_shard
        )

    def _shrink_and_check(
        self,
        cname,
        current_shards,
        smaller_shard,
        bigger_shard,
        expected_objects,
        bucket=None,
    ):
        # Trigger the shrinking
        bigger_is_root = False
        shards_to_merge = list()
        shards_to_merge.append(smaller_shard)
        if bigger_shard is None:  # The one and last shard
            bigger_is_root = True
            bigger_shard = {
                "cid": cid_from_name(self.account, cname),
                "lower": "",
                "upper": "",
                "metadata": None,
            }
        else:
            shards_to_merge.append(bigger_shard)
        reqid = request_id()
        modified = self.container_sharding.shrink_shards(shards_to_merge, reqid=reqid)
        self.assertTrue(modified)
        self.assertIsNotNone(smaller_shard)
        # Check the smaller shard
        self.assertRaises(
            NotFound,
            self.storage.container.container_get_properties,
            cid=smaller_shard["cid"],
        )
        # Check the bigger shard
        new_shard_meta = self.storage.container.container_get_properties(
            cid=bigger_shard["cid"]
        )
        self.assertEqual(
            NEW_SHARD_STATE_CLEANED_UP,
            int(new_shard_meta["system"][M2_PROP_SHARDING_STATE]),
        )
        _, new_shard = self.container_sharding.meta_to_shard(new_shard_meta)
        if bigger_is_root:  # The one and last shard
            self.assertIsNone(new_shard)
            new_shard = {  # Root container
                "cid": cid_from_name(self.account, cname),
                "lower": "",
                "upper": "",
                "metadata": None,
                "count": int(new_shard_meta["system"][M2_PROP_OBJECTS]),
            }
        else:
            self.assertIsNotNone(new_shard)
        self.assertEqual(
            min(smaller_shard["lower"], bigger_shard["lower"]), new_shard["lower"]
        )
        self.assertEqual(
            smaller_shard["upper"]
            if smaller_shard["upper"] == ""
            else bigger_shard["upper"]
            if bigger_shard["upper"] == ""
            else max(smaller_shard["upper"], bigger_shard["upper"]),
            new_shard["upper"],
        )
        self.assertEqual(expected_objects, new_shard["count"])
        # Check the new shards list
        new_shards = list(self.container_sharding.show_shards(self.account, cname))
        self.assertEqual(len(current_shards) - 1, len(new_shards))
        if new_shards:
            delta = 0
            for i, shard in enumerate(current_shards):
                if (
                    shard["cid"] == smaller_shard["cid"]
                    or shard["cid"] == bigger_shard["cid"]
                ):
                    self.assertTrue(
                        self.container_sharding._shards_equal(
                            new_shard, new_shards[i - delta]
                        )
                    )
                    if not delta:
                        delta = 1
                else:
                    self.assertTrue(
                        self.container_sharding._shards_equal(
                            shard, new_shards[i - delta]
                        )
                    )
        # Check objects
        self._check_objects(cname)
        # Check bucket stats
        if bucket:
            # Wait for the deletion of the smaller
            # and update of the bigger and the root
            nb_events = 3
            if bigger_is_root:  # The one and last shard
                # Wait for the deletion of the smaller and update of the root
                nb_events = 2
            for _ in range(nb_events):
                self.wait_for_event(
                    "oio-preserved",
                    reqid=reqid,
                    types=(EventTypes.CONTAINER_DELETED, EventTypes.CONTAINER_STATE),
                )
            stats = self.storage.bucket.bucket_show(bucket, account=self.account)
            self.assertEqual(len(self.created[cname]), stats["objects"])
        return new_shards

    def test_shrinking(self):
        self._create(self.cname)
        self._add_objects(self.cname, 10)
        # Split it in 5
        params = {"partition": "30,10,20,30,10", "threshold": 1}
        shards = self.container_sharding.find_shards(
            self.account,
            self.cname,
            strategy="shard-with-partition",
            strategy_params=params,
        )
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, shards, enable=True
        )
        self.assertTrue(modified)
        shards = list(self.container_sharding.show_shards(self.account, self.cname))
        self.assertEqual(5, len(shards))
        # First shard
        shards = self._shrink_and_check(self.cname, shards, shards[1], shards[0], 4)
        # Middle shard
        shards = self._shrink_and_check(self.cname, shards, shards[1], shards[2], 5)
        # Last shard
        shards = self._shrink_and_check(self.cname, shards, shards[-1], shards[-2], 6)

    def test_shrinking_until_having_container_without_shards(self):
        self._create(self.cname, bucket=self.cname)
        self._add_objects(self.cname, 10, bucket=self.cname)
        # Split it in 2
        params = {"partition": "60,40", "threshold": 1}
        shards = self.container_sharding.find_shards(
            self.account,
            self.cname,
            strategy="shard-with-partition",
            strategy_params=params,
        )
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, shards, enable=True
        )
        self.assertTrue(modified)
        shards = list(self.container_sharding.show_shards(self.account, self.cname))
        self.assertEqual(2, len(shards))
        # Go back to 1 single shard
        shards = self._shrink_and_check(
            self.cname, shards, shards[1], shards[0], 10, bucket=self.cname
        )
        # Go back to the container without shard
        shards = self._shrink_and_check(
            self.cname, shards, shards[0], None, 10, bucket=self.cname
        )
        # Check the container without shards
        root_meta = self.storage.container.container_get_properties(
            self.account, self.cname
        )
        self.assertNotIn(M2_PROP_SHARDING_ROOT, root_meta["system"])
        self.assertNotIn(M2_PROP_SHARDING_LOWER, root_meta["system"])
        self.assertNotIn(M2_PROP_SHARDING_UPPER, root_meta["system"])

    def test_shrinking_on_root(self):
        self._create(self.cname)
        self._add_objects(self.cname, 2)
        # Split it in 2
        params = {"partition": "50,50", "threshold": 1}
        shards = self.container_sharding.find_shards(
            self.account,
            self.cname,
            strategy="shard-with-partition",
            strategy_params=params,
        )
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, shards, enable=True
        )
        self.assertTrue(modified)
        shards = list(self.container_sharding.show_shards(self.account, self.cname))
        self.assertEqual(2, len(shards))
        # Try to trigger the shrinking on the root
        small_shard = {  # Root container
            "cid": cid_from_name(self.account, self.cname),
            "lower": "",
            "upper": "",
            "metadata": None,
        }
        self.assertRaises(
            ValueError, self.container_sharding.shrink_shards, [small_shard]
        )

    def test_shrinking_with_neighbor_of_neighbor(self):
        self._create(self.cname)
        self._add_objects(self.cname, 4)
        # Split it in 4
        params = {"partition": "25,25,25,25", "threshold": 1}
        shards = self.container_sharding.find_shards(
            self.account,
            self.cname,
            strategy="shard-with-partition",
            strategy_params=params,
        )
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, shards, enable=True
        )
        self.assertTrue(modified)
        shards = list(self.container_sharding.show_shards(self.account, self.cname))
        self.assertEqual(4, len(shards))
        # Try to trigger the shrinking with the neighbor of the neighbor
        self.assertRaises(
            ValueError, self.container_sharding.shrink_shards, [shards[1], shards[3]]
        )

    def test_shrinking_with_no_shard(self):
        self.assertFalse(self.container_sharding.shrink_shards([]))

    def test_shrinking_not_same_root(self):
        # First container
        self._create(self.cname)
        self._add_objects(self.cname, 2)
        # Split it in 2
        params = {"partition": "50,50", "threshold": 1}
        shards = self.container_sharding.find_shards(
            self.account,
            self.cname,
            strategy="shard-with-partition",
            strategy_params=params,
        )
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, shards, enable=True
        )
        self.assertTrue(modified)
        shards = list(self.container_sharding.show_shards(self.account, self.cname))
        self.assertEqual(2, len(shards))
        # Second container
        self._create(self.cname + "bis")
        self._add_objects(self.cname + "bis", 2)
        # Split the first container in 2
        shards_bis = self.container_sharding.find_shards(
            self.account,
            self.cname + "bis",
            strategy="shard-with-partition",
            strategy_params=params,
        )
        modified = self.container_sharding.replace_shard(
            self.account, self.cname + "bis", shards, enable=True
        )
        self.assertTrue(modified)
        shards_bis = list(
            self.container_sharding.show_shards(self.account, self.cname + "bis")
        )
        self.assertEqual(2, len(shards_bis))
        # Try to trigger the shrinking with two different root containers
        self.assertRaises(
            ValueError,
            self.container_sharding.shrink_shards,
            [shards[0], shards_bis[1]],
        )

    def _get_account_cname_shard(self, shard_index):
        shards = self.container_sharding.show_shards(self.account, self.cname)
        for _ in range(shard_index + 1):
            shard_cid = next(shards)["cid"]
        props = self.storage.container.container_get_properties(cid=shard_cid)
        shard_cname = props["system"]["sys.user.name"]
        shard_account = ".shards_%s" % self.account
        return shard_account, shard_cname

    def _test_locate_on_shard(self, chunks, obj_name, shard_index):
        shard_account, shard_cname = self._get_account_cname_shard(shard_index)
        _, chunks_shard = self.storage.object_locate(
            shard_account, shard_cname, obj_name
        )
        chunks = chunks.copy()
        chunks.sort(key=lambda c: c["url"])
        for chunk in chunks:
            chunk.pop("score")
        chunks_shard.sort(key=lambda c: c["url"])
        for chunk_shard in chunks_shard:
            chunk_shard.pop("score")
        self.assertListEqual(chunks, chunks_shard)

    def test_locate_on_shard(self):
        """
        Check the locate command directly on the shard (with account and cname
        of the shard).
        """
        nb_obj_to_add = 10
        self._create(self.cname)
        self._add_objects(self.cname, nb_obj_to_add)

        # random object to locate (that will be located in first shard)
        obj_id_s1 = random.randrange(nb_obj_to_add // 2)
        obj_name_s1 = "content_" + str(obj_id_s1)
        _, chunks_s1 = self.storage.object_locate(self.account, self.cname, obj_name_s1)

        # random object to locate (that will be located in second shard)
        obj_id_s2 = random.randrange(nb_obj_to_add // 2, nb_obj_to_add)
        obj_name_s2 = "content_" + str(obj_id_s2)
        _, chunks_s2 = self.storage.object_locate(self.account, self.cname, obj_name_s2)

        # Split it in 2
        params = {"partition": "50,50", "threshold": 1}
        shards = self.container_sharding.find_shards(
            self.account,
            self.cname,
            strategy="shard-with-partition",
            strategy_params=params,
        )
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, shards, enable=True
        )
        self.assertTrue(modified)

        # Test locate on both shards
        self._test_locate_on_shard(chunks_s1, obj_name_s1, 0)
        self._test_locate_on_shard(chunks_s2, obj_name_s2, 1)

    def test_create_on_shard(self):
        """
        Check the create command directly on the shard (with account and cname
        of the shard).
        Right now, it is not implemented, so check that 403 error is raised.
        """
        nb_obj_to_add = 10
        self._create(self.cname)
        self._add_objects(self.cname, nb_obj_to_add)

        # Split it in 2
        params = {"partition": "50,50", "threshold": 1}
        shards = self.container_sharding.find_shards(
            self.account,
            self.cname,
            strategy="shard-with-partition",
            strategy_params=params,
        )
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, shards, enable=True
        )
        self.assertTrue(modified)

        # Get cname and account of the first shard
        shard_account, shard_cname = self._get_account_cname_shard(0)
        # Adding 1 object directly in this shard should raises a 403 error
        self.assertRaises(
            Forbidden,
            self._add_objects,
            shard_cname,
            1,
            prefix="content-bis",
            account=shard_account,
            cname_root=self.cname,
        )
        self._check_objects(self.cname)

        # Get cname and account of the second shard
        shard_account, shard_cname = self._get_account_cname_shard(1)
        # Adding 1 object directly in this shard should raises a 403 error
        self.assertRaises(
            Forbidden,
            self._add_objects,
            shard_cname,
            1,
            prefix="contentbis",
            account=shard_account,
            cname_root=self.cname,
        )
        self._check_objects(self.cname)

    def _delete_object(self, account, container, obj_name, reqid=None):
        self.storage.object_delete(account, container, obj_name, reqid=reqid)
        if self.versioning_enabled:
            versions = self.created[self.cname].setdefault(obj_name, [])
            versions.append((str(int(versions[-1][1]) + 1), True))
        else:
            self.created[self.cname].remove(obj_name)
        self.wait_event = True

    def test_delete_on_shard(self):
        """
        Check the delete command directly on the shard (with account and cname
        of the shard).
        """
        nb_obj_to_add = 10
        self._create(self.cname)
        self._add_objects(self.cname, nb_obj_to_add)

        # Split it in 2
        params = {"partition": "50,50", "threshold": 1}
        shards = self.container_sharding.find_shards(
            self.account,
            self.cname,
            strategy="shard-with-partition",
            strategy_params=params,
        )
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, shards, enable=True
        )
        self.assertTrue(modified)

        # Get cname and account of the first shard
        shard_account, shard_cname = self._get_account_cname_shard(0)
        # Delete 1 object directly in this shard
        file_id = random.randrange(nb_obj_to_add // 2)
        obj_name = "content_%s" % file_id
        self._delete_object(shard_account, shard_cname, obj_name)
        self._check_objects(self.cname)

        # Get cname and account of the second shard
        shard_account, shard_cname = self._get_account_cname_shard(1)
        # Delete 1 object directly in this shard
        file_id = random.randrange(nb_obj_to_add // 2, nb_obj_to_add)
        obj_name = "content_%s" % file_id
        self._delete_object(shard_account, shard_cname, obj_name)

        self._check_objects(self.cname)

    def _set_property(
        self, property_, value, expected_value_shards, flag_propagate_to_shards=False
    ):
        # Set properties to root
        system = {property_: value}
        output = self.storage.container_set_properties(
            self.account,
            self.cname,
            system=system,
            propagate_to_shards=flag_propagate_to_shards,
        )
        self.assertEqual(b"", output)

        # Check property on root
        resp = self.storage.container.container_get_properties(self.account, self.cname)
        self.assertEqual(value, resp["system"][property_])

        # Check property on each shards
        show_shards = self.container_sharding.show_shards(self.account, self.cname)
        for _, shard in enumerate(show_shards):
            resp = self.storage.container.container_get_properties(cid=shard["cid"])
            self.assertEqual(expected_value_shards, resp["system"][property_])

    def test_set_properties(self):
        """
        Test that properties are propagated from root to shards.
        """
        nb_obj_to_add = 4
        self._create(self.cname)
        self._add_objects(self.cname, nb_obj_to_add)

        # Split it in 2
        params = {"partition": "50,50", "threshold": 1}
        shards = self.container_sharding.find_shards(
            self.account,
            self.cname,
            strategy="shard-with-partition",
            strategy_params=params,
        )
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, shards, enable=True
        )
        self.assertTrue(modified)

        # Propagatation of property with property that should always be
        # propagated to shards
        value_1 = str(random.randrange(0, 10))
        self._set_property(M2_PROP_VERSIONING_POLICY, value_1, value_1)

        value_2 = str(random.randrange(10, 20))
        self._set_property(M2_PROP_VERSIONING_POLICY, value_2, value_2)

        # Reset to 0
        # Needed for the flush in the teardown of the test
        value_3 = str(0)
        self._set_property(M2_PROP_VERSIONING_POLICY, value_3, value_3)

        # Propagatation of property with propagation flag
        value_1 = str(random.randrange(0, 10))
        self._set_property(
            M2_PROP_DRAINING_TIMESTAMP, value_1, value_1, flag_propagate_to_shards=True
        )

        # Propagatation of property without propagation flag (shard keeps
        # old value)
        value_2 = str(random.randrange(10, 20))
        self._set_property(M2_PROP_DRAINING_TIMESTAMP, value_2, value_1)

        # Reset value
        value_3 = str(0)
        self._set_property(
            M2_PROP_DRAINING_TIMESTAMP, value_3, value_3, flag_propagate_to_shards=True
        )

    def test_optimized_object_listing_many_delete_markers(self):
        """
        This test ensures we do not miss object prefixes when the first
        shard has only delete markers.

        Historically we also got a case of infinite loop inside meta2.
        """
        self._create(self.cname, versioning=True)
        self._add_objects(self.cname, 10, prefix="dir/obj")

        test_shards = [
            {"index": 0, "lower": "", "upper": "dir/obj_3"},
            {"index": 1, "lower": "dir/obj_3", "upper": "dir/obj_5"},
            {"index": 2, "lower": "dir/obj_5", "upper": "dir/obj_8"},
            {"index": 3, "lower": "dir/obj_8", "upper": ""},
        ]
        new_shards = self.container_sharding.format_shards(test_shards, are_new=True)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, new_shards, enable=True
        )
        self.assertTrue(modified)
        self._delete_objects(self.cname, 9, prefix="dir/obj")

        # check objects
        list_res = self.storage.object_list(
            self.account, self.cname, delimiter="/", limit=4
        )
        self.assertIn("dir/", list_res["prefixes"])

    def test_optimized_object_listing_several_prefixes(self):
        """
        This test ensures we do not miss object prefixes.
        """
        self._create(self.cname)
        self._add_objects(self.cname, 4, prefix="dir1/obj")
        self._add_objects(self.cname, 4, prefix="dir2/obj")
        self._add_objects(self.cname, 4, prefix="dir3/obj")

        test_shards = [
            {"index": 0, "lower": "", "upper": "dir2/obj_1"},
            {"index": 1, "lower": "dir2/obj_1", "upper": ""},
        ]
        new_shards = self.container_sharding.format_shards(test_shards, are_new=True)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, new_shards, enable=True
        )
        self.assertTrue(modified)
        self._delete_objects(self.cname, 2, prefix="dir2/obj")

        # check objects
        list_res = self.storage.object_list(self.account, self.cname, delimiter="/")
        self.assertIn("dir2/", list_res["prefixes"])

    def test_optimized_object_listing_many_empty_shards(self):
        """
        This test ensures we do not miss object prefixes when the first
        shards are empty.
        """
        self._create(self.cname, versioning=False)
        self._add_objects(self.cname, 10, prefix="dir/obj")

        test_shards = [
            {"index": 0, "lower": "", "upper": "dir/obj_3"},
            {"index": 1, "lower": "dir/obj_3", "upper": "dir/obj_5"},
            {"index": 2, "lower": "dir/obj_5", "upper": "dir/obj_8"},
            {"index": 3, "lower": "dir/obj_8", "upper": ""},
        ]
        new_shards = self.container_sharding.format_shards(test_shards, are_new=True)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, new_shards, enable=True
        )
        self.assertTrue(modified)
        self._delete_objects(self.cname, 9, prefix="dir/obj")

        # check objects
        list_res = self.storage.object_list(
            self.account, self.cname, delimiter="/", limit=4
        )
        self.assertIn("dir/", list_res["prefixes"])

    def test_sharding_with_frozen_container(self):
        self._create(self.cname)
        self._add_objects(self.cname, 4)

        # freeze the container
        self.storage.container_set_properties(
            self.account, self.cname, system={"sys.status": str(OIO_DB_FROZEN)}
        )

        try:
            test_shards = [
                {"index": 0, "lower": "", "upper": "content_0."},
                {"index": 1, "lower": "content_0.", "upper": ""},
            ]
            new_shards = self.container_sharding.format_shards(
                test_shards, are_new=True
            )
            modified = self.container_sharding.replace_shard(
                self.account, self.cname, new_shards, enable=True
            )
            self.assertTrue(modified)

            # check objects
            self._check_objects(self.cname)

            # check shards
            show_shards = self.container_sharding.show_shards(self.account, self.cname)
            shards_content = [{"content_0"}, {"content_1", "content_2", "content_3"}]
            self._check_shards(show_shards, test_shards, shards_content)

            # check root container properties
            resp = self.storage.container.container_get_properties(
                self.account, self.cname
            )
            self.assertEqual(int(resp["system"][M2_PROP_OBJECTS]), 0)
            self.assertEqual(int(resp["system"]["sys.m2.shards"]), len(test_shards))
        finally:
            # unfreeze the container for the deletion
            self.storage.container_set_properties(
                self.account, self.cname, system={"sys.status": str(OIO_DB_ENABLED)}
            )

    def test_shrinking_with_frozen_container(self):
        self._create(self.cname)
        self._add_objects(self.cname, 10)

        # Split it in 5
        params = {"partition": "30,10,20,30,10", "threshold": 1}
        shards = self.container_sharding.find_shards(
            self.account,
            self.cname,
            strategy="shard-with-partition",
            strategy_params=params,
        )
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, shards, enable=True
        )
        self.assertTrue(modified)
        shards = list(self.container_sharding.show_shards(self.account, self.cname))
        self.assertEqual(5, len(shards))

        # Freeze the container
        self.storage.container_set_properties(
            self.account, self.cname, system={"sys.status": str(OIO_DB_FROZEN)}
        )

        try:
            # First shard
            shards = self._shrink_and_check(self.cname, shards, shards[1], shards[0], 4)
            # Middle shard
            shards = self._shrink_and_check(self.cname, shards, shards[1], shards[2], 5)
            # Last shard
            shards = self._shrink_and_check(
                self.cname, shards, shards[-1], shards[-2], 6
            )
        finally:
            # unfreeze the container for the deletion
            self.storage.container_set_properties(
                self.account, self.cname, system={"sys.status": str(OIO_DB_ENABLED)}
            )

    def _test_clean_container_with_timeout(self, vacuum=False):
        """
        1st request: clean with urgent mode to be sure to start cleaning
            -> success (truncated)
        2nd request: clean without urgent mode to have less impact
            -> timeout
        3rd request: clean with urgent mode because the previous request has timeout
            -> success (truncated)
        4th request: clean without urgent mode to have less impact
            -> 503
        5th request: clean with urgent mode because the previous request returned 503
            -> timeout
        6th request: clean with urgent mode because the previous request has timeout
            -> success (truncated)
        7th request: clean without urgent mode to have less impact
            -> 500
        8th request: clean without urgent mode to have less impact
            -> success
        """
        shards = self._shard_container()

        requests = {"count": 0, "unexpected_errors": []}
        _request = self.container_sharding._request

        def _wrap_request(*args, **kwargs):
            requests["count"] = requests["count"] + 1
            try:
                # Check number of requests and method parameters
                if requests["count"] > 8:
                    raise Exception("Too many requests")
                self.assertEqual(("POST", "/clean"), args)
                expected_params = {"cid": shard_cid}
                if requests["count"] in (1, 3, 5, 6):
                    expected_params["urgent"] = 1
                self.assertDictEqual(expected_params, kwargs.get("params"))
                # Change the request and the response
                if requests["count"] in (2, 5):
                    kwargs["timeout"] = 0.00001
                elif requests["count"] in (4,):
                    return FakeResponse(503), b""
                elif requests["count"] in (7,):
                    return FakeResponse(500), b""
                resp, body = _request(*args, **kwargs)
                self.assertNotIn(requests["count"], (2, 4, 5, 7))
                if requests["count"] < 8:
                    resp.headers["x-oio-truncated"] = "true"
                return resp, body
            except (OioTimeout, ServiceBusy, DeadlineReached) as exc:
                if requests["count"] not in (2, 5, 8):
                    requests["unexpected_errors"].append(exc)
                raise
            except Exception as exc:
                requests["unexpected_errors"].append(exc)
                raise

        # Clean (again) the first shard
        shard_cid = shards[0]["cid"]
        with patch(
            "oio.container.sharding.ContainerSharding._request", wraps=_wrap_request
        ) as mock_request:
            _vacuum = self.container_sharding.admin.vacuum_base
            with patch(
                "oio.directory.admin.AdminClient.vacuum_base", wraps=_vacuum
            ) as mock_vacuum:
                self.container_sharding.clean_container(
                    None,
                    None,
                    cid=shards[0]["cid"],
                    attempts=3,
                    vacuum=vacuum,
                )
                self.assertListEqual([], requests["unexpected_errors"])
            if vacuum:
                mock_vacuum.assert_called_once()
            else:
                mock_vacuum.assert_not_called()
        self.assertEqual(8, mock_request.call_count)

    def test_clean_container_with_timeout(self):
        self._test_clean_container_with_timeout()

    def test_clean_container_with_timeout_and_vacuum(self):
        self._test_clean_container_with_timeout(vacuum=True)

    def test_clean_container_with_too_many_errors(self):
        """
        1st request: clean with urgent mode to be sure to start cleaning
            -> success (truncated)
        2nd request: clean without urgent mode to have less impact
            -> timeout
        3rd request: clean with urgent mode because the previous request has timeout
            -> success (truncated)
        4th request: clean without urgent mode to have less impact
            -> 503
        5th request: clean with urgent mode because the previous request returned 503
            -> timeout
        6th request: clean with urgent mode because the previous request has timeout
            -> success (truncated)
        7th request: clean without urgent mode to have less impact
            -> 503
        8th request: clean with urgent mode because the previous request returned 503
            -> timeout
        9th request: clean with urgent mode because the previous request returned 503
            -> 503
        """
        shards = self._shard_container()

        requests = {"count": 0, "unexpected_errors": []}
        _request = self.container_sharding._request

        def _wrap_request(*args, **kwargs):
            requests["count"] = requests["count"] + 1
            try:
                # Check number of requests and method parameters
                if requests["count"] > 9:
                    raise Exception("Too many requests")
                self.assertEqual(("POST", "/clean"), args)
                expected_params = {"cid": shard_cid}
                if requests["count"] in (1, 3, 5, 6, 8, 9):
                    expected_params["urgent"] = 1
                self.assertDictEqual(expected_params, kwargs.get("params"))
                # Change the request and the response
                if requests["count"] in (2, 5, 8):
                    kwargs["timeout"] = 0.00001
                elif requests["count"] in (4, 7, 9):
                    return FakeResponse(503), b""
                resp, body = _request(*args, **kwargs)
                self.assertNotIn(requests["count"], (2, 4, 5, 7, 8, 9))
                resp.headers["x-oio-truncated"] = "true"
                return resp, body
            except (OioTimeout, ServiceBusy, DeadlineReached) as exc:
                if requests["count"] not in (2, 5, 8):
                    requests["unexpected_errors"].append(exc)
                raise
            except Exception as exc:
                requests["unexpected_errors"].append(exc)
                raise

        # Clean (again) the first shard
        shard_cid = shards[0]["cid"]
        with patch(
            "oio.container.sharding.ContainerSharding._request", wraps=_wrap_request
        ) as mock_request:
            _vacuum = self.container_sharding.admin.vacuum_base
            with patch(
                "oio.directory.admin.AdminClient.vacuum_base", wraps=_vacuum
            ) as mock_vacuum:
                self.assertRaises(
                    ServiceBusy,
                    self.container_sharding.clean_container,
                    None,
                    None,
                    cid=shards[0]["cid"],
                    attempts=3,
                )
                self.assertListEqual([], requests["unexpected_errors"])
            mock_vacuum.assert_not_called()
        self.assertEqual(9, mock_request.call_count)


class TestShardingObjectLockRetention(TestSharding):
    def setUp(self):
        super(TestShardingObjectLockRetention, self).setUp()
        self.cname = "test_sharding_retention_%f" % time.time()
        self.object_lock = True
        self.system = {
            M2_PROP_BUCKET_NAME: self.cname,
            "sys.m2.bucket.objectlock.enabled": "1",
        }
        now = datetime.now(timezone.utc) + timedelta(minutes=20)
        now_str = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        self.objects_properties = {
            "x-object-sysmeta-s3api-retention-retainuntildate": now_str,
            "x-object-sysmeta-s3api-retention-mode": "GOVERNANCE",
        }

    def _add_objects(
        self,
        cname,
        nb_objects,
        prefix="content",
        bucket=None,
        account=None,
        cname_root=None,
        properties=None,
    ):
        super(TestShardingObjectLockRetention, self)._add_objects(
            cname,
            nb_objects,
            prefix=prefix,
            bucket=bucket,
            account=account,
            cname_root=cname_root,
            properties=self.objects_properties,
        )

    def _delete_object(self, account, container, obj_name, reqid=None):
        self.wait_event = False
        self.assertRaises(
            Forbidden,
            self.storage.object_delete,
            account,
            container,
            obj_name,
            reqid=reqid,
        )

    def _check_shards_objectlock_properties(self, resp):
        # check obejctlock sysmeta
        objlock_enabled = resp["system"]["sys.m2.bucket.objectlock.enabled"]
        self.assertEqual(objlock_enabled, "1")

    def test_optimized_object_listing_several_prefixes(self):
        self.skip("This tests removes objects, cannot run it with Object Lock enabled")

    def test_optimized_object_listing_many_empty_shards(self):
        self.skip("This tests removes objects, cannot run it with Object Lock enabled")


class TestShardingObjectLockLegalHold(TestShardingObjectLockRetention):
    def setUp(self):
        super(TestShardingObjectLockLegalHold, self).setUp()
        self.cname = "test_sharding_legalhold_%f" % time.time()
        self.system = {
            M2_PROP_BUCKET_NAME: self.cname,
            "sys.m2.bucket.objectlock.enabled": "1",
        }
        self.objects_properties = {"x-object-sysmeta-s3api-legal-hold-status": "ON"}
