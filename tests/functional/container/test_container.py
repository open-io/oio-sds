# -*- coding: utf-8 -*-

# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2025 OVH SAS
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

import binascii
import logging
import random
import struct
import time

import simplejson as json

from oio.common import exceptions as exc
from oio.common.constants import (
    DELETEMARKER_HEADER,
    ENDUSERREQUEST_HEADER,
    FORCEVERSIONING_HEADER,
    M2_PROP_OBJECTS,
    M2_PROP_USAGE,
    OBJECT_METADATA_PREFIX,
    OIO_DB_DISABLED,
    OIO_DB_ENABLED,
    OIO_DB_FROZEN,
    OIO_DB_STATUS_NAME,
    SIMULATEVERSIONING_HEADER,
    VERSIONID_HEADER,
)
from oio.common.easy_value import boolean_value
from oio.common.utils import request_id
from oio.conscience.client import ConscienceClient
from oio.event.evob import EventTypes
from tests.utils import (
    CODE_POLICY_NOT_SUPPORTED,
    BaseTestCase,
    random_id,
    random_str,
    strange_paths,
)


def random_content():
    """Generate an object name."""
    return random_str(16)


def random_container():
    """Generate a container name."""
    return random_str(8)


def merge(s0, s1):
    """Create a new dict with entries from both input dicts."""
    out = dict()
    out.update(s0)
    out.update(s1)
    return out


def gen_chunks(n):
    """Yield dummy chunk descriptions."""
    for i in range(n):
        hexid = binascii.hexlify(struct.pack("q", i)).decode("utf-8")
        yield {
            "type": "chunk",
            "id": "http://127.0.0.1:6008/" + hexid,
            "hash": "0" * 32,
            "pos": "0.0",
            "size": 0,
            "ctime": 0,
            "content": hexid,
        }


def gen_names(width=8, depth=1):
    index = 0
    for c0 in range(width):
        for c1 in range(width):
            for x in range(depth):
                i, index = index, index + 1
                yield i, "{0}/{1}/{2}plop".format(c0, c1, x)


class TestMeta2Containers(BaseTestCase):
    def setUp(self):
        super(TestMeta2Containers, self).setUp()
        self.ref = f"TestMeta2Containers-{random_container()}"

    def __tearDown(self):
        super(TestMeta2Containers, self).tearDown()
        try:
            params = self.param_ref(self.ref)
            self.request(
                "POST",
                self.url_container("destroy"),
                params=params,
                headers={"X-oio-action-mode": "force"},
            )
            self.request(
                "POST",
                self._url_ref("destroy"),
                params=params,
                headers={"X-oio-action-mode": "force"},
            )
        except Exception as err:
            self.logger.debug("Failed to clean %s: %s", self.ref, err)

    def _create(self, params, code, autocreate=True):
        headers = {}
        if autocreate:
            headers["x-oio-action-mode"] = "autocreate"
        data = json.dumps({"properties": {}})
        resp = self.request(
            "POST",
            self.url_container("create"),
            params=params,
            data=data,
            headers=headers,
        )
        self.assertEqual(resp.status, code)

    def _delete(self, params):
        resp = self.request("POST", self.url_container("destroy"), params=params)
        self.assertEqual(resp.status, 204)
        resp = self.request(
            "POST",
            self._url_ref("destroy"),
            params=params,
            headers={"X-oio-action-mode": "force"},
        )
        self.assertEqual(resp.status, 204)

    def check_list_output(self, body, nbobj, nbpref):
        self.assertIsInstance(body, dict)
        self.assertIn("prefixes", body)
        self.assertIsInstance(body["prefixes"], list)
        self.assertEqual(len(body["prefixes"]), nbpref)
        self.assertIn("objects", body)
        self.assertIsInstance(body["objects"], list)
        self.assertEqual(len(body["objects"]), nbobj)

    def test_mass_delete(self):
        containers = []
        for i in range(50):
            container = f"test_mass_delete-{random_container()}"
            param = self.param_ref(container)
            self._create(param, 201)
            self._delete(param)
            containers.append(container)

        args = {"id": self.account, "prefix": "container-"}
        url = "".join(
            [
                "http://",
                self.conf["services"]["account"][0]["addr"],
                "/v1.0/account/containers",
            ]
        )
        resp = self.request("GET", url, params=args)
        self.assertEqual(resp.status, 200)
        data = self.json_loads(resp.data)

        for descr in data["listing"]:
            self.assertNotIn(descr[0], containers)

    def test_create_many(self):
        params = {"acct": self.account}
        headers = {}
        headers["x-oio-action-mode"] = "autocreate"
        headers["Content-Type"] = "application/json"

        # Create different uploads
        data = (
            '{"containers":'
            + '[{"name":"test1","properties":{},"system":{}},'
            + '{"name":"test2","properties":{},"system":{}}]}'
        )
        resp = self.request(
            "POST",
            self.url_container("create_many"),
            params=params,
            data=data,
            headers=headers,
        )
        self.assertEqual(resp.status, 200)
        data = self.json_loads(resp.data)["containers"]
        self.assertEqual(data[0]["status"], 201)
        self.assertEqual(data[1]["status"], 201)
        self._delete(self.param_ref("test1"))
        self._delete(self.param_ref("test2"))

        # Create same upload
        data = (
            '{"containers":'
            + '[{"name":"test1","properties":{},"system":{}},'
            + '{"name":"test1","properties":{},"system":{}}]}'
        )
        resp = self.request(
            "POST",
            self.url_container("create_many"),
            params=params,
            data=data,
            headers=headers,
        )
        self.assertEqual(resp.status, 200)
        data = self.json_loads(resp.data)["containers"]
        self.assertEqual(data[0]["status"], 201)
        self.assertEqual(data[1]["status"], 433)
        self._delete(self.param_ref("test1"))

        # Empty body should be answered with an error
        resp = self.request(
            "POST", self.url_container("create_many"), params=params, headers=headers
        )
        self.assertEqual(resp.status, 400)

        # Create with  missing name
        data = '{"containers":' + '[{"properties":{},"system":{}}' + "]}"
        resp = self.request(
            "POST",
            self.url_container("create_many"),
            params=params,
            data=data,
            headers=headers,
        )
        self.assertEqual(resp.status, 400)

        # Send a non conform json (missing '{')
        data = '{"containers":' + '["name":"test","properties":{},"system":{}}' + "]}"
        resp = self.request(
            "POST",
            self.url_container("create_many"),
            params=params,
            data=data,
            headers=headers,
        )
        self.assertEqual(resp.status, 400)

        # Don't send account
        data = '{"containers":' + '[{"name":"test1","properties":{},"system":{}}' + "]}"
        resp = self.request(
            "POST", self.url_container("create_many"), data=data, headers=headers
        )
        self.assertEqual(resp.status, 400)

        # Send empty array
        data = '{"containers":[]}'
        resp = self.request(
            "POST", self.url_container("create_many"), data=data, headers=headers
        )
        self.assertEqual(resp.status, 400)

    def _fill_content(self, width, depth):
        # Fill some contents
        for i, name in gen_names(width, depth):
            hexid = binascii.hexlify(struct.pack("q", i)).decode("utf-8")
            logging.debug("id=%s name=%s", hexid, name)
            chunk = {
                "url": "http://127.0.0.1:6008/" + hexid,
                "pos": "0",
                "size": 0,
                "hash": "0" * 32,
            }
            p = "X-oio-content-meta-"
            headers = {
                p + "policy": "NONE",
                p + "id": hexid,
                p + "version": "1",
                p + "hash": "0" * 32,
                p + "length": "0",
                p + "mime-type": "application/octet-stream",
                p + "chunk-method": "plain/nb_copy=3",
            }
            p = self.param_content(self.ref, name)
            body = json.dumps(
                [
                    chunk,
                ]
            )
            resp = self.request(
                "POST", self.url_content("create"), params=p, headers=headers, data=body
            )
            self.assertEqual(resp.status, 204)

    def test_list(self):
        params = self.param_ref(self.ref)
        self._create(params, 201)

        # Fill some contents
        self._fill_content(8, 1)

        params = self.param_ref(self.ref)
        # List everything
        resp = self.request("GET", self.url_container("list"), params=params)
        self.assertEqual(resp.status, 200)
        self.check_list_output(self.json_loads(resp.data), 64, 0)

        # List with a limit
        params["max"] = 3
        resp = self.request("GET", self.url_container("list"), params=params)
        self.assertEqual(resp.status, 200)
        self.check_list_output(self.json_loads(resp.data), 3, 0)
        del params["max"]

        # List with a delimiter
        params["delimiter"] = "/"
        resp = self.request("GET", self.url_container("list"), params=params)
        self.assertEqual(resp.status, 200)
        self.check_list_output(self.json_loads(resp.data), 0, 8)
        del params["delimiter"]

        # List with a string delimiter
        params["delimiter"] = "0/"
        resp = self.request("GET", self.url_container("list"), params=params)
        self.assertEqual(resp.status, 200)
        data = self.json_loads(resp.data)
        self.check_list_output(data, 49, 8)
        self.assertEqual(
            data["prefixes"],
            ["0/", "1/0/", "2/0/", "3/0/", "4/0/", "5/0/", "6/0/", "7/0/"],
        )
        del params["delimiter"]

        # List with a prefix
        params["prefix"] = "1/"
        resp = self.request("GET", self.url_container("list"), params=params)
        self.assertEqual(resp.status, 200)
        self.check_list_output(self.json_loads(resp.data), 8, 0)
        del params["prefix"]

        # List with a marker
        params["marker"] = "0/"
        resp = self.request("GET", self.url_container("list"), params=params)
        self.assertEqual(resp.status, 200)
        self.check_list_output(self.json_loads(resp.data), 64, 0)
        del params["marker"]

        # List with an end marker
        params["end_marker"] = "1/"
        resp = self.request("GET", self.url_container("list"), params=params)
        self.assertEqual(resp.status, 200)
        self.check_list_output(self.json_loads(resp.data), 8, 0)
        del params["end_marker"]

    def test_list_extend_delimiter(self):
        params = self.param_ref(self.ref)
        self._create(params, 201)

        # Fill some contents
        self._fill_content(4, 3)

        params = self.param_ref(self.ref)
        # List everything
        resp = self.request("GET", self.url_container("list"), params=params)
        self.assertEqual(resp.status, 200)
        self.check_list_output(self.json_loads(resp.data), 48, 0)

        # Empty delimiter
        params["delimiter"] = ""
        resp = self.request("GET", self.url_container("list"), params=params)
        self.assertEqual(resp.status, 200)
        data = self.json_loads(resp.data)
        self.check_list_output(data, 48, 0)
        del params["delimiter"]

        # List with a string delimiter
        params["delimiter"] = "0/1"
        resp = self.request("GET", self.url_container("list"), params=params)
        self.assertEqual(resp.status, 200)
        data = self.json_loads(resp.data)
        self.check_list_output(data, 41, 5)
        self.assertEqual(data["prefixes"], ["0/0/1", "0/1", "1/0/1", "2/0/1", "3/0/1"])
        del params["delimiter"]

        # List with a prefix and string delimiter
        params["prefix"] = "1/"
        params["delimiter"] = "3/"
        resp = self.request("GET", self.url_container("list"), params=params)
        self.assertEqual(resp.status, 200)
        data = self.json_loads(resp.data)
        self.check_list_output(data, 9, 1)
        self.assertEqual(data["prefixes"], ["1/3/"])
        del params["prefix"]
        del params["delimiter"]

        # List with a marker and delimiter
        params["marker"] = "2/"
        params["delimiter"] = "0/"
        resp = self.request("GET", self.url_container("list"), params=params)
        self.assertEqual(resp.status, 200)
        data = self.json_loads(resp.data)
        self.check_list_output(data, 18, 2)
        self.assertEqual(data["prefixes"], ["2/0/", "3/0/"])
        del params["marker"]
        del params["delimiter"]

        # Prefix is equal to delimiter
        params["prefix"] = "2/0/"
        params["delimiter"] = "2/0/"
        resp = self.request("GET", self.url_container("list"), params=params)
        self.assertEqual(resp.status, 200)
        data = self.json_loads(resp.data)
        self.check_list_output(data, 3, 0)
        del params["prefix"]
        del params["delimiter"]

    def test_list_too_long_marker(self):
        params = self.param_ref(self.ref)
        self._create(params, 201)
        self._create_content("a")
        self._create_content("z")

        params["marker"] = "a" * 1024
        resp = self.request("GET", self.url_container("list"), params=params)
        self.assertEqual(resp.status, 200)
        data = self.json_loads(resp.data)
        self.check_list_output(data, 1, 0)

        params["marker"] = "a" * 1087
        resp = self.request("GET", self.url_container("list"), params=params)
        self.assertEqual(resp.status, 200)
        self.check_list_output(data, 1, 0)

        params["marker"] = "a" * 1088
        resp = self.request("GET", self.url_container("list"), params=params)
        self.assertEqual(resp.status, 400)

        params["marker"] = "a" * 2048
        resp = self.request("GET", self.url_container("list"), params=params)
        self.assertEqual(resp.status, 400)

    def test_touch(self):
        params = self.param_ref(self.ref)
        resp = self.request("POST", self.url_container("touch"), params=params)
        self.assertEqual(resp.status, 403)
        self._create(params, 201)
        resp = self.request("POST", self.url_container("touch"), params=params)
        self.assertEqual(resp.status, 204)

    def _raw_insert(self, ref, what, exception=None, **kwargs):
        if exception:
            self.assertRaises(
                exception,
                self.storage.container.container_raw_insert,
                what,
                reference=ref,
                account=self.account,
                **kwargs,
            )
        else:
            self.storage.container.container_raw_insert(
                what, reference=ref, account=self.account, **kwargs
            )

    def test_raw(self):
        params = self.param_ref(self.ref)

        # Missing/invalid body
        self._raw_insert(self.ref, None, exception=exc.BadRequest)
        self._raw_insert(self.ref, "lmlkmlk", exception=exc.BadRequest)
        self._raw_insert(self.ref, 1, exception=exc.BadRequest)
        self._raw_insert(self.ref, [], exception=exc.BadRequest)
        self._raw_insert(self.ref, {}, exception=exc.BadRequest)
        self._raw_insert(self.ref, [{}], exception=exc.BadRequest)

        chunks = list(gen_chunks(16))
        # any missing field
        for i in ("type", "id", "hash", "pos", "size", "content"):

            def remove_field(x):
                x = dict(x)
                del x[i]
                return x

            self._raw_insert(
                self.ref, [remove_field(x) for x in chunks], exception=exc.BadRequest
            )

        # bad size
        c0 = list(map(lambda x: dict(x).update({"size": "0"}), chunks))
        self._raw_insert(self.ref, c0, exception=exc.BadRequest)
        # bad ctime
        c0 = list(map(lambda x: dict(x).update({"ctime": "0"}), chunks))
        self._raw_insert(self.ref, c0, exception=exc.BadRequest)
        # bad position
        c0 = list(map(lambda x: dict(x).update({"pos": 0}), chunks))
        self._raw_insert(self.ref, c0, exception=exc.BadRequest)
        # bad content
        c0 = list(map(lambda x: dict(x).update({"content": "x"}), chunks))
        self._raw_insert(self.ref, c0, exception=exc.BadRequest)
        # ok but no such container
        self._raw_insert(self.ref, chunks, exception=exc.NotFound)

        self._create(params, 201)
        expected_chunks, _, _, meta = self.storage.object_create_ext(
            self.account, self.ref, obj_name="test", data="123"
        )
        expected_chunks = sorted(expected_chunks, key=lambda c: c["url"])

        def generate_chunks_payload(content, chunks):
            return [
                {
                    "type": "chunk",
                    "id": c["url"],
                    "hash": c["hash"],
                    "size": c["size"],
                    "content": content,
                    "pos": c["pos"],
                }
                for c in chunks
            ]

        # Delete all chunks
        self.storage.container.container_raw_delete(
            self.account,
            self.ref,
            path="test",
            data=generate_chunks_payload(meta["id"], expected_chunks),
        )
        with self.assertRaises(exc.ServiceBusy) as e:
            self.storage.object_locate(self.account, self.ref, "test", chunk_info=True)
            self.assertRegex(e.msg, "chunks are missing")

        # Restore chunks
        self._raw_insert(
            self.ref, generate_chunks_payload(meta["id"], expected_chunks), path="test"
        )

        _, obj_chunks = self.storage.object_locate(
            self.account, self.ref, "test", chunk_info=False
        )
        self.assertIsNotNone(obj_chunks)
        obj_chunks = sorted(obj_chunks, key=lambda c: c["url"])
        for c in obj_chunks:
            c["hash"] = c["hash"].lower()
        self.assertEqual(len(expected_chunks), len(obj_chunks))
        for i in range(len(expected_chunks)):
            self.assertDictContainsSubset(obj_chunks[i], expected_chunks[i])

        # Insert arbitrary chunks
        self._raw_insert(self.ref, chunks, exception=exc.BadRequest)
        self._raw_insert(self.ref, chunks, force=True)

        # Insert chunks one by one
        for chunk in chunks:
            self._raw_insert(self.ref, chunk, force=True)

    def test_create_with_unknown_storage_policy(self):
        params = self.param_ref(self.ref)
        headers = {}
        headers["x-oio-action-mode"] = "autocreate"
        headers["Content-Type"] = "application/json"

        data = '{"properties":{},' + '"system":{"sys.m2.policy.storage": "unknown"}}'
        resp = self.request(
            "POST",
            self.url_container("create"),
            params=params,
            data=data,
            headers=headers,
        )
        self.assertEqual(resp.status, 400)
        data = self.json_loads(resp.data)
        self.assertEqual(data["status"], CODE_POLICY_NOT_SUPPORTED)

    def _test_create_with_status(self, status=None):
        def _status(_data):
            return _data["system"]["sys.status"]

        params = self.param_ref(self.ref)
        headers = {}
        headers["x-oio-action-mode"] = "autocreate"
        headers["Content-Type"] = "application/json"
        if status:
            data = '{"properties":{},' + '"system":{"sys.status": "%d"}}' % status
        else:
            data = None
            status = OIO_DB_ENABLED

        resp = self.request(
            "POST",
            self.url_container("create"),
            params=params,
            data=data,
            headers=headers,
        )
        self.assertEqual(resp.status, 201)

        resp = self.request("POST", self.url_container("get_properties"), params=params)
        data = self.json_loads(resp.data)
        self.assertEqual(
            OIO_DB_STATUS_NAME.get(_status(data), "Unknown"), OIO_DB_STATUS_NAME[status]
        )

    def test_create_without_status(self):
        self._test_create_with_status(None)

    def test_create_with_enabled_status(self):
        self._test_create_with_status(OIO_DB_ENABLED)

    def test_create_with_frozen_status(self):
        self._test_create_with_status(OIO_DB_FROZEN)

    def test_create_with_disabled_status(self):
        self._test_create_with_status(OIO_DB_DISABLED)

    def test_cycle_properties(self):
        params = self.param_ref(self.ref)

        def check_properties(expected):
            resp = self.request(
                "POST", self.url_container("get_properties"), params=params
            )
            self.assertEqual(resp.status, 200)
            body = self.json_loads(resp.data)
            self.assertIsInstance(body, dict)
            self.assertIsInstance(body.get("properties"), dict)
            self.assertDictEqual(expected, body["properties"])

        def del_properties(keys):
            resp = self.request(
                "POST",
                self.url_container("del_properties"),
                params=params,
                data=json.dumps(keys),
            )
            self.assertEqual(resp.status, 204)

        def set_properties(kv):
            resp = self.request(
                "POST",
                self.url_container("set_properties"),
                params=params,
                data=json.dumps({"properties": kv}),
            )
            self.assertEqual(resp.status, 204)

        # GetProperties on no container
        resp = self.request("POST", self.url_container("get_properties"), params=params)
        self.assertError(resp, 404, 406)

        # Create the container
        self._create(params, 201)

        p0 = {random_content(): random_content()}
        p1 = {random_content(): random_content()}

        check_properties({})
        set_properties(p0)
        check_properties(p0)
        set_properties(p1)
        check_properties(merge(p0, p1))
        del_properties(list(p0.keys()))
        check_properties(p1)
        del_properties(list(p0.keys()))
        check_properties(p1)

    def _create_content(self, name, version=None, headers_add=None, create_status=204):
        headers = {"X-oio-action-mode": "autocreate"}
        params = self.param_content(self.ref, name, version=version)

        resp = self.request(
            "POST",
            self.url_content("prepare"),
            params=params,
            headers=headers,
            data=json.dumps({"size": "1024"}),
        )
        self.assertEqual(200, resp.status)
        chunks = self.json_loads(resp.data)

        stgpol = resp.headers.get("x-oio-content-meta-policy")
        version = resp.headers.get("x-oio-content-meta-version")
        headers = {
            "x-oio-action-mode": "autocreate",
            "x-oio-content-meta-size": "1024",
            "x-oio-content-meta-policy": stgpol,
            "x-oio-content-meta-version": version,
            "x-oio-content-meta-id": random_id(32),
        }

        if headers_add:
            headers.update(headers_add)
        resp = self.request(
            "POST",
            self.url_content("create"),
            params=params,
            headers=headers,
            data=json.dumps(chunks),
        )
        self.assertEqual(create_status, resp.status)

    def _append_content(self, name):
        headers = {"X-oio-action-mode": "autocreate"}
        params = self.param_content(self.ref, name)
        resp = self.request(
            "POST",
            self.url_content("prepare"),
            params=params,
            headers=headers,
            data=json.dumps({"size": "1024"}),
        )
        self.assertEqual(resp.status, 200)
        chunks = self.json_loads(resp.data)

        params["append"] = 1
        stgpol = resp.headers.get("x-oio-content-meta-policy")
        chunk_method = resp.headers.get("x-oio-content-meta-chunk-method")
        headers = {
            "x-oio-action-mode": "autocreate",
            "x-oio-content-meta-length": "1024",
            "x-oio-content-meta-policy": stgpol,
            "x-oio-content-meta-chunk-method": chunk_method,
            "x-oio-content-meta-id": random_id(32),
        }
        resp = self.request(
            "POST",
            self.url_content("create"),
            params=params,
            headers=headers,
            data=json.dumps(chunks),
        )
        self.assertEqual(204, resp.status)

    def _truncate_content(self, name):
        params = self.param_content(self.ref, name)
        params["size"] = 1048576
        resp = self.request("POST", self.url_content("truncate"), params=params)
        self.assertEqual(204, resp.status)

    def test_purge(self):
        params = self.param_ref(self.ref)

        # no container
        resp = self.request("POST", self.url_container("purge"), params=params)
        self.assertEqual(404, resp.status)

        def purge_and_check(expected_object):
            resp = self.request("POST", self.url_container("purge"), params=params)
            self.assertEqual(204, resp.status)
            resp = self.request(
                "POST", self.url_container("get_properties"), params=params
            )
            data = self.json_loads(resp.data)
            self.assertEqual(str(expected_object), data["system"][M2_PROP_OBJECTS])
            resp = self.request(
                "GET", self.url_container("list"), params=merge(params, {"all": 1})
            )
            data = self.json_loads(resp.data)
            self.assertEqual(expected_object, len(data["objects"]))

        # empty container
        self._create(params, 201)
        props = {"system": {"sys.m2.policy.version": "3"}}
        resp = self.request(
            "POST",
            self.url_container("set_properties"),
            params=params,
            data=json.dumps(props),
        )
        purge_and_check(0)

        # one content
        self._create_content("content")
        purge_and_check(1)

        # many contents
        for i in range(50):
            self._create_content("content")
            self._create_content("content2")
        purge_and_check(6)

    def _wait_account_meta2(self):
        # give account and meta2 time to catch their breath
        wait = False
        cluster = ConscienceClient({"namespace": self.ns})
        for i in range(10):
            try:
                for service in cluster.all_services("account"):
                    # Score depends only on CPU usage.
                    if int(service["score"]) < 70:
                        wait = True
                        continue
                if not wait:
                    for service in cluster.all_services("meta2"):
                        # Score depends also on available storage.
                        if int(service["score"]) < 50:
                            wait = True
                            continue
                    if not wait:
                        return
            except exc.OioException:
                pass
            wait = False
            time.sleep(5)
        else:
            logging.warning(
                "Some scores may still be low, but we already waited for 50 seconds"
            )

    def test_flush(self):
        params = self.param_ref(self.ref)

        # no container
        resp = self.request("POST", self.url_container("flush"), params=params)
        self.assertEqual(404, resp.status)

        def flush_and_check(truncated=False, objects=0, usage=0):
            resp = self.request("POST", self.url_container("flush"), params=params)
            self.assertEqual(204, resp.status)
            self.assertEqual(
                truncated, boolean_value(resp.headers.get("x-oio-truncated"))
            )
            self._wait_account_meta2()
            resp = self.request(
                "POST", self.url_container("get_properties"), params=params
            )
            data = self.json_loads(resp.data)
            self.assertEqual(data["system"][M2_PROP_OBJECTS], str(objects))
            self.assertEqual(data["system"][M2_PROP_USAGE], str(usage))
            if objects:
                self.assertEqual(
                    objects,
                    sum(
                        (
                            int(v)
                            for k, v in data["system"].items()
                            if k.startswith(M2_PROP_OBJECTS + ".")
                        )
                    ),
                )
            if usage:
                self.assertEqual(
                    usage,
                    sum(
                        (
                            int(v)
                            for k, v in data["system"].items()
                            if k.startswith(M2_PROP_USAGE + ".")
                        )
                    ),
                )
            resp = self.request("GET", self.url_container("list"), params=params)
            data = self.json_loads(resp.data)
            self.assertEqual(len(data["objects"]), objects)

        # empty container
        self._create(params, 201)
        flush_and_check()

        # one content
        self._create_content("content")
        flush_and_check()

        # many contents
        for i in range(80):
            self._create_content("content%02d" % i)
        flush_and_check(truncated=True, objects=16, usage=16384)
        flush_and_check()

    def _delete_content(self, obj_name, headers=None):
        params = self.param_content(self.ref, obj_name)
        resp = self.request(
            "POST", self.url_content("delete"), params=params, headers=headers
        )
        self.assertEqual(resp.status, 204)

    def test_object_with_versioning_header(self):
        path = random_content()
        params = self.param_ref(self.ref)

        self._create_content(path)
        resp = self.request("POST", self.url_container("get_properties"), params=params)

        data = json.loads(resp.data)
        self.assertNotIn("sys.m2.policy.version", data["system"].keys())

        self._create_content(path, headers_add={FORCEVERSIONING_HEADER: 1})
        resp = self.request("POST", self.url_container("get_properties"), params=params)
        data = json.loads(resp.data)
        self.assertEqual("1", data["system"].get("sys.m2.policy.version", 0))

        self._create_content(path, headers_add={FORCEVERSIONING_HEADER: -1})
        resp = self.request("POST", self.url_container("get_properties"), params=params)
        data = json.loads(resp.data)
        self.assertEqual("-1", data["system"].get("sys.m2.policy.version", 0))

        resp = self.request(
            "GET", self.url_container("list"), params=merge(params, {"all": 1})
        )
        data = json.loads(resp.data)
        self.assertEqual(2, len(data["objects"]))

        self._delete_content(path, headers={FORCEVERSIONING_HEADER: 1})
        resp = self.request("POST", self.url_container("get_properties"), params=params)
        data = json.loads(resp.data)
        self.assertEqual("1", data["system"].get("sys.m2.policy.version", 0))

        resp = self.request(
            "GET", self.url_container("list"), params=merge(params, {"all": 1})
        )
        data = json.loads(resp.data)
        self.assertEqual(1, len(data["objects"]))

        self._delete_content(path, headers={FORCEVERSIONING_HEADER: -1})
        resp = self.request("POST", self.url_container("get_properties"), params=params)
        data = json.loads(resp.data)
        self.assertEqual("-1", data["system"].get("sys.m2.policy.version", 0))

        resp = self.request(
            "GET", self.url_container("list"), params=merge(params, {"all": 1})
        )
        data = json.loads(resp.data)
        self.assertEqual(2, len(data["objects"]))
        self.assertTrue(data["objects"][0]["deleted"])

    def test_object_with_versioning_header_with_delete_many(self):
        params = self.param_ref(self.ref)
        objs = []

        for _ in range(10):
            path = random_content()
            objs.append(path)
            self._create_content(path)

        resp = self.request("POST", self.url_container("get_properties"), params=params)
        data = json.loads(resp.data)
        self.assertNotIn("sys.m2.policy.version", data["system"].keys())

        # delete two objects without header
        data = {"contents": [{"name": objs.pop()}, {"name": objs.pop()}]}
        resp = self.request(
            "POST",
            self.url_content("delete_many"),
            params=params,
            data=json.dumps(data),
        )
        resp = self.request("POST", self.url_container("get_properties"), params=params)
        data = json.loads(resp.data)
        self.assertNotIn("sys.m2.policy.version", data["system"].keys())
        self.assertEqual("8", data["system"].get(M2_PROP_OBJECTS, -1))

        # delete two objects with header enabling versioning
        data = {"contents": [{"name": objs.pop()}, {"name": objs.pop()}]}
        resp = self.request(
            "POST",
            self.url_content("delete_many"),
            params=params,
            data=json.dumps(data),
            headers={FORCEVERSIONING_HEADER: -1},
        )
        self.assertEqual(resp.status, 200)

        resp = self.request("POST", self.url_container("get_properties"), params=params)
        data = json.loads(resp.data)
        self.assertEqual("-1", data["system"].get("sys.m2.policy.version", 0))

        resp = self.request(
            "GET", self.url_container("list"), params=merge(params, {"all": 1})
        )
        data = json.loads(resp.data)
        self.assertEqual(10, len(data["objects"]))

        resp = self.request("GET", self.url_container("list"), params=params)
        data = json.loads(resp.data)
        self.assertEqual(6, len(data["objects"]))

        # delete two objects with header disabling versioning
        data = {"contents": [{"name": objs.pop()}, {"name": objs.pop()}]}
        resp = self.request(
            "POST",
            self.url_content("delete_many"),
            params=params,
            data=json.dumps(data),
            headers={FORCEVERSIONING_HEADER: 1},
        )
        self.assertEqual(resp.status, 200)

        resp = self.request("POST", self.url_container("get_properties"), params=params)
        data = json.loads(resp.data)
        self.assertEqual("1", data["system"].get("sys.m2.policy.version", 0))

        resp = self.request(
            "GET", self.url_container("list"), params=merge(params, {"all": 1})
        )
        data = json.loads(resp.data)
        self.assertEqual(8, len(data["objects"]))

    def test_object_by_simulating_versioning(self):
        path = random_content()
        params_container = self.param_ref(self.ref)
        headers = {SIMULATEVERSIONING_HEADER: 1}
        versions = dict()

        def _check(max_versions=None):
            resp = self.request(
                "POST", self.url_container("get_properties"), params=params_container
            )
            data = json.loads(resp.data)
            self.assertEqual(
                str(
                    len(
                        [
                            version
                            for version, deleted in versions.items()
                            if not deleted
                        ]
                    )
                ),
                data["system"][M2_PROP_OBJECTS],
            )
            if max_versions is None:
                self.assertNotIn("sys.m2.policy.version", data["system"].keys())
            else:
                self.assertEqual(
                    data["system"]["sys.m2.policy.version"], str(max_versions)
                )
            param_content = self.param_content(self.ref, path)
            resp = self.request(
                "POST", self.url_content("get_properties"), params=param_content
            )
            sorted_versions = list(versions.keys())
            sorted_versions.sort()
            self.assertEqual(200, resp.status)
            self.assertEqual(
                str(sorted_versions[-1]),
                resp.headers[OBJECT_METADATA_PREFIX + "version"],
            )

            for version in versions:
                param_content = self.param_content(self.ref, path, version=version)
                resp = self.request(
                    "POST", self.url_content("get_properties"), params=param_content
                )
                self.assertEqual(200, resp.status)

        def _set_max_version(max_versions):
            props = {"system": {"sys.m2.policy.version": str(max_versions)}}
            resp = self.request(
                "POST",
                self.url_container("set_properties"),
                params=params_container,
                data=json.dumps(props),
            )
            self.assertEqual(204, resp.status)

        def _random_delete_object():
            version = random.choice(list(versions))
            param_content = self.param_content(self.ref, path, version=version)
            resp = self.request(
                "POST",
                self.url_content("delete"),
                params=param_content,
                headers=headers,
            )
            self.assertEqual(204, resp.status)

            resp = self.request(
                "POST", self.url_content("get_properties"), params=param_content
            )
            self.assertEqual(404, resp.status)
            del versions[version]

        def _create_delete_marker():
            param_content = self.param_content(self.ref, path)
            resp = self.request(
                "POST",
                self.url_content("delete"),
                params=param_content,
                headers=headers,
            )
            self.assertEqual(204, resp.status)
            self.assertIn(DELETEMARKER_HEADER, resp.headers)
            self.assertIn(VERSIONID_HEADER, resp.headers)
            sorted_versions = list(versions.keys())
            sorted_versions.sort()
            versions[sorted_versions[-1] + 1] = True

        # Default versioning
        version = int(time.time() * 1000000)
        self._create_content(path, version=version, headers_add=headers)
        versions[version] = False
        _check()

        version += 10
        self._create_content(path, version=version, headers_add=headers)
        versions[version] = False
        _check()

        version -= 5
        self._create_content(path, version=version, headers_add=headers)
        versions[version] = False
        _check()

        _random_delete_object()
        _check()

        _create_delete_marker()
        _check()

        # Versioning unlimited
        _set_max_version(-1)
        version += 15
        self._create_content(path, version=version, headers_add=headers)
        versions[version] = False
        _check(max_versions=-1)

        version -= 5
        self._create_content(path, version=version, headers_add=headers)
        versions[version] = False
        _check(max_versions=-1)

        _random_delete_object()
        _check(max_versions=-1)

        _create_delete_marker()
        _check(max_versions=-1)

        # Versioning disabled
        _set_max_version(0)
        version += 15
        self._create_content(path, version=version, headers_add=headers)
        versions[version] = False
        _check(max_versions=0)

        version -= 5
        self._create_content(path, version=version, headers_add=headers)
        versions[version] = False
        _check(max_versions=0)

        _random_delete_object()
        _check(max_versions=0)

        _create_delete_marker()
        _check(max_versions=0)

        # Versioning suspended
        _set_max_version(1)
        version += 15
        self._create_content(path, version=version, headers_add=headers)
        versions[version] = False
        _check(max_versions=1)

        version -= 5
        self._create_content(path, version=version, headers_add=headers)
        versions[version] = False
        _check(max_versions=1)

        _random_delete_object()
        _check(max_versions=1)

        _create_delete_marker()
        _check(max_versions=1)

    def test_object_with_specific_delete_marker(self):
        path = random_content()
        params_container = self.param_ref(self.ref)
        param_content = self.param_content(self.ref, path)
        param_content["delete_marker"] = 1

        # Create the first object version
        self._create_content(path, version=12345)

        # Versioning not enabled
        resp = self.request("POST", self.url_content("delete"), params=param_content)
        self.assertEqual(400, resp.status)

        # Versioning enabled
        props = {"system": {"sys.m2.policy.version": "-1"}}
        resp = self.request(
            "POST",
            self.url_container("set_properties"),
            params=params_container,
            data=json.dumps(props),
        )
        self.assertEqual(204, resp.status)

        # Create delete marker without version
        resp = self.request("POST", self.url_content("delete"), params=param_content)
        self.assertEqual(400, resp.status)

        # Create delete marker with the same version
        param_content["version"] = 12345
        resp = self.request("POST", self.url_content("delete"), params=param_content)
        self.assertEqual(409, resp.status)
        resp = self.request(
            "POST", self.url_content("get_properties"), params=param_content
        )
        self.assertEqual(200, resp.status)
        self.assertEqual("12345", resp.headers[OBJECT_METADATA_PREFIX + "version"])
        self.assertEqual("False", resp.headers[OBJECT_METADATA_PREFIX + "deleted"])

        # Create delete marker after the first object version
        param_content["version"] = 123456
        resp = self.request("POST", self.url_content("delete"), params=param_content)
        self.assertEqual(204, resp.status)
        self.assertIn(DELETEMARKER_HEADER, resp.headers)
        self.assertEqual(
            str(param_content["version"]), resp.headers.get(VERSIONID_HEADER)
        )
        resp = self.request(
            "POST", self.url_content("get_properties"), params=param_content
        )
        self.assertEqual(200, resp.status)
        self.assertEqual("123456", resp.headers[OBJECT_METADATA_PREFIX + "version"])
        self.assertEqual("True", resp.headers[OBJECT_METADATA_PREFIX + "deleted"])
        param_content["version"] = 12345
        resp = self.request(
            "POST", self.url_content("get_properties"), params=param_content
        )
        self.assertEqual(200, resp.status)
        self.assertEqual("12345", resp.headers[OBJECT_METADATA_PREFIX + "version"])
        self.assertEqual("False", resp.headers[OBJECT_METADATA_PREFIX + "deleted"])

        # Create delete marker before the first object version
        param_content["version"] = 1234
        resp = self.request("POST", self.url_content("delete"), params=param_content)
        self.assertEqual(204, resp.status)
        self.assertIn(DELETEMARKER_HEADER, resp.headers)
        self.assertEqual(
            str(param_content["version"]), resp.headers.get(VERSIONID_HEADER)
        )
        resp = self.request(
            "POST", self.url_content("get_properties"), params=param_content
        )
        self.assertEqual(200, resp.status)
        self.assertEqual("1234", resp.headers[OBJECT_METADATA_PREFIX + "version"])
        self.assertEqual("True", resp.headers[OBJECT_METADATA_PREFIX + "deleted"])
        param_content["version"] = 12345
        resp = self.request(
            "POST", self.url_content("get_properties"), params=param_content
        )
        self.assertEqual(200, resp.status)
        self.assertEqual("12345", resp.headers[OBJECT_METADATA_PREFIX + "version"])
        self.assertEqual("False", resp.headers[OBJECT_METADATA_PREFIX + "deleted"])

        # Create a delete marker for an object that does not exist
        param_content["path"] = random_content()
        resp = self.request("POST", self.url_content("delete"), params=param_content)
        self.assertEqual(204, resp.status)
        self.assertIn(DELETEMARKER_HEADER, resp.headers)
        self.assertEqual(
            str(param_content["version"]), resp.headers.get(VERSIONID_HEADER)
        )
        resp = self.request(
            "POST", self.url_content("get_properties"), params=param_content
        )
        self.assertEqual(200, resp.status)
        self.assertEqual("12345", resp.headers[OBJECT_METADATA_PREFIX + "version"])
        self.assertEqual("True", resp.headers[OBJECT_METADATA_PREFIX + "deleted"])

    def test_object_with_versioned_objects_before_latest(self):
        path = random_content()
        params_container = self.param_ref(self.ref)

        self._create_content(path)
        props = {"system": {"sys.m2.policy.version": "-1"}}
        resp = self.request(
            "POST",
            self.url_container("set_properties"),
            params=params_container,
            data=json.dumps(props),
        )
        self.assertEqual(204, resp.status)

        self._create_content(path, version=12345)
        self._create_content(path, version=12345, create_status=409)

    def test_drain_during_sharding(self):
        path = random_content()
        params_container = self.param_ref(self.ref)
        self._create_content(path)

        system = [
            {"sys.m2.sharding.state": "129"},  # sharding in progress
            {
                "sys.m2.sharding.root": "1" * 64,
                "sys.m2.sharding.state": "3",
            },  # root container
        ]
        for sys in system:
            props = {"system": sys}
            resp = self.request(
                "POST",
                self.url_container("set_properties"),
                params=params_container,
                data=json.dumps(props),
            )
            self.assertEqual(204, resp.status)

            # Try to drain
            resp = self.request(
                "POST",
                self.url_container("drain"),
                params=params_container,
            )
            self.assertEqual(400, resp.status)

            # No object drain
            params_content = params_container.copy()
            params_content["path"] = path
            resp = self.request(
                "GET", self.url_content("locate"), params=params_content
            )
            self.assertEqual(resp.status, 200)


class TestMeta2Contents(BaseTestCase):
    def setUp(self):
        super(TestMeta2Contents, self).setUp()
        self.ref = f"TestMeta2Contents-{random_container()}"

    @classmethod
    def setUpClass(cls):
        super(TestMeta2Contents, cls).setUpClass()
        cls._cls_mpu_consumer = cls._register_consumer(topic="oio-delete-mpu-parts")
        cls._cls_reload_meta()
        cls._cls_reload_proxy()

    def tearDown(self):
        super(TestMeta2Contents, self).tearDown()
        try:
            params = self.param_ref(self.ref)
            self.request(
                "POST",
                self.url_container("destroy"),
                params=params,
                headers={"X-oio-action-mode": "force"},
            )
            self.request(
                "POST",
                self._url_ref("destroy"),
                params=params,
                headers={"X-oio-action-mode": "force"},
            )
        except Exception:
            pass

    def valid_chunks(self, tab, end_user_request):
        self.assertIsInstance(tab, list)
        for chunk in tab:
            self.assertIsInstance(chunk, dict)
            expected_keys = ["url", "pos", "hash", "size", "score", "real_url"]
            if not end_user_request:
                expected_keys.append("internal_url")
            self.assertListEqual(
                sorted(chunk.keys()),
                sorted(expected_keys),
            )
            self.assertIsInstance(chunk["size"], int)
        return True

    def _test_prepare(self, end_user_request=False):
        params = self.param_content(self.ref, random_content())
        headers = {}
        if end_user_request:
            headers[ENDUSERREQUEST_HEADER] = True

        resp = self.request(
            "POST", self.url_content("prepare"), params=params, headers=headers
        )
        self.assertError(resp, 400, 400)
        # A content/prepare now works despite the container is not created
        resp = self.request(
            "POST",
            self.url_content("prepare"),
            params=params,
            headers=headers,
            data=json.dumps({"size": 1024}),
        )
        self.assertTrue(self.valid_chunks(self.json_loads(resp.data), end_user_request))
        # TODO test /content/prepare with additional useless parameters
        # TODO test /content/prepare with invalid sizes

    def test_prepare(self):
        self._test_prepare()

    def test_prepare_client_request(self):
        self._test_prepare(True)

    def test_create_without_content_id(self):
        headers = {"X-oio-action-mode": "autocreate"}
        params = self.param_content(self.ref, random_content())
        resp = self.request(
            "POST",
            self.url_content("prepare"),
            params=params,
            headers=headers,
            data=json.dumps({"size": "1024"}),
        )
        self.assertEqual(resp.status, 200)
        chunks = self.json_loads(resp.data)

        stgpol = resp.headers.get("x-oio-content-meta-policy")
        headers = {
            "x-oio-action-mode": "autocreate",
            "x-oio-content-meta-size": "1024",
            "x-oio-content-meta-policy": stgpol,
        }
        resp = self.request(
            "POST",
            self.url_content("create"),
            params=params,
            headers=headers,
            data=json.dumps(chunks),
        )
        self.assertEqual(resp.status, 400)

    def test_spare_with_one_missing(self):
        stg_policy = self.conscience.info().get("options", dict()).get("storage_policy")
        headers = {"X-oio-action-mode": "autocreate"}
        params = self.param_content(self.ref, random_content())
        params.update({"stgpol": stg_policy})
        resp = self.request(
            "POST",
            self.url_content("prepare2"),
            params=params,
            data=json.dumps({"size": 1024}),
            headers=headers,
        )
        obj_meta = self.json_loads(resp.data)
        # Get a list of chunks for future spare request
        chunks = obj_meta["chunks"]
        # Extract one chunk from the list
        chunks.pop()
        if len(chunks) < 1:
            self.skipTest("Must run with a storage policy requiring more than 1 chunk")

        # Do the spare request, specify that we already know some chunks
        resp = self.request(
            "POST",
            self.url_content("spare"),
            params=params,
            data=json.dumps({"notin": chunks, "broken": []}),
        )
        self.assertEqual(resp.status, 200)
        spare_data = self.json_loads(resp.data)
        # Since we extracted one chunk, there must be exactly one chunk in
        # the response (plus one property telling the "quality" of the chunk)
        self.assertEqual(1, len(spare_data["chunks"]))
        self.assertEqual(1, len(spare_data["properties"]))

    def _test_spare_with_n_broken(self, count_broken):
        stg_policy = self.conscience.info().get("options", dict()).get("storage_policy")

        headers = {"X-oio-action-mode": "autocreate"}
        params = self.param_content(self.ref, random_content())
        params.update({"stgpol": stg_policy})
        resp = self.request(
            "POST",
            self.url_content("prepare2"),
            params=params,
            data=json.dumps({"size": 1024}),
            headers=headers,
        )
        obj_meta = self.json_loads(resp.data)
        # Get a list of chunks for future spare request
        chunks = obj_meta["chunks"]
        if len(chunks) < count_broken + 1:
            self.skipTest(
                "Must run with a storage policy requiring more than %d chunk"
                % count_broken
            )
        elif len(self.conf["services"]["rawx"]) < len(chunks) + 1:
            self.skipTest("Not enough rawx services (%d+1 required)" % len(chunks))

        # Extract one chunk from the list, keep it for later
        broken = [chunks.pop() for _ in range(count_broken)]

        # Do the spare request, specify that we already know some chunks,
        # and we know some chunk location is broken.
        resp = self.request(
            "POST",
            self.url_content("spare"),
            params=params,
            data=json.dumps({"notin": chunks, "broken": broken}),
        )
        self.assertEqual(resp.status, 200)
        spare_data = self.json_loads(resp.data)
        # Since we extracted N chunks, there must be exactly N chunks in
        # the response (plus N properties telling the "quality" of the chunks).
        self.assertEqual(count_broken, len(spare_data["chunks"]))
        self.assertEqual(count_broken, len(spare_data["properties"]))
        broken_netlocs = {b["url"].split("/")[2] for b in broken}
        spare_netlocs = {s["id"].split("/")[2] for s in spare_data["chunks"]}
        # There should be no elements in common.
        self.assertFalse(broken_netlocs.intersection(spare_netlocs))

    def test_spare_with_1_broken(self):
        return self._test_spare_with_n_broken(1)

    def test_spare_with_2_broken(self):
        return self._test_spare_with_n_broken(2)

    def test_spare_with_3_broken(self):
        return self._test_spare_with_n_broken(3)

    def test_spare_errors(self):
        params = self.param_content(self.ref, random_content())
        resp = self.request("POST", self.url_content("spare"), params=params)
        self.assertError(resp, 400, 400)
        resp = self.request(
            "POST", self.url_content("spare"), params=params, data=json.dumps({})
        )
        self.assertError(resp, 400, 400)
        resp = self.request(
            "POST",
            self.url_content("spare"),
            params=params,
            data=json.dumps({"notin": "", "broken": ""}),
        )
        self.assertError(resp, 400, 400)
        resp = self.request(
            "POST",
            self.url_content("spare"),
            params=params,
            data=json.dumps({"notin": [], "broken": []}),
        )
        self.assertError(resp, 400, 400)

    def _create_content(self, name, expected_status_create=204, restore_drained=False):
        headers = {"X-oio-action-mode": "autocreate"}
        params = self.param_content(self.ref, name)
        resp = self.request(
            "POST",
            self.url_content("prepare"),
            params=params,
            headers=headers,
            data=json.dumps({"size": "1024"}),
        )
        self.assertEqual(resp.status, 200)
        chunks = self.json_loads(resp.data)

        stgpol = resp.headers.get("x-oio-content-meta-policy")
        headers = {
            "x-oio-action-mode": "autocreate",
            "x-oio-content-meta-size": "1024",
            "x-oio-content-meta-policy": stgpol,
            "x-oio-content-meta-version": int(time.time() * 1000000),
            "x-oio-content-meta-id": random_id(32),
        }
        if restore_drained:
            params["restore_drained"] = "1"
        resp = self.request(
            "POST",
            self.url_content("create"),
            params=params,
            headers=headers,
            data=json.dumps(chunks),
        )
        self.assertEqual(resp.status, expected_status_create)

    def test_delete_many(self):
        # Send no account
        params = self.param_ref(self.ref)
        params["acct"] = ""
        resp = self.request("POST", self.url_content("delete_many"), params=params)
        self.assertError(resp, 400, 400)

        # Send no container
        params = self.param_ref("")
        resp = self.request("POST", self.url_content("delete_many"), params=params)
        self.assertError(resp, 400, 400)

        # Send empty body
        params = self.param_ref(self.ref)
        resp = self.request("POST", self.url_content("delete_many"), params=params)
        self.assertError(resp, 400, 400)

        # Send empty content
        data = '{"contents"}'
        resp = self.request(
            "POST", self.url_content("delete_many"), params=params, data=data
        )
        self.assertError(resp, 400, 400)

        # Send empty array
        data = '{"contents":[]}'
        resp = self.request(
            "POST", self.url_content("delete_many"), params=params, data=data
        )
        self.assertError(resp, 400, 400)

        # Send one existent
        self._create_content("should_exist")
        data = '{"contents":[{"name":"should_exist"}]}'
        resp = self.request(
            "POST", self.url_content("delete_many"), params=params, data=data
        )
        json_data = self.json_loads(resp.data)
        self.assertEqual(resp.status, 200)
        self.assertEqual(json_data["contents"][0]["status"], 204)

        # Send one nonexistent
        data = '{"contents":[{"name":"should_not_exist"}]}'
        resp = self.request(
            "POST", self.url_content("delete_many"), params=params, data=data
        )
        json_data = self.json_loads(resp.data)
        self.assertEqual(json_data["contents"][0]["status"], 420)
        # Send one existent and one nonexistent
        self._create_content("should_exist")
        data = '{"contents":[{"name":"should_exist"},' + '{"name":"should_not_exist"}]}'
        resp = self.request(
            "POST", self.url_content("delete_many"), params=params, data=data
        )
        json_data = self.json_loads(resp.data)
        self.assertEqual(resp.status, 200)
        self.assertEqual(json_data["contents"][0]["status"], 204)
        self.assertEqual(json_data["contents"][1]["status"], 420)
        # Send 2 nonexistents
        data = (
            '{"contents":[{"name":"should_not_exist"},'
            + '{"name":"should_also_not_exist"}]}'
        )
        resp = self.request(
            "POST", self.url_content("delete_many"), params=params, data=data
        )
        json_data = self.json_loads(resp.data)
        self.assertEqual(json_data["contents"][0]["status"], 420)
        self.assertEqual(json_data["contents"][1]["status"], 420)
        # Send 2 existents
        self._create_content("should_exist")
        self._create_content("should_also_exist")
        data = (
            '{"contents":[{"name":"should_exist"},' + '{"name":"should_also_exist"}]}'
        )
        resp = self.request(
            "POST", self.url_content("delete_many"), params=params, data=data
        )
        json_data = self.json_loads(resp.data)
        self.assertEqual(resp.status, 200)
        self.assertEqual(json_data["contents"][0]["status"], 204)
        self.assertEqual(json_data["contents"][1]["status"], 204)

        contents = []
        for name in strange_paths:
            self._create_content(name)
            contents.append({"name": name})
        data = json.dumps({"contents": contents})
        resp = self.request(
            "POST", self.url_content("delete_many"), params=params, data=data
        )
        json_data = self.json_loads(resp.data)
        self.assertEqual(resp.status, 200)
        for r in json_data["contents"]:
            self.assertEqual(r["status"], 204)

    def test_cycle_properties(self):
        path = random_content()
        params = self.param_content(self.ref, path)

        def get_ok(expected):
            resp = self.request(
                "POST", self.url_content("get_properties"), params=params
            )
            self.assertEqual(resp.status, 200)
            body = self.json_loads(resp.data)
            self.assertIsInstance(body, dict)
            self.assertIsInstance(body.get("properties"), dict)
            self.assertDictEqual(expected, body["properties"])

        def del_ok(keys):
            resp = self.request(
                "POST",
                self.url_content("del_properties"),
                params=params,
                data=json.dumps(list(keys)),
            )
            self.assertEqual(resp.status, 204)

        def set_ok(kv):
            resp = self.request(
                "POST",
                self.url_content("set_properties"),
                params=params,
                data=json.dumps({"properties": kv}),
            )
            self.assertEqual(resp.status, 204)

        # GetProperties on no content
        resp = self.request("POST", self.url_content("get_properties"), params=params)
        self.assertError(resp, 404, 406)

        # Create the content
        self._create_content(path)

        p0 = {random_content(): random_content()}
        p1 = {random_content(): random_content()}

        get_ok({})
        set_ok(p0)
        set_ok(p1)
        get_ok(merge(p0, p1))
        del_ok(p0.keys())
        get_ok(p1)
        del_ok(p0.keys())
        get_ok(p1)

    def test_cycle_content(self):
        path = random_content()
        headers = {"x-oio-action-mode": "autocreate"}
        params = self.param_content(self.ref, path)

        resp = self.request("GET", self.url_content("show"), params=params)
        self.assertError(resp, 404, 406)

        resp = self.request("POST", self.url_content("touch"), params=params)
        self.assertError(resp, 404, 406)

        resp = self.request(
            "POST",
            self.url_content("prepare"),
            data=json.dumps({"size": "1024"}),
            params=params,
            headers=headers,
        )
        self.assertEqual(resp.status, 200)
        chunks = self.json_loads(resp.data)

        stgpol = resp.headers.get("x-oio-content-meta-policy")
        headers = {
            "x-oio-action-mode": "autocreate",
            "x-oio-content-meta-size": "1024",
            "x-oio-content-meta-policy": stgpol,
            "x-oio-content-meta-version": int(time.time() * 1000000),
            "x-oio-content-meta-id": random_id(32),
        }
        resp = self.request(
            "POST",
            self.url_content("create"),
            params=params,
            headers=headers,
            data=json.dumps(chunks),
        )
        self.assertEqual(resp.status, 204)

        # # FIXME check re-create depending on the container's ver'policy
        # resp = self.request('POST', self.url_content('create'),
        #                         params=params,
        #                         headers=headers,
        #                         data=json.dumps(chunks))
        # self.assertEqual(resp.status, 201)

        resp = self.request("GET", self.url_content("show"), params=params)
        self.assertEqual(resp.status, 200)

        resp = self.request("GET", self.url_content("show"), params=params)
        self.assertEqual(resp.status, 200)

        resp = self.request("POST", self.url_content("delete"), params=params)
        self.assertEqual(resp.status, 204)
        self.assertIn(VERSIONID_HEADER, resp.headers)

        resp = self.request("GET", self.url_content("show"), params=params)
        self.assertError(resp, 404, 420)

        resp = self.request("POST", self.url_content("delete"), params=params)
        self.assertError(resp, 404, 420)

    def test_drain_content(self):
        path = random_content()
        params = self.param_content(self.ref, path)
        params_ref = self.param_ref(self.ref)
        params_ref["extra_counters"] = 1

        def check_nb_objects_drained(nb_objects):
            resp = self.request(
                "POST", self.url_container("get_properties"), params=params_ref
            )
            props = self.json_loads(resp.data)
            self.assertEqual(nb_objects, int(props["system"]["extra_counter.drained"]))

        self._create_content(path)
        check_nb_objects_drained(0)
        # Drain Content
        resp = self.request("POST", self.url_content("drain"), params=params)
        self.assertEqual(resp.status, 204)
        check_nb_objects_drained(1)
        # TruncateShouldFail
        trunc_param = {"size": 0}
        trunc_param.update(params)
        resp = self.request("POST", self.url_content("truncate"), params=trunc_param)
        self.assertError(resp, 410, 427)
        # AppendShouldFail
        headers = {"X-oio-action-mode": "autocreate"}
        resp = self.request(
            "POST",
            self.url_content("prepare"),
            data=json.dumps({"size": "1024"}),
            params=params,
            headers=headers,
        )
        self.assertEqual(resp.status, 200)
        chunks = self.json_loads(resp.data)
        append_param = {"append": 1}
        append_param.update(params)
        stgpol = resp.headers.get("x-oio-content-meta-policy")
        headers = {
            "x-oio-action-mode": "autocreate",
            "x-oio-content-meta-size": "1024",
            "x-oio-content-meta-policy": stgpol,
            "x-oio-content-meta-id": random_id(32),
        }
        resp = self.request(
            "POST",
            self.url_content("create"),
            params=append_param,
            headers=headers,
            data=json.dumps(chunks),
        )
        self.assertError(resp, 410, 427)
        # ShowShouldFail
        # Currently the proxy execute the same action for 'show' and 'locate'.
        # Since this give the location of the chunks it should failed for a
        # drained content.
        resp = self.request("GET", self.url_content("show"), params=params)
        self.assertError(resp, 410, 427)
        # LocateShouldFail
        resp = self.request("GET", self.url_content("locate"), params=params)
        self.assertError(resp, 410, 427)

        # UpdateShouldFail
        headers = {"X-oio-action-mode": "autocreate"}
        resp = self.request(
            "POST",
            self.url_content("prepare"),
            data=json.dumps({"size": "1024"}),
            params=params,
            headers=headers,
        )
        self.assertEqual(resp.status, 200)
        chunks = self.json_loads(resp.data)

        stgpol = resp.headers.get("x-oio-content-meta-policy")
        headers = {
            "x-oio-action-mode": "autocreate",
            "x-oio-content-meta-policy": stgpol,
            "x-oio-content-meta-size": "1024",
        }
        resp = self.request(
            "POST",
            self.url_content("update"),
            params=params,
            headers=headers,
            data=json.dumps(chunks),
        )
        self.assertError(resp, 410, 427)

        # DeleteShouldWork
        resp = self.request("POST", self.url_content("delete"), params=params)
        self.assertEqual(resp.status, 204)
        check_nb_objects_drained(0)
        # CreateShouldWork
        self._create_content(path)
        check_nb_objects_drained(0)
        self.assertEqual(resp.status, 204)
        resp = self.request("POST", self.url_content("drain"), params=params)
        self.assertEqual(resp.status, 204)
        check_nb_objects_drained(1)
        self._create_content(path)
        resp = self.request("POST", self.url_content("drain"), params=params)
        self.assertEqual(resp.status, 204)
        # TouchShouldWork
        resp = self.request("POST", self.url_content("touch"), params=params)
        self.assertEqual(resp.status, 204)
        # SetpropShouldWork
        # If a drain is done on a snapshot we will no be able to set a
        # property because the container would be frozen, but if a drain is
        # done on a content of a none frozen container it should work
        resp = self.request(
            "POST",
            self.url_content("set_properties"),
            params=params,
            data=json.dumps({"properties": {"color": "blue"}}),
        )
        self.assertEqual(resp.status, 204)
        # getpropShouldWork
        resp = self.request("POST", self.url_content("get_properties"), params=params)
        self.assertEqual(resp.status, 200)
        # delpropShouldWork
        resp = self.request(
            "POST",
            self.url_content("del_properties"),
            params=params,
            data=json.dumps(["color"]),
        )
        self.assertEqual(resp.status, 204)

        # Drain non existing content should failed
        params = self.param_content(self.ref, "Non_existing")
        resp = self.request("POST", self.url_content("drain"), params=params)
        self.assertError(resp, 404, 420)

    def test_restore_drained_content(self):
        path = random_content()
        params = self.param_content(self.ref, path)

        # Restore should fail on not existing object
        self._create_content(path, expected_status_create=404, restore_drained=True)
        self._create_content(path)
        # Restore should fail on not drained objects
        self._create_content(path, expected_status_create=403, restore_drained=True)

        # Drain Content
        resp = self.request("POST", self.url_content("drain"), params=params)
        self.assertEqual(resp.status, 204)

        # Restore content and check locate
        self._create_content(path, expected_status_create=204, restore_drained=True)
        resp = self.request("GET", self.url_content("locate"), params=params)
        self.assertEqual(resp.status, 200)

    def test_purge(self):
        path = random_content()
        params = self.param_content(self.ref, path)

        # no container
        resp = self.request("POST", self.url_content("purge"), params=params)
        self.assertEqual(404, resp.status)

        def purge_and_check(expected_object):
            resp = self.request("POST", self.url_content("purge"), params=params)
            self.assertEqual(204, resp.status)
            resp = self.request(
                "POST", self.url_container("get_properties"), params=params
            )
            data = self.json_loads(resp.data)
            self.assertEqual(str(expected_object), data["system"][M2_PROP_OBJECTS])
            resp = self.request(
                "GET", self.url_container("list"), params=merge(params, {"all": 1})
            )
            data = self.json_loads(resp.data)
            self.assertEqual(expected_object, len(data["objects"]))

        # one content
        self._create_content(path)
        props = {"system": {"sys.m2.policy.version": "3"}}
        resp = self.request(
            "POST",
            self.url_container("set_properties"),
            params=params,
            data=json.dumps(props),
        )
        purge_and_check(1)

        # many contents
        for i in range(100):
            self._create_content(path)
        purge_and_check(3)

        # other contents
        for i in range(5):
            self._create_content("content")
        purge_and_check(8)

        # object desn't exist
        params = self.param_content(self.ref, "wrong")
        purge_and_check(8)

    def test_upgrade_tls(self):
        if not self.conf.get("use_tls"):
            self.skipTest("TLS support must enabled for RAWX")

        name = random_content()
        headers = {"X-oio-action-mode": "autocreate", "X-oio-upgrade-to-tls": "true"}
        params = self.param_content(self.ref, name)

        # with legay prepare
        resp = self.request(
            "POST",
            self.url_content("prepare"),
            params=params,
            headers=headers,
            data=json.dumps({"size": "1024"}),
        )

        chunks = self.json_loads(resp.data)
        for chunk in chunks:
            self.assertTrue(chunk["real_url"].startswith("https://"))

        # with new prepare2
        resp = self.request(
            "POST",
            self.url_content("prepare2"),
            params=params,
            headers=headers,
            data=json.dumps({"size": "1024"}),
        )

        chunks = self.json_loads(resp.data)["chunks"]
        for chunk in chunks:
            self.assertTrue(chunk["real_url"].startswith("https://"))

    def test_locate_with_tls(self):
        if not self.conf.get("use_tls"):
            self.skipTest("TLS support must enabled for RAWX")
        name = random_content()
        self._create_content(name)

        headers = {"X-oio-upgrade-to-tls": "true"}
        params = self.param_content(self.ref, name)
        resp = self.request(
            "GET", self.url_content("locate"), params=params, headers=headers
        )
        chunks = self.json_loads(resp.data)
        for chunk in chunks:
            self.assertTrue(chunk["real_url"].startswith("https://"))

    def test_replication(self):
        self.ref = "test_replication_" + random_str(8)
        reqid = request_id()

        # Create a container
        self.storage.container_create(self.account, self.ref, reqid=reqid)
        self.clean_later(self.ref)

        # Enable versioning on the container
        params = self.param_content(self.ref, self.ref)
        props = {"system": {"sys.m2.policy.version": "-1"}}
        resp = self.request(
            "POST",
            self.url_container("set_properties"),
            params=params,
            data=json.dumps(props),
        )
        self.assertEqual(204, resp.status)

        # Create an object
        self.storage.object_create_ext(
            self.account,
            self.ref,
            obj_name=self.ref,
            data=self.ref,
            reqid=reqid,
            replication_destinations="dst1;dst2",
            replication_replicator_id="obj_create_ext_1",
            replication_role_project_id="obj_create_ext_2",
            properties={"x-object-sysmeta-s3api-acl": "myuseracls"},
        )
        event = self.wait_for_kafka_event(
            reqid=reqid,
            types=(EventTypes.CONTENT_NEW,),
        )
        self.assertIsNotNone(event)
        found = False
        for d in event.data:
            key = d.get("key")
            if key and key == "x-object-sysmeta-s3api-acl":
                self.assertEqual("myuseracls", d["value"])
                found = True
                break
        self.assertTrue(found)
        self.assertEqual("dst1;dst2", event.repli["destinations"])
        self.assertEqual("obj_create_ext_1", event.repli["replicator_id"])
        self.assertEqual("obj_create_ext_2", event.repli["src_project_id"])

        # Set properties
        reqid = request_id()
        self.storage.object_set_properties(
            self.account,
            self.ref,
            obj=self.ref,
            properties={"foo": "bar"},
            reqid=reqid,
            replication_destinations="dst3;dst4",
            replication_replicator_id="obj_set_props_1",
            replication_role_project_id="obj_set_props_2",
        )
        event = self.wait_for_kafka_event(
            reqid=reqid,
            types=(EventTypes.CONTENT_UPDATE,),
        )
        self.assertIsNotNone(event)
        self.assertEqual("dst3;dst4", event.repli["destinations"])
        self.assertEqual("obj_set_props_1", event.repli["replicator_id"])
        self.assertEqual("obj_set_props_2", event.repli["src_project_id"])
        self.assertEqual("myuseracls", event.repli["x-object-sysmeta-s3api-acl"])

        # Delete properties
        reqid = request_id()
        self.storage.object_del_properties(
            self.account,
            self.ref,
            obj=self.ref,
            properties=["foo"],
            reqid=reqid,
            replication_destinations="dst5;dst6",
            replication_replicator_id="obj_del_props_1",
            replication_role_project_id="obj_del_props_2",
        )

        event = self.wait_for_kafka_event(
            reqid=reqid,
            types=(EventTypes.CONTENT_UPDATE,),
        )
        self.assertIsNotNone(event)
        self.assertEqual("dst5;dst6", event.repli["destinations"])
        self.assertEqual("obj_del_props_1", event.repli["replicator_id"])
        self.assertEqual("obj_del_props_2", event.repli["src_project_id"])
        self.assertEqual("myuseracls", event.repli["x-object-sysmeta-s3api-acl"])

        # Delete object (as versioning is enabled, a delete marker will be created)
        self.storage.object_delete(
            self.account,
            self.ref,
            obj=self.ref,
            reqid=reqid,
            replication_destinations="dst7;dst8",
            replication_replicator_id="obj_del_1",
            replication_role_project_id="obj_del_2",
        )
        event = self.wait_for_kafka_event(reqid=reqid, types=(EventTypes.CONTENT_NEW,))
        self.assertIsNotNone(event)
        self.assertEqual("dst7;dst8", event.repli["destinations"])
        self.assertEqual("obj_del_1", event.repli["replicator_id"])
        self.assertEqual("obj_del_2", event.repli["src_project_id"])
        # No acl for delete markers
        self.assertNotIn("x-object-sysmeta-s3api-acl", event.repli)
        found = False
        for d in event.data:
            key = d.get("key")
            if key and key == "x-object-sysmeta-s3api-acl":
                found = True
                break
        self.assertFalse(found)

    def test_no_manifest_deleted_event(self):
        self.ref = "test_no_manifest_deleted_event_" + random_str(8)
        reqid = request_id()

        # Create a container
        self.storage.container_create(self.account, self.ref, reqid=reqid)
        self.clean_later(self.ref)

        # Create an object
        self.storage.object_create_ext(
            self.account,
            self.ref,
            obj_name=self.ref,
            data=self.ref,
            reqid=reqid,
        )
        event = self.wait_for_kafka_event(
            reqid=reqid,
            types=(EventTypes.CONTENT_NEW,),
        )
        self.assertIsNotNone(event)

        # Delete without slo_manifest=True: no manifest event created
        reqid = request_id()
        self.storage.object_delete(
            self.account,
            self.ref,
            obj=self.ref,
            reqid=reqid,
        )
        event = self.wait_for_kafka_event(
            reqid=reqid,
            types=(EventTypes.MANIFEST_DELETED,),
            kafka_consumer=self._cls_mpu_consumer,
        )
        self.assertIsNone(event)

    def test_manifest_deleted_event(self):
        self.ref = "test_manifest_deleted_event_" + random_str(8)
        reqid = request_id()

        # Create a container
        self.storage.container_create(self.account, self.ref, reqid=reqid)
        self.clean_later(self.ref)

        # Create an object
        self.storage.object_create_ext(
            self.account,
            self.ref,
            obj_name=self.ref,
            data=self.ref,
            reqid=reqid,
        )
        event = self.wait_for_kafka_event(
            reqid=reqid,
            types=(EventTypes.CONTENT_NEW,),
        )
        self.assertIsNotNone(event)

        # Delete without upload_id (no event generated and object not deleted)
        reqid = request_id()
        self.assertRaises(
            exc.BadRequest,
            self.storage.object_delete,
            self.account,
            self.ref,
            obj=self.ref,
            reqid=reqid,
            slo_manifest=True,
        )
        event = self.wait_for_kafka_event(
            reqid=reqid,
            types=(EventTypes.MANIFEST_DELETED,),
            kafka_consumer=self._cls_mpu_consumer,
        )
        self.assertIsNone(event)

        # Add upload_id to obj (to fake a manifest)
        reqid = request_id()
        self.storage.object_set_properties(
            self.account,
            self.ref,
            obj=self.ref,
            properties={"x-object-sysmeta-s3api-upload-id": random_str(48)},
            reqid=reqid,
        )
        event = self.wait_for_kafka_event(
            reqid=reqid,
            types=(EventTypes.CONTENT_UPDATE,),
        )
        self.assertIsNotNone(event)

        # Event should now be generated
        reqid = request_id()
        self.storage.object_delete(
            self.account,
            self.ref,
            obj=self.ref,
            reqid=reqid,
            slo_manifest=True,
        )
        event = self.wait_for_kafka_event(
            reqid=reqid,
            types=(EventTypes.MANIFEST_DELETED,),
            kafka_consumer=self._cls_mpu_consumer,
        )
        self.assertIsNotNone(event)
