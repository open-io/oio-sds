# Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
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

import subprocess
import tempfile
import time
import uuid
from os import getuid, remove
from shutil import rmtree

from oio.common.http_urllib3 import get_pool_manager
from oio.common.json import json
from tests.proc import check_process_absent, does_startup_fail, wait_for_slow_startup
from tests.utils import CommonTestCase, random_id, random_str


def _key(rec):
    return "|".join((rec["container_id"], rec["chunk_id"]))


def _value(rec):
    """
    Get the expected value fetched from the server for the
    specified record.
    """
    return {
        k: v for k, v in rec.items() if k in ("mtime", "content_id", "path", "version")
    }


map_cfg = {
    "host": "bind_addr",
    "port": "bind_port",
    "ns": "namespace",
    "db": "db_path",
    "service_id": "service_id",
}


def _write_config(path, config):
    with open(path, "w") as f:
        f.write("[rdir-server]\n")
        for k, v in config.items():
            f.write("{0} = {1}\n".format(map_cfg[k], config[k]))
        f.write("syslog_prefix = OIO,OPENIO,rdir,1\n")


class RdirTestCase(CommonTestCase):
    def setUp(self):
        super(RdirTestCase, self).setUp()
        self.host = self.port = None
        self._http_pool = get_pool_manager(max_retries=10, backoff_factor=0.05)
        self.garbage_files = list()
        self.garbage_procs = list()

    def tearDown(self):
        super(RdirTestCase, self).tearDown()
        self.http_pool.clear()
        for p in self.garbage_procs:
            try:
                p.terminate()
                p.kill()
            except Exception:
                pass
        for f in self.garbage_files:
            ignore_errors = True
            try:
                rmtree(f, ignore_errors)
                remove(f)
            except Exception:
                pass

    def _volume(self):
        return "fake-" + random_id(6)

    def _record(self, new_format=False):
        rec = {
            "container_id": random_id(64),
            "content_id": random_id(32),
            "chunk_id": random_id(64),
            "mtime": int(time.time()),
            "path": "obj-" + random_id(4),
            "version": 1,
        }
        if new_format:
            return [rec]
        return rec

    def _meta2_record(self, new_format=False):
        rec = {
            "container_id": random_id(64),
            "container_url": "{0}/{1}/{2}".format(
                random_str(12), random_str(12), random_str(12)
            ),
            "mtime": int(time.time()),
        }
        if new_format:
            return [rec]
        return rec

    def _rdir_url(self, tail):
        return "http://{0}:{1}{2}".format(self.host, self.port, tail)

    def _get(self, url, **kwargs):
        return self.request("GET", self._rdir_url(url), **kwargs)

    def _post(self, url, **kwargs):
        return self.request("POST", self._rdir_url(url), **kwargs)

    def _delete(self, url, **kwargs):
        return self.request("DELETE", self._rdir_url(url), **kwargs)


class TestRdirServer(RdirTestCase):
    def setUp(self):
        super(TestRdirServer, self).setUp()
        self.num, self.db_path, self.host, self.port = self.get_service("rdir")
        self.port = int(self.port)
        self.vol = self._volume()

    def tearDown(self):
        super(TestRdirServer, self).tearDown()

    def test_status(self):
        resp = self._get("/status")
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.headers["Content-Type"], "application/json")
        decoded = json.loads(resp.data)
        self.assertIn("meta2_volumes", decoded)
        self.assertIn("rawx_volumes", decoded)

        resp = self._get("/config")
        self.assertEqual(resp.status, 200)

    def test_status_prometheus(self):
        resp = self._get("/status", params={"format": "prometheus"})
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.headers["Content-Type"], "text/plain")
        decoded = resp.data.decode("utf-8")
        self.assertIn("rdir_db_count", decoded)
        # Only if details are asked
        self.assertNotIn("meta2_db_count", decoded)

    def test_status_prometheus_details(self):
        resp = self._get("/status", params={"format": "prometheus", "details": "true"})
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.headers["Content-Type"], "text/plain")
        decoded = resp.data.decode("utf-8")
        self.assertIn("rdir_db_count", decoded)
        self.assertIn("meta2_db_count", decoded)

    def test_explicit_create(self):
        rec = self._record()

        # try to push on unknown volume
        resp = self._post(
            "/v1/rdir/push", params={"vol": self.vol}, data=json.dumps(rec)
        )
        self.assertEqual(resp.status, 404)

        # fetch without volume
        resp = self._get("/v1/rdir/fetch")
        self.assertEqual(resp.status, 400)

        # fetch with non-json body
        resp = self._get(
            "/v1/rdir/fetch", params={"vol": self.vol}, data="this is not json"
        )
        self.assertEqual(resp.status, 400)

        # The fetch fails
        resp = self._get("/v1/rdir/fetch", params={"vol": self.vol})
        self.assertEqual(resp.status, 404)

        # create volume without the volume
        resp = self._post("/v1/rdir/create")
        self.assertEqual(resp.status, 400)

        # create volume
        resp = self._post("/v1/rdir/create", params={"vol": self.vol})
        self.assertEqual(resp.status, 201)

        resp = self._get("/v1/status", params={"vol": self.vol})
        self.assertEqual(resp.status, 200)

        # the fetch returns an empty array
        resp = self._get("/v1/rdir/fetch", params={"vol": self.vol})
        self.assertEqual(resp.status, 200)
        self.assertEqual(self.json_loads(resp.data), [])

        # now the push must succeed
        resp = self._post(
            "/v1/rdir/push", params={"vol": self.vol}, data=json.dumps(rec)
        )
        self.assertEqual(resp.status, 204)

        # we must fetch the same data
        resp = self._get("/v1/rdir/fetch", params={"vol": self.vol})
        self.assertEqual(resp.status, 200)
        reference = [[_key(rec), _value(rec)]]
        self.assertListEqual(self.json_loads(resp.data), reference)

        # delete without volume
        resp = self._delete("/v1/rdir/delete")
        self.assertEqual(resp.status, 400)

        resp = self._delete("/v1/rdir/delete", params={"vol": ""})
        self.assertEqual(resp.status, 400)

        # deleting must succeed
        resp = self._delete(
            "/v1/rdir/delete", params={"vol": self.vol}, data=json.dumps(rec)
        )
        self.assertEqual(resp.status, 204)

        # fetching must return an empty array
        resp = self._get("/v1/rdir/fetch", params={"vol": self.vol})
        self.assertEqual(resp.status, 200)
        self.assertEqual(self.json_loads(resp.data), [])

    def test_implicit_create(self):
        rec = self._record()

        # try to push on unknown volume
        resp = self._post(
            "/v1/rdir/push", params={"vol": self.vol}, data=json.dumps(rec)
        )
        self.assertEqual(resp.status, 404)

        # try to push on unknown volume WITH create flag
        resp = self._post(
            "/v1/rdir/push",
            params={"vol": self.vol, "create": True},
            data=json.dumps(rec),
        )
        self.assertEqual(resp.status, 204)

        # We must fetch the same data
        resp = self._get("/v1/rdir/fetch", params={"vol": self.vol})
        self.assertEqual(resp.status, 200)
        self.assertEqual([[_key(rec), _value(rec)]], self.json_loads(resp.data))

    def test_push_several_chunks(self):
        recs = self._record(new_format=True)
        recs.extend(self._record(new_format=True))
        recs.extend(self._record(new_format=True))

        # try to push on unknown volume
        resp = self._post(
            "/v1/rdir/push", params={"vol": self.vol}, data=json.dumps(recs)
        )
        self.assertEqual(resp.status, 404)

        # try to push on unknown volume WITH create flag
        resp = self._post(
            "/v1/rdir/push",
            params={"vol": self.vol, "create": True},
            data=json.dumps(recs),
        )
        self.assertEqual(resp.status, 204)

        # We must fetch the same data
        resp = self._get("/v1/rdir/fetch", params={"vol": self.vol})
        self.assertEqual(resp.status, 200)
        reference = [[_key(rec), _value(rec)] for rec in recs]
        reference.sort()
        self.assertEqual(reference, self.json_loads(resp.data))

    def test_push_missing_fields(self):
        rec = self._record()

        # Push without volume
        resp = self._post("/v1/rdir/push")
        self.assertEqual(resp.status, 400)

        # DB creation
        resp = self._post("/v1/rdir/create", params={"vol": self.vol})
        self.assertEqual(resp.status, 201)

        for k in ("container_id", "chunk_id", "path", "version"):
            save = rec.pop(k)
            # push an incomplete record
            resp = self._post(
                "/v1/rdir/push", params={"vol": self.vol}, data=json.dumps(rec)
            )
            self.assertEqual(resp.status, 400)
            # check we list nothing
            resp = self._get("/v1/rdir/fetch", params={"vol": self.vol})
            self.assertEqual(resp.status, 200)
            self.assertListEqual(self.json_loads(resp.data), [])
            rec[k] = save

    def test_lock_unlock(self):
        who = random_str(64)

        # lock without who, DB not created
        resp = self._post(
            "/v1/rdir/admin/lock", params={"vol": self.vol}, data=json.dumps({})
        )
        self.assertEqual(resp.status, 400)

        # lock with who, DB not created
        resp = self._post(
            "/v1/rdir/admin/lock",
            params={"vol": self.vol},
            data=json.dumps({"who": who}),
        )
        self.assertEqual(resp.status, 404)

        # DB creation
        resp = self._post("/v1/rdir/create", params={"vol": self.vol})
        self.assertEqual(resp.status, 201)

        # lock without volume
        resp = self._post("/v1/rdir/admin/lock", data=json.dumps({}))
        self.assertEqual(resp.status, 400)

        # lock without who
        resp = self._post(
            "/v1/rdir/admin/lock", params={"vol": self.vol}, data=json.dumps({})
        )
        self.assertEqual(resp.status, 400)

        # lock
        resp = self._post(
            "/v1/rdir/admin/lock",
            params={"vol": self.vol},
            data=json.dumps({"who": who}),
        )
        self.assertEqual(resp.status, 204)

        # double lock, different who
        resp = self._post(
            "/v1/rdir/admin/lock",
            params={"vol": self.vol},
            data=json.dumps({"who": random_str(64)}),
        )
        self.assertEqual(resp.status, 403)
        body = self.json_loads(resp.data)
        self.assertEqual(body["message"], "Already locked by %s" % who)

        # unlock
        resp = self._post("/v1/rdir/admin/unlock", params={"vol": self.vol})
        self.assertEqual(resp.status, 204)

    def test_rdir_clear_and_lock(self):
        rec = self._record()
        who = random_id(32)

        # clear without volume
        resp = self._post("/v1/rdir/admin/clear", params={"all": True})
        self.assertEqual(resp.status, 400)

        # push with autocreate
        resp = self._post(
            "/v1/rdir/push",
            params={"vol": self.vol, "create": True},
            data=json.dumps(rec),
        )
        self.assertEqual(resp.status, 204)

        # lock
        resp = self._post(
            "/v1/rdir/admin/lock",
            params={"vol": self.vol},
            data=json.dumps({"who": who}),
        )
        self.assertEqual(resp.status, 204)

        # try to clear while the lock is held
        resp = self._post("/v1/rdir/admin/clear", params={"vol": self.vol, "all": True})
        self.assertEqual(resp.status, 403)

        # unlock
        resp = self._post("/v1/rdir/admin/unlock", params={"vol": self.vol})
        self.assertEqual(resp.status, 204)

        # clear all entries
        resp = self._post("/v1/rdir/admin/clear", params={"vol": self.vol, "all": True})
        self.assertEqual(resp.status, 200)
        self.assertDictEqual(
            self.json_loads(resp.data), {"removed": 1, "repaired": 0, "errors": 0}
        )

    def test_rdir_clear_with_repair(self):
        rec = self._record()
        who = random_id(32)

        # clear without volume
        resp = self._post("/v1/rdir/admin/clear", params={"repair": True})
        self.assertEqual(resp.status, 400)

        # push with autocreate
        resp = self._post(
            "/v1/rdir/push",
            params={"vol": self.vol, "create": True},
            data=json.dumps(rec),
        )
        self.assertEqual(resp.status, 204)

        # lock
        resp = self._post(
            "/v1/rdir/admin/lock",
            params={"vol": self.vol},
            data=json.dumps({"who": who}),
        )
        self.assertEqual(resp.status, 204)

        # try to clear while the lock is held
        resp = self._post(
            "/v1/rdir/admin/clear", params={"vol": self.vol, "repair": True}
        )
        self.assertEqual(resp.status, 403)

        # unlock
        resp = self._post("/v1/rdir/admin/unlock", params={"vol": self.vol})
        self.assertEqual(resp.status, 204)

        # repair all entries
        resp = self._post(
            "/v1/rdir/admin/clear", params={"vol": self.vol, "repair": True}
        )
        self.assertEqual(resp.status, 200)
        self.assertDictEqual(
            self.json_loads(resp.data), {"removed": 0, "repaired": 1, "errors": 0}
        )

    def test_rdir_clear_with_before_incident(self):
        rec = self._record()
        who = random_id(32)

        # clear without volume
        resp = self._post("/v1/rdir/admin/clear", params={"before_incident": True})
        self.assertEqual(resp.status, 400)

        # push with autocreate
        resp = self._post(
            "/v1/rdir/push",
            params={"vol": self.vol, "create": True},
            data=json.dumps(rec),
        )
        self.assertEqual(resp.status, 204)

        # create incident
        resp = self._post(
            "/v1/rdir/admin/incident",
            params={"vol": self.vol},
            data=json.dumps({"date": int(time.time())}),
        )
        self.assertEqual(resp.status, 204)

        # push with autocreate after incident
        time.sleep(1)
        rec2 = self._record()
        resp = self._post(
            "/v1/rdir/push",
            params={"vol": self.vol, "create": True},
            data=json.dumps(rec2),
        )
        self.assertEqual(resp.status, 204)

        # lock
        resp = self._post(
            "/v1/rdir/admin/lock",
            params={"vol": self.vol},
            data=json.dumps({"who": who}),
        )
        self.assertEqual(resp.status, 204)

        # try to clear while the lock is held
        resp = self._post(
            "/v1/rdir/admin/clear", params={"vol": self.vol, "before_incident": True}
        )
        self.assertEqual(resp.status, 403)

        # unlock
        resp = self._post("/v1/rdir/admin/unlock", params={"vol": self.vol})
        self.assertEqual(resp.status, 204)

        # clear all entries before incident date
        resp = self._post(
            "/v1/rdir/admin/clear", params={"vol": self.vol, "before_incident": True}
        )
        self.assertEqual(resp.status, 200)
        self.assertDictEqual(
            self.json_loads(resp.data), {"removed": 1, "repaired": 0, "errors": 0}
        )

    def test_vol_status(self):
        # Status without volume
        resp = self._post("/v1/rdir/status")
        self.assertEqual(resp.status, 400)

        # Status on inexistent DB
        resp = self._post("/v1/rdir/status", params={"vol": self.vol})
        self.assertEqual(resp.status, 404)

        # DB creation
        resp = self._post("/v1/rdir/create", params={"vol": self.vol})
        self.assertEqual(resp.status, 201)

        # Status on an empty DB
        resp = self._get("/v1/rdir/status", params={"vol": self.vol})
        self.assertEqual(resp.status, 200)
        self.assertDictEqual(
            self.json_loads(resp.data), {"chunk": {"total": 0}, "container": {}}
        )

        # push with autocreate
        rec = self._record()
        resp = self._post(
            "/v1/rdir/push",
            params={"vol": self.vol, "create": True},
            data=json.dumps(rec),
        )
        self.assertEqual(resp.status, 204)

        # Status with 1 entries
        resp = self._get("/v1/rdir/status", params={"vol": self.vol})
        self.assertEqual(resp.status, 200)
        self.assertDictEqual(
            self.json_loads(resp.data),
            {"chunk": {"total": 1}, "container": {rec["container_id"]: {"total": 1}}},
        )

        # create incident
        incident_date = int(time.time())
        resp = self._post(
            "/v1/rdir/admin/incident",
            params={"vol": self.vol},
            data=json.dumps({"date": incident_date}),
        )
        self.assertEqual(resp.status, 204)

        # Status with 1 entries and incident
        resp = self._get("/v1/rdir/status", params={"vol": self.vol})
        self.assertEqual(resp.status, 200)
        self.assertDictEqual(
            self.json_loads(resp.data),
            {
                "chunk": {"total": 1, "to_rebuild": 1},
                "container": {rec["container_id"]: {"total": 1, "to_rebuild": 1}},
                "rebuild": {"incident_date": incident_date},
            },
        )

        # push with autocreate after incident
        time.sleep(1)
        rec2 = self._record()
        resp = self._post(
            "/v1/rdir/push",
            params={"vol": self.vol, "create": True},
            data=json.dumps(rec2),
        )
        self.assertEqual(resp.status, 204)

        # Status with 2 entries and incident
        resp = self._get("/v1/rdir/status", params={"vol": self.vol})
        self.assertEqual(resp.status, 200)
        self.assertDictEqual(
            self.json_loads(resp.data),
            {
                "chunk": {"total": 2, "to_rebuild": 1},
                "container": {
                    rec["container_id"]: {"total": 1, "to_rebuild": 1},
                    rec2["container_id"]: {"total": 1},
                },
                "rebuild": {"incident_date": incident_date},
            },
        )

        # clear incident
        resp = self._post("/v1/rdir/admin/clear", params={"vol": self.vol})
        self.assertEqual(resp.status, 200)

        # Status with 2 entries
        resp = self._get("/v1/rdir/status", params={"vol": self.vol})
        self.assertEqual(resp.status, 200)
        self.assertDictEqual(
            self.json_loads(resp.data),
            {
                "chunk": {"total": 2},
                "container": {
                    rec["container_id"]: {"total": 1},
                    rec2["container_id"]: {"total": 1},
                },
            },
        )


class TestRdirServerWithSubproces(RdirTestCase):
    def setUp(self):
        super(TestRdirServerWithSubproces, self).setUp()
        # Start a sandboxed rdir service
        self.num, self.host, self.port = 17, "127.0.0.1", 5999
        self.cfg_path = tempfile.mktemp()
        self.db_path = tempfile.mkdtemp()
        self.service_id = str(uuid.uuid4())
        self.garbage_files.extend((self.cfg_path, self.db_path))

        config = {
            "host": self.host,
            "port": self.port,
            "ns": self.ns,
            "db": self.db_path,
            "service_id": self.service_id,
        }
        _write_config(self.cfg_path, config)

        child = subprocess.Popen(["oio-rdir-server", self.cfg_path], close_fds=True)
        if not wait_for_slow_startup(self.port):
            child.kill()
            raise Exception("The rdir server is too long to start")
        else:
            self.garbage_procs.append(child)

    def test_status(self):
        vol = self._volume()

        # check the service has no opened DB
        resp = self._get("/status")
        self.assertEqual(resp.status, 200)
        self.assertEqual(
            self.json_loads(resp.data),
            {
                "opened_db_count": 0,
                "service_id": self.service_id,
                "meta2_volumes": [],
                "rawx_volumes": [],
            },
        )

        # DB creation
        resp = self._post("/v1/rdir/create", params={"vol": vol})
        self.assertEqual(resp.status, 201)

        # The base remains open after it has been created
        resp = self._get("/status")
        self.assertEqual(resp.status, 200)
        self.assertEqual(
            self.json_loads(resp.data),
            {
                "opened_db_count": 1,
                "service_id": self.service_id,
                "meta2_volumes": [],
                "rawx_volumes": [vol],
            },
        )

    def test_bad_routes(self):
        routes = (
            "/status",
            "/config",
            "/v1/status",
            "/v1/rdir/admin/show",
            "/v1/rdir/admin/lock",
            "/v1/rdir/admin/unlock",
            "/v1/rdir/admin/incident",
            "/v1/rdir/admin/clear",
            "/v1/rdir/create",
            "/v1/rdir/push",
            "/v1/rdir/delete",
            "/v1/rdir/fetch",
            "/v1/rdir/status",
            "/v1/rdir/meta2/create",
            "/v1/rdir/meta2/push",
            "/v1/rdir/meta2/delete",
            "/v1/rdir/meta2/fetch",
        )
        for r in routes:
            resp = self._get("/" + r)
            self.assertEqual(resp.status, 404)
            resp = self._get(r + "/")
            self.assertEqual(resp.status, 404)
            bulk = random_id(4)
            resp = self._get("/" + bulk + r)
            self.assertEqual(resp.status, 404)
            resp = self._get(r + "/" + bulk)
            self.assertEqual(resp.status, 404)
            resp = self._get(r + bulk)
            self.assertEqual(resp.status, 404)

    def test_bad_methods(self):
        actions = (
            ("/status", self._post),
            ("/status", self._delete),
            ("/config", self._delete),
            ("/v1/status", self._post),
            ("/v1/status", self._delete),
            ("/v1/rdir/admin/show", self._post),
            ("/v1/rdir/admin/show", self._delete),
            ("/v1/rdir/admin/lock", self._get),
            ("/v1/rdir/admin/lock", self._delete),
            ("/v1/rdir/admin/unlock", self._get),
            ("/v1/rdir/admin/unlock", self._delete),
            ("/v1/rdir/admin/incident", self._delete),
            ("/v1/rdir/admin/clear", self._get),
            ("/v1/rdir/admin/clear", self._delete),
            ("/v1/rdir/create", self._get),
            ("/v1/rdir/create", self._delete),
            ("/v1/rdir/push", self._get),
            ("/v1/rdir/push", self._delete),
            ("/v1/rdir/delete", self._get),
            ("/v1/rdir/delete", self._post),
            ("/v1/rdir/fetch", self._delete),
            ("/v1/rdir/status", self._delete),
            ("/v1/rdir/meta2/create", self._get),
            ("/v1/rdir/meta2/create", self._delete),
            ("/v1/rdir/meta2/push", self._get),
            ("/v1/rdir/meta2/push", self._delete),
            ("/v1/rdir/meta2/delete", self._get),
            ("/v1/rdir/meta2/delete", self._delete),
            ("/v1/rdir/meta2/fetch", self._delete),
        )
        for route, method in actions:
            resp = method(route)
            self.assertEqual(resp.status, 405)


class TestRdirServerConfig(RdirTestCase):
    """Test the oio-rdir-server with invalid configuration"""

    def test_no_config(self):
        with open("/dev/null", "w") as out:
            fd = out.fileno()
            proc = subprocess.Popen(["oio-rdir-server"], stderr=fd)
            self.assertTrue(check_process_absent(proc))

    def test_wrong_config(self):
        cfg = "/x/y/z/not_found/on_any/server/rdir.conf"
        with open("/dev/null", "w") as out:
            fd = out.fileno()
            proc = subprocess.Popen(["oio-rdir-server", cfg], stderr=fd)
            self.assertTrue(check_process_absent(proc))

    def _check_rdir_startup_fail(self, path, config):
        self.garbage_files.append(path)
        _write_config(path, config)
        self.assertTrue(does_startup_fail(path))

    def test_basedir_not_found(self):
        path = tempfile.mktemp()
        config = {
            "host": "127.0.0.1",
            "port": 5999,
            "ns": self.ns,
            "db": "/x/y/z/not_found",
        }
        self._check_rdir_startup_fail(path, config)

    def test_basedir_not_dir(self):
        path = tempfile.mktemp()
        config = {"host": "127.0.0.1", "port": 5999, "ns": self.ns, "db": "/etc/magic"}
        self._check_rdir_startup_fail(path, config)

    def test_basedir_denied(self):
        if getuid() == 0:
            self.skipTest("User is root, cannot run this test.")
        path = tempfile.mktemp()
        config = {"host": "127.0.0.1", "port": 5999, "ns": self.ns, "db": "/var"}
        self._check_rdir_startup_fail(path, config)

    def test_incomplete_config(self):
        path = tempfile.mktemp()
        self._check_rdir_startup_fail(
            path, {"host": "127.0.0.1", "port": 5999, "db": "/var"}
        )
        self._check_rdir_startup_fail(
            path, {"host": "127.0.0.1", "port": 5999, "ns": self.ns}
        )
        self._check_rdir_startup_fail(path, {"port": 5999, "ns": self.ns, "db": "/var"})
        self._check_rdir_startup_fail(
            path, {"host": "127.0.0.1", "ns": self.ns, "db": "/var"}
        )

    def test_good_config(self):
        host, port = "127.0.0.1", 5999
        cfg = tempfile.mktemp()
        db = tempfile.mkdtemp()
        self.garbage_files.extend((cfg, db))
        with open("/dev/null", "w") as out:
            fd = out.fileno()
            # start a first rdir
            config = {"host": host, "port": port, "ns": self.ns, "db": db}
            _write_config(cfg, config)
            proc0 = subprocess.Popen(["oio-rdir-server", cfg], stderr=fd)
            self.garbage_procs.append(proc0)
            self.assertTrue(wait_for_slow_startup(port))

    def test_volume_lock(self):
        host, port = "127.0.0.1", 5998
        _, cfg0 = tempfile.mkstemp()
        _, cfg1 = tempfile.mkstemp()
        db = tempfile.mkdtemp()
        self.garbage_files.extend((cfg0, cfg1, db))

        with open("/dev/null", "w") as out:
            fd = out.fileno()

            # start a first rdir
            config = {"host": host, "port": port, "ns": self.ns, "db": db}
            _write_config(cfg0, config)
            proc0 = subprocess.Popen(["oio-rdir-server", cfg0], stderr=fd)
            self.garbage_procs.append(proc0)
            self.assertTrue(wait_for_slow_startup(port))

            # now start a second rdir on another port
            config.update({"port": port + 1})
            _write_config(cfg1, config)
            proc1 = subprocess.Popen(["oio-rdir-server", cfg1], stderr=fd)
            self.garbage_procs.append(proc1)
            self.assertTrue(check_process_absent(proc1))


class TestRdirServerMeta2Ops(RdirTestCase):
    def setUp(self):
        super(TestRdirServerMeta2Ops, self).setUp()
        self.num, self.db_path, self.host, self.port = self.get_service("rdir")
        self.port = int(self.port)
        self.vol = self._volume()

    def test_meta2_fetch_invalid_parameters(self):
        # fetch without volume
        resp = self._get("/v1/rdir/meta2/fetch", data=json.dumps({"rand": "random"}))
        self.assertEqual(resp.status, 400)

        # fetch with non-json body
        resp = self._get(
            "/v1/rdir/meta2/fetch", params={"vol": self.vol}, data="this is not json"
        )
        self.assertEqual(resp.status, 400)

        # The fetch fails (database not found, no body is OK since 8.0.0)
        resp = self._get("/v1/rdir/meta2/fetch", params={"vol": self.vol})
        self.assertEqual(resp.status, 404)

    def test_meta2_delete_invalid_parameters(self):
        # delete without volume
        resp = self._post("/v1/rdir/meta2/delete")
        self.assertEqual(resp.status, 400)

        resp = self._post("/v1/rdir/meta2/delete", params={"vol": ""})
        self.assertEqual(resp.status, 400)

    def test_meta2_create_missing_parameters(self):
        # create volume without the volume
        resp = self._post("/v1/rdir/meta2/create")
        self.assertEqual(resp.status, 400)

    def test_meta2_push_missing_fields(self):
        rec = self._meta2_record()

        # Push without volume
        resp = self._post("/v1/rdir/meta2/push")
        self.assertEqual(resp.status, 400)

        # DB creation
        resp = self._post("/v1/rdir/meta2/create", params={"vol": self.vol})
        self.assertEqual(resp.status, 201)

        # mtime is optional
        for k in ["container_url", "container_id"]:
            save = rec.pop(k)
            # push an incomplete record
            resp = self._post(
                "/v1/rdir/meta2/push", params={"vol": self.vol}, data=json.dumps(rec)
            )
            self.assertEqual(resp.status, 400)
            # check we list nothing
            resp = self._get(
                "/v1/rdir/meta2/fetch", params={"vol": self.vol}, data=json.dumps({})
            )
            self.assertEqual(resp.status, 200)
            self.assertEqual(
                self.json_loads(resp.data), {"records": [], "truncated": False}
            )
            rec[k] = save

    def test_meta2_count(self):
        resp = self._post("/v1/rdir/meta2/create", params={"vol": self.vol})
        self.assertEqual(resp.status, 201)

        # Meta2 is empty, count should be zero
        resp = self._get("/v1/rdir/meta2/count", params={"vol": self.vol}, json={})
        self.assertEqual(resp.status, 200)
        decoded = json.loads(resp.data)
        self.assertIn("count", decoded)
        self.assertEqual(decoded["count"], 0)

        # Simulate the creation of a meta2 database, count should be one
        rec = self._meta2_record()
        resp = self._post(
            "/v1/rdir/meta2/push", params={"vol": self.vol}, data=json.dumps(rec)
        )
        self.assertEqual(resp.status, 204)
        resp = self._get("/v1/rdir/meta2/count", params={"vol": self.vol}, json={})
        self.assertEqual(resp.status, 200)
        decoded = json.loads(resp.data)
        self.assertIn("count", decoded)
        self.assertEqual(decoded["count"], 1)

        # Simulate the deletion of a meta2 database, count should be zero again
        resp = self._post(
            "/v1/rdir/meta2/delete", params={"vol": self.vol}, data=json.dumps(rec)
        )
        self.assertEqual(resp.status, 204)
        resp = self._get("/v1/rdir/meta2/count", params={"vol": self.vol}, json={})
        self.assertEqual(resp.status, 200)
        decoded = json.loads(resp.data)
        self.assertIn("count", decoded)
        self.assertEqual(decoded["count"], 0)

    def test_meta2_count_not_found(self):
        resp = self._get("/v1/rdir/meta2/count", params={"vol": self.vol}, json={})
        self.assertEqual(resp.status, 404)
        decoded = json.loads(resp.data)
        self.assertIn("message", decoded)
        self.assertIn("not found", decoded["message"])

    def test_meta2_create(self):
        # create volume
        resp = self._post("/v1/rdir/meta2/create", params={"vol": self.vol})
        self.assertEqual(resp.status, 201)

        # the fetch returns an empty array
        resp = self._get(
            "/v1/rdir/meta2/fetch", params={"vol": self.vol}, data=json.dumps({})
        )
        self.assertEqual(resp.status, 200)
        self.assertEqual(
            self.json_loads(resp.data), {"records": [], "truncated": False}
        )

    def test_meta2_push(self):
        rec = self._meta2_record()

        # create volume
        resp = self._post("/v1/rdir/meta2/create", params={"vol": self.vol})
        self.assertEqual(resp.status, 201)

        # now the push must succeed
        resp = self._post(
            "/v1/rdir/meta2/push", params={"vol": self.vol}, data=json.dumps(rec)
        )
        self.assertEqual(resp.status, 204)

        # we must fetch the same data with an additional empty extra_data
        resp = self._get(
            "/v1/rdir/meta2/fetch", params={"vol": self.vol}, data=json.dumps({})
        )
        self.assertEqual(resp.status, 200)

        rec["extra_data"] = None
        reference = {"records": [rec], "truncated": False}
        self.assertEqual(self.json_loads(resp.data), reference)

    def test_meta2_push_several(self):
        recs = self._meta2_record(new_format=True)
        recs.extend(self._meta2_record(new_format=True))
        recs.extend(self._meta2_record(new_format=True))

        # create volume
        resp = self._post("/v1/rdir/meta2/create", params={"vol": self.vol})
        self.assertEqual(resp.status, 201)

        # now the push must succeed
        resp = self._post(
            "/v1/rdir/meta2/push", params={"vol": self.vol}, data=json.dumps(recs)
        )
        self.assertEqual(resp.status, 204)

        # we must fetch the same data with an additional empty extra_data
        resp = self._get("/v1/rdir/meta2/fetch", params={"vol": self.vol})
        self.assertEqual(resp.status, 200)

        recs.sort(key=lambda x: x["container_url"])
        for rec in recs:
            rec["extra_data"] = None
        reference = {"records": recs, "truncated": False}
        self.assertEqual(reference, self.json_loads(resp.data))

    def test_meta2_delete(self):
        rec = self._meta2_record()

        # create volume
        resp = self._post("/v1/rdir/meta2/create", params={"vol": self.vol})
        self.assertEqual(resp.status, 201)

        # the fetch returns an empty array
        resp = self._get(
            "/v1/rdir/meta2/fetch", params={"vol": self.vol}, data=json.dumps({})
        )
        self.assertEqual(resp.status, 200)
        self.assertEqual(
            self.json_loads(resp.data), {"records": [], "truncated": False}
        )

        # deleting must succeed
        resp = self._post(
            "/v1/rdir/meta2/delete", params={"vol": self.vol}, data=json.dumps(rec)
        )
        self.assertEqual(resp.status, 204)

        # fetching must return an empty array
        resp = self._get(
            "/v1/rdir/meta2/fetch", params={"vol": self.vol}, data=json.dumps({})
        )
        self.assertEqual(resp.status, 200)
        self.assertEqual(
            self.json_loads(resp.data), {"records": [], "truncated": False}
        )
