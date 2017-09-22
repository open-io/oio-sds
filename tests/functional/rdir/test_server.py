# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
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
import tempfile
import shutil
import simplejson as json
import subprocess
from os import remove
from oio.common.http import get_pool_manager

from tests.utils import CommonTestCase, random_str, random_id


def _key(rec):
    return '|'.join((rec['container_id'], rec['content_id'], rec['chunk_id']))


def _write_config(path, config):
    with open(path, 'w') as f:
        f.write("[rdir-server]\n")
        f.write("bind_addr = {0}\n".format(config['host']))
        f.write("bind_port = {0}\n".format(config['port']))
        f.write("namespace = {0}\n".format(config['ns']))
        f.write("db_path = {0}\n".format(config['db']))
        f.write("syslog_prefix = OIO,OPENIO,rdir,1\n")


class RdirTestCase(CommonTestCase):
    def setUp(self):
        super(RdirTestCase, self).setUp()
        self.http_pool = get_pool_manager(max_retries=10)

    def tearDown(self):
        super(RdirTestCase, self).tearDown()
        self.http_pool.clear()

    def _volume(self):
        return random_id(8)

    def _record(self):
        return {"container_id": random_id(64),
                "content_id": random_id(32),
                "chunk_id": random_id(64),
                "mtime": 17}

    def _rdir_url(self, tail):
        return 'http://{0}:{1}{2}'.format(self.host, self.port, tail)

    def _get(self, url, **kwargs):
        return self.request('GET', self._rdir_url(url), **kwargs)

    def _post(self, url, **kwargs):
        return self.request('POST', self._rdir_url(url), **kwargs)

    def _delete(self, url, **kwargs):
        return self.request('DELETE', self._rdir_url(url), **kwargs)

    def _kill_and_watch_it_die(self):
        self.child.terminate()
        self.child.wait()

    def _wait_for_that_fucking_slow_startup_on_travis(self):
        for i in range(5):
            if self._check_for_server():
                return True
            time.sleep(i * 0.2)
        return False

    def _check_for_server(self):
        hexport = "%04X" % self.port
        with open("/proc/net/tcp", "r") as f:
            for line in f:
                tokens = line.strip().split()
                port = tokens[1][9:13]
                if port == hexport:
                    return True
        return False


class TestRdirServer(RdirTestCase):
    def setUp(self):
        super(TestRdirServer, self).setUp()
        self.num, self.db_path, self.host, self.port = self.get_service('rdir')
        self.port = int(self.port)
        self.vol = self._volume()

    def tearDown(self):
        super(TestRdirServer, self).tearDown()

    def test_explicit_create(self):
        rec = self._record()

        # try to push on unknown volume
        resp = self._post(
                "/v1/rdir/push", params={'vol': self.vol},
                data=json.dumps(rec))
        self.assertEqual(resp.status, 404)

        # The fetch fails
        resp = self._post("/v1/rdir/fetch", params={'vol': self.vol})
        self.assertEqual(resp.status, 404)

        # create volume
        resp = self._post("/v1/rdir/create", params={'vol': self.vol})
        self.assertEqual(resp.status, 201)

        # the fetch returns an empty array
        resp = self._post("/v1/rdir/fetch", params={'vol': self.vol})
        self.assertEqual(resp.status, 200)
        self.assertEqual(self.json_loads(resp.data), [])

        # now the push must succeed
        resp = self._post(
                "/v1/rdir/push", params={'vol': self.vol},
                data=json.dumps(rec))
        self.assertEqual(resp.status, 204)

        # we must fetch the same data
        resp = self._post("/v1/rdir/fetch", params={'vol': self.vol})
        self.assertEqual(resp.status, 200)
        reference = [
            [_key(rec), {'mtime': rec['mtime'], 'rtime': 0}]
        ]
        self.assertListEqual(self.json_loads(resp.data), reference)

        # deleting must succeed
        resp = self._delete(
                "/v1/rdir/delete", params={'vol': self.vol},
                data=json.dumps(rec))
        self.assertEqual(resp.status, 204)

        # fetching must return an empty array
        resp = self._post("/v1/rdir/fetch", params={'vol': self.vol})
        self.assertEqual(resp.status, 200)
        self.assertEqual(self.json_loads(resp.data), [])

    def test_implicit_create(self):
        rec = self._record()

        # try to push on unknown volume
        resp = self._post(
                "/v1/rdir/push", params={'vol': self.vol},
                data=json.dumps(rec))
        self.assertEqual(resp.status, 404)

        # try to push on unknown volume WITH create flag
        resp = self._post(
                "/v1/rdir/push", params={'vol': self.vol, 'create': True},
                data=json.dumps(rec))
        self.assertEqual(resp.status, 204)

        # We must fetch the same data
        resp = self._post("/v1/rdir/fetch", params={'vol': self.vol})
        self.assertEqual(resp.status, 200)
        self.assertEqual(self.json_loads(resp.data), [
            [_key(rec), {'mtime': rec['mtime'], 'rtime': 0}]
        ])

    def test_push_missing_fields(self):
        rec = self._record()

        # DB creation
        resp = self._post("/v1/rdir/create", params={'vol': self.vol})
        self.assertEqual(resp.status, 201)

        for k in ['container_id', 'content_id', 'chunk_id']:
            save = rec.pop(k)
            # push an incomplete record
            resp = self._post(
                    "/v1/rdir/push", params={'vol': self.vol},
                    data=json.dumps(rec))
            self.assertEqual(resp.status, 400)
            # check we list nothing
            resp = self._post("/v1/rdir/fetch", params={'vol': self.vol})
            self.assertEqual(resp.status, 200)
            self.assertListEqual(self.json_loads(resp.data), [])
            rec[k] = save

    def test_lock_unlock(self):
        who = random_str(64)

        # lock without who, DB not created
        resp = self._post(
                "/v1/rdir/admin/lock", params={'vol': self.vol},
                data=json.dumps({}))
        self.assertEqual(resp.status, 400)

        # lock with who, DB not created
        resp = self._post(
                "/v1/rdir/admin/lock", params={'vol': self.vol},
                data=json.dumps({'who': who}))
        self.assertEqual(resp.status, 404)

        # DB creation
        resp = self._post("/v1/rdir/create", params={'vol': self.vol})
        self.assertEqual(resp.status, 201)

        # lock without who
        resp = self._post(
                "/v1/rdir/admin/lock", params={'vol': self.vol},
                data=json.dumps({}))
        self.assertEqual(resp.status, 400)

        # lock
        resp = self._post(
                "/v1/rdir/admin/lock", params={'vol': self.vol},
                data=json.dumps({'who': who}))
        self.assertEqual(resp.status, 204)

        # double lock, different who
        resp = self._post(
                "/v1/rdir/admin/lock", params={'vol': self.vol},
                data=json.dumps({'who': random_str(64)}))
        self.assertEqual(resp.status, 403)
        body = self.json_loads(resp.data)
        self.assertEqual(body['message'], "Already locked by %s" % who)

        # unlock
        resp = self._post("/v1/rdir/admin/unlock", params={'vol': self.vol})
        self.assertEqual(resp.status, 204)

    def test_rdir_clear_and_lock(self):
        rec = self._record()
        who = random_id(32)

        # push with autocreate
        resp = self._post(
                "/v1/rdir/push", params={'vol': self.vol, 'create': True},
                data=json.dumps(rec))
        self.assertEqual(resp.status, 204)

        # lock
        resp = self._post(
                "/v1/rdir/admin/lock", params={'vol': self.vol},
                data=json.dumps({'who': who}))
        self.assertEqual(resp.status, 204)

        # try to clear while the lock is held
        resp = self._post("/v1/rdir/admin/clear", params={'vol': self.vol})
        self.assertEqual(resp.status, 403)

        # unlock
        resp = self._post("/v1/rdir/admin/unlock", params={'vol': self.vol})
        self.assertEqual(resp.status, 204)

        # clear all entries
        resp = self._post(
                "/v1/rdir/admin/clear", params={'vol': self.vol},
                data=json.dumps({'all': True}))
        self.assertEqual(resp.status, 200)
        self.assertEqual(self.json_loads(resp.data), {'removed': 1})

    def test_vol_status(self):
        # Status on inexistant DB
        resp = self._post("/v1/rdir/status", params={'vol': self.vol})
        self.assertEqual(resp.status, 404)

        # DB creation
        resp = self._post("/v1/rdir/create", params={'vol': self.vol})
        self.assertEqual(resp.status, 201)

        # Status on an empty DB
        resp = self._get("/v1/rdir/status", params={'vol': self.vol})
        self.assertEqual(resp.status, 200)
        self.assertEqual(self.json_loads(resp.data),
                         {'chunk': {'total': 0}, 'container': {}})


class TestRdirServer2(RdirTestCase):
    def setUp(self):
        super(TestRdirServer2, self).setUp()
        self.vol = self._volume()
        self.num, self.host, self.port = 17, '127.0.0.1', 5999
        self.cfg_path = tempfile.mktemp()
        self.db_path = tempfile.mkdtemp()
        config = {'host': self.host, 'port': self.port,
                  'ns': self.ns, 'db': self.db_path}
        _write_config(self.cfg_path, config)

        self.child = subprocess.Popen(['oio-rdir-server', self.cfg_path],
                                      close_fds=True)
        if not self._wait_for_that_fucking_slow_startup_on_travis():
            self.child.kill()
            raise Exception("The RDIR server is too long to start")

    def tearDown(self):
        super(TestRdirServer2, self).tearDown()
        self.http_pool.clear()
        self._kill_and_watch_it_die()
        shutil.rmtree(self.db_path)
        remove(self.cfg_path)

    def test_status(self):

        # check the service has no opened DB
        resp = self._get('/status')
        self.assertEqual(resp.status, 200)
        self.assertEqual(self.json_loads(resp.data), {'opened_db_count': 0})

        # DB creation
        resp = self._post("/v1/rdir/create", params={'vol': self.vol})
        self.assertEqual(resp.status, 201)

        # The base remains open after it has been created
        resp = self._get('/status')
        self.assertEqual(resp.status, 200)
        self.assertEqual(self.json_loads(resp.data), {'opened_db_count': 1})


def _check_process_absent(proc):
    for i in range(5):
        if not proc.poll():
            return True
        time.sleep(i * 0.2)
    proc.terminate()
    return False


class TestRdirServer3(RdirTestCase):
    """Test the oio-rdir-server with invalid configuration"""

    def setUp(self):
        super(TestRdirServer3, self).setUp()

    def tearDown(self):
        super(TestRdirServer3, self).tearDown()

    def test_wrong_config(self):
        cfg = '/x/y/z/not_found/on_any/server/rdir.conf'
        with open('/dev/null', 'w') as out:
            fd = out.fileno()
            proc = subprocess.Popen(
                    ['oio-rdir-server', cfg], stderr=fd)
            self.assertTrue(_check_process_absent(proc))

    def test_basedir_not_found(self):
        self.num, self.host, self.port = 17, '127.0.0.1', 5999
        self.cfg_path = tempfile.mktemp()
        config = {'host': self.host, 'port': self.port,
                  'ns': self.ns, 'db': '/x/y/z/not_found'}
        _write_config(self.cfg_path, config)
        with open('/dev/null', 'w') as out:
            fd = out.fileno()
            proc = subprocess.Popen(
                    ['oio-rdir-server', self.cfg_path], stderr=fd)
        self.assertTrue(_check_process_absent(proc))

    def test_basedir_not_dir(self):
        self.num, self.host, self.port = 17, '127.0.0.1', 5999
        self.cfg_path = tempfile.mktemp()
        config = {'host': self.host, 'port': self.port,
                  'ns': self.ns, 'db': '/etc/magic'}
        _write_config(self.cfg_path, config)
        with open('/dev/null', 'w') as out:
            fd = out.fileno()
            proc = subprocess.Popen(
                    ['oio-rdir-server', self.cfg_path], stderr=fd)
        self.assertTrue(_check_process_absent(proc))

    def test_basedir_denied(self):
        self.num, self.host, self.port = 17, '127.0.0.1', 5999
        self.cfg_path = tempfile.mktemp()
        config = {'host': self.host, 'port': self.port,
                  'ns': self.ns, 'db': '/var'}
        _write_config(self.cfg_path, config)
        with open('/dev/null', 'w') as out:
            fd = out.fileno()
            proc = subprocess.Popen(
                    ['oio-rdir-server', self.cfg_path], stderr=fd)
        self.assertTrue(_check_process_absent(proc))

