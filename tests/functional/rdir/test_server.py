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
import errno
from os import remove
from oio.common.http_urllib3 import get_pool_manager

from tests.utils import CommonTestCase, random_str, random_id


def _key(rec):
    return '|'.join((rec['container_id'], rec['content_id'], rec['chunk_id']))


map_cfg = {'host': 'bind_addr', 'port': 'bind_port',
           'ns': 'namespace', 'db': 'db_path'}


def _write_config(path, config):
    with open(path, 'w') as f:
        f.write("[rdir-server]\n")
        for k, v in config.iteritems():
            f.write("{0} = {1}\n".format(map_cfg[k], config[k]))
        f.write("syslog_prefix = OIO,OPENIO,rdir,1\n")


def _check_for_server(port):
    hexport = "%04X" % port
    with open("/proc/net/tcp", "r") as f:
        for line in f:
            tokens = line.strip().split()
            port = tokens[1][9:13]
            if port == hexport:
                return True
    return False


def _wait_for_slow_startup(port):
    for i in range(5):
        if _check_for_server(port):
            return True
        time.sleep(i * 0.2)
    return False


def _kill_and_watch_it_die(proc):
    proc.terminate()
    proc.wait()


def _does_startup_fail(path, config):
    _write_config(path, config)
    with open('/dev/null', 'w') as out:
        fd = out.fileno()
        proc = subprocess.Popen(['oio-rdir-server', path], stderr=fd)
        return _check_process_absent(proc)


def _check_process_absent(proc):
    for i in range(5):
        if not proc.poll():
            return True
        time.sleep(i * 0.2)
    try:
        proc.terminate()
    except OSError as exc:
        return exc.errno == errno.ESRCH
    return False


class RdirTestCase(CommonTestCase):
    def setUp(self):
        super(RdirTestCase, self).setUp()
        self.http_pool = get_pool_manager(max_retries=10)
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
                shutil.rmtree(f, ignore_errors)
                remove(f)
            except Exception:
                pass

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


class TestRdirServer(RdirTestCase):
    def setUp(self):
        super(TestRdirServer, self).setUp()
        self.num, self.db_path, self.host, self.port = self.get_service('rdir')
        self.port = int(self.port)
        self.vol = self._volume()

    def tearDown(self):
        super(TestRdirServer, self).tearDown()

    def test_status(self):
        resp = self._get("/status")
        self.assertEqual(resp.status, 200)
        resp = self._get("/config")
        self.assertEqual(resp.status, 200)

    def test_explicit_create(self):
        rec = self._record()

        # try to push on unknown volume
        resp = self._post(
                "/v1/rdir/push", params={'vol': self.vol},
                data=json.dumps(rec))
        self.assertEqual(resp.status, 404)

        # fetch without volume
        resp = self._post("/v1/rdir/fetch")
        self.assertEqual(resp.status, 400)

        # fetch with non-json body
        resp = self._post("/v1/rdir/fetch", params={'vol': self.vol},
                          data='this is not json')
        self.assertEqual(resp.status, 400)

        # The fetch fails
        resp = self._post("/v1/rdir/fetch", params={'vol': self.vol})
        self.assertEqual(resp.status, 404)

        # create volume without the volume
        resp = self._post("/v1/rdir/create")
        self.assertEqual(resp.status, 400)

        # create volume
        resp = self._post("/v1/rdir/create", params={'vol': self.vol})
        self.assertEqual(resp.status, 201)

        resp = self._get("/v1/status", params={'vol': self.vol})
        self.assertEqual(resp.status, 200)

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

        # delete without volume
        resp = self._delete("/v1/rdir/delete")
        self.assertEqual(resp.status, 400)

        resp = self._delete("/v1/rdir/delete", params={'vol': ''})
        self.assertEqual(resp.status, 400)

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

        # Push without volume
        resp = self._post("/v1/rdir/push")
        self.assertEqual(resp.status, 400)

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

        # lock without volume
        resp = self._post("/v1/rdir/admin/lock", data=json.dumps({}))
        self.assertEqual(resp.status, 400)

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

        # clear without volume
        resp = self._post("/v1/rdir/admin/clear",
                          data=json.dumps({'all': True}))
        self.assertEqual(resp.status, 400)

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
        # Status without volume
        resp = self._post("/v1/rdir/status")
        self.assertEqual(resp.status, 400)

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
        # Start a sandboxed rdir service
        self.num, self.host, self.port = 17, '127.0.0.1', 5999
        self.cfg_path = tempfile.mktemp()
        self.db_path = tempfile.mkdtemp()
        self.garbage_files.extend((self.cfg_path, self.db_path))

        config = {'host': self.host, 'port': self.port,
                  'ns': self.ns, 'db': self.db_path}
        _write_config(self.cfg_path, config)

        child = subprocess.Popen(['oio-rdir-server', self.cfg_path],
                                 close_fds=True)
        if not _wait_for_slow_startup(self.port):
            child.kill()
            raise Exception("The RDIR server is too long to start")
        else:
            self.garbage_procs.append(child)

    def tearDown(self):
        super(TestRdirServer2, self).tearDown()

    def test_status(self):
        vol = self._volume()

        # check the service has no opened DB
        resp = self._get('/status')
        self.assertEqual(resp.status, 200)
        self.assertEqual(self.json_loads(resp.data), {'opened_db_count': 0})

        # DB creation
        resp = self._post("/v1/rdir/create", params={'vol': vol})
        self.assertEqual(resp.status, 201)

        # The base remains open after it has been created
        resp = self._get('/status')
        self.assertEqual(resp.status, 200)
        self.assertEqual(self.json_loads(resp.data), {'opened_db_count': 1})

    def test_bad_routes(self):
        routes = ('/status', '/config',
                  '/v1/status',
                  '/v1/rdir/admin/show',
                  '/v1/rdir/admin/lock',
                  '/v1/rdir/admin/unlock',
                  '/v1/rdir/admin/incident',
                  '/v1/rdir/admin/clear',
                  '/v1/rdir/create',
                  '/v1/rdir/push',
                  '/v1/rdir/delete',
                  '/v1/rdir/fetch',
                  '/v1/rdir/status')
        for r in routes:
            resp = self._get('/' + r)
            self.assertEqual(resp.status, 404)
            resp = self._get(r + '/')
            self.assertEqual(resp.status, 404)
            bulk = random_id(4)
            resp = self._get('/' + bulk + r)
            self.assertEqual(resp.status, 404)
            resp = self._get(r + '/' + bulk)
            self.assertEqual(resp.status, 404)
            resp = self._get(r + bulk)
            self.assertEqual(resp.status, 404)

    def test_bad_methods(self):
        actions = (('/status', self._post),
                   ('/status', self._delete),
                   ('/config', self._delete),
                   ('/v1/status', self._post),
                   ('/v1/status', self._delete),
                   ('/v1/rdir/admin/show', self._post),
                   ('/v1/rdir/admin/show', self._delete),
                   ('/v1/rdir/admin/lock', self._get),
                   ('/v1/rdir/admin/lock', self._delete),
                   ('/v1/rdir/admin/unlock', self._get),
                   ('/v1/rdir/admin/unlock', self._delete),
                   ('/v1/rdir/admin/incident', self._delete),
                   ('/v1/rdir/admin/clear', self._get),
                   ('/v1/rdir/admin/clear', self._delete),
                   ('/v1/rdir/create', self._get),
                   ('/v1/rdir/create', self._delete),
                   ('/v1/rdir/push', self._get),
                   ('/v1/rdir/push', self._delete),
                   ('/v1/rdir/delete', self._get),
                   ('/v1/rdir/delete', self._post),
                   ('/v1/rdir/fetch', self._get),
                   ('/v1/rdir/fetch', self._delete),
                   ('/v1/rdir/status', self._delete))
        for route, method in actions:
            resp = method(route)
            self.assertEqual(resp.status, 405)


class TestRdirServer3(RdirTestCase):
    """Test the oio-rdir-server with invalid configuration"""

    def setUp(self):
        super(TestRdirServer3, self).setUp()

    def tearDown(self):
        super(TestRdirServer3, self).tearDown()

    def test_no_config(self):
        with open('/dev/null', 'w') as out:
            fd = out.fileno()
            proc = subprocess.Popen(['oio-rdir-server'], stderr=fd)
            self.assertTrue(_check_process_absent(proc))

    def test_wrong_config(self):
        cfg = '/x/y/z/not_found/on_any/server/rdir.conf'
        with open('/dev/null', 'w') as out:
            fd = out.fileno()
            proc = subprocess.Popen(
                    ['oio-rdir-server', cfg], stderr=fd)
            self.assertTrue(_check_process_absent(proc))

    def _check_rdir_startup_fail(self, path, config):
        self.garbage_files.append(path)
        self.assertTrue(_does_startup_fail(path, config))

    def test_basedir_not_found(self):
        path = tempfile.mktemp()
        config = {'host': '127.0.0.1', 'port': 5999, 'ns': self.ns,
                  'db': '/x/y/z/not_found'}
        self._check_rdir_startup_fail(path, config)

    def test_basedir_not_dir(self):
        path = tempfile.mktemp()
        config = {'host': '127.0.0.1', 'port': 5999, 'ns': self.ns,
                  'db': '/etc/magic'}
        self._check_rdir_startup_fail(path, config)

    def test_basedir_denied(self):
        path = tempfile.mktemp()
        config = {'host': '127.0.0.1', 'port': 5999, 'ns': self.ns,
                  'db': '/var'}
        self._check_rdir_startup_fail(path, config)

    def test_incomplete_config(self):
        path = tempfile.mktemp()
        self._check_rdir_startup_fail(
                path, {'host': '127.0.0.1', 'port': 5999, 'db': '/var'})
        self._check_rdir_startup_fail(
                path, {'host': '127.0.0.1', 'port': 5999, 'ns': self.ns})
        self._check_rdir_startup_fail(
                path, {'port': 5999, 'ns': self.ns, 'db': '/var'})
        self._check_rdir_startup_fail(
                path, {'host': '127.0.0.1', 'ns': self.ns, 'db': '/var'})

    def test_good_config(self):
        host, port = '127.0.0.1', 5999
        cfg = tempfile.mktemp()
        db = tempfile.mkdtemp()
        self.garbage_files.extend((cfg, db))
        with open('/dev/null', 'w') as out:
            fd = out.fileno()
            # start a first rdir
            config = {'host': host, 'port': port, 'ns': self.ns, 'db': db}
            _write_config(cfg, config)
            proc0 = subprocess.Popen(['oio-rdir-server', cfg], stderr=fd)
            self.garbage_procs.append(proc0)
            self.assertTrue(_wait_for_slow_startup(port))

    def test_volume_lock(self):
        host, port = '127.0.0.1', 5999
        cfg = tempfile.mktemp()
        db = tempfile.mkdtemp()
        self.garbage_files.extend((cfg, db))
        out = open('/dev/null', 'w')
        fd = out.fileno()

        # start a first rdir
        config = {'host': host, 'port': port, 'ns': self.ns, 'db': db}
        _write_config(cfg, config)
        proc0 = subprocess.Popen(['oio-rdir-server', cfg], stderr=fd)
        self.garbage_procs.append(proc0)
        self.assertTrue(_wait_for_slow_startup(port))

        # now start a second rdir on another port
        config.update({'port': port + 1})
        _write_config(cfg, config)
        proc1 = subprocess.Popen(['oio-rdir-server', cfg], stderr=fd)
        self.garbage_procs.append(proc1)
        self.assertTrue(_check_process_absent(proc1))
