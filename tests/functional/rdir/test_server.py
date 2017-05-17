import time
import tempfile
import shutil
import simplejson as json
import subprocess
import requests
from os import remove

from tests.utils import BaseTestCase, random_str, random_id


def _key(rec):
    return '|'.join((rec['container_id'], rec['content_id'], rec['chunk_id']))


class TestRdirServer(BaseTestCase):
    def setUp(self):
        super(TestRdirServer, self).setUp()
        self.num, self.db_path, self.host, self.port = self.get_service('rdir')
        self.session = requests.Session()
        self.vol = self._volume()

    def tearDown(self):
        super(TestRdirServer, self).tearDown()
        self.session.close()

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
        return self.session.get(self._rdir_url(url), **kwargs)

    def _post(self, url, **kwargs):
        return self.session.post(self._rdir_url(url), **kwargs)

    def _delete(self, url, **kwargs):
        return self.session.delete(self._rdir_url(url), **kwargs)

    def test_explicit_create(self):
        rec = self._record()

        # try to push on unknown volume
        resp = self._post(
                "/v1/rdir/push", params={'vol': self.vol},
                data=json.dumps(rec))
        self.assertEqual(resp.status_code, 404)

        # The fetch fails
        resp = self._post("/v1/rdir/fetch", params={'vol': self.vol})
        self.assertEqual(resp.status_code, 404)

        # create volume
        resp = self._post("/v1/rdir/create", params={'vol': self.vol})
        self.assertEqual(resp.status_code, 201)

        # the fetch returns an empty array
        resp = self._post("/v1/rdir/fetch", params={'vol': self.vol})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), [])

        # now the push must succeed
        resp = self._post(
                "/v1/rdir/push", params={'vol': self.vol},
                data=json.dumps(rec))
        self.assertEqual(resp.status_code, 204)

        # we must fetch the same data
        resp = self._post("/v1/rdir/fetch", params={'vol': self.vol})
        self.assertEqual(resp.status_code, 200)
        reference = [
            [_key(rec), {'mtime': rec['mtime'], 'rtime': 0}]
        ]
        self.assertListEqual(resp.json(), reference)

        # deleting must succeed
        resp = self._delete(
                "/v1/rdir/delete", params={'vol': self.vol},
                data=json.dumps(rec))
        self.assertEqual(resp.status_code, 204)

        # fetching must return an empty array
        resp = self._post("/v1/rdir/fetch", params={'vol': self.vol})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), [])

    def test_implicit_create(self):
        rec = self._record()

        # try to push on unknown volume
        resp = self._post(
                "/v1/rdir/push", params={'vol': self.vol},
                data=json.dumps(rec))
        self.assertEqual(resp.status_code, 404)

        # try to push on unknown volume WITH create flag
        resp = self._post(
                "/v1/rdir/push", params={'vol': self.vol, 'create': True},
                data=json.dumps(rec))
        self.assertEqual(resp.status_code, 204)

        # We must fetch the same data
        resp = self._post("/v1/rdir/fetch", params={'vol': self.vol})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), [
            [_key(rec), {'mtime': rec['mtime'], 'rtime': 0}]
        ])

    def test_push_missing_fields(self):
        rec = self._record()

        # DB creation
        resp = self._post("/v1/rdir/create", params={'vol': self.vol})
        self.assertEqual(resp.status_code, 201)

        for k in ['container_id', 'content_id', 'chunk_id']:
            save = rec.pop(k)
            # push an incomplete record
            resp = self._post(
                    "/v1/rdir/push", params={'vol': self.vol},
                    data=json.dumps(rec))
            self.assertEqual(resp.status_code, 400)
            # check we list nothing
            resp = self._post("/v1/rdir/fetch", params={'vol': self.vol})
            self.assertEqual(resp.status_code, 200)
            self.assertListEqual(resp.json(), [])
            rec[k] = save

    def test_lock_unlock(self):
        who = random_str(64)

        # lock without who, DB not created
        resp = self._post(
                "/v1/rdir/admin/lock", params={'vol': self.vol},
                data=json.dumps({}))
        self.assertEqual(resp.status_code, 400)

        # lock with who, DB not created
        resp = self._post(
                "/v1/rdir/admin/lock", params={'vol': self.vol},
                data=json.dumps({'who': who}))
        self.assertEqual(resp.status_code, 404)

        # DB creation
        resp = self._post("/v1/rdir/create", params={'vol': self.vol})
        self.assertEqual(resp.status_code, 201)

        # lock without who
        resp = self._post(
                "/v1/rdir/admin/lock", params={'vol': self.vol},
                data=json.dumps({}))
        self.assertEqual(resp.status_code, 400)

        # lock
        resp = self._post(
                "/v1/rdir/admin/lock", params={'vol': self.vol},
                data=json.dumps({'who': who}))
        self.assertEqual(resp.status_code, 204)

        # double lock, different who
        resp = self._post(
                "/v1/rdir/admin/lock", params={'vol': self.vol},
                data=json.dumps({'who': random_str(64)}))
        self.assertEqual(resp.status_code, 403)
        body = resp.json()
        self.assertEqual(body['message'], "Already locked by %s" % who)

        # unlock
        resp = self._post("/v1/rdir/admin/unlock", params={'vol': self.vol})
        self.assertEqual(resp.status_code, 204)

    def test_rdir_clear_and_lock(self):
        rec = self._record()
        who = random_id(32)

        # push with autocreate
        resp = self._post(
                "/v1/rdir/push", params={'vol': self.vol, 'create': True},
                data=json.dumps(rec))
        self.assertEqual(resp.status_code, 204)

        # lock
        resp = self._post(
                "/v1/rdir/admin/lock", params={'vol': self.vol},
                data=json.dumps({'who': who}))
        self.assertEqual(resp.status_code, 204)

        # try to clear while the lock is held
        resp = self._post("/v1/rdir/admin/clear", params={'vol': self.vol})
        self.assertEqual(resp.status_code, 403)

        # unlock
        resp = self._post("/v1/rdir/admin/unlock", params={'vol': self.vol})
        self.assertEqual(resp.status_code, 204)

        # clear all entries
        resp = self._post(
                "/v1/rdir/admin/clear", params={'vol': self.vol},
                data=json.dumps({'all': True}))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {'removed': 1})

    def test_vol_status(self):
        # Status on inexistant DB
        resp = self._post("/v1/rdir/status", params={'vol': self.vol})
        self.assertEqual(resp.status_code, 404)

        # DB creation
        resp = self._post("/v1/rdir/create", params={'vol': self.vol})
        self.assertEqual(resp.status_code, 201)

        # Status on an empty DB
        resp = self._get("/v1/rdir/status", params={'vol': self.vol})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {'chunk': {'total': 0}, 'container': {}})


class TestRdirServer2(TestRdirServer):
    def setUp(self):
        super(TestRdirServer2, self).setUp()
        self.host = '127.0.0.1'
        self.port = 5999
        self.db_path = tempfile.mkdtemp()
        self.cfg_path = tempfile.mktemp()
        with open(self.cfg_path, 'w') as f:
            f.write("[rdir-server]\n")
            f.write("bind_addr = {0}\n".format(self.host))
            f.write("bind_port = {0}\n".format(self.port))
            f.write("namespace = {0}\n".format(self.ns))
            f.write("db_path = {0}\n".format(self.db_path))
            f.write("syslog_prefix = OIO,OPENIO,rdir,1\n")

        self.child = subprocess.Popen(['oio-rdir-server', self.cfg_path],
                                      close_fds=True)
        if not self._wait_for_that_fucking_slow_startup_on_travis():
            self.child.kill()
            raise Exception("The RDIR server is too long to start")

    def tearDown(self):
        super(TestRdirServer2, self).tearDown()
        self.session.close()
        self._kill_and_watch_it_die()
        shutil.rmtree(self.db_path)
        remove(self.cfg_path)

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

    def test_status(self):

        # check the service has no opened DB
        resp = self._get('/status')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {'opened_db_count': 0})

        # DB creation
        resp = self._post("/v1/rdir/create", params={'vol': self.vol})
        self.assertEqual(resp.status_code, 201)

        # The base remains open after it has been created
        resp = self._get('/status')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {'opened_db_count': 1})
