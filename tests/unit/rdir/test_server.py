import logging
import time
import tempfile
import shutil
import simplejson as json
import unittest
import subprocess
import requests
from os import remove

from tests.utils import random_str, random_id


def _key(rec):
    return '|'.join((rec['container_id'], rec['content_id'], rec['chunk_id']))


class TestRdirServer(unittest.TestCase):
    def setUp(self):
        super(TestRdirServer, self).setUp()
        self.addr = ('127.0.0.1', 5999)
        self.db_path = tempfile.mkdtemp()
        self.cfg_path = tempfile.mktemp()
        with open(self.cfg_path, 'w') as f:
            f.write("[rdir-server]\n")
            f.write("bind_addr = {0}\n".format(self.addr[0]))
            f.write("bind_port = {0}\n".format(self.addr[1]))
            f.write("namespace = OPENIO\n")
            f.write("db_path = {0}\n".format(self.db_path))
            f.write("syslog_prefix = OIO,OPENIO,rdir,1\n")

        self.child = subprocess.Popen(['oio-rdir-server', self.cfg_path])
        self.session = requests.Session()
        time.sleep(0.5)

    def tearDown(self):
        super(TestRdirServer, self).tearDown()
        if self.child:
            self.child.kill()
        self.session.close()
        shutil.rmtree(self.db_path)
        remove(self.cfg_path)

    def _volume(self):
        return random_id(8)

    def _record(self):
        return {"container_id": random_id(64),
                "content_id": random_id(32),
                "chunk_id": random_id(64),
                "mtime": 17}

    def _url(self, tail):
        return 'http://{0}:{1}{2}'.format(self.addr[0], self.addr[1], tail)

    def _get(self, url, **kwargs):
        return self.session.get(self._url(url), **kwargs)

    def _post(self, url, **kwargs):
        return self.session.post(self._url(url), **kwargs)

    def _delete(self, url, **kwargs):
        return self.session.delete(self._url(url), **kwargs)

    def test_explicit_create(self):
        vol = self._volume()
        rec = self._record()

        # try to push on unknown volume
        resp = self._post(
                "/v1/rdir/push", params={'vol': vol},
                data=json.dumps(rec))
        self.assertEqual(resp.status_code, 404)

        # The fetch fails
        resp = self._post("/v1/rdir/fetch", params={'vol': vol})
        self.assertEqual(resp.status_code, 404)

        # create volume
        resp = self._post("/v1/rdir/create", params={'vol': vol})
        self.assertEqual(resp.status_code, 201)

        # the fetch returns an empty array
        resp = self._post("/v1/rdir/fetch", params={'vol': vol})
        self.assertEqual(resp.status_code, 200)
        logging.debug("%s", resp.json())
        self.assertEqual(resp.json(), [])

        # now the push must succeed
        resp = self._post(
                "/v1/rdir/push", params={'vol': vol},
                data=json.dumps(rec))
        self.assertEqual(resp.status_code, 204)

        # we must fetch the same data
        resp = self._post("/v1/rdir/fetch", params={'vol': vol})
        self.assertEqual(resp.status_code, 200)
        reference = [
            [_key(rec), {'mtime': rec['mtime'], 'rtime': 0}]
        ]
        self.assertListEqual(resp.json(), reference)

        # deleting must succeed
        resp = self._delete(
                "/v1/rdir/delete", params={'vol': vol}, data=json.dumps(rec))
        self.assertEqual(resp.status_code, 204)

        # fetching must return an empty array
        resp = self._post("/v1/rdir/fetch", params={'vol': vol})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), [])

    def test_implicit_create(self):
        vol = self._volume()
        rec = self._record()

        # try to push on unknown volume
        resp = self._post(
                "/v1/rdir/push", params={'vol': vol},
                data=json.dumps(rec))
        self.assertEqual(resp.status_code, 404)

        # try to push on unknown volume WITH create flag
        resp = self._post(
                "/v1/rdir/push", params={'vol': vol, 'create': True},
                data=json.dumps(rec))
        self.assertEqual(resp.status_code, 204)

        # We must fetch the same data
        resp = self._post("/v1/rdir/fetch", params={'vol': vol})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), [
            [_key(rec), {'mtime': rec['mtime'], 'rtime': 0}]
        ])

    def test_push_missing_fields(self):
        rec = self._record()
        vol = self._volume()

        # DB creation
        resp = self._post("/v1/rdir/create", params={'vol': vol})
        self.assertEqual(resp.status_code, 201)

        for k in ['container_id', 'content_id', 'chunk_id']:
            save = rec.pop(k)
            # push an incomplete record
            resp = self._post(
                    "/v1/rdir/push", params={'vol': vol},
                    data=json.dumps(rec))
            self.assertEqual(resp.status_code, 400)
            # check we list nothing
            resp = self._post("/v1/rdir/fetch", params={'vol': vol})
            self.assertEqual(resp.status_code, 200)
            self.assertListEqual(resp.json(), [])
            rec[k] = save

    def test_lock_unlock(self):
        vol = self._volume()
        who = random_str(64)

        # lock without who, DB not created
        resp = self._post(
                "/v1/rdir/admin/lock", params={'vol': vol},
                data=json.dumps({}))
        self.assertEqual(resp.status_code, 400)

        # lock with who, DB not created
        resp = self._post(
                "/v1/rdir/admin/lock", params={'vol': vol},
                data=json.dumps({'who': who}))
        self.assertEqual(resp.status_code, 404)

        # DB creation
        resp = self._post("/v1/rdir/create", params={'vol': vol})
        self.assertEqual(resp.status_code, 201)

        # lock without who
        resp = self._post(
                "/v1/rdir/admin/lock", params={'vol': vol},
                data=json.dumps({}))
        self.assertEqual(resp.status_code, 400)

        # lock
        resp = self._post(
                "/v1/rdir/admin/lock", params={'vol': vol},
                data=json.dumps({'who': who}))
        self.assertEqual(resp.status_code, 204)

        # double lock, different who
        resp = self._post(
                "/v1/rdir/admin/lock", params={'vol': vol},
                data=json.dumps({'who': random_str(64)}))
        self.assertEqual(resp.status_code, 403)
        body = resp.json()
        self.assertEqual(body['message'], "Already locked by %s" % who)

        # unlock
        resp = self._post("/v1/rdir/admin/unlock", params={'vol': vol})
        self.assertEqual(resp.status_code, 204)

    def test_rdir_clear_and_lock(self):
        rec = self._record()
        vol = self._volume()
        who = random_id(32)

        # push with autocreate
        resp = self._post(
                "/v1/rdir/push", params={'vol': vol, 'create': True},
                data=json.dumps(rec))
        self.assertEqual(resp.status_code, 204)

        # lock
        resp = self._post(
                "/v1/rdir/admin/lock", params={'vol': vol},
                data=json.dumps({'who': who}))
        self.assertEqual(resp.status_code, 204)

        # try to clear while the lock is held
        resp = self._post("/v1/rdir/admin/clear", params={'vol': vol})
        self.assertEqual(resp.status_code, 403)

        # unlock
        resp = self._post("/v1/rdir/admin/unlock", params={'vol': vol})
        self.assertEqual(resp.status_code, 204)

        # clear all entries
        resp = self._post(
                "/v1/rdir/admin/clear", params={'vol': vol},
                data=json.dumps({'all': True}))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {'removed': 1})

    def test_vol_status(self):
        vol = self._volume()

        # Status on inexistant DB
        resp = self._post("/v1/rdir/status", params={'vol': vol})
        self.assertEqual(resp.status_code, 404)

        # DB creation
        resp = self._post("/v1/rdir/create", params={'vol': vol})
        self.assertEqual(resp.status_code, 201)

        # Status on an empty DB
        resp = self._get("/v1/rdir/status", params={'vol': vol})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {'chunk': {'total': 0}, 'container': {}})

    def test_status(self):
        vol = self._volume()

        resp = self._get('/status')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {'opened_db_count': 0})

        # DB creation
        resp = self._post("/v1/rdir/create", params={'vol': vol})
        self.assertEqual(resp.status_code, 201)

        # The base remains open after it has been created
        resp = self._get('/status')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {'opened_db_count': 1})
