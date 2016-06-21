import time
import tempfile
import shutil
import simplejson as json
import unittest

from werkzeug.test import Client
from werkzeug.wrappers import BaseResponse
from oio.rdir.server import create_app
from tests.utils import random_str, random_id


class TestRdirServer(unittest.TestCase):
    def setUp(self):
        super(TestRdirServer, self).setUp()

        self.db_path = tempfile.mkdtemp()
        self.conf = {'db_path': self.db_path,
                     'namespace': 'OPENIO'}

        self.app = Client(create_app(self.conf), BaseResponse)
        self.volume = 'testvolume'
        self.app.get("/v1/rdir/create", query_string={'vol': self.volume})
        self.container_id = random_id(64)
        self.content_id = random_id(32)
        self.chunk_id = random_id(64)
        self.mtime = int(time.time())
        self.rtime = 0
        self.meta = {
            'container_id': self.container_id,
            'content_id': self.content_id,
            'chunk_id': self.chunk_id,
            'mtime': self.mtime,
            'rtime': self.rtime}

    def tearDown(self):
        super(TestRdirServer, self).tearDown()
        del self.app
        shutil.rmtree(self.db_path)

    def test_explicit_create(self):
        # try to push on unknown volume
        resp = self.app.post("/v1/rdir/push",
                             query_string={'vol': "testvolume2"},
                             data=json.dumps(self.meta),
                             content_type="application/json")
        self.assertEqual(resp.status_code, 404)
        # create volume
        self.app.get("/v1/rdir/create", query_string={'vol': "testvolume2"})
        resp = self.app.post("/v1/rdir/push",
                             query_string={'vol': "testvolume2"},
                             data=json.dumps(self.meta),
                             content_type="application/json")
        self.assertEqual(resp.status_code, 204)

    def test_push(self):
        resp = self.app.post("/v1/rdir/push",
                             query_string={'vol': self.volume},
                             data=json.dumps(self.meta),
                             content_type="application/json")
        self.assertEqual(resp.status_code, 204)

        resp = self.app.post("/v1/rdir/fetch",
                             query_string={'vol': self.volume},
                             data=json.dumps({}),
                             content_type="application/json")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(json.loads(resp.data), [
            [
                "%s|%s|%s" %
                (self.container_id, self.content_id, self.chunk_id),
                {
                    'mtime': self.mtime,
                    'rtime': self.rtime
                }
            ]
        ])

    def test_push_missing_fields(self):
        for k in ['container_id', 'content_id', 'chunk_id']:
            save = self.meta.pop(k)
            resp = self.app.post("/v1/rdir/push",
                                 query_string={'vol': self.volume},
                                 data=json.dumps(self.meta),
                                 content_type="application/json")
            self.assertEqual(resp.status_code, 400)
            resp = self.app.post("/v1/rdir/fetch",
                                 query_string={'vol': self.volume},
                                 data=json.dumps({}),
                                 content_type="application/json")
            self.assertEqual(resp.status_code, 200)
            # verify that no chunk got indexed
            self.assertEqual(len(json.loads(resp.data)), 0)
            self.meta[k] = save

    def test_push_fetch_delete(self):
        # push
        resp = self.app.post("/v1/rdir/push",
                             query_string={'vol': self.volume},
                             data=json.dumps(self.meta),
                             content_type="application/json")
        self.assertEqual(resp.status_code, 204)

        # fetch
        resp = self.app.post("/v1/rdir/fetch",
                             query_string={'vol': self.volume},
                             data=json.dumps({}),
                             content_type="application/json")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(json.loads(resp.data), [
            [
                "%s|%s|%s" %
                (self.container_id, self.content_id, self.chunk_id),
                {
                    'mtime': self.mtime,
                    'rtime': self.rtime
                }
            ]
        ])

        # delete
        data = {
            'container_id': self.container_id,
            'content_id': self.content_id,
            'chunk_id': self.chunk_id,
        }
        resp = self.app.delete("/v1/rdir/delete",
                               query_string={'vol': self.volume},
                               data=json.dumps(data),
                               content_type="application/json")
        self.assertEqual(resp.status_code, 204)

        # fetch
        resp = self.app.post("/v1/rdir/fetch",
                             query_string={'vol': self.volume},
                             data=json.dumps({}),
                             content_type="application/json")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(json.loads(resp.data), [])

    def test_rdir_status(self):
        resp = self.app.get("/v1/rdir/status",
                            query_string={'vol': self.volume})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(json.loads(resp.data),
                         {'chunk': {'total': 0},
                          'container': {}
                          })

    def test_lock_unlock(self):
        # lock without who
        resp = self.app.post("/v1/rdir/admin/lock",
                             query_string={'vol': self.volume},
                             data=json.dumps({}))
        self.assertEqual(resp.status_code, 400)

        # lock
        who = random_str(64)
        data = {'who': who}
        resp = self.app.post("/v1/rdir/admin/lock",
                             query_string={'vol': self.volume},
                             data=json.dumps(data))
        self.assertEqual(resp.status_code, 204)

        # double lock
        data = {'who': random_str(64)}
        resp = self.app.post("/v1/rdir/admin/lock",
                             query_string={'vol': self.volume},
                             data=json.dumps(data))
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.data, "Already locked by %s" % who)

        # unlock
        resp = self.app.post("/v1/rdir/admin/unlock",
                             query_string={'vol': self.volume})
        self.assertEqual(resp.status_code, 204)

    def test_rdir_bad_ns(self):
        resp = self.app.get("/v1/badns/rdir/status",
                            query_string={'vol': self.volume})
        self.assertEqual(resp.status_code, 400)

    def test_rdir_clear_and_lock(self):
        # push
        resp = self.app.post("/v1/rdir/push",
                             query_string={'vol': self.volume},
                             data=json.dumps(self.meta),
                             content_type="application/json")
        self.assertEqual(resp.status_code, 204)

        # lock
        data = {'who': "a functionnal test"}
        resp = self.app.post("/v1/rdir/admin/lock",
                             query_string={'vol': self.volume},
                             data=json.dumps(data))
        self.assertEqual(resp.status_code, 204)

        # try to clear while the lock is held
        resp = self.app.post("/v1/rdir/admin/clear",
                             query_string={'vol': self.volume},
                             data=json.dumps({}))
        self.assertEqual(resp.status_code, 403)

        # unlock
        resp = self.app.post("/v1/rdir/admin/unlock",
                             query_string={'vol': self.volume})
        self.assertEqual(resp.status_code, 204)

        # clear all entries
        resp = self.app.post("/v1/rdir/admin/clear",
                             query_string={'vol': self.volume},
                             data=json.dumps({'all': True}))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(json.loads(resp.data), {'removed': 1})

    def test_status(self):
        resp = self.app.get('/status')
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertEqual(data, {'opened_db_count': 0})
