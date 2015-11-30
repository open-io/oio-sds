import tempfile
import shutil
import simplejson as json
from oio.rdir.server import create_app
from tests.utils import BaseTestCase


class TestRdirServer(BaseTestCase):
    def setUp(self):
        super(TestRdirServer, self).setUp()

        self.db_path = tempfile.mkdtemp()
        self.conf = {'db_path': self.db_path,
                     'namespace': 'NS'}

        self.app = create_app(self.conf).test_client()

    def tearDown(self):
        super(TestRdirServer, self).tearDown()
        del self.app
        shutil.rmtree(self.db_path)

    def test_push_allowed_tokens(self):
        data_put = {
            'container_id': "mycontainer",
            'content_id': "mycontent",
            'chunk_id': "mychunk",
            'content_version': "1",
            'content_nbchunks': "3",
            'content_path': "path",
            'content_size': "1234",
            'chunk_hash': "1234567890ABCDEF",
            'chunk_position': "1",
            'chunk_size': "123",
            'mtime': 123456,
            'rtime': 456
        }
        resp = self.app.post("/v1/NS/rdir/push", query_string={'vol': "xxx"},
                             data=json.dumps(data_put),
                             content_type="application/json")
        self.assertEqual(resp.status_code, 204)

        resp = self.app.post("/v1/NS/rdir/fetch", query_string={'vol': "xxx"},
                             data=json.dumps({}),
                             content_type="application/json")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(json.loads(resp.data), {
            "mycontainer|mycontent|mychunk": {
                'content_version': 1,
                'content_nbchunks': 3,
                'content_path': "path",
                'content_size': 1234,
                'chunk_hash': "1234567890ABCDEF",
                'chunk_position': "1",
                'chunk_size': 123,
                'mtime': 123456,
                'rtime': 456
            }
        })

    def test_push_fetch_delete(self):
        # push
        data = {
            'container_id': "mycontainer",
            'content_id': "mycontent",
            'chunk_id': "mychunk",
            'mtime': 1234
        }
        resp = self.app.post("/v1/NS/rdir/push", query_string={'vol': "xxx"},
                             data=json.dumps(data),
                             content_type="application/json")
        self.assertEqual(resp.status_code, 204)

        # fetch
        resp = self.app.post("/v1/NS/rdir/fetch", query_string={'vol': "xxx"},
                             data=json.dumps({}),
                             content_type="application/json")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(json.loads(resp.data),
                         {"mycontainer|mycontent|mychunk": {'mtime': 1234}})

        # delete
        data = {
            'container_id': "mycontainer",
            'content_id': "mycontent",
            'chunk_id': "mychunk",
        }
        resp = self.app.delete("/v1/NS/rdir/delete",
                               query_string={'vol': "xxx"},
                               data=json.dumps(data),
                               content_type="application/json")
        self.assertEqual(resp.status_code, 204)

        # fetch
        resp = self.app.post("/v1/NS/rdir/fetch", query_string={'vol': "xxx"},
                             data=json.dumps({}),
                             content_type="application/json")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(json.loads(resp.data), {})

    def test_rdir_status(self):
        resp = self.app.get("/v1/NS/rdir/status",
                            query_string={'vol': "xxx"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(json.loads(resp.data),
                         {'chunk': {'total': 0},
                          'container': {}
                          })

    def test_lock_unlock(self):
        # lock without who
        resp = self.app.post("/v1/NS/rdir/admin/lock",
                             query_string={'vol': "xxx"},
                             data=json.dumps({}))
        self.assertEqual(resp.status_code, 400)

        # lock
        data = {'who': "a functionnal test"}
        resp = self.app.post("/v1/NS/rdir/admin/lock",
                             query_string={'vol': "xxx"},
                             data=json.dumps(data))
        self.assertEqual(resp.status_code, 204)

        # double lock
        data = {'who': "an other functionnal test"}
        resp = self.app.post("/v1/NS/rdir/admin/lock",
                             query_string={'vol': "xxx"},
                             data=json.dumps(data))
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.data, "Already locked by a functionnal test")

        # unlock
        resp = self.app.post("/v1/NS/rdir/admin/unlock",
                             query_string={'vol': "xxx"})
        self.assertEqual(resp.status_code, 204)

    def test_rdir_bad_ns(self):
        resp = self.app.get("/v1/badns/rdir/status",
                            query_string={'vol': "xxx"})
        self.assertEqual(resp.status_code, 400)

    def test_status(self):
        resp = self.app.get('/status')
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertEqual(data, {'opened_db_count': 0})
