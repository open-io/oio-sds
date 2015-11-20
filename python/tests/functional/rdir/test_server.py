import tempfile
import shutil

import simplejson as json

from oio.rdir.server import create_app
from tests.utils import BaseTestCase


class TestRdirServer(BaseTestCase):
    def setUp(self):
        super(TestRdirServer, self).setUp()

        self.db_path = tempfile.mkdtemp()
        self.conf = {'db_path': self.db_path}

        self.app = create_app(self.conf).test_client()

    def tearDown(self):
        super(TestRdirServer, self).tearDown()
        del self.app
        shutil.rmtree(self.db_path)

    def test_push_fetch_delete(self):
        # push
        data = {
            "container": "mycontainer",
            "content": "mycontent",
            "chunk": "mychunk",
            "mtime": 1234
        }
        resp = self.app.post('/NS/rdir/push', query_string={"vol": "xxx"},
                             data=json.dumps(data),
                             content_type="application/json")
        self.assertEqual(resp.status_code, 204)

        # fetch
        resp = self.app.get('/NS/rdir/fetch', query_string={"vol": "xxx"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(json.loads(resp.data),
                         {"mycontainer|mycontent|mychunk": {"mtime": 1234}})

        # delete
        data = {
            "container": "mycontainer",
            "content": "mycontent",
            "chunk": "mychunk",
        }
        resp = self.app.delete('/NS/rdir/delete', query_string={"vol": "xxx"},
                               data=json.dumps(data),
                               content_type="application/json")
        self.assertEqual(resp.status_code, 204)

        # fetch
        resp = self.app.get('/NS/rdir/fetch', query_string={"vol": "xxx"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(json.loads(resp.data), {})

    def test_rebuild_status(self):
        resp = self.app.get('/NS/rdir/rebuild_status',
                            query_string={"vol": "xxx"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(json.loads(resp.data),
                         {'chunk': {'total': 0, 'rebuilt': 0},
                          'container': {}
                          })

    def test_status(self):
        resp = self.app.get('/status')
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertEqual(data, {'opened_db_count': 0})
