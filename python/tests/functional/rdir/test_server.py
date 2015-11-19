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

    def _create_account(self):
        self.app.put('/v1.0/account/create',
                     query_string={"id": self.account_id})

    def test_status(self):
        resp = self.app.get('/status')
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertEqual(data, {'opened_db_count': 0})
