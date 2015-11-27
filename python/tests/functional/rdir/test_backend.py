import tempfile
import shutil
from oio.common.exceptions import ServerException
from oio.rdir.server_db import RdirBackend
from tests.utils import BaseTestCase


class TestRdirBackend(BaseTestCase):
    def setUp(self):
        super(TestRdirBackend, self).setUp()
        self.db_path = tempfile.mkdtemp()
        self.conf = {'db_path': self.db_path}
        self.rdir = RdirBackend(self.conf)

    def tearDown(self):
        super(TestRdirBackend, self).tearDown()
        del self.rdir
        shutil.rmtree(self.db_path)

    def test_chunk_push_mtime(self):
        self.rdir.chunk_push("myvolume", "mycontainer", "mycontent", "mychunk",
                             mtime=1234)
        data = self.rdir.chunk_fetch("myvolume")
        self.assertEqual(data["mycontainer|mycontent|mychunk"],
                         {'mtime': 1234})

    def test_chunk_push_rtime(self):
        self.assertRaises(ServerException,
                          self.rdir.chunk_push,
                          "myvolume", "mycontainer",
                          "mycontent", "mychunk",
                          rtime=5555)
        self.rdir.chunk_push("myvolume", "mycontainer", "mycontent", "mychunk",
                             mtime=4444, rtime=5555)
        data = self.rdir.chunk_fetch("myvolume")
        self.assertEqual(data["mycontainer|mycontent|mychunk"],
                         {'mtime': 4444, 'rtime': 5555})

    def test_push_allowed_tokens(self):
        data_put = {
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
        self.rdir.chunk_push("myvolume", "mycontainer", "mycontent", "mychunk",
                             **data_put)
        data_fetch = self.rdir.chunk_fetch("myvolume")
        self.assertEqual(data_fetch["mycontainer|mycontent|mychunk"], data_put)

    def test_chunk_push_update_data(self):
        # initial push
        self.rdir.chunk_push("myvolume", "mycontainer", "mycontent", "mychunk",
                             rtime=5555, mtime=6666)
        data = self.rdir.chunk_fetch("myvolume")
        self.assertEqual(data["mycontainer|mycontent|mychunk"],
                         {'mtime': 6666, 'rtime': 5555})

        # update mtime and rtime
        self.rdir.chunk_push("myvolume", "mycontainer", "mycontent", "mychunk",
                             mtime=1111, rtime=2222)
        data = self.rdir.chunk_fetch("myvolume")
        self.assertEqual(data["mycontainer|mycontent|mychunk"],
                         {'mtime': 1111, 'rtime': 2222})

        # update only mtime
        self.rdir.chunk_push("myvolume", "mycontainer", "mycontent", "mychunk",
                             mtime=9999)
        data = self.rdir.chunk_fetch("myvolume")
        self.assertEqual(data["mycontainer|mycontent|mychunk"],
                         {'mtime': 9999, 'rtime': 2222})

        # update only rtime
        self.rdir.chunk_push("myvolume", "mycontainer", "mycontent", "mychunk",
                             rtime=7777)
        data = self.rdir.chunk_fetch("myvolume")
        self.assertEqual(data["mycontainer|mycontent|mychunk"],
                         {'mtime': 9999, 'rtime': 7777})

    def test_chunk_delete(self):
        self.rdir.chunk_push("myvolume", "mycontainer", "mycontent", "mychunk",
                             rtime=5555, mtime=6666)
        data = self.rdir.chunk_fetch("myvolume")
        self.assertEqual(data["mycontainer|mycontent|mychunk"],
                         {'mtime': 6666, 'rtime': 5555})

        self.rdir.chunk_delete("myvolume", "mycontainer", "mycontent",
                               "mychunk")
        data = self.rdir.chunk_fetch("myvolume")
        self.assertEqual(data, {})

    def test_fetch(self):
        # initial push
        self.rdir.chunk_push("myvolume", "mycontainer0", "mycontent1",
                             "mychunk",
                             mtime=1)
        self.rdir.chunk_push("myvolume", "mycontainer0", "mycontent2",
                             "mychunk",
                             mtime=2)
        self.rdir.chunk_push("myvolume", "mycontainer1", "mycontent3",
                             "mychunk",
                             mtime=3, rtime=4)
        self.rdir.chunk_push("myvolume", "mycontainer2", "mycontent4",
                             "mychunk",
                             mtime=10)

        # fetch all data
        data = self.rdir.chunk_fetch("myvolume")
        self.assertEqual(data,
                         {
                             "mycontainer0|mycontent1|mychunk": {"mtime": 1},
                             "mycontainer0|mycontent2|mychunk": {"mtime": 2},
                             "mycontainer1|mycontent3|mychunk":
                                 {"mtime": 3, "rtime": 4},
                             "mycontainer2|mycontent4|mychunk": {"mtime": 10}
                         })

        # fetch 0 records max
        data = self.rdir.chunk_fetch("myvolume", limit=0)
        self.assertEqual(data, {})

        # fetch 2 records max
        data = self.rdir.chunk_fetch("myvolume", limit=2)
        self.assertEqual(data,
                         {
                             "mycontainer0|mycontent1|mychunk": {"mtime": 1},
                             "mycontainer0|mycontent2|mychunk": {"mtime": 2}
                         })

        # fetch 5 records max from record number 3
        data = self.rdir.chunk_fetch("myvolume", limit=5,
                                     start_after="mycontainer0|"
                                                 "mycontent2|mychunk")
        self.assertEqual(data,
                         {
                             "mycontainer1|mycontent3|mychunk":
                                 {"mtime": 3, "rtime": 4},
                             "mycontainer2|mycontent4|mychunk": {"mtime": 10}
                         })

        # fetch 5 records max from last record
        data = self.rdir.chunk_fetch("myvolume", limit=2,
                                     start_after="mycontainer2|"
                                                 "mycontent4|mychunk")
        self.assertEqual(data, {})

        # fetch all data from record number 2
        data = self.rdir.chunk_fetch("myvolume", start_after="mycontainer0|"
                                                             "mycontent2|"
                                                             "mychunk")
        self.assertEqual(data,
                         {
                             "mycontainer1|mycontent3|mychunk":
                                 {"mtime": 3, "rtime": 4},
                             "mycontainer2|mycontent4|mychunk": {"mtime": 10}
                         })

        # rebuild mode: no broken date so no entry
        data = self.rdir.chunk_fetch("myvolume", rebuild=True)
        self.assertEqual(data, {})

        # rebuild mode: with broken date
        self.rdir.admin_set_broken_date("myvolume", 6)
        data = self.rdir.chunk_fetch("myvolume", rebuild=True)
        self.assertEqual(data, {
            "mycontainer0|mycontent1|mychunk": {"mtime": 1},
            "mycontainer0|mycontent2|mychunk": {"mtime": 2},
        })

    def test_rdir_status(self):
        # initial pushes
        self.rdir.chunk_push("myvolume", "mycontainer0", "mycontent1",
                             "mychunk", mtime=10)
        self.rdir.chunk_push("myvolume", "mycontainer1", "mycontent2",
                             "mychunk", mtime=10)
        self.rdir.chunk_push("myvolume", "mycontainer2", "mycontent4",
                             "mychunk", mtime=10)
        self.rdir.chunk_push("myvolume", "mycontainer2", "mycontent5",
                             "mychunk", mtime=20)

        data = self.rdir.chunk_status("myvolume")
        self.assertEqual(data,
                         {
                             'chunk': {
                                 'total': 4
                             },
                             'container': {
                                 'mycontainer0': {
                                     'total': 1
                                 },
                                 'mycontainer1': {
                                     'total': 1
                                 },
                                 'mycontainer2': {
                                     'total': 2
                                 },
                             }
                         })

    def test_rdir_status_rebuild(self):
        self.rdir.admin_set_broken_date("myvolume", 30)
        # initial pushes
        self.rdir.chunk_push("myvolume", "mycontainer0", "mycontent1",
                             "mychunk", mtime=10)
        self.rdir.chunk_push("myvolume", "mycontainer1", "mycontent2",
                             "mychunk", mtime=10, rtime=20)
        self.rdir.chunk_push("myvolume", "mycontainer2", "mycontent4",
                             "mychunk", mtime=10)
        self.rdir.chunk_push("myvolume", "mycontainer2", "mycontent5",
                             "mychunk", mtime=20, rtime=30)

        data = self.rdir.chunk_status("myvolume")
        self.assertEqual(data,
                         {
                             'rebuild': {
                                 'incident_date': 30
                             },
                             'chunk': {
                                 'total': 4,
                                 'rebuilt': 2
                             },
                             'container': {
                                 'mycontainer0': {
                                     'total': 1,
                                     'rebuilt': 0
                                 },
                                 'mycontainer1': {
                                     'total': 1,
                                     'rebuilt': 1
                                 },
                                 'mycontainer2': {
                                     'total': 2,
                                     'rebuilt': 1
                                 },
                             }
                         })

    def test_status(self):
        self.assertEqual(self.rdir.status(), {'opened_db_count': 0})
        self.rdir.chunk_push("myvolume", "mycontainer", "mycontent", "mychunk",
                             rtime=5555, mtime=6666)
        self.assertEqual(self.rdir.status(), {'opened_db_count': 1})

    def test_multi_volume(self):
        self.rdir.chunk_push("myvolume1", "mycontainer", "mycontent",
                             "mychunk",
                             mtime=1111)
        self.rdir.chunk_push("myvolume2", "mycontainer", "mycontent",
                             "mychunk",
                             mtime=2222)

        data = self.rdir.chunk_fetch("myvolume1")
        self.assertEqual(data["mycontainer|mycontent|mychunk"],
                         {'mtime': 1111})

        data = self.rdir.chunk_fetch("myvolume2")
        self.assertEqual(data["mycontainer|mycontent|mychunk"],
                         {'mtime': 2222})

    def test_push_mix_container_content_chunk(self):
        self.rdir.chunk_push("myvolume", "mycontainer1", "mycontent",
                             "mychunk",
                             mtime=1)
        self.rdir.chunk_push("myvolume", "mycontainer2", "mycontent1",
                             "mychunk",
                             mtime=2)
        self.rdir.chunk_push("myvolume", "mycontainer2", "mycontent2",
                             "mychunk1",
                             mtime=3)
        self.rdir.chunk_push("myvolume", "mycontainer2", "mycontent2",
                             "mychunk2",
                             mtime=4)
        data = self.rdir.chunk_fetch("myvolume")
        self.assertEqual(data,
                         {
                             "mycontainer1|mycontent|mychunk": {'mtime': 1},
                             "mycontainer2|mycontent1|mychunk": {'mtime': 2},
                             "mycontainer2|mycontent2|mychunk1": {'mtime': 3},
                             "mycontainer2|mycontent2|mychunk2": {'mtime': 4}
                         })

    def test_admin_broken_date(self):
        # no broken date
        date = self.rdir.admin_get_broken_date("myvolume")
        self.assertEqual(date, None)

        # add broken date
        self.rdir.admin_set_broken_date("myvolume", 1234)
        self.assertEqual(self.rdir.admin_get_broken_date("myvolume"), 1234)

        # update broken date
        self.rdir.admin_set_broken_date("myvolume", 5555)
        self.assertEqual(self.rdir.admin_get_broken_date("myvolume"), 5555)

    def test_admin_lock_unlock(self):
        # unlock without lock
        self.rdir.admin_unlock("myvolume")

        # lock
        res = self.rdir.admin_lock("myvolume", "a functionnal test")
        self.assertEqual(res, None)

        # double lock
        res = self.rdir.admin_lock("myvolume", "an other functionnal test")
        self.assertEqual(res, "a functionnal test")

        # unlock
        self.rdir.admin_unlock("myvolume")

        # lock again
        res = self.rdir.admin_lock("myvolume", "a third functionnal test")
        self.assertEqual(res, None)

    def test_admin_show(self):
        self.rdir.admin_lock("myvolume", "a functionnal test")
        self.rdir.admin_set_broken_date("myvolume", 1234)
        res = self.rdir.admin_show("myvolume")
        self.assertEqual(res, {'broken_date': "1234",
                               'lock': "a functionnal test"})
