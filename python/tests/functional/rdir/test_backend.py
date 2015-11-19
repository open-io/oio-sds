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
        self.rdir.push("myvolume", "mycontainer", "mycontent", "mychunk",
                       mtime=1234)
        data = self.rdir.fetch("myvolume")
        self.assertEqual(data["mycontainer|mycontent|mychunk"],
                         {'mtime': 1234})

    def test_chunk_push_rtime(self):
        self.assertRaises(ServerException,
                          self.rdir.push,
                          "myvolume", "mycontainer",
                          "mycontent", "mychunk",
                          rtime=5555)
        self.rdir.push("myvolume", "mycontainer", "mycontent", "mychunk",
                       mtime=4444, rtime=5555)
        data = self.rdir.fetch("myvolume")
        self.assertEqual(data["mycontainer|mycontent|mychunk"],
                         {'mtime': 4444, 'rtime': 5555})

    def test_chunk_push_update_data(self):
        # initial push
        self.rdir.push("myvolume", "mycontainer", "mycontent", "mychunk",
                       rtime=5555, mtime=6666)
        data = self.rdir.fetch("myvolume")
        self.assertEqual(data["mycontainer|mycontent|mychunk"],
                         {'mtime': 6666, 'rtime': 5555})

        # update mtime and rtime
        self.rdir.push("myvolume", "mycontainer", "mycontent", "mychunk",
                       mtime=1111, rtime=2222)
        data = self.rdir.fetch("myvolume")
        self.assertEqual(data["mycontainer|mycontent|mychunk"],
                         {'mtime': 1111, 'rtime': 2222})

        # update only mtime
        self.rdir.push("myvolume", "mycontainer", "mycontent", "mychunk",
                       mtime=9999)
        data = self.rdir.fetch("myvolume")
        self.assertEqual(data["mycontainer|mycontent|mychunk"],
                         {'mtime': 9999, 'rtime': 2222})

        # update only rtime
        self.rdir.push("myvolume", "mycontainer", "mycontent", "mychunk",
                       rtime=7777)
        data = self.rdir.fetch("myvolume")
        self.assertEqual(data["mycontainer|mycontent|mychunk"],
                         {'mtime': 9999, 'rtime': 7777})

    def test_chunk_delete(self):
        self.rdir.push("myvolume", "mycontainer", "mycontent", "mychunk",
                       rtime=5555, mtime=6666)
        data = self.rdir.fetch("myvolume")
        self.assertEqual(data["mycontainer|mycontent|mychunk"],
                         {'mtime': 6666, 'rtime': 5555})

        self.rdir.delete("myvolume", "mycontainer", "mycontent", "mychunk")
        data = self.rdir.fetch("myvolume")
        self.assertEqual(data, {})

    def test_fetch(self):
        # initial push
        self.rdir.push("myvolume", "mycontainer0", "mycontent1", "mychunk",
                       mtime=1)
        self.rdir.push("myvolume", "mycontainer0", "mycontent2", "mychunk",
                       mtime=2)
        self.rdir.push("myvolume", "mycontainer1", "mycontent3", "mychunk",
                       mtime=3, rtime=4)
        self.rdir.push("myvolume", "mycontainer2", "mycontent4", "mychunk",
                       mtime=4)

        # fetch all data
        data = self.rdir.fetch("myvolume")
        self.assertEqual(data,
                         {
                             "mycontainer0|mycontent1|mychunk": {"mtime": 1},
                             "mycontainer0|mycontent2|mychunk": {"mtime": 2},
                             "mycontainer1|mycontent3|mychunk":
                                 {"mtime": 3, "rtime": 4},
                             "mycontainer2|mycontent4|mychunk": {"mtime": 4}
                         })

        # fetch 0 records max
        data = self.rdir.fetch("myvolume", limit=0)
        self.assertEqual(data, {})

        # fetch 2 records max
        data = self.rdir.fetch("myvolume", limit=2)
        self.assertEqual(data,
                         {
                             "mycontainer0|mycontent1|mychunk": {"mtime": 1},
                             "mycontainer0|mycontent2|mychunk": {"mtime": 2}
                         })

        # fetch 5 records max from record number 3
        data = self.rdir.fetch("myvolume", limit=5,
                               start_after="mycontainer0|mycontent2|mychunk")
        self.assertEqual(data,
                         {
                             "mycontainer1|mycontent3|mychunk":
                                 {"mtime": 3, "rtime": 4},
                             "mycontainer2|mycontent4|mychunk": {"mtime": 4}
                         })

        # fetch 5 records max from last record
        data = self.rdir.fetch("myvolume", limit=2,
                               start_after="mycontainer2|mycontent4|mychunk")
        self.assertEqual(data, {})

        # fetch all data from record number 2
        data = self.rdir.fetch("myvolume",
                               start_after="mycontainer0|mycontent2|mychunk")
        self.assertEqual(data,
                         {
                             "mycontainer1|mycontent3|mychunk":
                                 {"mtime": 3, "rtime": 4},
                             "mycontainer2|mycontent4|mychunk": {"mtime": 4}
                         })

        # ignore rebuild chunks
        data = self.rdir.fetch("myvolume", ignore_rebuilt=True)
        self.assertEqual(data,
                         {
                             "mycontainer0|mycontent1|mychunk": {"mtime": 1},
                             "mycontainer0|mycontent2|mychunk": {"mtime": 2},
                             "mycontainer2|mycontent4|mychunk": {"mtime": 4}
                         })

    def test_rebuild_status(self):
        # initial pushes
        self.rdir.push("myvolume", "mycontainer0", "mycontent1", "mychunk",
                       mtime=10)
        self.rdir.push("myvolume", "mycontainer1", "mycontent2", "mychunk",
                       mtime=10, rtime=20)
        self.rdir.push("myvolume", "mycontainer2", "mycontent4", "mychunk",
                       mtime=10)
        self.rdir.push("myvolume", "mycontainer2", "mycontent5", "mychunk",
                       mtime=20, rtime=30)

        data = self.rdir.rebuild_status("myvolume")
        self.assertEqual(data,
                         {
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
        self.rdir.push("myvolume", "mycontainer", "mycontent", "mychunk",
                       rtime=5555, mtime=6666)
        self.assertEqual(self.rdir.status(), {'opened_db_count': 1})

    def test_multi_volume(self):
        self.rdir.push("myvolume1", "mycontainer", "mycontent", "mychunk",
                       mtime=1111)
        self.rdir.push("myvolume2", "mycontainer", "mycontent", "mychunk",
                       mtime=2222)

        data = self.rdir.fetch("myvolume1")
        self.assertEqual(data["mycontainer|mycontent|mychunk"],
                         {'mtime': 1111})

        data = self.rdir.fetch("myvolume2")
        self.assertEqual(data["mycontainer|mycontent|mychunk"],
                         {'mtime': 2222})

    def test_push_mix_container_content_chunk(self):
        self.rdir.push("myvolume", "mycontainer1", "mycontent", "mychunk",
                       mtime=1)
        self.rdir.push("myvolume", "mycontainer2", "mycontent1", "mychunk",
                       mtime=2)
        self.rdir.push("myvolume", "mycontainer2", "mycontent2", "mychunk1",
                       mtime=3)
        self.rdir.push("myvolume", "mycontainer2", "mycontent2", "mychunk2",
                       mtime=4)
        data = self.rdir.fetch("myvolume")
        self.assertEqual(data,
                         {
                             "mycontainer1|mycontent|mychunk": {'mtime': 1},
                             "mycontainer2|mycontent1|mychunk": {'mtime': 2},
                             "mycontainer2|mycontent2|mychunk1": {'mtime': 3},
                             "mycontainer2|mycontent2|mychunk2": {'mtime': 4}
                         })
