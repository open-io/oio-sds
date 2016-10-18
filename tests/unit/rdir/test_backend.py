import tempfile
import shutil
import unittest

from oio.common.exceptions import ServerException
from oio.rdir.server_db import NoSuchDb, RdirBackend
from tests.utils import random_id


class TestRdirBackend(unittest.TestCase):
    def setUp(self):
        super(TestRdirBackend, self).setUp()
        self.db_path = tempfile.mkdtemp()
        self.conf = {'db_path': self.db_path}
        self.rdir = RdirBackend(self.conf)
        self.volume = random_id(32)
        self.rdir.create(self.volume)
        self.container_0 = '0' + random_id(63)
        self.container_1 = '1' + random_id(63)
        self.container_2 = '2' + random_id(63)
        self.content_0 = '0' + random_id(31)
        self.content_1 = '1' + random_id(31)
        self.chunk_0 = random_id(64)

    def tearDown(self):
        super(TestRdirBackend, self).tearDown()
        del self.rdir
        shutil.rmtree(self.db_path)

    def test_explicit_create(self):
        newvolume = "mynewvolume"
        self.assertRaises(NoSuchDb,
                          self.rdir.chunk_push,
                          newvolume, self.container_0, self.content_0,
                          self.chunk_0, mtime=1234)
        self.rdir.create(newvolume)
        self.rdir.chunk_push(newvolume, self.container_0, self.content_0,
                             self.chunk_0, mtime=1234)

    def test_chunk_push_mtime(self):
        self.rdir.chunk_push(self.volume, self.container_0, self.content_0,
                             self.chunk_0, mtime=1234)
        data = self.rdir.chunk_fetch(self.volume)
        self.assertEqual(data, [
            ("%s|%s|%s" %
             (self.container_0, self.content_0, self.chunk_0), {'mtime': 1234})
        ])

    def test_chunk_push_rtime(self):
        self.rdir.chunk_push(self.volume, self.container_0, self.content_0,
                             self.chunk_0, rtime=5555)
        data = self.rdir.chunk_fetch(self.volume)
        self.assertEqual(data, [
            ("%s|%s|%s" %
                (self.container_0, self.content_0, self.chunk_0),
                {'mtime': 5555, 'rtime': 5555})
        ])

        self.rdir.chunk_push(self.volume, self.container_0, self.content_0,
                             self.chunk_0, mtime=4444, rtime=5555)
        data = self.rdir.chunk_fetch(self.volume)
        self.assertEqual(data, [
            ("%s|%s|%s" %
                (self.container_0, self.content_0, self.chunk_0),
                {'mtime': 4444, 'rtime': 5555})
        ])

    def test_chunk_push_no_rtime_no_mtime(self):
        self.assertRaises(ServerException,
                          self.rdir.chunk_push,
                          self.volume, self.container_0,
                          self.content_0, self.chunk_0)

    def test_chunk_push_update_data(self):
        # initial push
        self.rdir.chunk_push(self.volume, self.container_0, self.content_0,
                             self.chunk_0, rtime=5555, mtime=6666)
        data = self.rdir.chunk_fetch(self.volume)
        self.assertEqual(data, [
            ("%s|%s|%s" %
                (self.container_0, self.content_0, self.chunk_0),
                {'mtime': 6666, 'rtime': 5555})
        ])

        # update mtime and rtime
        self.rdir.chunk_push(self.volume, self.container_0, self.content_0,
                             self.chunk_0, mtime=1111, rtime=2222)
        data = self.rdir.chunk_fetch(self.volume)
        self.assertEqual(data, [
            ("%s|%s|%s" %
                (self.container_0, self.content_0, self.chunk_0),
                {'mtime': 1111, 'rtime': 2222})
        ])

        # update only mtime
        self.rdir.chunk_push(self.volume, self.container_0, self.content_0,
                             self.chunk_0, mtime=9999)
        data = self.rdir.chunk_fetch(self.volume)
        self.assertEqual(data, [
            ("%s|%s|%s" %
                (self.container_0, self.content_0, self.chunk_0),
                {'mtime': 9999, 'rtime': 2222})
        ])

        # update only rtime
        self.rdir.chunk_push(self.volume, self.container_0, self.content_0,
                             self.chunk_0, rtime=7777)
        data = self.rdir.chunk_fetch(self.volume)
        self.assertEqual(data, [
            ("%s|%s|%s" %
                (self.container_0, self.content_0, self.chunk_0),
                {'mtime': 9999, 'rtime': 7777})
        ])

    def test_chunk_delete(self):
        self.rdir.chunk_push(self.volume, self.container_0, self.content_0,
                             self.chunk_0, rtime=5555, mtime=6666)
        data = self.rdir.chunk_fetch(self.volume)
        self.assertEqual(data, [
            ("%s|%s|%s" %
                (self.container_0, self.content_0, self.chunk_0),
                {'mtime': 6666, 'rtime': 5555})
        ])

        self.rdir.chunk_delete(self.volume, self.container_0, self.content_0,
                               self.chunk_0)
        data = self.rdir.chunk_fetch(self.volume)
        self.assertEqual(data, [])

    def test_fetch(self):
        # initial push (container name are unordered)
        self.rdir.chunk_push(self.volume, self.container_0, self.content_1,
                             self.chunk_0, mtime=2)
        self.rdir.chunk_push(self.volume, self.container_0, self.content_0,
                             self.chunk_0, mtime=1)
        self.rdir.chunk_push(self.volume, self.container_2, self.content_0,
                             self.chunk_0, mtime=10)
        self.rdir.chunk_push(self.volume, self.container_1, self.content_0,
                             self.chunk_0, mtime=3, rtime=4)

        # fetch all data
        data = self.rdir.chunk_fetch(self.volume)
        self.assertEqual(len(data), 4)
        for c in [
            ("%s|%s|%s" %
                (self.container_0, self.content_0, self.chunk_0),
                {"mtime": 1}),
            ("%s|%s|%s" %
                (self.container_0, self.content_1, self.chunk_0),
                {"mtime": 2}),
            ("%s|%s|%s" %
                (self.container_1, self.content_0, self.chunk_0),
                {"mtime": 3, "rtime": 4}),
            ("%s|%s|%s" %
                (self.container_2, self.content_0, self.chunk_0),
                {"mtime": 10})]:
            self.assertTrue(c in data)

        # fetch 0 records max
        data = self.rdir.chunk_fetch(self.volume, limit=0)
        self.assertEqual(data, [])

        # fetch 2 records max
        data = self.rdir.chunk_fetch(self.volume, limit=2)
        self.assertEqual(len(data), 2)
        for c in [
            ("%s|%s|%s" %
                (self.container_0, self.content_0, self.chunk_0),
                {"mtime": 1}),
            ("%s|%s|%s" %
                (self.container_0, self.content_1, self.chunk_0),
                {"mtime": 2})]:
            self.assertTrue(c in data)

        # fetch 5 records max from record number 3
        data = self.rdir.chunk_fetch(
            self.volume, limit=5,
            start_after="%s|%s|%s" %
            (self.container_0, self.content_1, self.chunk_0))
        self.assertEqual(len(data), 2)
        for c in [
            ("%s|%s|%s" %
                (self.container_1, self.content_0, self.chunk_0),
                {"mtime": 3, "rtime": 4}),
            ("%s|%s|%s" %
                (self.container_2, self.content_0, self.chunk_0),
                {"mtime": 10})]:
            self.assertTrue(c in data)

        # fetch 5 records max from last record
        data = self.rdir.chunk_fetch(
            self.volume, limit=2,
            start_after="%s|%s|%s" %
            (self.container_2, self.content_0, self.chunk_0))
        self.assertEqual(data, [])

        # fetch all data from record number 2
        data = self.rdir.chunk_fetch(
            self.volume,
            start_after="%s|%s|%s" %
            (self.container_0, self.content_1, self.chunk_0))
        self.assertEqual(len(data), 2)
        for c in [
            ("%s|%s|%s" %
                (self.container_1, self.content_0, self.chunk_0),
                {"mtime": 3, "rtime": 4}),
            ("%s|%s|%s" %
                (self.container_2, self.content_0, self.chunk_0),
                {"mtime": 10})]:
            self.assertTrue(c in data)

        # rebuild mode: no incident date so no entry
        data = self.rdir.chunk_fetch(self.volume, rebuild=True)
        self.assertEqual(data, [])

        # rebuild mode: with incident date
        self.rdir.admin_set_incident_date(self.volume, 6)
        data = self.rdir.chunk_fetch(self.volume, rebuild=True)
        self.assertEqual(len(data), 2)
        for c in [
            ("%s|%s|%s" %
                (self.container_0, self.content_0, self.chunk_0),
                {"mtime": 1}),
            ("%s|%s|%s" %
                (self.container_0, self.content_1, self.chunk_0),
                {"mtime": 2})]:
            self.assertTrue(c in data)

    def test_rdir_status(self):
        # initial pushes
        self.rdir.chunk_push(self.volume, self.container_0, self.content_0,
                             self.chunk_0, mtime=10)
        self.rdir.chunk_push(self.volume, self.container_1, self.content_0,
                             self.chunk_0, mtime=10)
        self.rdir.chunk_push(self.volume, self.container_2, self.content_0,
                             self.chunk_0, mtime=10)
        self.rdir.chunk_push(self.volume, self.container_2, self.content_1,
                             self.chunk_0, mtime=20)

        data = self.rdir.chunk_status(self.volume)
        self.assertEqual(data,
                         {
                             'chunk': {
                                 'total': 4
                             },
                             'container': {
                                 self.container_0: {
                                     'total': 1
                                 },
                                 self.container_1: {
                                     'total': 1
                                 },
                                 self.container_2: {
                                     'total': 2
                                 },
                             }
                         })

    def test_rdir_status_rebuild(self):
        self.rdir.admin_set_incident_date(self.volume, 30)
        # initial pushes
        self.rdir.chunk_push(self.volume, self.container_0, self.content_0,
                             self.chunk_0, mtime=10)
        self.rdir.chunk_push(self.volume, self.container_1, self.content_0,
                             self.chunk_0, mtime=10, rtime=20)
        self.rdir.chunk_push(self.volume, self.container_2, self.content_0,
                             self.chunk_0, mtime=10)
        self.rdir.chunk_push(self.volume, self.container_2, self.content_1,
                             self.chunk_0, mtime=20, rtime=30)

        data = self.rdir.chunk_status(self.volume)
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
                                 self.container_0: {
                                     'total': 1,
                                     'rebuilt': 0
                                 },
                                 self.container_1: {
                                     'total': 1,
                                     'rebuilt': 1
                                 },
                                 self.container_2: {
                                     'total': 2,
                                     'rebuilt': 1
                                 },
                             }
                         })

    def test_status(self):
        self.assertEqual(self.rdir.status(), {'opened_db_count': 0})
        self.rdir.chunk_push(self.volume, self.container_0, self.content_0,
                             self.chunk_0, rtime=5555, mtime=6666)
        self.assertEqual(self.rdir.status(), {'opened_db_count': 1})

    def test_multi_volume(self):
        self.rdir.create("myvolume1")
        self.rdir.create("myvolume2")
        self.rdir.chunk_push("myvolume1", self.container_0, self.content_0,
                             self.chunk_0, mtime=1111)
        self.rdir.chunk_push("myvolume2", self.container_0, self.content_0,
                             self.chunk_0, mtime=2222)

        data = self.rdir.chunk_fetch("myvolume1")
        self.assertEqual(data, [
            ("%s|%s|%s" %
             (self.container_0, self.content_0, self.chunk_0), {'mtime': 1111})
        ])

        data = self.rdir.chunk_fetch("myvolume2")
        self.assertEqual(data, [
            ("%s|%s|%s" %
             (self.container_0, self.content_0, self.chunk_0), {'mtime': 2222})
        ])

    def test_admin_incident_date(self):
        # no incident date
        date = self.rdir.admin_get_incident_date(self.volume)
        self.assertEqual(date, None)

        # add incident date
        self.rdir.admin_set_incident_date(self.volume, 1234)
        self.assertEqual(self.rdir.admin_get_incident_date(self.volume), 1234)

        # update incident date
        self.rdir.admin_set_incident_date(self.volume, 5555)
        self.assertEqual(self.rdir.admin_get_incident_date(self.volume), 5555)

    def test_admin_lock_unlock(self):
        # unlock without lock
        self.rdir.admin_unlock(self.volume)

        # lock
        who = random_id(32)
        res = self.rdir.admin_lock(self.volume, who)
        self.assertEqual(res, None)

        # double lock
        res = self.rdir.admin_lock(self.volume, random_id(32))
        self.assertEqual(res, who)

        # unlock
        self.rdir.admin_unlock(self.volume)

        # lock again
        res = self.rdir.admin_lock(self.volume, random_id(32))
        self.assertEqual(res, None)

    def test_admin_show(self):
        who = random_id(32)
        self.rdir.admin_lock(self.volume, who)
        self.rdir.admin_set_incident_date(self.volume, 1234)
        res = self.rdir.admin_show(self.volume)
        self.assertEqual(res, {'incident_date': "1234",
                               'lock': who})

    def test_admin_clear(self):
        # populate the db
        self.rdir.admin_set_incident_date(self.volume, 666)
        self.rdir.chunk_push(self.volume, self.container_0, self.content_0,
                             self.chunk_0, mtime=1)
        self.rdir.chunk_push(self.volume, self.container_1, self.content_0,
                             self.chunk_0, mtime=2, rtime=3)

        # clear rebuilt chunk entries
        count = self.rdir.admin_clear(self.volume, False)
        self.assertEqual(count, 1)

        # check db state
        data = self.rdir.chunk_fetch(self.volume)
        self.assertEqual(data, [
            ("%s|%s|%s" %
             (self.container_0, self.content_0, self.chunk_0), {'mtime': 1})
        ])
        self.assertEqual(self.rdir.admin_get_incident_date(self.volume), None)

        # populate again the db
        self.rdir.chunk_push(self.volume, self.container_2, self.content_0,
                             self.chunk_0, mtime=3, rtime=4)

        # clear all entries
        count = self.rdir.admin_clear(self.volume, True)
        self.assertEqual(count, 2)

        # check db state
        data = self.rdir.chunk_fetch(self.volume)
        self.assertEqual(data, [])
