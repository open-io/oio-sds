from mock import patch, MagicMock
from eventlet import Timeout
from oio.common.queue.sqlite import DBConnection, get_db_connection
import unittest
import sqlite3


class TestDBConnection(unittest.TestCase):
    def test_execute_locking(self):
        class TestCursor(sqlite3.Cursor):
            pass
        db_error = sqlite3.OperationalError('locked database')
        TestCursor.execute = MagicMock(side_effect=db_error)
        with patch('sqlite3.Cursor', new=TestCursor):
            conn = sqlite3.connect(':memory:', check_same_thread=False,
                                   factory=DBConnection, timeout=0.1)
            self.assertRaises(Timeout, conn.execute, 'select *')
            self.assertTrue(TestCursor.execute.called)
            self.assertEqual(TestCursor.execute.call_args_list,
                             list((TestCursor.execute.call_args,) *
                                  TestCursor.execute.call_count))

    def test_commit_locking(self):
        class TestConnection(sqlite3.Connection):
            pass
        db_error = sqlite3.OperationalError('locked database')
        TestConnection.commit = MagicMock(side_effect=db_error)
        with patch('sqlite3.Connection', new=TestConnection):
            conn = sqlite3.connect(':memory:', check_same_thread=False,
                                   factory=DBConnection, timeout=0.1)
            self.assertRaises(Timeout, conn.commit)
            self.assertTrue(TestConnection.commit.called)
            self.assertEqual(TestConnection.commit.call_args_list,
                             list((TestConnection.commit.call_args,) *
                                  TestConnection.commit.call_count))


class TestGetDBConnection(unittest.TestCase):
    def test_locking(self):
        class TestCursor(sqlite3.Cursor):
            pass

        db_error = sqlite3.OperationalError('locked database')
        TestCursor.execute = MagicMock(side_effect=db_error)
        with patch('sqlite3.Cursor', new=TestCursor):
            self.assertRaises(Timeout, get_db_connection, ':memory:',
                              timeout=0.1)
            self.assertTrue(TestCursor.execute.called)
            self.assertEqual(TestCursor.execute.call_args_list,
                             list((TestCursor.execute.call_args,) *
                                  TestCursor.execute.call_count))
