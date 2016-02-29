from contextlib import contextmanager, closing
from eventlet import sleep, Timeout
import sqlite3

from oio.common.queue.base import BaseQueue


DEFAULT_TIMEOUT = 30


def get_db_connection(path, timeout):
    try:
        conn = sqlite3.connect(path, check_same_thread=False,
                               factory=DBConnection, timeout=timeout)
        conn.row_factory = sqlite3.Row
        conn.text_factory = str
        with closing(conn.cursor()) as c:
            c.execute('PRAGMA journal_mode=WAL')
            c.execute('PRAGMA synchronous=NORMAL')
            c.execute('PRAGMA temp_store=MEMORY')

    except sqlite3.DatabaseError:
        raise
    return conn


class SqliteDB(object):
    def __init__(self, location, timeout=DEFAULT_TIMEOUT):
        self.conn = None
        self.location = location
        self.timeout = timeout

    @contextmanager
    def get(self):
        if not self.conn:
            try:
                self.conn = get_db_connection(self.location, self.timeout)
            except sqlite3.DatabaseError:
                raise
        conn = self.conn
        self.conn = None
        try:
            yield conn
            conn.rollback()
            self.conn = conn
        except sqlite3.DatabaseError:
            try:
                conn.close()
            except Exception:
                raise
        except (Exception, Timeout):
            conn.close()
            raise


class LockTimeout(Timeout):
    def __init__(self, seconds=None, msg=None):
        Timeout.__init__(self, seconds=seconds)
        self.msg = msg

    def __str__(self):
        return '%s: %s' % (Timeout.__str__(self), self.msg)


def handle_timeout(timeout, db_file, func):
    with LockTimeout(timeout, db_file):
        retry_interval = 0.001
        while True:
            try:
                return func()
            except sqlite3.OperationalError as e:
                # check if db is locked
                if 'locked' not in str(e):
                    raise
            # make this work nicely with eventlet
            sleep(retry_interval)
            # backoff
            retry_interval = min(retry_interval * 2, 0.05)


class DBConnection(sqlite3.Connection):
    def __init__(self, db, timeout=None, *args, **kwargs):
        if timeout is None:
            timeout = DEFAULT_TIMEOUT
        self.timeout = timeout
        self.db_file = db
        super(DBConnection, self).__init__(db, 0, *args, **kwargs)

    def cursor(self, cls=None):
        if cls is None:
            cls = DBCursor
        return sqlite3.Connection.cursor(self, cls)

    def commit(self):
        return handle_timeout(self.timeout, self.db_file,
                              lambda: sqlite3.Connection.commit(self))


class DBCursor(sqlite3.Cursor):
    def __init__(self, *args, **kwargs):
        self.timeout = args[0].timeout
        self.db_file = args[0].db_file
        super(DBCursor, self).__init__(*args, **kwargs)

    def execute(self, *args, **kwargs):
        return handle_timeout(self.timeout, self.db_file,
                              lambda: sqlite3.Cursor.execute(
                                  self, *args, **kwargs))


class SqliteQueue(BaseQueue):
    _create = """
        CREATE TABLE IF NOT EXISTS {0}
        (
            id TEXT PRIMARY KEY,
            data BLOB,
            ts INTEGER
        );
        CREATE TABLE IF NOT EXISTS {0}_failed
        (
            id TEST PRIMARY KEY,
            data BLOB,
            ts INTEGER
        );
    """
    _remove = "DELETE FROM {0} WHERE id = ?"
    _add = "INSERT OR IGNORE INTO {0} (id, data, ts) \
            VALUES (?, ?, DATETIME('now'))"
    _load = "SELECT id, data FROM {0} LIMIT ?"
    _failed = "INSERT OR IGNORE INTO {0}_failed (id, data, ts) \
    SELECT id, data, DATETIME('now') FROM {0} WHERE id = ?"

    def __init__(self, name, location):
        super(SqliteQueue, self).__init__(name, location)
        self.db = SqliteDB(location)
        self.name = name
        with self.db.get() as conn:
            conn.executescript(self._create.format(self.name))

    def put(self, event_id, data):
        with self.db.get() as conn:
            conn.execute(self._add.format(self.name), (event_id, data,))
            conn.commit()

    def delete(self, event_id):
        with self.db.get() as conn:
            conn.execute(self._remove.format(self.name), (event_id,))
            conn.commit()

    def load(self, count):
        with self.db.get() as conn:
            c = conn.execute(self._load.format(self.name), (count,))
            return c

    def failed(self, event_id):
        with self.db.get() as conn:
            conn.execute(self._failed.format(self.name), (event_id,))
            conn.execute(self._remove.format(self.name), (event_id,))
            conn.commit()
