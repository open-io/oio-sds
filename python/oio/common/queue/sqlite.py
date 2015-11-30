import sqlite3

from oio.common.queue.base import BaseQueue


class SqliteDB(object):
    def __init__(self, location):
        self.location = location
        self.conn = None
        with self.get_conn() as conn:
            conn.execute('PRAGMA journal_mode=WAL;')
            conn.execute('PRAGMA synchronous=NORMAL;')
            conn.execute('PRAGMA temp_store=MEMORY;')

    def get_conn(self):
        if not self.conn:
            self.conn = sqlite3.Connection(self.location)
        return self.conn


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
    _add = "INSERT INTO {0} (id, data, ts) VALUES (?, ?, DATETIME('now'))"
    _load = "SELECT id, data FROM {0} LIMIT ?"
    _failed = "INSERT INTO {0}_failed (id, data, ts) \
    SELECT id, data, DATETIME('now') FROM {0} WHERE id = ?"

    def __init__(self, name, location):
        super(SqliteQueue, self).__init__(name, location)
        self._db = SqliteDB(location)
        self.name = name
        with self._db.get_conn() as conn:
            conn.executescript(self._create.format(self.name))

    def put(self, event_id, data):
        with self._db.get_conn() as conn:
            conn.execute(self._add.format(self.name), (event_id, data,))

    def delete(self, event_id):
        with self._db.get_conn() as conn:
            conn.execute(self._remove.format(self.name), (event_id,))

    def load(self, count):
        with self._db.get_conn() as conn:
            c = conn.execute(self._load.format(self.name), (count,))
            return c

    def failed(self, event_id):
        with self._db.get_conn() as conn:
            conn.execute(self._failed.format(self.name), (event_id,))
            conn.execute(self._remove.format(self.name), (event_id,))
