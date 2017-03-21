from time import time, sleep
import uuid
import math

import redis
import redis.sentinel
from oio.common.utils import Timestamp
from oio.common.utils import int_value
from oio.common.utils import true_value


EXPIRE_TIME = 60  # seconds

account_fields = ['ns', 'name', 'ctime', 'containers', 'objects',
                  'bytes', 'storage_policy']

container_fields = ['ns', 'account', 'type', 'objects', 'bytes', 'ctime',
                    'mtime', 'name']


def acquire_lock_with_timeout(conn, lockname, acquire_timeout=10,
                              lock_timeout=10):
    identifier = str(uuid.uuid4())
    lockname = 'lock:' + lockname
    lock_timeout = int(math.ceil(lock_timeout))
    end = time() + acquire_timeout

    while time() < end:
        if conn.setnx(lockname, identifier):
            conn.expire(lockname, lock_timeout)
            return identifier
        elif not conn.ttl(lockname):
            conn.expire(lockname, lock_timeout)

        sleep(.001)
    return False


def release_lock(conn, lockname, identifier):
    pipe = conn.pipeline(True)
    lockname = 'lock:' + lockname

    while True:
        try:
            pipe.watch(lockname)
            if pipe.get(lockname) == identifier:
                pipe.multi()
                pipe.delete(lockname)
                pipe.execute()
                return True

            pipe.unwatch()
            break

        except redis.exceptions.WatchError:
            pass

    return False


class AccountBackend(object):
    def __init__(self, conf, connection=None):
        self.conf = conf
        self._conn = connection
        self._sentinel = None
        self._sentinel_hosts = conf.get('sentinel_hosts', None)
        self._sentinel_name = conf.get('sentinel_master_name', 'oio')
        self.autocreate = true_value(conf.get('autocreate', 'true'))

        # Do not use Sentinel if a connection object is provided
        if self._sentinel_hosts and not self._conn:
            self._sentinel = redis.sentinel.Sentinel(
                    [(h, int(p)) for h, p, in (hp.split(':', 2)
                     for hp in self._sentinel_hosts.split(','))])

    @property
    def conn(self):
        if self._sentinel:
            return self._sentinel.master_for(self._sentinel_name)
        if not self._conn:
            redis_host = self.conf.get('redis_host', '127.0.0.1')
            redis_port = int(self.conf.get('redis_port', '6379'))
            self._conn = redis.StrictRedis(host=redis_host, port=redis_port)
        return self._conn

    @staticmethod
    def ckey(account, name):
        """Build the key of a container description"""
        return 'container:%s:%s' % (account, unicode(name))

    def create_account(self, account_id):
        conn = self.conn
        if not account_id:
            return None
        if conn.hget('accounts:', account_id):
            return None

        lock = acquire_lock_with_timeout(conn, 'account:%s' % account_id, 1)
        if not lock:
            return None

        pipeline = conn.pipeline(True)
        pipeline.hset('accounts:', account_id, 1)
        pipeline.hmset('account:%s' % account_id, {
            'id': account_id,
            'bytes': 0,
            'objects': 0,
            'ctime': Timestamp(time()).normal
        })
        pipeline.execute()
        release_lock(conn, 'account:%s' % account_id, lock)
        return account_id

    def delete_account(self, account_id):
        conn = self.conn
        if not account_id:
            return None
        account_id = conn.hget('account:%s' % account_id, 'id')

        if not account_id:
            return None

        lock = acquire_lock_with_timeout(conn, 'account:%s' % account_id, 1)
        if not lock:
            return None

        num_containers = conn.zcard('containers:%s' % account_id)

        if int(num_containers) > 0:
            return False

        pipeline = conn.pipeline(True)
        pipeline.delete('metadata:%s' % account_id)
        pipeline.delete('containers:%s' % account_id)
        pipeline.delete('account:%s' % account_id)
        pipeline.hdel('accounts:', account_id)
        pipeline.execute()
        release_lock(conn, 'account:%s' % account_id, lock)
        return True

    def get_account_metadata(self, account_id):
        conn = self.conn
        if not account_id:
            return None
        account_id = conn.hget('account:%s' % account_id, 'id')

        if not account_id:
            return None

        meta = conn.hgetall('metadata:%s' % account_id)
        return meta

    def update_account_metadata(self, account_id, metadata, to_delete=None):
        conn = self.conn
        if not account_id:
            return None
        _account_id = conn.hget('account:%s' % account_id, 'id')

        if not _account_id:
            if self.autocreate:
                self.create_account(account_id)
            else:
                return None

        if not metadata and not to_delete:
            return account_id
        pipeline = conn.pipeline(True)
        if to_delete:
            pipeline.hdel('metadata:%s' % account_id, *to_delete)
        if metadata:
            pipeline.hmset('metadata:%s' % account_id, metadata)
        pipeline.execute()
        return account_id

    def info_account(self, account_id):
        conn = self.conn
        if not account_id:
            return None
        account_id = conn.hget('account:%s' % account_id, 'id')

        if not account_id:
            return None

        pipeline = conn.pipeline(False)
        pipeline.hgetall('account:%s' % account_id)
        pipeline.zcard('containers:%s' % account_id)
        pipeline.hgetall('metadata:%s' % account_id)
        data = pipeline.execute()
        info = data[0]
        for r in ['bytes', 'objects']:
            info[r] = int_value(info[r], 0)
        info['containers'] = data[1]
        info['metadata'] = data[2]
        return info

    def update_container(self, account_id, name, mtime, dtime, object_count,
                         bytes_used):
        conn = self.conn
        if not account_id or not name:
            return None
        _account_id = conn.hget('account:%s' % account_id, 'id')

        if not _account_id:
            if self.autocreate:
                self.create_account(account_id)
            else:
                return None

        lock = acquire_lock_with_timeout(
                conn, AccountBackend.ckey(account_id, name), 1)
        if not lock:
            return None

        data = conn.hgetall(AccountBackend.ckey(account_id, name))

        record = {'name': name, 'mtime': mtime or dtime, 'dtime': dtime,
                  'objects': object_count, 'bytes': bytes_used}
        if data:
            data['mtime'] = Timestamp(data['mtime'])
            data['dtime'] = Timestamp(data['dtime'])

            for r in ['name', 'mtime', 'dtime', 'objects', 'bytes']:
                if record[r] is None and data[r] is not None:
                    record[r] = data[r]
            if data['mtime'] > record['mtime']:
                record['mtime'] = data['mtime']
            if data['dtime'] > record['dtime']:
                record['dtime'] = data['dtime']

        deleted = record['dtime'] >= record['mtime']

        if not deleted:
            incr_bytes_used = int_value(record.get('bytes'), 0) -\
                int_value(data.get('bytes'), 0)
            incr_object_count = int_value(record.get('objects'), 0) -\
                int_value(data.get('objects'), 0)
        elif record.get('mtime') > data.get('mtime'):
            incr_bytes_used = - int_value(data.get('bytes'), 0)
            incr_object_count = - int_value(data.get('objects'), 0)
        else:
            # The event has been delayed, the container has already
            # been deleted, and the object and bytes statistics have
            # already been reported to the account.
            incr_bytes_used = 0
            incr_object_count = 0

        record.update({
            'name': name,
            'account_uid': account_id
        })

        # replace None values
        for r in ['bytes', 'objects', 'mtime', 'dtime']:
            if record[r] is None:
                record[r] = 0

        ct = {name: 0}
        pipeline = conn.pipeline(True)
        pipeline.hmset(AccountBackend.ckey(account_id, name), record)
        if deleted:
            pipeline.expire(AccountBackend.ckey(account_id, name), EXPIRE_TIME)
            pipeline.zrem('containers:%s' % account_id, name)
        else:
            pipeline.persist(AccountBackend.ckey(account_id, name))
            pipeline.zadd('containers:%s' % account_id, **ct)
        if incr_object_count:
            pipeline.hincrby('account:%s' % account_id, 'objects',
                             incr_object_count)
        if incr_bytes_used:
            pipeline.hincrby('account:%s' % account_id, 'bytes',
                             incr_bytes_used)
        pipeline.execute()
        release_lock(conn, AccountBackend.ckey(account_id, name), lock)
        return name

    def _raw_listing(self, account_id, limit, marker, end_marker, delimiter,
                     prefix):
        conn = self.conn
        if delimiter and not prefix:
            prefix = ''
        orig_marker = marker

        results = []
        while len(results) < limit:
            min = '-'
            max = '+'
            if end_marker:
                max = '(' + end_marker
            if marker and marker >= prefix:
                min = '(' + marker
            elif prefix:
                min = '[' + prefix

            offset = 0

            container_ids = conn.zrangebylex('containers:%s' % account_id, min,
                                             max, offset, limit - len(results))
            container_ids = [cid.decode('utf8', errors='ignore')
                             for cid in container_ids]

            if prefix is None:
                containers = [[c_id, 0, 0, 0] for c_id in container_ids]
                return containers
            if not delimiter:
                if not prefix:
                    containers = [[c_id, 0, 0, 0] for c_id in container_ids]
                    return containers
                else:
                    containers = [[c_id, 0, 0, 0] for c_id in container_ids if
                                  c_id.startswith(prefix)]
                    return containers

            count = 0
            for container_id in container_ids:
                count += 1
                marker = container_id
                if len(results) >= limit\
                        or not container_id.startswith(prefix):
                    return results
                end = container_id.find(delimiter, len(prefix))
                if end > 0:
                    marker = container_id[:end] + chr(ord(delimiter) + 1)
                    dir_name = container_id[:end + 1]
                    if dir_name != orig_marker:
                        results.append([dir_name, 0, 0, 1])
                    break
                results.append([container_id, 0, 0, 0])
            if not count:
                break
        return results

    def list_containers(self, account_id, limit=1000, marker=None,
                        end_marker=None, prefix=None, delimiter=None):
        raw_list = self._raw_listing(account_id, limit=limit, marker=marker,
                                     end_marker=end_marker, prefix=prefix,
                                     delimiter=delimiter)
        pipeline = self.conn.pipeline(True)
        for container in raw_list:
            pipeline.hmget(AccountBackend.ckey(account_id, container[0]),
                           'objects', 'bytes')
        res = pipeline.execute()

        i = 0
        for container in raw_list:
            if not container[3]:
                container[1] = int_value(res[i][0], 0)
                container[2] = int_value(res[i][1], 0)
                i += 1

        return raw_list

    def status(self):
        conn = self.conn
        account_count = conn.hlen('accounts:')
        status = {'account_count': account_count}
        return status
