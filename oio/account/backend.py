from time import time, sleep
import uuid
import math

import redis
import redis.sentinel
from werkzeug.exceptions import NotFound, Conflict
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
    lua_update_container = """
               -- With lua float we are losing precision for this reason
               -- we keep the number as a string
               local is_sup = function(a,b)
                 if string.len(a) < string.len(b) then
                   return false;
                 end;
                 return a > b;
               end;

               local account_id = redis.call('HGET', KEYS[4], 'id');
               if not account_id and ARGV[6] then
                 redis.call('HSET', 'accounts:', KEYS[1], 1)
                 redis.call('HMSET', KEYS[4], 'id', KEYS[1],
                            'bytes', 0, 'objects', 0, 'ctime', ARGV[7])
               elseif not account_id then
                 return redis.error_reply('no_account')
               end;

               local objects = redis.call('HGET', KEYS[2], 'objects');
               local name = ARGV[1];
               local mtime = redis.call('HGET', KEYS[2], 'mtime');
               local dtime = redis.call('HGET', KEYS[2], 'dtime');
               local bytes = redis.call('HGET', KEYS[2], 'bytes');

               -- When the keys do not exist redis return false and not nil
               if objects == false then
                 objects = 0
               end
               if dtime == false then
                 dtime = '0'
               end
               if mtime == false then
                 mtime = '0'
               end
               if bytes == false then
                 bytes = 0
               end

               local old_mtime = mtime;
               local inc_objects;
               local inc_bytes;

               if not is_sup(ARGV[3],dtime) and
                  not is_sup(ARGV[2],mtime) then
                 return redis.error_reply('no_update_needed');
               end;

               if is_sup(ARGV[2],mtime) then
                 mtime = ARGV[2];
               end;

               if is_sup(ARGV[3],dtime) then
                 dtime = ARGV[3];
               end;
               if is_sup(dtime,mtime) then
                 inc_objects = -objects;
                 inc_bytes = -bytes;
                 redis.call('HMSET', KEYS[2], 'bytes', 0, 'objects', 0);
                 redis.call('EXPIRE', KEYS[2], tonumber(ARGV[8]));
                 redis.call('ZREM', KEYS[3], name);
               elseif is_sup(mtime,old_mtime) then
                 redis.call('PERSIST', KEYS[2]);
                 inc_objects = tonumber(ARGV[4]) - objects
                 inc_bytes = tonumber(ARGV[5]) - bytes
                 redis.call('HMSET', KEYS[2], 'bytes', tonumber(ARGV[5]),
                            'objects', tonumber(ARGV[4]));
                 redis.call('ZADD', KEYS[3], '0', name);
               else
                 return redis.error_reply('no_update_needed');
               end;

               redis.call('HMSET', KEYS[2], 'mtime', mtime,
                          'dtime', dtime, 'name', name)
               if inc_objects ~= 0 then
                 redis.call('HINCRBY', KEYS[4], 'objects', inc_objects);
               end;
               if inc_bytes ~= 0 then
                 redis.call('HINCRBY', KEYS[4], 'bytes', inc_bytes);
               end;
               """

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
        self.script_update_container = self.conn.register_script(
            self.lua_update_container)

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

    def list_account(self):
        conn = self.conn
        accounts = conn.hkeys('accounts:')
        return accounts

    def update_container(self, account_id, name, mtime, dtime, object_count,
                         bytes_used):
        conn = self.conn
        if not account_id or not name:
            raise NotFound("Missing account or container")

        if mtime is None:
            mtime = '0'
        if dtime is None:
            dtime = '0'
        if object_count is None:
            object_count = 0
        if bytes_used is None:
            bytes_used = 0

        keys = [account_id, AccountBackend.ckey(account_id, name),
                ("containers:%s" % (account_id)),
                ("account:%s" % (account_id))]
        args = [name, mtime, dtime, object_count, bytes_used,
                self.autocreate, Timestamp(time()).normal, EXPIRE_TIME]
        try:
            self.script_update_container(keys=keys, args=args, client=conn)
        except redis.exceptions.ResponseError as e:
            if str(e) == "no_account":
                raise NotFound(account_id)
            elif str(e) == "no_update_needed":
                raise Conflict("No updated needed")
            else:
                raise e

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
