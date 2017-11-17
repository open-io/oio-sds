# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


from time import time

from six import text_type
import redis
import redis.sentinel
from werkzeug.exceptions import NotFound, Conflict, BadRequest
from oio.common.timestamp import Timestamp
from oio.common.easy_value import int_value, true_value
from oio.common.redis_conn import RedisConn


EXPIRE_TIME = 60  # seconds

account_fields = ['ns', 'name', 'ctime', 'containers', 'objects',
                  'bytes', 'storage_policy']

container_fields = ['ns', 'account', 'type', 'objects', 'bytes', 'ctime',
                    'mtime', 'name']


class AccountBackend(RedisConn):
    lua_is_sup = """
               -- With lua float we are losing precision for this reason
               -- we keep the number as a string
               local is_sup = function(a,b)
                 local int_a = string.match(a,"%d+")
                 local int_b = string.match(b,"%d+")
                 if string.len(int_a) > string.len(int_b) then
                   return true;
                 end;
                 return a > b;
               end;
               """

    lua_update_container = (lua_is_sup + """
               local account_id = redis.call('HGET', KEYS[4], 'id');
               if not account_id then
                 if ARGV[6] == 'True' then
                   redis.call('HSET', 'accounts:', KEYS[1], 1);
                   redis.call('HMSET', KEYS[4], 'id', KEYS[1],
                              'bytes', 0, 'objects', 0, 'ctime', ARGV[7]);
                 else
                   return redis.error_reply('no_account');
                 end;
               end;

               if ARGV[9] == 'False' then
                 local container_name = redis.call('HGET', KEYS[2], 'name');
                 if not container_name then
                   return redis.error_reply('no_container');
                 end;
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

               if ARGV[9] == 'False' and is_sup(dtime, mtime) then
                 return redis.error_reply('no_container');
               end;

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
               """)

    lua_refresh_account = """
        local account_id = redis.call('HGET', KEYS[1], 'id');
        if not account_id then
            return redis.error_reply('no_account');
        end;

        local containers = redis.call('ZRANGE', KEYS[2], 0, -1);
        local container_key = ''
        local bytes_sum = 0;
        local objects_sum = 0;
        for _,container in ipairs(containers) do
            container_key = KEYS[3] .. container;
            bytes_sum = bytes_sum + redis.call('HGET', container_key, 'bytes')
            objects_sum = objects_sum + redis.call('HGET', container_key,
                                                   'objects')
        end;

        redis.call('HMSET', KEYS[1], 'bytes', bytes_sum,
                   'objects', objects_sum)
        """

    lua_flush_account = """
        local account_id = redis.call('HGET', KEYS[1], 'id');
        if not account_id then
            return redis.error_reply('no_account');
        end;

        redis.call('HMSET', KEYS[1], 'bytes', 0, 'objects', 0)

        local containers = redis.call('ZRANGE', KEYS[2], 0, -1);
        redis.call('DEL', KEYS[2]);

        for _,container in ipairs(containers) do
            redis.call('DEL', KEYS[3] .. container);
        end;
        """

    def __init__(self, conf, connection=None):
        self.conf = conf
        self.autocreate = true_value(conf.get('autocreate', 'true'))
        super(AccountBackend, self).__init__(conf, connection)
        self.script_update_container = self.register_script(
            self.lua_update_container)
        self.script_refresh_account = self.register_script(
            self.lua_refresh_account)
        self.script_flush_account = self.register_script(
            self.lua_flush_account)

    @staticmethod
    def ckey(account, name):
        """Build the key of a container description"""
        return 'container:%s:%s' % (account, text_type(name))

    def create_account(self, account_id):
        conn = self.conn
        if not account_id:
            return None
        if conn.hget('accounts:', account_id):
            return None

        lock = self.acquire_lock_with_timeout('account:%s' % account_id, 1)
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
        self.release_lock('account:%s' % account_id, lock)
        return account_id

    def delete_account(self, account_id):
        conn = self.conn
        if not account_id:
            return None
        account_id = conn.hget('account:%s' % account_id, 'id')

        if not account_id:
            return None

        lock = self.acquire_lock_with_timeout('account:%s' % account_id, 1)
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
        self.release_lock('account:%s' % account_id, lock)
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
                         bytes_used, autocreate_account=None,
                         autocreate_container=True):
        conn = self.conn
        if not account_id or not name:
            raise BadRequest("Missing account or container")

        if autocreate_account is None:
            autocreate_account = self.autocreate

        if mtime is None:
            mtime = '0'
        else:
            mtime = Timestamp(float(mtime)).normal
        if dtime is None:
            dtime = '0'
        else:
            dtime = Timestamp(float(dtime)).normal
        if object_count is None:
            object_count = 0
        if bytes_used is None:
            bytes_used = 0

        keys = [account_id, AccountBackend.ckey(account_id, name),
                ("containers:%s" % (account_id)),
                ("account:%s" % (account_id))]
        args = [name, mtime, dtime, object_count, bytes_used,
                autocreate_account, Timestamp(time()).normal, EXPIRE_TIME,
                autocreate_container]
        try:
            self.script_update_container(keys=keys, args=args, client=conn)
        except redis.exceptions.ResponseError as exc:
            if str(exc) == "no_account":
                raise NotFound("Account %s not found" % account_id)
            if str(exc) == "no_container":
                raise NotFound("Container %s not found" % name)
            elif str(exc) == "no_update_needed":
                raise Conflict("No update needed, "
                               "event older than last container update")
            else:
                raise

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

    def refresh_account(self, account_id):
        if not account_id:
            raise BadRequest("Missing account")

        keys = ["account:%s" % account_id,
                "containers:%s" % account_id,
                "container:%s:" % account_id]

        try:
            self.script_refresh_account(keys=keys, client=self.conn)
        except redis.exceptions.ResponseError as exc:
            if str(exc) == "no_account":
                raise NotFound(account_id)
            else:
                raise

    def flush_account(self, account_id):
        if not account_id:
            raise BadRequest("Missing account")

        keys = ["account:%s" % account_id,
                "containers:%s" % account_id,
                "container:%s:" % account_id]

        try:
            self.script_flush_account(keys=keys, client=self.conn)
        except redis.exceptions.ResponseError as exc:
            if str(exc) == "no_account":
                raise NotFound(account_id)
            else:
                raise
