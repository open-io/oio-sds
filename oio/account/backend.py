# Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
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
from urlparse import urlparse

import re
import redis
import redis.sentinel
from werkzeug.exceptions import NotFound, Conflict, BadRequest
from oio.common.timestamp import Timestamp
from oio.common.easy_value import int_value, true_value, float_value
from oio.common.redis_conn import RedisConnection


EXPIRE_TIME = 60  # seconds

account_fields = ['ns', 'name', 'ctime', 'containers', 'objects',
                  'bytes', 'storage_policy']

container_fields = ['ns', 'account', 'type', 'objects', 'bytes', 'ctime',
                    'mtime', 'name']


class AccountBackend(RedisConnection):
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
                 if ARGV[8] == 'True' then
                   redis.call('HSET', 'accounts:', KEYS[1], 1);
                   redis.call('HMSET', KEYS[4], 'id', KEYS[1],
                              'bytes', 0, 'objects', 0,
                              'damaged_objects', 0, 'missing_chunks', 0,
                              'ctime', ARGV[9]);
                 else
                   return redis.error_reply('no_account');
                 end;
               end;

               if ARGV[11] == 'False' then
                 local container_name = redis.call('HGET', KEYS[2], 'name');
                 if not container_name then
                   return redis.error_reply('no_container');
                 end;
               end;

               local name = ARGV[1];
               local mtime = redis.call('HGET', KEYS[2], 'mtime');
               local dtime = redis.call('HGET', KEYS[2], 'dtime');
               local objects = redis.call('HGET', KEYS[2], 'objects');
               local bytes = redis.call('HGET', KEYS[2], 'bytes');
               local damaged_objects = redis.call('HGET', KEYS[2],
                                                  'damaged_objects');
               local missing_chunks = redis.call('HGET', KEYS[2],
                                                 'missing_chunks');

               -- When the keys do not exist redis return false and not nil
               if dtime == false then
                 dtime = '0'
               end
               if mtime == false then
                 mtime = '0'
               end
               if objects == false then
                 objects = 0
               end
               if bytes == false then
                 bytes = 0
               end
               if damaged_objects == false then
                 damaged_objects = 0
               end
               if missing_chunks == false then
                 missing_chunks = 0
               end

               if ARGV[11] == 'False' and is_sup(dtime, mtime) then
                 return redis.error_reply('no_container');
               end;

               local old_mtime = mtime;
               local inc_objects;
               local inc_bytes;
               local inc_damaged_objects;
               local inc_missing_chunks;

               if not is_sup(ARGV[3],dtime) and not is_sup(ARGV[2],mtime) then
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
                 inc_damaged_objects = -damaged_objects
                 inc_missing_chunks = -missing_chunks;
                 redis.call('HMSET', KEYS[2],
                            'bytes', 0, 'objects', 0,
                            'damaged_objects', 0, 'missing_chunks', 0);
                 redis.call('EXPIRE', KEYS[2], tonumber(ARGV[10]));
                 redis.call('ZREM', KEYS[3], name);
               elseif is_sup(mtime,old_mtime) then
                 redis.call('PERSIST', KEYS[2]);
                 inc_objects = tonumber(ARGV[4]) - objects
                 inc_bytes = tonumber(ARGV[5]) - bytes
                 inc_damaged_objects = tonumber(ARGV[6]) - damaged_objects
                 inc_missing_chunks = tonumber(ARGV[7]) - missing_chunks
                 redis.call('HMSET', KEYS[2],
                            'objects', tonumber(ARGV[4]),
                            'bytes', tonumber(ARGV[5]),
                            'damaged_objects', tonumber(ARGV[6]),
                            'missing_chunks', tonumber(ARGV[7]));
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
               if inc_damaged_objects ~= 0 then
                 redis.call('HINCRBY', KEYS[4], 'damaged_objects',
                            inc_damaged_objects);
               end;
               if inc_missing_chunks ~= 0 then
                 redis.call('HINCRBY', KEYS[4], 'missing_chunks',
                            inc_missing_chunks);
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
        local damaged_objects_sum = 0;
        local missing_chunks_sum = 0;
        for _,container in ipairs(containers) do
            container_key = KEYS[3] .. container;
            objects_sum = objects_sum + redis.call('HGET', container_key,
                                                   'objects')
            bytes_sum = bytes_sum + redis.call('HGET', container_key, 'bytes')
            local damaged_objects = redis.call('HGET', container_key,
                                               'damaged_objects')
            if damaged_objects == false then
                damaged_objects = 0
            end
            damaged_objects_sum = damaged_objects_sum + damaged_objects
            local missing_chunks = redis.call('HGET', container_key,
                                              'missing_chunks')
            if missing_chunks == false then
                missing_chunks = 0
            end
            missing_chunks_sum = missing_chunks_sum + missing_chunks
        end;

        redis.call('HMSET', KEYS[1], 'objects', objects_sum,
                   'bytes', bytes_sum,
                   'damaged_objects', damaged_objects_sum,
                   'missing_chunks', missing_chunks_sum)
        """

    lua_flush_account = """
        local account_id = redis.call('HGET', KEYS[1], 'id');
        if not account_id then
            return redis.error_reply('no_account');
        end;

        redis.call('HMSET', KEYS[1], 'objects', 0, 'bytes', 0,
                   'damaged_objects', 0, 'missing_chunks', 0)

        local containers = redis.call('ZRANGE', KEYS[2], 0, -1);
        redis.call('DEL', KEYS[2]);

        for _,container in ipairs(containers) do
            redis.call('DEL', KEYS[3] .. container);
        end;
        """

    # This regex comes from https://stackoverflow.com/a/50484916
    #
    # The first group looks ahead to ensure that the match
    # is between 3 and 63 characters long.
    #
    # The next group (?!^(\d+\.)+\d+$) looks ahead to forbid matching
    # bucket names that look like IP addresses.
    #
    # <The last group matches zero or more labels followed by a dot *
    buckets_pattern = re.compile(
        r"""(?=^.{3,63}$)   # first group
        (?!^(\d+\.)+\d+$) # second
        (^(([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\.)* #third
        ([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])$)""", re.X)

    def __init__(self, conf):
        self.conf = conf
        redis_conf = {k[6:]: v for k, v in self.conf.items()
                      if k.startswith("redis_")}
        redis_host = redis_conf.pop('host', None)
        if redis_host:
            parsed = urlparse('http://' + redis_host)
            if parsed.port is None:
                redis_host = '%s:%s' % (redis_host,
                                        redis_conf.pop('port', '6379'))
        redis_sentinel_hosts = redis_conf.pop(
            'sentinel_hosts',
            # TODO(adu): Delete when it will no longer be used
            self.conf.get('sentinel_hosts'))
        redis_sentinel_name = redis_conf.pop(
            'sentinel_name',
            # TODO(adu): Delete when it will no longer be used
            self.conf.get('sentinel_master_name'))
        super(AccountBackend, self).__init__(
            host=redis_host, sentinel_hosts=redis_sentinel_hosts,
            sentinel_name=redis_sentinel_name, **redis_conf)
        self.autocreate = true_value(conf.get('autocreate', 'true'))
        self.script_update_container = self.register_script(
            self.lua_update_container)
        self.script_refresh_account = self.register_script(
            self.lua_refresh_account)
        self.script_flush_account = self.register_script(
            self.lua_flush_account)

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

        lock = self.acquire_lock_with_timeout('account:%s' % account_id, 1)
        if not lock:
            return None

        pipeline = conn.pipeline(True)
        pipeline.hset('accounts:', account_id, 1)
        pipeline.hmset('account:%s' % account_id, {
            'id': account_id,
            'objects': 0,
            'bytes': 0,
            'damaged_objects': 0,
            'missing_chunks': 0,
            'ctime': Timestamp().normal
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
        conn = self.conn_slave
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
        conn = self.conn_slave
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
        for r in ['bytes', 'objects', 'damaged_objects', 'missing_chunks']:
            info[r] = int_value(info.get(r), 0)
        info['containers'] = data[1]
        info['metadata'] = data[2]
        return info

    def list_account(self):
        conn = self.conn_slave
        accounts = conn.hkeys('accounts:')
        return accounts

    def update_container(self, account_id, name, mtime, dtime,
                         object_count, bytes_used,
                         damaged_objects, missing_chunks,
                         autocreate_account=None, autocreate_container=True):
        conn = self.conn
        if not account_id or not name:
            raise BadRequest("Missing account or container")

        if autocreate_account is None:
            autocreate_account = self.autocreate

        if mtime is None:
            mtime = '0'
        else:
            mtime = Timestamp(mtime).normal
        if dtime is None:
            dtime = '0'
        else:
            dtime = Timestamp(dtime).normal
        if object_count is None:
            object_count = 0
        if bytes_used is None:
            bytes_used = 0
        if damaged_objects is None:
            damaged_objects = 0
        if missing_chunks is None:
            missing_chunks = 0

        keys = [account_id, AccountBackend.ckey(account_id, name),
                ("containers:%s" % (account_id)),
                ("account:%s" % (account_id))]
        args = [name, mtime, dtime, object_count, bytes_used,
                damaged_objects, missing_chunks,
                str(autocreate_account), Timestamp().normal, EXPIRE_TIME,
                str(autocreate_container)]
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

    def _should_be_listed(self, c_id, s3_buckets_only):
        return not s3_buckets_only or self.buckets_pattern.match(c_id)

    def _raw_listing(self, account_id, limit, marker=None, end_marker=None,
                     delimiter=None, prefix=None, s3_buckets_only=False):
        """
        Fetch a list of tuples of containers matching the specified options.
        Each tuple is formed like
            [(container|prefix),
             0 *reserved for objects*,
             0 *reserved for size*,
             0 for container, 1 for prefix,
             0 *reserved for mtime*]
        """
        orig_marker = marker
        results = list()
        beyond_prefix = False
        if prefix is None:
            prefix = ''

        while len(results) < limit and not beyond_prefix:
            min_k = '-'
            max_k = '+'
            if end_marker:
                max_k = '(' + end_marker
            if marker:
                if marker < prefix:
                    # Start on the prefix
                    min_k = '[' + prefix
                else:
                    # Start just after the marker
                    min_k = '(' + marker
            elif prefix:
                min_k = '[' + prefix

            cnames = self.conn_slave.zrangebylex(
                'containers:%s' % account_id, min_k, max_k,
                0, limit - len(results))
            if not cnames:
                break
            cnames = [c.decode('utf8', errors='ignore') for c in cnames]

            for cname in cnames:
                marker = cname
                if len(results) >= limit:
                    break
                elif prefix and not cname.startswith(prefix):
                    beyond_prefix = True
                    break
                if delimiter:
                    end = cname.find(delimiter, len(prefix))
                    if end > 0:
                        # Delimiter found after the prefix.
                        # Build a new marker, and continue listing from there.
                        # TODO(FVE): we can avoid another request to Redis by
                        # analyzing the rest of the list ourselves.
                        dir_name = cname[:end + 1]
                        marker = dir_name + u'\ufffd'
                        if dir_name != orig_marker:
                            results.append([dir_name, 0, 0, 1, 0])
                        break
                if self._should_be_listed(cname, s3_buckets_only):
                    results.append([cname, 0, 0, 0, 0])
        return results

    def list_containers(self, account_id, limit=1000, marker=None,
                        end_marker=None, prefix=None, delimiter=None,
                        s3_buckets_only=False):
        raw_list = self._raw_listing(account_id, limit=limit, marker=marker,
                                     end_marker=end_marker, prefix=prefix,
                                     delimiter=delimiter,
                                     s3_buckets_only=s3_buckets_only)
        pipeline = self.conn_slave.pipeline(True)
        # skip prefix
        for container in [entry for entry in raw_list if not entry[3]]:
            pipeline.hmget(AccountBackend.ckey(account_id, container[0]),
                           'objects', 'bytes', 'mtime')
        res = pipeline.execute()

        i = 0
        for container in raw_list:
            if not container[3]:
                # FIXME(adu) Convert to dict
                container[1] = int_value(res[i][0], 0)
                container[2] = int_value(res[i][1], 0)
                container[4] = float_value(res[i][2], 0.0)
                i += 1

        return raw_list

    def status(self):
        conn = self.conn_slave
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
