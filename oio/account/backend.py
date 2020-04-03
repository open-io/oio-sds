# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
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

import re
from six import text_type
from six.moves.urllib_parse import urlparse
import redis
import redis.sentinel
from werkzeug.exceptions import NotFound, Conflict, BadRequest
from oio.common.constants import BUCKET_PROP_REPLI_ENABLED
from oio.common.timestamp import Timestamp
from oio.common.easy_value import int_value, boolean_value, float_value, \
    debinarize
from oio.common.redis_conn import RedisConnection, catch_service_errors


ACCOUNT_KEY_PREFIX = 'account:'
BUCKET_KEY_PREFIX = 'bucket:'
BUCKET_LIST_PREFIX = 'buckets:'
CONTAINER_LIST_PREFIX = 'containers:'
SEGMENTS_BUCKET_SUFFIX = '+segments'

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

    lua_update_bucket_func = """
        -- Note that bucket is the key name, not just the bucket name
        -- (it has a prefix).
        local update_bucket_stats = function(
            bucket, account, mtime,
            inc_objects, inc_bytes, inc_damaged_objects, inc_missing_chunks)
          -- Set the bucket owner.
          -- FIXME(FVE): do some checks instead of overwriting
          redis.call('HSET', bucket, 'account', account)

          -- Increment the counters.
          redis.call('HINCRBY', bucket, 'objects', inc_objects)
          redis.call('HINCRBY', bucket, 'bytes', inc_bytes)
          redis.call('HINCRBY', bucket, 'damaged_objects', inc_damaged_objects)
          redis.call('HINCRBY', bucket, 'missing_chunks', inc_missing_chunks)

          -- Finally update the modification time.
          redis.call('HSET', bucket, 'mtime', mtime)
        end
    """

    lua_update_bucket_list = """
        -- Key to the set of bucket of a specific account
        local bucket_set = KEYS[1]
        -- Actual name of the bucket
        local bucket_name = ARGV[1]
        -- True if the bucket has just been deleted
        local deleted = ARGV[2]

        if deleted ~= 'True' then
          redis.call('ZADD', bucket_set, 0, bucket_name);
        else
          redis.call('ZREM', bucket_set, bucket_name);
        end
    """

    # FIXME(FVE): declare local variables
    lua_update_container = (
        lua_is_sup +
        lua_update_bucket_func +
        """
               -- KEYS[1] account name
               -- KEYS[2] key to the container hash
               -- KEYS[3] key to the account's container set
               -- KEYS[4] key to the account hash
               -- KEYS[5] key to the bucket hash
               local bkey = KEYS[5]
               -- ARGV[1] container name
               -- ARGV[2] mtime
               -- ARGV[3] dtime
               -- ARGV[4] new object count
               -- ARGV[5] new total size
               -- ARGV[6] damaged objects
               -- ARGV[7] missing chunks
               -- ARGV[8] autocreate account?
               -- ARGV[9] current timestamp
               local now = ARGV[9]
               -- ARGV[10] container key expiration time
               -- ARGV[11] autocreate container?
               -- ARGV[12] update bucket object count?
               local update_bucket_object_count = ARGV[12]

               local account_id = redis.call('HGET', KEYS[4], 'id');
               if not account_id then
                 if ARGV[8] == 'True' then
                   redis.call('HSET', 'accounts:', KEYS[1], 1);
                   redis.call('HMSET', KEYS[4], 'id', KEYS[1],
                              'bytes', 0, 'objects', 0,
                              'damaged_objects', 0, 'missing_chunks', 0,
                              'ctime', now);
                   account_id = KEYS[1]
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
               else
                 objects = tonumber(objects)
               end
               if bytes == false then
                 bytes = 0
               else
                 bytes = tonumber(bytes)
               end
               if damaged_objects == false then
                 damaged_objects = 0
               else
                 damaged_objects = tonumber(damaged_objects)
               end
               if missing_chunks == false then
                 missing_chunks = 0
               else
                 missing_chunks = tonumber(missing_chunks)
               end

               if ARGV[11] == 'False' and is_sup(dtime, mtime) then
                 return redis.error_reply('no_container');
               end;

               local old_mtime = mtime;
               local inc_objects = 0;
               local inc_bytes = 0;
               local inc_damaged_objects = 0;
               local inc_missing_chunks = 0;

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
                 -- Protect against "minus zero".
                 if objects ~= 0 then
                   inc_objects = -objects;
                 end
                 if bytes ~= 0 then
                   inc_bytes = -bytes;
                 end
                 if damaged_objects ~= 0 then
                   inc_damaged_objects = -damaged_objects
                 end
                 if missing_chunks ~= 0 then
                   inc_missing_chunks = -missing_chunks;
                 end
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

               if bkey ~= 'False' then
                 -- For container holding MPU segments, we do not want to count
                 -- each segment as an object. But we still want to consider
                 -- their size.
                 if update_bucket_object_count ~= 'True' then
                   inc_objects = 0
                 end
                 update_bucket_stats(bkey, account_id, now,
                                     inc_objects, inc_bytes,
                                     inc_damaged_objects, inc_missing_chunks)
               end
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

    lua_get_extended_container_info = """
        local ckey = KEYS[1]
        local bucket_prefix = ARGV[1]
        local bname = redis.call('HGET', ckey, 'bucket')

        local replication_enabled = 'false'
        if bname then
            local bkey = bucket_prefix .. bname
            local enabled_str = redis.call('HGET', bkey, 'replication_enabled')
            if enabled_str ~= nil then
                -- Do not cast into boolean here
                replication_enabled = enabled_str
            end
        end
        local res = redis.call('HGETALL', ckey)
        table.insert(res, 'replication_enabled')
        table.insert(res, replication_enabled)
        return res
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
        self.autocreate = boolean_value(conf.get('autocreate'), True)
        self.script_update_container = self.register_script(
            self.lua_update_container)
        self.script_update_bucket_list = self.register_script(
            self.lua_update_bucket_list)
        self.script_refresh_account = self.register_script(
            self.lua_refresh_account)
        self.script_flush_account = self.register_script(
            self.lua_flush_account)
        self.script_get_container_info = self.register_script(
            self.lua_get_extended_container_info)

        self._account_prefix = conf.get('account_prefix', ACCOUNT_KEY_PREFIX)
        self._bucket_prefix = conf.get('bucket_prefix', BUCKET_KEY_PREFIX)
        self._bucket_list_prefix = conf.get('bucket_list_prefix',
                                            BUCKET_LIST_PREFIX)
        self._container_list_prefix = conf.get('container_list_prefix',
                                               CONTAINER_LIST_PREFIX)

    def akey(self, account):
        """Build the key of an account description"""
        return self._account_prefix + account

    def bkey(self, bucket):
        """Build the key of a bucket description"""
        return self._bucket_prefix + bucket

    def blistkey(self, account):
        """Build the key of an account's bucket list"""
        return self._bucket_list_prefix + account

    @staticmethod
    def ckey(account, name):
        """Build the key of a container description"""
        return 'container:%s:%s' % (account, text_type(name))

    def clistkey(self, account):
        """Build the key of an account's container list"""
        return self._container_list_prefix + account

    @catch_service_errors
    def create_account(self, account_id):
        conn = self.conn
        if not account_id:
            return None
        if conn.hget('accounts:', account_id):
            return None

        lock = self.acquire_lock_with_timeout(self.akey(account_id), 1)
        if not lock:
            return None

        pipeline = conn.pipeline(True)
        pipeline.hset('accounts:', account_id, 1)
        pipeline.hmset(self.akey(account_id), {
            'id': account_id,
            'objects': 0,
            'bytes': 0,
            'damaged_objects': 0,
            'missing_chunks': 0,
            'ctime': Timestamp().normal
        })
        pipeline.execute()
        self.release_lock(self.akey(account_id), lock)
        return account_id

    @catch_service_errors
    def delete_account(self, req_account_id):
        conn = self.conn
        if not req_account_id:
            return None
        account_id = conn.hget(self.akey(req_account_id), 'id')

        if not account_id:
            return None

        account_id = account_id.decode('utf-8')
        lock = self.acquire_lock_with_timeout(self.akey(account_id), 1)
        if not lock:
            return None

        num_containers = conn.zcard(self.clistkey(account_id))

        if int(num_containers) > 0:
            self.release_lock('account:%s' % account_id, lock)
            return False

        pipeline = conn.pipeline(True)
        pipeline.delete('metadata:%s' % account_id)
        pipeline.delete(self.clistkey(account_id))
        pipeline.delete(self.akey(account_id))
        pipeline.hdel('accounts:', account_id)
        pipeline.execute()
        self.release_lock(self.akey(account_id), lock)
        return True

    @catch_service_errors
    def get_account_metadata(self, req_account_id):
        conn = self.conn_slave
        if not req_account_id:
            return None
        account_id = conn.hget(self.akey(req_account_id), 'id')

        if not account_id:
            return None

        meta = conn.hgetall('metadata:%s' % account_id.decode('utf-8'))
        return debinarize(meta)

    def cast_fields(self, info):
        """
        Cast dict entries to the type they are supposed to be.
        """
        for what in (b'bytes', b'objects', b'damaged_objects',
                     b'missing_chunks'):
            try:
                info[what] = int_value(info.get(what), 0)
            except (TypeError, ValueError):
                pass
        for what in (BUCKET_PROP_REPLI_ENABLED.encode('utf-8'), ):
            try:
                decoded = info.get(what, b'').decode('utf-8')
                info[what] = boolean_value(decoded)
            except (TypeError, ValueError):
                pass

    @catch_service_errors
    def get_bucket_info(self, bname):
        """
        Get all available information about a bucket.
        """
        if not bname:
            return None
        binfo = self.conn_slave.hgetall(self.bkey(bname))
        self.cast_fields(binfo)
        return binfo

    @catch_service_errors
    def get_container_info(self, account_id, cname):
        """
        Get all available information about a container, including some
        information coming from the bucket it belongs to.
        """
        if not cname:
            return None
        keys = [self.ckey(account_id, cname)]
        args = [self._bucket_prefix]
        cinfolist = self.script_get_container_info(
            keys=keys, args=args, client=self.conn_slave)
        key = None
        cinfo = dict()
        for cursor in cinfolist:
            if key is not None:
                cinfo[key] = cursor
                key = None
                continue
            key = cursor
        self.cast_fields(cinfo)
        return cinfo

    @catch_service_errors
    def update_account_metadata(self, account_id, metadata, to_delete=None):
        conn = self.conn
        if not account_id:
            return None
        _acct_id = conn.hget(self.akey(account_id), 'id')

        if not _acct_id:
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

    @catch_service_errors
    def update_bucket_metadata(self, bname, metadata, to_delete=None):
        """
        Update (or delete) bucket metadata.

        :param metadata: dict of entries to set (or update)
        :param to_delete: iterable of keys to delete
        """
        bkey = self.bkey(bname)
        pipeline = self.conn.pipeline(True)
        if to_delete:
            pipeline.hdel(bkey, *to_delete)
        # FIXME(FVE): cast known metadata into the appropriate type/value
        if metadata:
            pipeline.hmset(bkey, metadata)
        pipeline.hgetall(bkey)
        res = pipeline.execute()
        binfo = res[-1]
        self.cast_fields(binfo)
        return binfo
        # return None

    @catch_service_errors
    def info_account(self, req_account_id):
        conn = self.conn_slave
        if not req_account_id:
            return None
        account_id = conn.hget(self.akey(req_account_id), 'id')

        if not account_id:
            return None

        account_id = account_id.decode('utf-8')
        pipeline = conn.pipeline(False)
        pipeline.hgetall(self.akey(account_id))
        pipeline.zcard(self.blistkey(account_id))
        pipeline.zcard(self.clistkey(account_id))
        pipeline.hgetall('metadata:%s' % account_id)
        data = pipeline.execute()
        info = data[0]
        self.cast_fields(info)
        info[b'buckets'] = data[1]
        info[b'containers'] = data[2]
        info[b'metadata'] = data[3]
        return debinarize(info)

    @catch_service_errors
    def list_accounts(self):
        """
        Get the list of all accounts.
        """
        conn = self.conn_slave
        accounts = conn.hkeys('accounts:')
        return debinarize(accounts)

    @catch_service_errors
    def update_container(self, account_id, name, mtime, dtime,
                         object_count, bytes_used,
                         damaged_objects, missing_chunks,
                         bucket_name=None,
                         autocreate_account=None, autocreate_container=True):
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
        deleted = float(dtime) > float(mtime)
        if object_count is None:
            object_count = 0
        if bytes_used is None:
            bytes_used = 0
        if damaged_objects is None:
            damaged_objects = 0
        if missing_chunks is None:
            missing_chunks = 0

        # If no bucket name is provided, set it to 'False'
        # (we cannot pass None to the Lua script).
        bucket_key = self.bkey(bucket_name) if bucket_name else str(False)
        now = Timestamp().normal
        # With some sharding middlewares, the suffix may be
        # in the middle of the container name.
        update_bucket_object_count = SEGMENTS_BUCKET_SUFFIX not in name

        ckey = AccountBackend.ckey(account_id, name)
        keys = [account_id, ckey,
                self.clistkey(account_id),
                self.akey(account_id),
                bucket_key]
        args = [name, mtime, dtime, object_count, bytes_used,
                damaged_objects, missing_chunks,
                str(autocreate_account), now, EXPIRE_TIME,
                str(autocreate_container),
                str(update_bucket_object_count)]
        pipeline = self.conn.pipeline(True)
        try:
            self.script_update_container(
                keys=keys, args=args, client=pipeline)
            if bucket_name and not deleted:
                pipeline.hset(ckey, "bucket", bucket_name)
            # Only execute when the main shard is created/deleted.
            if bucket_name == name:
                self.script_update_bucket_list(
                    keys=[self.blistkey(account_id)],
                    args=[bucket_name, str(deleted)],
                    client=pipeline)
            pipeline.execute()
        except redis.exceptions.ResponseError as exc:
            if text_type(exc).endswith("no_account"):
                raise NotFound("Account %s not found" % account_id)
            if text_type(exc).endswith("no_container"):
                raise NotFound("Container %s not found" % name)
            elif text_type(exc).endswith("no_update_needed"):
                raise Conflict("No update needed, "
                               "event older than last container update")
            else:
                raise

        return name

    def _should_be_listed(self, c_id, s3_buckets_only):
        return not s3_buckets_only or self.buckets_pattern.match(c_id)

    @catch_service_errors
    def _raw_listing(self, key, limit, marker=None, end_marker=None,
                     delimiter=None, prefix=None, s3_buckets_only=False):
        """
        Fetch a list of tuples of items matching the specified options.
        Each tuple is formed like
            [(container|prefix),
             0 *reserved for objects*,
             0 *reserved for size*,
             0 for container, 1 for prefix,
             0 *reserved for mtime*]
        :returns: the list of results, and the marker for the next request
            (in case the list of results is truncated)
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

            # Ask for one extra element, to be able to tell if the
            # list of results is truncated.
            cnames = self.conn_slave.zrangebylex(
                key, min_k, max_k,
                0, limit - len(results) + 1)
            if not cnames:
                # No more items
                marker = None
                break
            cnames = [c.decode('utf8', errors='ignore') for c in cnames]

            for cname in cnames:
                if len(results) >= limit:
                    # Do not reset marker, there are more items
                    break
                elif prefix and not cname.startswith(prefix):
                    beyond_prefix = True
                    # No more items
                    marker = None
                    break
                marker = cname
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
        return results, marker

    @catch_service_errors
    def list_buckets(self, account_id, limit=1000, marker=None,
                     end_marker=None, prefix=None):
        """
        Get the list of buckets of the specified account.

        :returns: the list of buckets (with metadata), and the next
            marker (in case the list is truncated).
        """
        raw_list, next_marker = self._raw_listing(
            self.blistkey(account_id),
            limit=limit, marker=marker,
            end_marker=end_marker, prefix=prefix)
        pipeline = self.conn_slave.pipeline(True)
        for entry in raw_list:
            # For real buckets (not prefixes), fetch metadata.
            if not entry[3]:
                pipeline.hmget(self.bkey(entry[0]),
                               'objects', 'bytes', 'mtime')
        res = pipeline.execute()

        output = list()
        i = 0
        for bucket in raw_list:
            if not bucket[3]:
                bdict = {
                    'name': bucket[0],
                    'objects': int_value(res[i][0], 0),
                    'bytes': int_value(res[i][1], 0),
                    'mtime': float_value(res[i][2], 0.0),
                }
                i += 1
            else:
                bdict = {'prefix': bucket}
            output.append(bdict)

        return output, next_marker

    @catch_service_errors
    def list_containers(self, account_id, limit=1000, marker=None,
                        end_marker=None, prefix=None, delimiter=None,
                        s3_buckets_only=False):
        raw_list, _next_marker = self._raw_listing(
            self.clistkey(account_id),
            limit=limit, marker=marker,
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

    @catch_service_errors
    def status(self):
        conn = self.conn_slave
        account_count = conn.hlen('accounts:')
        status = {'account_count': account_count}
        return status

    @catch_service_errors
    def refresh_account(self, account_id):
        if not account_id:
            raise BadRequest("Missing account")

        keys = [self.akey(account_id),
                self.clistkey(account_id),
                "container:%s:" % account_id]

        try:
            self.script_refresh_account(keys=keys, client=self.conn)
        except redis.exceptions.ResponseError as exc:
            if str(exc) == "no_account":
                raise NotFound(account_id)
            else:
                raise

    @catch_service_errors
    def flush_account(self, account_id):
        if not account_id:
            raise BadRequest("Missing account")

        keys = [self.akey(account_id),
                self.clistkey(account_id),
                "container:%s:" % account_id]

        try:
            self.script_flush_account(keys=keys, client=self.conn)
        except redis.exceptions.ResponseError as exc:
            if str(exc) == "no_account":
                raise NotFound(account_id)
            else:
                raise
