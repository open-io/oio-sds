# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021 OVH SAS
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

import re
from six import text_type
from six.moves.urllib_parse import urlparse
import redis
import redis.sentinel

from werkzeug.exceptions import NotFound, Conflict, BadRequest
from oio.common.constants import BUCKET_PROP_REPLI_ENABLED, \
    CH_ENCODED_SEPARATOR
from oio.common.timestamp import Timestamp
from oio.common.easy_value import int_value, boolean_value, float_value, \
    debinarize
from oio.common.redis_conn import RedisConnection, catch_service_errors, \
    catch_io_errors


END_MARKER = u"\U0010fffd"

ACCOUNT_KEY_PREFIX = 'account:'
BUCKET_KEY_PREFIX = 'bucket:'
BUCKET_LIST_PREFIX = 'buckets:'
CONTAINER_LIST_PREFIX = 'containers:'
BUCKET_LOCK_KEY_PREFIX = 'bucketlock:'

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
                 local int_a = string.match(a,"%%d+")
                 local int_b = string.match(b,"%%d+")
                 if string.len(int_a) > string.len(int_b) then
                   return true;
                 end;
                 return a > b;
               end;
               local is_sup_eq = function(a,b)
                 local int_a = string.match(a,"%%d+")
                 local int_b = string.match(b,"%%d+")
                 if string.len(int_a) > string.len(int_b) then
                   return true;
                 end;
                 return a >= b;
               end;
               """

    lua_update_bucket_func = """
        -- Note that bucket is the key name, not just the bucket name
        -- (it has a prefix).
        local update_bucket_stats = function(
            container_key, bucket_key, buckets_list_key,
            account, container_name, bucket_name, bucket_lock, mtime, deleted,
            inc_objects, inc_bytes)
          if deleted then
            redis.call('HDEL', container_key, 'bucket');

            -- Update the buckets list if it's the root container
            if bucket_name == container_name then
              redis.call('ZREM', buckets_list_key, bucket_name);
              redis.call('ZREM', '%(bucket_list_prefix)s', bucket_name);
              -- Also delete the bucket
              redis.call('DEL', bucket_key);
              return;
            end;
            -- We used to return here. But since we delete shard before
            -- cleaning them, we need to fix counters first.
          end;

          -- For container holding MPU segments, we do not want to count
          -- each segment as an object. But we still want to consider
          -- their size.
          if string.find(container_name, '+segments') then
            inc_objects = 0;
          end;

          -- Check if a refresh bucket is in progress
          local marker = redis.call("HGET", bucket_lock, "marker");

          -- Increment the counters if needed.
          if marker == false or container_name <= marker then
            redis.call('HINCRBY', bucket_key, 'objects', inc_objects);
            redis.call('HINCRBY', bucket_key, 'bytes', inc_bytes);
          end;

          -- Update the modification time.
          if mtime ~= '' then
            redis.call('HSET', bucket_key, 'mtime', mtime);
          end;

          if deleted then
            return;
          end;

          -- Set the bucket owner.
          -- Filter the special accounts hosting bucket shards.
          if not string.find(account, '^\\.shards_') then
            redis.call('HSET', bucket_key, 'account', account);
          end;

          -- Update container info
          redis.call('HSET', container_key, 'bucket', bucket_name);

          -- Update the buckets list if it's the root container
          if bucket_name == container_name then
            redis.call('ZADD', buckets_list_key, 0, bucket_name);
            redis.call('ZADD', '%(bucket_list_prefix)s', 0, bucket_name);
          end;
        end;
    """

    lua_refresh_bucket_batch = (
        """
        local ckey_prefix = KEYS[1]; -- prefix of the key to the container hash
        local clistkey = KEYS[2]; -- key to the account's container set
        local bkey = KEYS[3]; -- key to the bucket hash
        local lkey = KEYS[4]; -- key to the bucket lock
        local bucket_name = ARGV[1];
        local mtime = ARGV[2];
        local batch_size = ARGV[3];

        -- Check if the bucket exists.
        local account_id = redis.call('HGET', bkey, 'account');
        if account_id == false then
          return redis.error_reply('no_bucket');
        end;
        ckey_prefix = ckey_prefix:gsub( "__account__", account_id);
        clistkey = clistkey:gsub("__account__", account_id);

        -- global counters
        local total_objects = 0;
        local total_bytes = 0;

        local marker = redis.call('HGET', lkey, 'marker');

        if marker == '' then
            marker = '-';
            redis.call('HMSET', bkey,
                    'objects', 0,
                    'bytes', 0);
        else
            marker = '(' .. marker;
        end;

        local new_marker = '';

        -- Increment the counters.
        local containers = redis.call('ZRANGEBYLEX', clistkey,
                                      marker, '+', 'LIMIT', 0, batch_size);

        local i;
        for i, container_name in ipairs(containers) do
          local ckey = ckey_prefix .. container_name;

          local bucket  = redis.call('HGET', ckey, 'bucket');
          if bucket ~= false and bucket == bucket_name then
            local info  = redis.call('HMGET', ckey,
                                     'objects',
                                     'bytes');
            local objects = info[1];
            local bytes = info[2];

            if not string.find(container_name, '+segments') then
                total_objects = total_objects + objects;
            end;
            total_bytes = total_bytes + bytes;
          end;
          new_marker = container_name
        end;

        -- Increment the counters.
        redis.call('HINCRBY', bkey, 'objects', total_objects);
        redis.call('HINCRBY', bkey, 'bytes', total_bytes);

        redis.call('HSET', lkey, 'marker', new_marker,
                                 'mtime', mtime);
        if i ~= batch_size then
            redis.call('DEL', lkey)
            return { 1 }
        end;
        return { 0 }
        """
    )

    lua_update_container = (
        lua_is_sup
        + lua_update_bucket_func
        + """
        local akey = KEYS[1]; -- key to the account hash
        local ckey = KEYS[2]; -- key to the container hash
        local clistkey = KEYS[3]; -- key to the account's container set
        local bkey_prefix = KEYS[4]; -- prefix of the key to the bucket hash
        local blistkey = KEYS[5]; -- key to the account's bucket set
        local account_id = ARGV[1];
        local container_name = ARGV[2];
        local bucket_name = ARGV[3];
        local bucket_lock = ARGV[4];
        local new_mtime = ARGV[5];
        local new_dtime = ARGV[6];
        local new_total_objects = ARGV[7];
        local new_total_bytes = ARGV[8];
        local autocreate_account = ARGV[9];
        local now = ARGV[10]; -- current timestamp
        local ckey_expiration_time = ARGV[11];
        local autocreate_container = ARGV[12];

        local account_exists = redis.call('EXISTS', akey);
        if account_exists ~= 1 then
          if autocreate_account == 'True' then
            redis.call('HSET', 'accounts:', account_id, 1);
            redis.call('HMSET', akey,
                       'id', account_id,
                       'bytes', 0,
                       'objects', 0,
                       'ctime', now);
          else
            return redis.error_reply('no_account');
          end;
        end;

        if autocreate_container == 'False' then
          local container_exists = redis.call('EXISTS', ckey);
          if container_exists ~= 1 then
            return redis.error_reply('no_container');
          end;
        end;

        local mtime = redis.call('HGET', ckey, 'mtime');
        local dtime = redis.call('HGET', ckey, 'dtime');
        local objects = redis.call('HGET', ckey, 'objects');
        local bytes = redis.call('HGET', ckey, 'bytes');

        -- When the keys do not exist redis returns false and not nil
        if dtime == false then
          dtime = '0';
        end;
        if mtime == false then
          mtime = '0';
        end;
        if objects == false then
          objects = 0;
        else
          objects = tonumber(objects);
        end;
        if bytes == false then
          bytes = 0;
        else
          bytes = tonumber(bytes);
        end;

        if autocreate_container == 'False' and is_sup_eq(dtime, mtime) then
          return redis.error_reply('no_container');
        end;

        local old_mtime = mtime;
        local inc_objects = 0;
        local inc_bytes = 0;
        local deleted = false;

        if not is_sup(new_dtime, dtime) and not is_sup(new_mtime, mtime) then
          return redis.error_reply('no_update_needed');
        end;

        if is_sup(new_mtime, mtime) then
          mtime = new_mtime;
        end;

        if is_sup(new_dtime, dtime) then
          dtime = new_dtime;
        end;
        if is_sup_eq(dtime, mtime) then
          mtime = dtime;
          -- Protect against "minus zero".
          if objects ~= 0 then
            inc_objects = -objects;
          end;
          if bytes ~= 0 then
            inc_bytes = -bytes;
          end;
          redis.call('HMSET', ckey,
                     'bytes', 0, 'objects', 0);
          redis.call('EXPIRE', ckey, tonumber(ckey_expiration_time));
          redis.call('ZREM', clistkey, container_name);
          deleted = true;
        elseif is_sup(mtime, old_mtime) then
          redis.call('PERSIST', ckey);
          inc_objects = tonumber(new_total_objects) - objects;
          inc_bytes = tonumber(new_total_bytes) - bytes;
          redis.call('HMSET', ckey,
                     'objects', tonumber(new_total_objects),
                     'bytes', tonumber(new_total_bytes));
          redis.call('ZADD', clistkey, '0', container_name);
        else
          return redis.error_reply('no_update_needed');
        end;

        redis.call('HMSET', ckey, 'mtime', mtime,
                   'dtime', dtime, 'name', container_name);
        if inc_objects ~= 0 then
          redis.call('HINCRBY', akey, 'objects', inc_objects);
        end;
        if inc_bytes ~= 0 then
          redis.call('HINCRBY', akey, 'bytes', inc_bytes);
        end;

        local current_bucket_name = redis.call('HGET', ckey, 'bucket');
        if bucket_name == '' and current_bucket_name ~= false then
          -- Use the bucket name already registered when it is not given
          bucket_name = current_bucket_name;
        end;
        if bucket_name ~= '' then
          local bkey = bkey_prefix .. bucket_name;

          -- FIXME(FVE): this may no be needed anymore
          -- This container is not yet associated with this bucket.
          -- We must add all the totals in case the container already existed
          -- but didn't know its parent bucket.
          if deleted == false and current_bucket_name == false then
            inc_objects = new_total_objects;
            inc_bytes = new_total_bytes;
          end;

          update_bucket_stats(
              ckey, bkey, blistkey, account_id, container_name, bucket_name,
              bucket_lock, mtime, deleted, inc_objects, inc_bytes);
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
            objects_sum = objects_sum + redis.call('HGET', container_key,
                                                   'objects')
            bytes_sum = bytes_sum + redis.call('HGET', container_key, 'bytes')
        end;

        redis.call('HMSET', KEYS[1], 'objects', objects_sum,
                   'bytes', bytes_sum)
        """

    lua_flush_account = """
        local account_id = redis.call('HGET', KEYS[1], 'id');
        if not account_id then
            return redis.error_reply('no_account');
        end;

        redis.call('HMSET', KEYS[1], 'objects', 0, 'bytes', 0)

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

    lua_lock_bucket = """
        local lkey = KEYS[1]
        local ctime = ARGV[1]

        local ret = redis.call('HSETNX', lkey, 'ctime', ctime);
        if ret == 0 then
            local mtime = redis.call('HGET', lkey, 'mtime');
            -- Recover dead lock
            if tonumber(ctime) < (tonumber(mtime) + 3600) then
                return redis.error_reply('bucket_lock');
            end;
            redis.call('HSET', lkey, 'ctime', ctime);
        end;
        redis.call('HSET', lkey, 'mtime', ctime,
                                 'marker', '');
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
        self._account_prefix = conf.get('account_prefix', ACCOUNT_KEY_PREFIX)
        self._bucket_prefix = conf.get('bucket_prefix', BUCKET_KEY_PREFIX)
        self._bucket_list_prefix = conf.get('bucket_list_prefix',
                                            BUCKET_LIST_PREFIX)
        self._container_list_prefix = conf.get('container_list_prefix',
                                               CONTAINER_LIST_PREFIX)
        self._bucket_lock_prefix = conf.get('bucket_lock_prefix',
                                            BUCKET_LOCK_KEY_PREFIX)

        update_container_patched = self.lua_update_container % {
            'bucket_list_prefix': self._bucket_list_prefix}
        self.script_update_container = self.register_script(
            update_container_patched)
        self.script_refresh_bucket = self.register_script(
            self.lua_refresh_bucket_batch)
        self.script_refresh_account = self.register_script(
            self.lua_refresh_account)
        self.script_flush_account = self.register_script(
            self.lua_flush_account)
        self.script_get_container_info = self.register_script(
            self.lua_get_extended_container_info)
        self.script_get_lock_bucket = self.register_script(
            self.lua_lock_bucket)

    def akey(self, account):
        """Build the key of an account description"""
        return self._account_prefix + account

    def bkey(self, bucket):
        """Build the key of a bucket description"""
        return self._bucket_prefix + bucket

    def lbucketkey(self, bucket):
        """Build the key of a bucket description"""
        return self._bucket_prefix + bucket

    def blistkey(self, account):
        """Build the key of an account's bucket list"""
        return self._bucket_list_prefix + account

    def blockkey(self, bucket):
        """Build the lock key for a bucket refresh operation"""
        return self._bucket_lock_prefix + bucket

    @staticmethod
    def ckey(account, name):
        """Build the key of a container description"""
        return 'container:%s:%s' % (account, text_type(name))

    def clistkey(self, account):
        """Build the key of an account's container list"""
        return self._container_list_prefix + account

    @catch_service_errors
    def create_account(self, account_id, **kwargs):
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
            'ctime': Timestamp().normal
        })
        pipeline.execute()
        self.release_lock(self.akey(account_id), lock)
        return account_id

    @catch_service_errors
    def delete_account(self, req_account_id, **kwargs):
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
    def get_account_metadata(self, req_account_id, **kwargs):
        if not req_account_id:
            return None

        conn = self.get_slave_conn(**kwargs)
        account_id = conn.hget(self.akey(req_account_id), 'id')

        if not account_id:
            return None

        meta = conn.hgetall('metadata:%s' % account_id.decode('utf-8'))
        return debinarize(meta)

    def cast_fields(self, info):
        """
        Cast dict entries to the type they are supposed to be.
        """
        for what in (b'bytes', b'objects'):
            try:
                info[what] = int_value(info.get(what), 0)
            except (TypeError, ValueError):
                pass
        for what in (BUCKET_PROP_REPLI_ENABLED.encode('utf-8'), ):
            try:
                val = info.get(what)
                decoded = val.decode('utf-8') if val is not None else None
                info[what] = boolean_value(decoded)
            except (TypeError, ValueError):
                pass

    @catch_service_errors
    def get_bucket_info(self, bname, **kwargs):
        """
        Get all available information about a bucket.
        """
        if not bname:
            return None

        conn = self.get_slave_conn(**kwargs)
        binfo = conn.hgetall(self.bkey(bname))
        if not binfo:
            return None
        self.cast_fields(binfo)
        return binfo

    @catch_service_errors
    @catch_io_errors
    def get_container_info(self, account_id, cname, **kwargs):
        """
        Get all available information about a container, including some
        information coming from the bucket it belongs to.
        """
        if not cname:
            return None

        conn = self.get_slave_conn(**kwargs)
        keys = [self.ckey(account_id, cname)]
        args = [self._bucket_prefix]
        cinfolist = self.script_get_container_info(
            keys=keys, args=args, client=conn)
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
    def update_account_metadata(self, account_id, metadata, to_delete=None,
                                **kwargs):
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
    def update_bucket_metadata(self, bname, metadata, to_delete=None,
                               **kwargs):
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
    def info_account(self, req_account_id, **kwargs):
        if not req_account_id:
            return None

        conn = self.get_slave_conn(**kwargs)
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
    def list_accounts(self, **kwargs):
        """
        Get the list of all accounts.
        """
        conn = self.get_slave_conn(**kwargs)
        accounts = conn.hkeys('accounts:')
        return debinarize(accounts)

    @catch_service_errors
    @catch_io_errors
    def update_container(self, account_id, name, mtime, dtime,
                         object_count, bytes_used,
                         bucket_name=None, autocreate_account=None,
                         autocreate_container=True, **kwargs):
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

        # If no bucket name is provided, set it to ''
        # (we cannot pass None to the Lua script).
        bucket_name = bucket_name or ''
        bucket_lock = self.blockkey(bucket_name)
        now = Timestamp().normal

        ckey = AccountBackend.ckey(account_id, name)
        keys = [self.akey(account_id), ckey, self.clistkey(account_id),
                self._bucket_prefix, self.blistkey(account_id)]
        args = [account_id, name, bucket_name, bucket_lock, mtime, dtime,
                object_count, bytes_used, str(autocreate_account), now,
                EXPIRE_TIME, str(autocreate_container)]
        try:
            self.script_update_container(
                keys=keys, args=args)
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
                     delimiter=None, prefix=None, s3_buckets_only=False,
                     **kwargs):
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

        conn = self.get_slave_conn(**kwargs)
        while len(results) < limit and not beyond_prefix:
            min_k = '-'
            max_k = '+'
            if prefix:
                min_k = '[' + prefix
                max_k = '[' + prefix + END_MARKER
            if marker and (not prefix or marker >= prefix):
                min_k = '(' + marker
            if end_marker and (not prefix
                               or end_marker <= prefix + END_MARKER):
                max_k = '(' + end_marker

            # Ask for one extra element, to be able to tell if the
            # list of results is truncated.
            cnames = conn.zrangebylex(
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
                        marker = dir_name + END_MARKER
                        if dir_name != orig_marker:
                            results.append([dir_name, 0, 0, 1, 0])
                        break
                if self._should_be_listed(cname, s3_buckets_only):
                    results.append([cname, 0, 0, 0, 0])
            if marker and s3_buckets_only:
                # Avoid listing shards to save a lot of time
                if '+segments' in marker:
                    marker = marker.split('+segments', 1)[0] + '+segments' + \
                        END_MARKER
                elif CH_ENCODED_SEPARATOR in marker:
                    marker = marker.split(CH_ENCODED_SEPARATOR, 1)[0] + \
                        CH_ENCODED_SEPARATOR + END_MARKER
        return results, marker

    @catch_service_errors
    def list_buckets(self, account_id, limit=1000, marker=None,
                     end_marker=None, prefix=None, **kwargs):
        """
        Get the list of buckets of the specified account.

        :returns: the list of buckets (with metadata), and the next
            marker (in case the list is truncated).
        """
        raw_list, next_marker = self._raw_listing(
            self.blistkey(account_id),
            limit=limit, marker=marker,
            end_marker=end_marker, prefix=prefix, **kwargs)
        conn = self.get_slave_conn(**kwargs)
        pipeline = conn.pipeline(True)
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
                        s3_buckets_only=False, **kwargs):
        raw_list, _next_marker = self._raw_listing(
            self.clistkey(account_id),
            limit=limit, marker=marker,
            end_marker=end_marker, prefix=prefix,
            delimiter=delimiter,
            s3_buckets_only=s3_buckets_only, **kwargs)
        conn = self.get_slave_conn(**kwargs)
        pipeline = conn.pipeline(True)
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
    def status(self, **kwargs):
        conn = self.get_slave_conn(**kwargs)
        account_count = conn.hlen('accounts:')
        status = {'account_count': account_count}
        return status

    @catch_service_errors
    @catch_io_errors
    def refresh_bucket(self, bucket_name, **kwargs):
        """
        Refresh the counters of a bucket. Recompute them from the counters
        of all shards (containers).
        """
        lkey = self.blockkey(bucket_name)
        batch_size = kwargs.get("batch_size", 10000)
        try:
            ctime = Timestamp().normal
            self.script_get_lock_bucket(keys=[lkey], args=[ctime])
        except redis.exceptions.ResponseError as exc:
            if text_type(exc).endswith("bucket_lock"):
                raise Conflict("Refresh on bucket already in progress")
            raise

        account_id = '__account__'
        keys = [AccountBackend.ckey(account_id, ''),
                self.clistkey(account_id), self.bkey(bucket_name),
                lkey]

        try:
            while True:
                args = [bucket_name, Timestamp().normal, batch_size]
                res = self.script_refresh_bucket(keys=keys, args=args)
                if res[0]:
                    break
        except redis.exceptions.ResponseError as exc:
            self.conn.delete(lkey)
            if text_type(exc).endswith("no_account"):
                raise NotFound("Account %s not found" % account_id)
            if text_type(exc).endswith("no_bucket"):
                raise NotFound("Bucket %s not found" % bucket_name)
            raise

    @catch_service_errors
    @catch_io_errors
    def refresh_account(self, account_id, **kwargs):
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
    @catch_io_errors
    def flush_account(self, account_id, **kwargs):
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

    @catch_service_errors
    @catch_io_errors
    def reserve_bucket(self, account_id, bucket_name, **kwargs):
        raise BadRequest('Bucket reservation not implemented for redis')

    @catch_service_errors
    @catch_io_errors
    def release_bucket(self, bucket_name, **kwargs):
        raise BadRequest('Bucket release not implemented for redis')

    @catch_service_errors
    @catch_io_errors
    def set_bucket_owner(self, account_id, bucket_name, **kwargs):
        raise BadRequest('Set bucket owner not implemented for redis')

    @catch_service_errors
    @catch_io_errors
    def get_bucket_owner(self, bucket_name, **kwargs):
        raise BadRequest('Get bucket owner not implemented for redis')

    @catch_service_errors
    @catch_io_errors
    def info_metrics(self, output_type, **kwargs):
        raise BadRequest('Metrics not implemented for redis')
