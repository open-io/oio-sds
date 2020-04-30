# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
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

from functools import wraps
from time import time, sleep
import uuid
import math
import importlib
from six import string_types

from oio.common.easy_value import true_value
from oio.common.exceptions import ServiceBusy


def catch_service_errors(func):
    """
    Catch errors attributable to the Redis service and raise ServiceBusy
    instead.

    :raises `ServiceBusy`: in case of a Redis service error
    """
    redis_exc_mod = importlib.import_module('redis.exceptions')
    error_types = (redis_exc_mod.ConnectionError,
                   redis_exc_mod.InvalidResponse,
                   redis_exc_mod.TimeoutError)

    @wraps(func)
    def catch_service_errors_wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        # Redis exception hierarchy has changed across versions, this is
        # why we catch several types here.
        except error_types as err:
            raise ServiceBusy(message=str(err))
    return catch_service_errors_wrapper


class RedisConnection(object):

    # Imported from redis-py, for compatibility with pre 2.10.6 versions.
    URL_QUERY_ARGUMENT_PARSERS = {
        'socket_timeout': float,
        'socket_connect_timeout': float,
        'socket_keepalive': true_value,
        'retry_on_timeout': true_value,
        'max_connections': int,
        'health_check_interval': int,
    }

    def __init__(self, host=None, sentinel_hosts=None,
                 sentinel_name=None, **kwargs):
        self.__redis_mod = importlib.import_module('redis')
        self.__redis_sentinel_mod = importlib.import_module('redis.sentinel')

        self._conn = None
        self._host = None
        self._port = None
        self._sentinel = None
        self._sentinel_hosts = None
        self._sentinel_name = None
        self._conn_kwargs = self._filter_conn_kwargs(kwargs)

        if host:
            self._host, self._port = host.rsplit(':', 1)
            self._port = int(self._port)
            return

        if not sentinel_name:
            raise ValueError("missing parameter 'sentinel_name'")

        if isinstance(sentinel_hosts, string_types):
            sentinel_hosts = sentinel_hosts.split(',')
        self._sentinel_hosts = [(h, int(p)) for h, p, in (hp.rsplit(':', 1)
                                for hp in sentinel_hosts)]
        self._sentinel_name = sentinel_name
        self._sentinel_conn_kwargs = self._filter_sentinel_conn_kwargs(kwargs)
        self._sentinel = self.__redis_sentinel_mod.Sentinel(
            self._sentinel_hosts,
            sentinel_kwargs=self._sentinel_conn_kwargs,
            **self._conn_kwargs)

    def _filter_conn_kwargs(self, conn_kwargs):
        """
        Keep only keyword arguments known by Redis classes, cast them to
        the appropriate type.
        """
        if conn_kwargs is None:
            return None
        if hasattr(self.__redis_mod.connection, 'URL_QUERY_ARGUMENT_PARSERS'):
            parsers = self.__redis_mod.connection.URL_QUERY_ARGUMENT_PARSERS
        else:
            parsers = self.URL_QUERY_ARGUMENT_PARSERS
        return {k: parsers[k](v)
                for k, v in conn_kwargs.items()
                if k in parsers}

    def _filter_sentinel_conn_kwargs(self, sentinel_conn_kwargs):
        if sentinel_conn_kwargs is None:
            return None
        return self._filter_conn_kwargs(
            {k[9:]: v for k, v in sentinel_conn_kwargs.items()
             if k.startswith('sentinel_')})

    @property
    def conn(self):
        """Retrieve Redis connection (normal or sentinel)"""
        if self._sentinel:
            return self._sentinel.master_for(self._sentinel_name)
        if not self._conn:
            self._conn = self.__redis_mod.StrictRedis(
                host=self._host, port=self._port,
                **self._conn_kwargs)
        return self._conn

    @property
    def conn_slave(self):
        """Retrieve Redis connection (normal or sentinel)"""
        if self._sentinel:
            return self._sentinel.slave_for(self._sentinel_name)
        return self.conn

    def register_script(self, script):
        """Register a LUA script and return Script object."""
        return self.conn.register_script(script)

    def acquire_lock_with_timeout(self, lockname, acquire_timeout=10,
                                  lock_timeout=10):
        """Acquire a lock :lockname:"""
        conn = self.conn
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

    def release_lock(self, lockname, identifier):
        """Release a previously acquired Lock"""
        conn = self.conn
        pipe = conn.pipeline(True)
        lockname = 'lock:' + lockname

        while True:
            try:
                pipe.watch(lockname)
                cur_id = pipe.get(lockname)
                if cur_id and cur_id.decode('utf-8') == identifier:
                    pipe.multi()
                    pipe.delete(lockname)
                    pipe.execute()
                    return True

                pipe.unwatch()
                break

            except self.__redis_mod.exceptions.WatchError:
                pass

        return False
