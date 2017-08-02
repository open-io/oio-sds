# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
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

from time import time, sleep
import uuid
import math

import redis
import redis.sentinel


class RedisConn(object):

    def __init__(self, conf, connection=None, **kwargs):
        self.conf = conf
        self._conn = connection
        self._sentinel = None
        self._sentinel_hosts = conf.get('sentinel_hosts', None)
        self._sentinel_name = conf.get('sentinel_master_name', 'oio')

        # Do not use Sentinel if a connection object is provided
        if self._sentinel_hosts and not self._conn:
            self._sentinel = redis.sentinel.Sentinel(
                    [(h, int(p)) for h, p, in (hp.split(':', 2)
                     for hp in self._sentinel_hosts.split(','))])

    def register_script(self, script):
        """Register a LUA script and return Script object."""
        return self.conn.register_script(script)

    @property
    def conn(self):
        """Retrieve Redis connection (normal or sentinel)"""
        if self._sentinel:
            return self._sentinel.master_for(self._sentinel_name)
        if not self._conn:
            redis_host = self.conf.get('redis_host', '127.0.0.1')
            redis_port = int(self.conf.get('redis_port', '6379'))
            self._conn = redis.StrictRedis(host=redis_host, port=redis_port)
        return self._conn

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
