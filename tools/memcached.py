# Copyright (C) 2024 OVH SAS
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

"""
Why our own memcache client?
By Michael Barton

python-memcached doesn't use consistent hashing, so adding or
removing a memcache server from the pool invalidates a huge
percentage of cached items.

If you keep a pool of python-memcached client objects, each client
object has its own connection to every memcached server, only one of
which is ever in use.  So you wind up with n * m open sockets and
almost all of them idle. This client effectively has a pool for each
server, so the number of backend connections is hopefully greatly
reduced.

python-memcache uses pickle to store things, and there was already a
huge stink about Swift using pickles in memcache
(http://osvdb.org/show/osvdb/86581).  That seemed sort of unfair,
since nova and keystone and everyone else use pickles for memcache
too, but it's hidden behind a "standard" library. But changing would
be a security regression at this point.

Also, pylibmc wouldn't work for us because it needs to use python
sockets in order to play nice with eventlet.

Lucid comes with memcached: v1.4.2.  Protocol documentation for that
version is at:

http://github.com/memcached/memcached/blob/1.4.2/doc/protocol.txt
"""

import hashlib
import re

import six
import six.moves.cPickle as pickle
import json
import logging
import time
from bisect import bisect

from eventlet.green import socket
from eventlet.pools import Pool
from eventlet import Timeout
from six.moves import range

DEFAULT_MEMCACHED_PORT = 11211

CONN_TIMEOUT = 0.3
POOL_TIMEOUT = 1.0  # WAG
IO_TIMEOUT = 2.0
PICKLE_FLAG = 1
JSON_FLAG = 2
NODE_WEIGHT = 50
PICKLE_PROTOCOL = 2
TRY_COUNT = 3

# if ERROR_LIMIT_COUNT errors occur in ERROR_LIMIT_TIME seconds, the server
# will be considered failed for ERROR_LIMIT_DURATION seconds.
ERROR_LIMIT_COUNT = 10
ERROR_LIMIT_TIME = ERROR_LIMIT_DURATION = 60
DEFAULT_ITEM_SIZE_WARNING_THRESHOLD = -1


# Functions copied from swift/common/utils.py

# Used by the parse_socket_string() function to validate IPv6 addresses
IPV6_RE = re.compile(r"^\[(?P<address>.*)\](:(?P<port>[0-9]+))?$")


try:
    _test_md5 = hashlib.md5(usedforsecurity=False)  # nosec

    def md5(string=b"", usedforsecurity=True):
        """Return an md5 hashlib object using usedforsecurity parameter

        For python distributions that support the usedforsecurity keyword
        parameter, this passes the parameter through as expected.
        See https://bugs.python.org/issue9216
        """
        return hashlib.md5(string, usedforsecurity=usedforsecurity)  # nosec

except TypeError:

    def md5(string=b"", usedforsecurity=True):
        """Return an md5 hashlib object without usedforsecurity parameter

        For python distributions that do not yet support this keyword
        parameter, we drop the parameter
        """
        return hashlib.md5(string)  # nosec


def human_readable(value):
    """
    Returns the number in a human readable format; for example 1048576 = "1Mi".
    """
    value = float(value)
    index = -1
    suffixes = "KMGTPEZY"
    while value >= 1024 and index + 1 < len(suffixes):
        index += 1
        value = round(value / 1024)
    if index == -1:
        return "%d" % value
    return "%d%si" % (round(value), suffixes[index])


def parse_socket_string(socket_string, default_port):
    """
    Given a string representing a socket, returns a tuple of (host, port).
    Valid strings are DNS names, IPv4 addresses, or IPv6 addresses, with an
    optional port. If an IPv6 address is specified it **must** be enclosed in
    [], like *[::1]* or *[::1]:11211*. This follows the accepted prescription
    for `IPv6 host literals`_.

    Examples::

        server.org
        server.org:1337
        127.0.0.1:1337
        [::1]:1337
        [::1]

    .. _IPv6 host literals: https://tools.ietf.org/html/rfc3986#section-3.2.2
    """
    port = default_port
    # IPv6 addresses must be between '[]'
    if socket_string.startswith("["):
        match = IPV6_RE.match(socket_string)
        if not match:
            raise ValueError("Invalid IPv6 address: %s" % socket_string)
        host = match.group("address")
        port = match.group("port") or port
    else:
        if ":" in socket_string:
            tokens = socket_string.split(":")
            if len(tokens) > 2:
                raise ValueError("IPv6 addresses must be between '[]'")
            host, port = tokens
        else:
            host = socket_string
    return (host, port)


def md5hash(key):
    if not isinstance(key, bytes):
        if six.PY2:
            key = key.encode("utf-8")
        else:
            key = key.encode("utf-8", errors="surrogateescape")
    return md5(key, usedforsecurity=False).hexdigest().encode("ascii")


def sanitize_timeout(timeout):
    """
    Sanitize a timeout value to use an absolute expiration time if the delta
    is greater than 30 days (in seconds). Note that the memcached server
    translates negative values to mean a delta of 30 days in seconds (and 1
    additional second), client beware.
    """
    if timeout > (30 * 24 * 60 * 60):
        timeout += time.time()
    return int(timeout)


def set_msg(key, flags, timeout, value):
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")
    if not isinstance(value, bytes):
        raise TypeError("value must be bytes")
    return b" ".join(
        [
            b"set",
            key,
            str(flags).encode("ascii"),
            str(timeout).encode("ascii"),
            str(len(value)).encode("ascii"),
        ]
    ) + (b"\r\n" + value + b"\r\n")


def add_msg(key, timeout, value):
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")
    if not isinstance(value, bytes):
        raise TypeError("value must be bytes")
    return b" ".join(
        [
            b"add",
            key,
            b"0",
            str(timeout).encode("ascii"),
            str(len(value)).encode("ascii"),
        ]
    ) + (b"\r\n" + value + b"\r\n")


def incr_msg(key, delta):
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")
    if not isinstance(delta, bytes):
        raise TypeError("delta must be bytes")
    return b" ".join([b"incr", key, delta]) + b"\r\n"


def decr_msg(key, delta):
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")
    if not isinstance(delta, bytes):
        raise TypeError("delta must be bytes")
    return b" ".join([b"decr", key, delta]) + b"\r\n"


class MemcacheConnectionError(Exception):
    pass


class MemcachePoolTimeout(Timeout):
    pass


class MemcacheConnPool(Pool):
    """
    Connection pool for Memcache Connections

    The *server* parameter can be a hostname, an IPv4 address, or an IPv6
    address with an optional port. See
    :func:`swift.common.utils.parse_socket_string` for details.
    """

    def __init__(self, server, size, connect_timeout, tls_context=None):
        Pool.__init__(self, max_size=size)
        self.host, self.port = parse_socket_string(server, DEFAULT_MEMCACHED_PORT)
        self._connect_timeout = connect_timeout
        self._tls_context = tls_context

    def create(self):
        addrs = socket.getaddrinfo(
            self.host, self.port, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
        family, socktype, proto, canonname, sockaddr = addrs[0]
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            with Timeout(self._connect_timeout):
                sock.connect(sockaddr)
            if self._tls_context:
                sock = self._tls_context.wrap_socket(sock, server_hostname=self.host)
        except (Exception, Timeout):
            sock.close()
            raise
        return (sock.makefile("rwb"), sock)

    def get(self):
        fp, sock = super(MemcacheConnPool, self).get()
        try:
            if fp is None:
                # An error happened previously, so we need a new connection
                fp, sock = self.create()
            return fp, sock
        except MemcachePoolTimeout:
            # This is the only place that knows an item was successfully taken
            # from the pool, so it has to be responsible for repopulating it.
            # Any other errors should get handled in _get_conns(); see the
            # comment about timeouts during create() there.
            self.put((None, None))
            raise


class MemcacheRing(object):
    """
    Simple, consistent-hashed memcache client.
    """

    def __init__(
        self,
        servers,
        connect_timeout=CONN_TIMEOUT,
        io_timeout=IO_TIMEOUT,
        pool_timeout=POOL_TIMEOUT,
        tries=TRY_COUNT,
        allow_pickle=False,
        allow_unpickle=False,
        max_conns=2,
        tls_context=None,
        logger=None,
        error_limit_count=ERROR_LIMIT_COUNT,
        error_limit_time=ERROR_LIMIT_TIME,
        error_limit_duration=ERROR_LIMIT_DURATION,
        item_size_warning_threshold=DEFAULT_ITEM_SIZE_WARNING_THRESHOLD,
    ):
        self._ring = {}
        self._errors = dict(((serv, []) for serv in servers))
        self._error_limited = dict(((serv, 0) for serv in servers))
        self._error_limit_count = error_limit_count
        self._error_limit_time = error_limit_time
        self._error_limit_duration = error_limit_duration
        for server in sorted(servers):
            for i in range(NODE_WEIGHT):
                self._ring[md5hash("%s-%s" % (server, i))] = server
        self._tries = tries if tries <= len(servers) else len(servers)
        self._sorted = sorted(self._ring)
        self._client_cache = dict(
            (
                (
                    server,
                    MemcacheConnPool(
                        server, max_conns, connect_timeout, tls_context=tls_context
                    ),
                )
                for server in servers
            )
        )
        self._connect_timeout = connect_timeout
        self._io_timeout = io_timeout
        self._pool_timeout = pool_timeout
        self._allow_pickle = allow_pickle
        self._allow_unpickle = allow_unpickle or allow_pickle
        if logger is None:
            self.logger = logging.getLogger()
        else:
            self.logger = logger
        self.item_size_warning_threshold = item_size_warning_threshold

    def _exception_occurred(
        self, server, e, action="talking", sock=None, fp=None, got_connection=True
    ):
        if isinstance(e, Timeout):
            self.logger.error(
                "Timeout %(action)s to memcached: %(server)s",
                {"action": action, "server": server},
            )
        elif isinstance(e, (socket.error, MemcacheConnectionError)):
            self.logger.error(
                "Error %(action)s to memcached: %(server)s: %(err)s",
                {"action": action, "server": server, "err": e},
            )
        else:
            self.logger.exception(
                "Error %(action)s to memcached: %(server)s",
                {"action": action, "server": server},
            )
        try:
            if fp:
                fp.close()
                del fp
        except Exception:
            pass
        try:
            if sock:
                sock.close()
                del sock
        except Exception:
            pass
        if got_connection:
            # We need to return something to the pool
            # A new connection will be created the next time it is retrieved
            self._return_conn(server, None, None)

        if self._error_limit_time <= 0 or self._error_limit_duration <= 0:
            return

        now = time.time()
        self._errors[server].append(now)
        if len(self._errors[server]) > self._error_limit_count:
            self._errors[server] = [
                err
                for err in self._errors[server]
                if err > now - self._error_limit_time
            ]
            if len(self._errors[server]) > self._error_limit_count:
                self._error_limited[server] = now + self._error_limit_duration
                self.logger.error("Error limiting server %s", server)

    def _get_conns(self, key):
        """
        Retrieves a server conn from the pool, or connects a new one.
        Chooses the server based on a consistent hash of "key".

        :return: generator to serve memcached connection
        """
        pos = bisect(self._sorted, key)
        served = []
        while len(served) < self._tries:
            pos = (pos + 1) % len(self._sorted)
            server = self._ring[self._sorted[pos]]
            if server in served:
                continue
            served.append(server)
            if self._error_limited[server] > time.time():
                continue
            sock = None
            try:
                with MemcachePoolTimeout(self._pool_timeout):
                    fp, sock = self._client_cache[server].get()
                yield server, fp, sock
            except MemcachePoolTimeout as e:
                self._exception_occurred(
                    server, e, action="getting a connection", got_connection=False
                )
            except (Exception, Timeout) as e:
                # Typically a Timeout exception caught here is the one raised
                # by the create() method of this server's MemcacheConnPool
                # object.
                self._exception_occurred(server, e, action="connecting", sock=sock)

    def _return_conn(self, server, fp, sock):
        """Returns a server connection to the pool."""
        self._client_cache[server].put((fp, sock))

    def set(
        self, key, value, serialize=True, time=0, min_compress_len=0, server_key=None
    ):
        """
        Set a key/value pair in memcache

        :param key: key
        :param value: value
        :param serialize: if True, value is serialized with JSON before sending
                          to memcache, or with pickle if configured to use
                          pickle instead of JSON (to avoid cache poisoning)
        :param time: the time to live
        :param min_compress_len: minimum compress length, this parameter was
                                 added to keep the signature compatible with
                                 python-memcached interface. This
                                 implementation ignores it.
        """
        key = md5hash(key)
        server_key = md5hash(server_key) if server_key else key
        timeout = sanitize_timeout(time)
        flags = 0
        if serialize and self._allow_pickle:
            value = pickle.dumps(value, PICKLE_PROTOCOL)
            flags |= PICKLE_FLAG
        elif serialize:
            if isinstance(value, bytes):
                value = value.decode("utf8")
            value = json.dumps(value, separators=(",", ":")).encode("ascii")
            flags |= JSON_FLAG
        elif not isinstance(value, bytes):
            value = str(value).encode("utf-8")
        if 0 <= self.item_size_warning_threshold <= len(value):
            self.logger.warning(
                "Item size larger than warning threshold: " "%d (%s) >= %d (%s)",
                len(value),
                human_readable(len(value)),
                self.item_size_warning_threshold,
                human_readable(self.item_size_warning_threshold),
            )
        msg = set_msg(key, flags, timeout, value)
        for server, fp, sock in self._get_conns(server_key):
            try:
                with Timeout(self._io_timeout):
                    sock.sendall(msg)
                    # Wait for the set to complete
                    line = fp.readline().strip()
                    if line != b"STORED":
                        if not six.PY2:
                            line = line.decode("ascii")
                        self.logger.error(
                            "Error setting value in memcached: " "%(server)s: %(line)s",
                            {"server": server, "line": line},
                        )
                    self._return_conn(server, fp, sock)
                    return
            except (Exception, Timeout) as e:
                self._exception_occurred(server, e, sock=sock, fp=fp)

    def get(self, key, server_key=None):
        """
        Gets the object specified by key.  It will also unserialize the object
        before returning if it is serialized in memcache with JSON, or if it
        is pickled and unpickling is allowed.

        :param key: key
        :returns: value of the key in memcache
        """
        key = md5hash(key)
        server_key = md5hash(server_key) if server_key else key
        value = None
        for server, fp, sock in self._get_conns(server_key):
            try:
                with Timeout(self._io_timeout):
                    sock.sendall(b"get " + key + b"\r\n")
                    line = fp.readline().strip().split()
                    while True:
                        if not line:
                            raise MemcacheConnectionError("incomplete read")
                        if line[0].upper() == b"END":
                            break
                        if line[0].upper() == b"VALUE" and line[1] == key:
                            size = int(line[3])
                            value = fp.read(size)
                            if int(line[2]) & PICKLE_FLAG:
                                if self._allow_unpickle:
                                    value = pickle.loads(value)
                                else:
                                    value = None
                            elif int(line[2]) & JSON_FLAG:
                                value = json.loads(value)
                            fp.readline()
                        line = fp.readline().strip().split()
                    self._return_conn(server, fp, sock)
                    return value
            except (Exception, Timeout) as e:
                self._exception_occurred(server, e, sock=sock, fp=fp)

    def add(self, key, value=0, time=0, server_key=None):
        """
        If the key does not exist, it's added with the value.
        Note: The data memcached stores as the result of incr/decr is
        an unsigned int. A value below 0 is stored as 0.

        :param key: key
        :param value: value to associate with the key (will be cast to an int)
        :param time: the time to live
        :returns: True if the key was added
        :raises MemcacheConnectionError:
        """
        key = md5hash(key)
        server_key = md5hash(server_key) if server_key else key
        timeout = sanitize_timeout(time)
        value = int(value)
        if value < 0:
            value = 0
        value = str(value).encode("ascii")
        msg = add_msg(key, timeout, value)
        for server, fp, sock in self._get_conns(server_key):
            try:
                with Timeout(self._io_timeout):
                    sock.sendall(msg)
                    line = fp.readline().strip().split()
                    self._return_conn(server, fp, sock)
                    return line[0].upper() != b"NOT_STORED"
            except (Exception, Timeout) as e:
                self._exception_occurred(server, e, sock=sock, fp=fp)
        raise MemcacheConnectionError("No Memcached connections succeeded.")

    def incr(self, key, delta=1, time=0, server_key=None):
        """
        Increments a key which has a numeric value by delta.
        If the key can't be found, it's added as delta or 0 if delta < 0.
        If passed a negative number, will use memcached's decr. Returns
        the int stored in memcached
        Note: The data memcached stores as the result of incr/decr is
        an unsigned int.  decr's that result in a number below 0 are
        stored as 0.

        :param key: key
        :param delta: amount to add to the value of key (or set as the value
                      if the key is not found) will be cast to an int
        :param time: the time to live
        :returns: result of incrementing
        :raises MemcacheConnectionError:
        """
        key = md5hash(key)
        server_key = md5hash(server_key) if server_key else key
        timeout = sanitize_timeout(time)
        decr = delta < 0
        delta = str(abs(int(delta))).encode("ascii")
        if decr:
            msg_func = decr_msg
            add_val = b"0"
        else:
            msg_func = incr_msg
            add_val = delta
        msg = msg_func(key, delta)
        for server, fp, sock in self._get_conns(server_key):
            try:
                with Timeout(self._io_timeout):
                    sock.sendall(msg)
                    line = fp.readline().strip().split()
                    if not line:
                        raise MemcacheConnectionError("incomplete read")
                    if line[0].upper() == b"NOT_FOUND":
                        sock.sendall(add_msg(key, timeout, add_val))
                        line = fp.readline().strip().split()
                        if line[0].upper() == b"NOT_STORED":
                            sock.sendall(msg)
                            line = fp.readline().strip().split()
                            if not line:
                                raise MemcacheConnectionError("incomplete read")
                            ret = int(line[0].strip())
                        else:
                            ret = int(add_val)
                    else:
                        ret = int(line[0].strip())
                    self._return_conn(server, fp, sock)
                    return ret
            except (Exception, Timeout) as e:
                self._exception_occurred(server, e, sock=sock, fp=fp)
        raise MemcacheConnectionError("No Memcached connections succeeded.")

    def decr(self, key, delta=1, time=0, server_key=None):
        """
        Decrements a key which has a numeric value by delta. Calls incr with
        -delta.

        :param key: key
        :param delta: amount to subtract to the value of key (or set the
                      value to 0 if the key is not found) will be cast to
                      an int
        :param time: the time to live
        :returns: result of decrementing
        :raises MemcacheConnectionError:
        """
        return self.incr(key, delta=-delta, time=time, server_key=server_key)

    def delete(self, key, server_key=None):
        """
        Deletes a key/value pair from memcache.

        :param key: key to be deleted
        :param server_key: key to use in determining which server in the ring
                            is used
        """
        key = md5hash(key)
        server_key = md5hash(server_key) if server_key else key
        for server, fp, sock in self._get_conns(server_key):
            try:
                with Timeout(self._io_timeout):
                    sock.sendall(b"delete " + key + b"\r\n")
                    # Wait for the delete to complete
                    fp.readline()
                    self._return_conn(server, fp, sock)
                    return
            except (Exception, Timeout) as e:
                self._exception_occurred(server, e, sock=sock, fp=fp)

    def set_multi(
        self, mapping, server_key, serialize=True, time=0, min_compress_len=0
    ):
        """
        Sets multiple key/value pairs in memcache.

        :param mapping: dictionary of keys and values to be set in memcache
        :param server_key: key to use in determining which server in the ring
                            is used
        :param serialize: if True, value is serialized with JSON before sending
                          to memcache, or with pickle if configured to use
                          pickle instead of JSON (to avoid cache poisoning)
        :param time: the time to live
        :min_compress_len: minimum compress length, this parameter was added
                           to keep the signature compatible with
                           python-memcached interface. This implementation
                           ignores it
        """
        server_key = md5hash(server_key)
        timeout = sanitize_timeout(time)
        msg = []
        for key, value in mapping.items():
            key = md5hash(key)
            flags = 0
            if serialize and self._allow_pickle:
                value = pickle.dumps(value, PICKLE_PROTOCOL)
                flags |= PICKLE_FLAG
            elif serialize:
                if isinstance(value, bytes):
                    value = value.decode("utf8")
                value = json.dumps(value).encode("ascii")
                flags |= JSON_FLAG
            msg.append(set_msg(key, flags, timeout, value))
        for server, fp, sock in self._get_conns(server_key):
            try:
                with Timeout(self._io_timeout):
                    sock.sendall(b"".join(msg))
                    # Wait for the set to complete
                    for line in range(len(mapping)):
                        fp.readline()
                    self._return_conn(server, fp, sock)
                    return
            except (Exception, Timeout) as e:
                self._exception_occurred(server, e, sock=sock, fp=fp)

    def get_multi(self, keys, server_key):
        """
        Gets multiple values from memcache for the given keys.

        :param keys: keys for values to be retrieved from memcache
        :param server_key: key to use in determining which server in the ring
                           is used
        :returns: list of values
        """
        server_key = md5hash(server_key)
        keys = [md5hash(key) for key in keys]
        for server, fp, sock in self._get_conns(server_key):
            try:
                with Timeout(self._io_timeout):
                    sock.sendall(b"get " + b" ".join(keys) + b"\r\n")
                    line = fp.readline().strip().split()
                    responses = {}
                    while True:
                        if not line:
                            raise MemcacheConnectionError("incomplete read")
                        if line[0].upper() == b"END":
                            break
                        if line[0].upper() == b"VALUE":
                            size = int(line[3])
                            value = fp.read(size)
                            if int(line[2]) & PICKLE_FLAG:
                                if self._allow_unpickle:
                                    value = pickle.loads(value)
                                else:
                                    value = None
                            elif int(line[2]) & JSON_FLAG:
                                value = json.loads(value)
                            responses[line[1]] = value
                            fp.readline()
                        line = fp.readline().strip().split()
                    values = []
                    for key in keys:
                        if key in responses:
                            values.append(responses[key])
                        else:
                            values.append(None)
                    self._return_conn(server, fp, sock)
                    return values
            except (Exception, Timeout) as e:
                self._exception_occurred(server, e, sock=sock, fp=fp)

    def add_multi(self, mapping, server_key, time=0):
        """
        If the keys does not exist, it's added with the values.
        Note: The data memcached stores as the result of incr/decr is
        an unsigned int. A value below 0 is stored as 0.

        :param mapping: keys with the values to associate
                        (will be cast to an int)
        :param time: the time to live
        :returns: dict indicating whether the key has been added
        :raises MemcacheConnectionError:
        """
        server_key = md5hash(server_key)
        timeout = sanitize_timeout(time)
        keys_to_add = []
        for real_key, value in mapping.items():
            key = md5hash(real_key)
            value = int(value)
            if value < 0:
                value = 0
            value = str(value).encode("ascii")
            keys_to_add.append((real_key, add_msg(key, timeout, value)))
        added = {}
        for server, fp, sock in self._get_conns(server_key):
            try:
                with Timeout(self._io_timeout):
                    sock.sendall(b"".join(key_info[1] for key_info in keys_to_add))
                    keys_to_add_copy = keys_to_add.copy()
                    for key_info in keys_to_add_copy:
                        line = fp.readline().strip().split()
                        added[key_info[0]] = line[0].upper() != b"NOT_STORED"
                        keys_to_add.remove(key_info)
                    self._return_conn(server, fp, sock)
                    return added
            except (Exception, Timeout) as e:
                self._exception_occurred(server, e, sock=sock, fp=fp)
        raise MemcacheConnectionError("No Memcached connections succeeded.")

    def incr_multi(self, mapping, server_key, time=0):
        server_key = md5hash(server_key)
        timeout = sanitize_timeout(time)
        keys_to_incr = []
        for real_key, delta in mapping.items():
            key = md5hash(real_key)
            decr = delta < 0
            delta = str(abs(int(delta))).encode("ascii")
            if decr:
                msg_func = decr_msg
                add_val = b"0"
            else:
                msg_func = incr_msg
                add_val = delta
            keys_to_incr.append((real_key, msg_func(key, delta), key, add_val))
        incremented = {}
        for server, fp, sock in self._get_conns(server_key):
            try:
                with Timeout(self._io_timeout):
                    sock.sendall(b"".join(key_info[1] for key_info in keys_to_incr))
                    keys_to_incr_copy = keys_to_incr.copy()
                    for key_info in keys_to_incr_copy:
                        line = fp.readline().strip().split()
                        if not line:
                            raise MemcacheConnectionError("incomplete read")
                        if line[0].upper() == b"NOT_FOUND":
                            continue  # Key doesn't exist
                        incremented[key_info[0]] = int(line[0].strip())
                        keys_to_incr.remove(key_info)
                    if keys_to_incr:
                        # Some keys do not exist yet, add keys
                        # that have not been incremented
                        sock.sendall(
                            b"".join(
                                add_msg(key, timeout, add_val)
                                for _, _, key, add_val in keys_to_incr
                            )
                        )
                        keys_to_incr_copy = keys_to_incr.copy()
                        for key_info in keys_to_incr_copy:
                            line = fp.readline().strip().split()
                            if line[0].upper() == b"NOT_STORED":
                                continue  # Key already exists
                            incremented[key_info[0]] = int(key_info[-1])
                            keys_to_incr.remove(key_info)
                    if keys_to_incr:
                        # Some keys (among the non-incremented keys) were
                        # created by another connection, redo the increment
                        sock.sendall(b"".join(key_info[1] for key_info in keys_to_incr))
                        keys_to_incr_copy = keys_to_incr.copy()
                        for key_info in keys_to_incr_copy:
                            line = fp.readline().strip().split()
                            if not line:
                                raise MemcacheConnectionError("incomplete read")
                            incremented[key_info[0]] = int(line[0].strip())
                            keys_to_incr.remove(key_info)
                    self._return_conn(server, fp, sock)
                    return incremented
            except (Exception, Timeout) as e:
                self._exception_occurred(server, e, sock=sock, fp=fp)
        raise MemcacheConnectionError("No Memcached connections succeeded.")


