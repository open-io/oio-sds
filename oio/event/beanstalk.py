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


import os
import sys
from six import iteritems
import yaml
from eventlet.green import socket
from eventlet.queue import Empty, LifoQueue
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse
from io import BytesIO


SYM_CRLF = '\r\n'

DEFAULT_PRIORITY = 2 ** 31

DEFAULT_TTR = 120

SERVER_CLOSED_CONNECTION_ERROR = "Connection closed by server."


class BeanstalkError(Exception):
    pass


class ConnectionError(BeanstalkError):
    pass


class TimeoutError(BeanstalkError):
    pass


class ResponseError(BeanstalkError):
    pass


class InvalidResponse(BeanstalkError):
    pass


class Reader(object):
    def __init__(self, socket, socket_read_size):
        self._sock = socket
        self.socket_read_size = socket_read_size
        self._buffer = BytesIO()
        self.bytes_written = 0
        self.bytes_read = 0

    @property
    def length(self):
        return self.bytes_written - self.bytes_read

    def _read_from_socket(self, length=None):
        socket_read_size = self.socket_read_size
        buf = self._buffer
        buf.seek(self.bytes_written)
        marker = 0

        try:
            while True:
                data = self._sock.recv(socket_read_size)
                if isinstance(data, bytes) and len(data) == 0:
                    raise socket.error(SERVER_CLOSED_CONNECTION_ERROR)
                buf.write(data)
                data_length = len(data)
                self.bytes_written += data_length
                marker += data_length

                if length is not None and length > marker:
                    continue
                break
        except socket.timeout:
            raise TimeoutError("Timeout reading from socket")
        except socket.error:
            e = sys.exc_info()[1]
            raise ConnectionError("Error while reading from socket: %s" %
                                  (e.args,))

    def read(self, length):
        length = length + 2
        if length > self.length:
            self._read_from_socket(length - self.length)

        self._buffer.seek(self.bytes_read)
        data = self._buffer.read(length)
        self.bytes_read += len(data)

        if self.bytes_read == self.bytes_written:
            self.purge()

        return data[:-2]

    def readline(self):
        buf = self._buffer
        buf.seek(self.bytes_read)
        data = buf.readline()
        while not data.endswith(SYM_CRLF):
            self._read_from_socket()
            buf.seek(self.bytes_read)
            data = buf.readline()

        self.bytes_read += len(data)

        if self.bytes_read == self.bytes_written:
            self.purge()

        return data[:-2]

    def purge(self):
        self._buffer.seek(0)
        self._buffer.truncate()
        self.bytes_written = 0
        self.bytes_read = 0

    def close(self):
        try:
            self.purge()
            self._buffer.close()
        except Exception:
            pass

        self._buffer = None
        self._sock = None


class BaseParser(object):
    def __init__(self, socket_read_size):
        self.socket_read_size = socket_read_size
        self._sock = None
        self._buffer = None

    def on_connect(self, connection):
        self._sock = connection._sock
        self._buffer = Reader(self._sock, self.socket_read_size)
        self.encoding = connection.encoding

    def on_disconnect(self):
        if self._sock is not None:
            self._sock.close()
            self._sock = None
        if self._buffer is not None:
            self._buffer.close()
            self._buffer = None
        self.encoding = None

    def can_read(self):
        return self._buffer and bool(self._buffer_length)

    def read_response(self):
        response = self._buffer.readline()
        if not response:
            raise ConnectionError(SERVER_CLOSED_CONNECTION_ERROR)
        response = response.split()
        return response[0], response[1:]

    def read(self, size):
        response = self._buffer.read(size)
        if not response:
            raise ConnectionError(SERVER_CLOSED_CONNECTION_ERROR)
        return response


class Connection(object):
    @classmethod
    def from_url(cls, url, **kwargs):
        url = urlparse(url)
        url_options = {}
        url_options.update({
            'host': url.hostname,
            'port': int(url.port or 11300)})
        kwargs.update(url_options)
        return cls(**kwargs)

    def __init__(self, host='localhost', port=11300, use_tubes=None,
                 watch_tubes=None, socket_timeout=None,
                 socket_connect_timeout=None, socket_keepalive=False,
                 socket_keepalive_options=None, encoding='utf-8',
                 socket_read_size=65536):
        self.pid = os.getpid()
        self.host = host
        self.port = port
        self.encoding = encoding
        self.socket_timeout = socket_timeout
        self.socket_connect_timeout = socket_connect_timeout
        self.socket_keepalive = socket_keepalive
        self.socket_keepalive_options = socket_keepalive_options
        self._sock = None
        self._parser = BaseParser(socket_read_size=socket_read_size)
        self.use_tubes = use_tubes or []
        self.watch_tubes = watch_tubes or []

    def use(self, tube):
        self.use_tubes.append(tube)

    def watch(self, tube):
        self.watch_tubes.append(tube)

    def connect(self):
        if self._sock:
            return

        try:
            sock = self._connect()
        except socket.timeout:
            raise TimeoutError("Timeout connecting to server")
        except socket.error:
            e = sys.exc_info()[1]
            raise ConnectionError(self._error_message(e))

        self._sock = sock
        try:
            self.on_connect()
        except BeanstalkError:
            self.disconnect()
            raise

    def _connect(self):
        err = None
        for res in socket.getaddrinfo(self.host, self.port,
                                      socktype=socket.SOCK_STREAM,
                                      flags=socket.AI_NUMERICHOST):
            family, socktype, proto, canonname, socket_address = res
            sock = None
            try:
                sock = socket.socket(family, socktype, proto)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

                if self.socket_keepalive:
                    sock.setsockopt(
                        socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    for k, v in iteritems(self.socket_keepalive_options):
                        sock.setsockopt(socket.SOL_TCP, k, v)

                sock.settimeout(self.socket_connect_timeout)

                sock.connect(socket_address)

                sock.settimeout(self.socket_timeout)
                return sock

            except socket.error as _:
                err = _
                if sock is not None:
                    sock.close()

        if err is not None:
            raise err
        raise socket.error("socket.getaddrinfo returned empty list")

    def _error_message(self, exception):
        if len(exception.args) == 1:
            return "Error connecting to %s:%s. %s." % \
                (self.host, self.port, exception.args[0])
        else:
            return "Error %s connecting to %s:%s. %s." % \
                (exception.args[0], self.host, self.port, exception.args[1])

    def on_connect(self):
        self._parser.on_connect(self)
        for use_tube in self.use_tubes:
            self._use(use_tube)
        for watch_tube in self.watch_tubes:
            self._watch(watch_tube)

    def _use(self, tube):
        self.send_command('use', tube)
        self.read_response()

    def _watch(self, tube):
        self.send_command('watch', tube)
        self.read_response()

    def disconnect(self):
        self._parser.on_disconnect()
        if self._sock is None:
            return
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
            self._sock.close()
        except socket.error:
            pass
        self._sock = None

    def pack_command(self, command, body, *args):
        output = []
        # TODO handle encoding
        output.append(command)
        for arg in args:
            output.append(' ' + str(arg))
        if body is not None:
            output.append(' ' + str(len(body)))
            output.append(SYM_CRLF)
            output.append(body)
        output.append(SYM_CRLF)
        return ''.join(output)

    def send_command(self, command, *args, **kwargs):
        command = self.pack_command(command, kwargs.get('body'), *args)
        if not self._sock:
            self.connect()
        try:
            if isinstance(command, str):
                command = [command]
            for item in command:
                self._sock.sendall(item)
        except socket.timeout:
            self.disconnect()
            raise TimeoutError("Timeout writing to socket")
        except socket.error:
            e = sys.exc_info()[1]
            self.disconnect()
            if len(e.args) == 1:
                errno, errmsg = 'UNKNOWN', e.args[0]
            else:
                errno = e.args[0]
                errmsg = e.args[1]
            raise ConnectionError("Error %s while writing to socket. %s." %
                                  (errno, errmsg))
        except Exception:
            self.disconnect()
            raise

    def read_response(self):
        try:
            response = self._parser.read_response()
        except Exception:
            self.disconnect()
            raise
        if isinstance(response, ResponseError):
            raise response
        return response

    def read_body(self, size):
        try:
            response = self._parser.read(size)
        except Exception:
            self.disconnect()
            raise
        if isinstance(response, ResponseError):
            raise response
        return response


def dict_merge(*dicts):
    merged = {}
    for d in dicts:
        merged.update(d)
    return merged


def parse_yaml(connection, response, **kwargs):
    (status, results) = response
    size = results[0]
    body = connection.read_body(int(size))
    if size > 0 and not body:
        raise ResponseError()
    return yaml.load(body)


def parse_body(connection, response, **kwargs):
    (status, results) = response
    job_id = results[0]
    job_size = results[1]
    body = connection.read_body(int(job_size))
    if job_size > 0 and not body:
        raise ResponseError()
    return job_id, body


class Beanstalk(object):
    RESPONSE_CALLBACKS = dict_merge(
        {'reserve': parse_body,
         'stats-tube': parse_yaml}
    )
    EXPECTED_OK = dict_merge(
        {'reserve': ['RESERVED'],
         'delete': ['DELETED'],
         'release': ['RELEASED'],
         'bury': ['BURIED'],
         'put': ['INSERTED'],
         'use': ['USING'],
         'watch': ['WATCHING'],
         'stats-tube': ['OK'],
         'kick': ['KICKED'],
         'kick-job': ['KICKED']}

    )
    EXPECTED_ERR = dict_merge(
        {'reserve': ['DEADLINE_SOON', 'TIMED_OUT'],
         'delete': ['NOT_FOUND'],
         'release': ['BURIED', 'NOT_FOUND', 'OUT_OF_MEMORY'],
         'bury': ['NOT_FOUND', 'OUT_OF_MEMORY'],
         'stats-tube': ['NOT_FOUND'],
         'use': [],
         'watch': [],
         'put': ['JOB_TOO_BIG', 'BURIED', 'DRAINING', 'OUT_OF_MEMORY'],
         'kick': ['OUT_OF_MEMORY'],
         'kick-job': ['NOT_FOUND', 'OUT_OF_MEMORY']}
    )

    @classmethod
    def from_url(cls, url, **kwargs):
        connection = Connection.from_url(url, **kwargs)
        return cls(connection=connection)

    def __init__(self, host='localhost', port=11300, socket_timeout=None,
                 socket_connect_timeout=None, socket_keepalive=None,
                 retry_on_timeout=False, socket_keepalive_options=None,
                 max_connections=None, connection=None):
        if not connection:
            self.socket_timeout = socket_timeout
            kwargs = {
                'host': host,
                'port': port,
                'socket_connect_timeout': socket_connect_timeout,
                'socket_keepalive': socket_keepalive,
                'socket_keepalive_options': socket_keepalive_options,
                'socket_timeout': socket_timeout,
                'retry_on_timeout': retry_on_timeout,
                'max_connections': max_connections
            }

            connection = Connection(**kwargs)
        self.conn_queue = LifoQueue()
        self.conn_queue.put_nowait(connection)
        self._connection = connection
        self.response_callbacks = self.__class__.RESPONSE_CALLBACKS.copy()
        self.expected_ok = self.__class__.EXPECTED_OK.copy()
        self.expected_err = self.__class__.EXPECTED_ERR.copy()

    def _get_connection(self):
        try:
            connection = self.conn_queue.get(block=True, timeout=None)
        except Empty:
            raise ConnectionError("No connection available")
        return connection

    def _release_connection(self, connection):
        self.conn_queue.put_nowait(connection)

    def execute_command(self, *args, **kwargs):
        connection = self._get_connection()
        command_name = args[0]
        try:
            connection.send_command(*args, **kwargs)
            return self.parse_response(connection, command_name, **kwargs)
        except (ConnectionError, TimeoutError):
            connection.disconnect()
            raise
        finally:
            self._release_connection(connection)

    def parse_response(self, connection, command_name, **kwargs):
        response = connection.read_response()
        status, results = response
        if status in self.expected_ok[command_name]:
            if command_name in self.response_callbacks:
                return self.response_callbacks[command_name](
                        connection, response, **kwargs)
            return response
        elif status in self.expected_err[command_name]:
            raise ResponseError(command_name, status, results)
        else:
            raise InvalidResponse(command_name, status, results)

        return response

    def put(self, body, priority=DEFAULT_PRIORITY, delay=0, ttr=DEFAULT_TTR):
        assert isinstance(body, str), 'body must be str'
        job_id = self.execute_command('put', priority, delay, ttr, body=body)
        return job_id

    def use(self, tube):
        self._connection.use(tube)

    def watch(self, tube):
        self._connection.watch(tube)

    def reserve(self, timeout=None):
        if timeout is not None:
            return self.execute_command('reserve-with-timeout', timeout)
        else:
            return self.execute_command('reserve')

    def bury(self, job_id, priority=DEFAULT_PRIORITY):
        self.execute_command('bury', job_id, priority)

    def release(self, job_id, priority=DEFAULT_PRIORITY, delay=0):
        self.execute_command('release', job_id, priority, delay)

    def delete(self, job_id):
        self.execute_command('delete', job_id)

    def kick_job(self, job_id):
        """
        Variant of` kick` that operates with a single job.

        :param job_id: the job id to kick
        :type job_id: `str`
        """
        self.execute_command('kick-job', job_id)

    def kick(self, bound=1000):
        """
        Move jobs into the ready queue.
        If there are any buried jobs, it will only kick buried jobs.
        Otherwise it will kick delayed jobs.

        :param bound: upper bound on the number of jobs to kick
        :type bound: `int`
        """
        kicked = int(self.execute_command('kick', str(bound))[1][0])
        return kicked

    def stats_tube(self, tube):
        return self.execute_command('stats-tube', tube)

    def close(self):
        if self._connection:
            self._connection.disconnect()
