# Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
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


from oio.common.green import socket, Empty, LifoQueue, threading, time

import os
import sys
from six import BytesIO, iteritems
from six.moves.urllib_parse import urlparse
import yaml

from oio.common import exceptions


SYM_CRLF = '\r\n'
SYM_CRLF_BYTES = b'\r\n'

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
        # pylint: disable=no-member
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

        return data[:-2].decode('utf-8')

    def readline(self):
        buf = self._buffer
        buf.seek(self.bytes_read)
        data = buf.readline()
        while not data.endswith(SYM_CRLF_BYTES):
            self._read_from_socket()
            buf.seek(self.bytes_read)
            data = buf.readline()

        self.bytes_read += len(data)

        if self.bytes_read == self.bytes_written:
            self.purge()

        return data[:-2].decode('utf-8')

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
        # pylint: disable=no-member
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
    # pylint: disable=no-member
    @classmethod
    def from_url(cls, url, **kwargs):
        url = urlparse(url)
        if not url.netloc:
            raise ConnectionError('Invalid URL')
        url_options = {}
        url_options.update({
            'host': url.hostname,
            'port': int(url.port)})
        kwargs.update(url_options)
        return cls(**kwargs)

    def __init__(self, host=None, port=None, use_tubes=None,
                 watch_tubes=None, socket_timeout=None,
                 socket_connect_timeout=None, socket_keepalive=False,
                 socket_keepalive_options=None, encoding='utf-8',
                 socket_read_size=65536):
        self.pid = os.getpid()
        self.host = host
        self.port = int(port)
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
        if self._sock:
            self._use(tube)

    def watch(self, tube):
        self.watch_tubes.append(tube)
        if self._sock:
            self._watch(tube)

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
        for res in socket.getaddrinfo(self.host, self.port, 0,
                                      socket.SOCK_STREAM):
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
            raise err  # pylint: disable=raising-bad-type
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
        return ''.join(output).encode('utf-8')

    def send_command(self, command, *args, **kwargs):
        encoded = self.pack_command(command, kwargs.get('body'), *args)
        if not self._sock:
            self.connect()
        try:
            self._sock.sendall(encoded)
        except socket.timeout:
            self.disconnect()
            raise TimeoutError("Timeout writing to socket")
        except socket.error:
            err = sys.exc_info()[1]
            self.disconnect()
            if len(err.args) == 1:
                errno, errmsg = 'UNKNOWN', err.args[0]
            else:
                errno = err.args[0]
                errmsg = err.args[1]
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
    results = response[1]
    size = int(results[0])
    body = connection.read_body(size)
    if size > 0 and not body:
        raise ResponseError()
    return yaml.load(body, Loader=yaml.Loader)


def parse_body(connection, response, **kwargs):
    results = response[1]
    job_id = results[0]
    job_size = int(results[1])
    body = connection.read_body(job_size)
    if job_size > 0 and not body:
        raise ResponseError()
    return job_id, body


class Beanstalk(object):
    RESPONSE_CALLBACKS = dict_merge({
        'list-tubes': parse_yaml,
        'peek': parse_body,
        'peek-buried': parse_body,
        'peek-delayed': parse_body,
        'peek-ready': parse_body,
        'reserve': parse_body,
        'reserve-with-timeout': parse_body,
        'stats': parse_yaml,
        'stats-tube': parse_yaml
    })
    EXPECTED_OK = dict_merge({
        'bury': ['BURIED'],
        'delete': ['DELETED'],
        'list-tubes': ['OK'],
        'kick': ['KICKED'],
        'kick-job': ['KICKED'],
        'peek': ['FOUND'],
        'peek-buried': ['FOUND'],
        'peek-delayed': ['FOUND'],
        'peek-ready': ['FOUND'],
        'put': ['INSERTED'],
        'release': ['RELEASED'],
        'reserve': ['RESERVED'],
        'reserve-with-timeout': ['RESERVED'],
        'stats': ['OK'],
        'stats-tube': ['OK'],
        'use': ['USING'],
        'watch': ['WATCHING'],
    })
    EXPECTED_ERR = dict_merge({
        'bury': ['NOT_FOUND', 'OUT_OF_MEMORY'],
        'delete': ['NOT_FOUND'],
        'list-tubes': [],
        'kick': ['OUT_OF_MEMORY'],
        'kick-job': ['NOT_FOUND', 'OUT_OF_MEMORY'],
        'peek': ['NOT_FOUND'],
        'peek-buried': ['NOT_FOUND'],
        'peek-delayed': ['NOT_FOUND'],
        'peek-ready': ['NOT_FOUND'],
        'put': ['JOB_TOO_BIG', 'BURIED', 'DRAINING', 'OUT_OF_MEMORY'],
        'reserve': ['DEADLINE_SOON', 'TIMED_OUT'],
        'reserve-with-timeout': ['DEADLINE_SOON', 'TIMED_OUT'],
        'release': ['BURIED', 'NOT_FOUND', 'OUT_OF_MEMORY'],
        'stats': [],
        'stats-tube': ['NOT_FOUND'],
        'use': [],
        'watch': [],
    })

    @classmethod
    def from_url(cls, url, **kwargs):
        if url is None or not url:
            raise ConnectionError('Empty URL')
        if not url.startswith('beanstalk://'):
            import warnings
            warnings.warn(
                    'Invalid URL scheme, expecting beanstalk',
                    DeprecationWarning)
        connection = Connection.from_url(url, **kwargs)
        return cls(connection=connection)

    def __init__(self, host=None, port=None, socket_timeout=None,
                 socket_connect_timeout=None, socket_keepalive=None,
                 socket_keepalive_options=None, connection=None,
                 **kwargs):
        if not connection:
            self.socket_timeout = socket_timeout
            kwargs2 = {
                'host': host,
                'port': int(port),
                'socket_connect_timeout': socket_connect_timeout,
                'socket_keepalive': socket_keepalive,
                'socket_keepalive_options': socket_keepalive_options,
                'socket_timeout': socket_timeout,
            }

            connection = Connection(**kwargs2)
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

    def _drain(self, fetch_func):
        try:
            job_id = True
            while job_id is not None:
                job_id, _ = fetch_func()
                self.delete(job_id)
        except ResponseError:
            pass

    def drain_buried(self, tube):
        self.use(tube)
        return self._drain(self.peek_buried)

    def drain_tube(self, tube, timeout=0.0):
        """Delete all jobs from the specified tube."""
        self.watch(tube)
        from functools import partial
        return self._drain(partial(self.reserve, timeout=timeout))

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

    def _peek_generic(self, command_suffix=''):
        command = 'peek' + command_suffix
        try:
            return self.execute_command(command)
        except ResponseError as err:
            if err.args[0] == command and err.args[1] == 'NOT_FOUND':
                return None, None
            else:
                raise

    def peek_buried(self):
        """
        Read the next buried job without kicking it.
        """
        return self._peek_generic('-buried')

    def peek_ready(self):
        """
        read the next ready job without reserving it.
        """
        return self._peek_generic('-ready')

    def wait_until_empty(self, tube, timeout=float('inf'), poll_interval=0.2,
                         initial_delay=0.0):
        """
        Wait until the the specified tube is empty, or the timeout expires.
        """
        # TODO(FVE): check tube stats to ensure some jobs have passed through
        # and then get rid of the initial_delay
        # peek-ready requires "use", not "watch"
        self.use(tube)
        if initial_delay > 0.0:
            time.sleep(initial_delay)
        job_id, _ = self.peek_ready()
        deadline = time.time() + timeout
        while job_id is not None and time.time() < deadline:
            time.sleep(poll_interval)
            job_id, _ = self.peek_ready()

    def wait_for_ready_job(self, tube, timeout=float('inf'),
                           poll_interval=0.2):
        """
        Wait until the the specified tube has a ready job,
        or the timeout expires.
        """
        self.use(tube)
        job_id, data = self.peek_ready()
        deadline = time.time() + timeout
        while job_id is None and time.time() < deadline:
            time.sleep(poll_interval)
            job_id, data = self.peek_ready()
        return job_id, data

    def stats(self):
        return self.execute_command('stats')

    def stats_tube(self, tube):
        return self.execute_command('stats-tube', tube)

    def tubes(self):
        return self.execute_command('list-tubes')

    def close(self):
        if self._connection:
            self._connection.disconnect()
            self._connection = None


class TubedBeanstalkd(object):
    """
    Beanstalkd wrapper that will talk to a single tube.
    """

    def __init__(self, addr, tube, logger, **kwargs):
        addr = addr.strip()
        if addr.startswith('beanstalk://'):
            addr = addr[12:]
        self.addr = addr
        self.tube = tube
        self.logger = logger
        self.beanstalkd = None
        self.connected = False
        self._connect()
        # Check the connection
        self.beanstalkd.stats_tube(self.tube)

    def _connect(self, **kwargs):
        if self.connected:
            return

        self.logger.debug('Connecting to %s using tube %s',
                          self.addr, self.tube)
        self.beanstalkd = Beanstalk.from_url('beanstalk://' + self.addr)
        self.beanstalkd.use(self.tube)
        self.beanstalkd.watch(self.tube)
        self.connected = True

    def close(self):
        """Disconnect the wrapped Beanstalkd client."""
        if not self.connected:
            return

        try:
            self.beanstalkd.close()
        except BeanstalkError:
            pass
        self.connected = False


class BeanstalkdListener(TubedBeanstalkd):

    def __init__(self, addr, tube, logger, **kwargs):
        # pylint: disable=no-member
        super(BeanstalkdListener, self).__init__(addr, tube, logger, **kwargs)
        self.running = True

    def fetch_job(self, on_job, timeout=None, **kwargs):
        job_id = None
        try:
            self._connect(**kwargs)
            job_id, data = self.beanstalkd.reserve(timeout=timeout)
            try:
                for job_info in on_job(job_id, data, **kwargs):
                    yield job_info
            except GeneratorExit:
                # If the reader finishes to handle the job, but does not want
                # any new job, it will break the generator. This does not mean
                # the current job has failed, thus we must delete it.
                self.beanstalkd.delete(job_id)
                raise
            except Exception as err:
                try:
                    self.beanstalkd.bury(job_id)
                except BeanstalkError as exc:
                    self.logger.error("Could not bury job %s: %s", job_id, exc)
                exceptions.reraise(err.__class__, err)
            else:
                self.beanstalkd.delete(job_id)
            return
        except ConnectionError as exc:
            self.close()
            self.logger.warn(
                'Disconnected from %s using tube %s (job=%s): %s',
                self.addr, self.tube, job_id, exc)
            if 'Invalid URL' in str(exc):
                raise
            time.sleep(1.0)
        except exceptions.ExplicitBury as exc:
            self.logger.warn("Job bury on %s using tube %s (job=%s): %s",
                             self.addr, self.tube, job_id, exc)
        except BeanstalkError as exc:
            if isinstance(exc, ResponseError) and 'TIMED_OUT' in str(exc):
                raise exceptions.OioTimeout()

            self.logger.exception("ERROR on %s using tube %s (job=%s)",
                                  self.addr, self.tube, job_id)
        except Exception:
            self.logger.exception("ERROR on %s using tube %s (job=%s)",
                                  self.addr, self.tube, job_id)

    def fetch_jobs(self, on_job, reserve_timeout=None, **kwargs):
        while self.running:
            try:
                for job_info in self.fetch_job(on_job, timeout=reserve_timeout,
                                               **kwargs):
                    yield job_info
            except exceptions.OioTimeout:
                pass


class BeanstalkdSender(TubedBeanstalkd):
    """
    Send jobs to the specified beanstalkd tube, until the specified
    high_limit is reached.
    """

    def __init__(self, addr, tube, logger,
                 low_limit=512, high_limit=1024, **kwargs):
        # pylint: disable=no-member
        super(BeanstalkdSender, self).__init__(addr, tube, logger, **kwargs)
        self.low_limit = low_limit
        self.high_limit = high_limit
        self.accepts_jobs = True
        self.nb_jobs = 0
        self.nb_jobs_lock = threading.Lock()

    def send_job(self, job, priority=DEFAULT_PRIORITY, delay=0, **kwargs):
        """
        Send a job, if the queue has not reached its size limit.

        :returns: True if the job has been sent, False otherwise.
        """
        if self.nb_jobs <= self.low_limit:
            self.accepts_jobs = True
        elif not self.accepts_jobs or self.nb_jobs > self.high_limit:
            return False

        job_id = None
        try:
            self._connect(**kwargs)
            with self.nb_jobs_lock:
                job_id = self.beanstalkd.put(
                    job, priority=priority, delay=delay)
                self.nb_jobs += 1
                if self.nb_jobs >= self.high_limit:
                    self.accepts_jobs = False
            return True
        except ConnectionError as exc:
            self.close()
            self.logger.warn(
                'Disconnected from %s using tube %s (job=%s): %s',
                self.addr, self.tube, job_id, exc)
            if 'Invalid URL' in str(exc):
                raise
        except Exception:
            self.logger.exception("ERROR on %s using tube %s (job=%s)",
                                  self.addr, self.tube, job_id)
        return False

    def send_event(self, event, **kwargs):
        """Deprecated"""
        return self.send_job(job=event, **kwargs)

    def job_done(self):
        """
        Declare that a job previously sent by this sender
        has been fully processed (the sender received a response,
        or does not expect one).
        """
        with self.nb_jobs_lock:
            self.nb_jobs -= 1
