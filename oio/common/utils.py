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
import grp
import pwd
import fcntl
from hashlib import sha256
from random import getrandbits
from io import RawIOBase
from itertools import islice
from codecs import getdecoder, getencoder
from six.moves import range
try:
    from urllib.parse import quote as _quote
except ImportError:
    from urllib import quote as _quote
from six import text_type
from oio.common.exceptions import OioException


try:
    import multiprocessing
    CPU_COUNT = multiprocessing.cpu_count() or 1
except (ImportError, NotImplementedError):
    CPU_COUNT = 1


utf8_decoder = getdecoder('utf-8')
utf8_encoder = getencoder('utf-8')


def quote(value, safe='/'):
    if isinstance(value, text_type):
        (value, _len) = utf8_encoder(value, 'replace')
    (valid_utf8_str, _len) = utf8_decoder(value, 'replace')
    return _quote(valid_utf8_str.encode('utf-8'), safe)


def encode(input, codec='utf-8'):
    """Recursively encode a list of dictionnaries"""
    if isinstance(input, dict):
        return {key: encode(value, codec) for key, value in input.items()}
    elif isinstance(input, list):
        return [encode(element, codec) for element in input]
    elif isinstance(input, text_type):
        return input.encode(codec)
    else:
        return input


def set_fd_non_blocking(fd):
    flags = fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK
    fcntl.fcntl(fd, fcntl.F_SETFL, flags)


def set_fd_close_on_exec(fd):
    flags = fcntl.fcntl(fd, fcntl.F_GETFD)
    flags |= fcntl.FD_CLOEXEC
    fcntl.fcntl(fd, fcntl.F_SETFL, flags)


def drop_privileges(user):
    if os.geteuid() == 0:
        groups = [g.gr_gid for g in grp.getgrall() if user in g.gr_mem]
        os.setgroups(groups)
    try:
        user_entry = pwd.getpwnam(user)
    except KeyError as exc:
        raise OioException("User %s does not exist (%s). Are you running "
                           "your namespace with another user name?" %
                           (user, exc))
    try:
        os.setgid(user_entry[3])
        os.setuid(user_entry[2])
    except OSError as exc:
        raise OioException("Failed to switch uid to %s or gid to %s: %s" %
                           (user_entry[2], user_entry[3], exc))
    os.environ['HOME'] = user_entry[5]
    try:
        os.setsid()
    except OSError:
        pass
    os.chdir('/')
    os.umask(0o22)


def paths_gen(volume_path):
    for root, dirs, files in os.walk(volume_path):
        for name in files:
            yield os.path.join(root, name)


def statfs(volume):
    st = os.statvfs(volume)
    total = st.f_blocks * st.f_frsize
    used = (st.f_blocks - st.f_bfree) * st.f_frsize
    return used, total


class RingBuffer(list):
    def __init__(self, size=1):
        self._count = 0
        self._zero = 0
        self._size = size

    @property
    def size(self):
        """Get the size of the ring buffer"""
        return self._size

    def __index(self, key):
        if not self._count:
            raise IndexError('list index out of range')
        return (key + self._zero) % self._count

    def append(self, value):
        if self._count < self._size:
            super(RingBuffer, self).append(value)
            self._count += 1
        else:
            super(RingBuffer, self).__setitem__(self._zero % self._size, value)
            self._zero += 1

    def __getitem__(self, key):
        return super(RingBuffer, self).__getitem__(self.__index(key))

    def __setitem__(self, key, value):
        return super(RingBuffer, self).__setitem__(self.__index(key), value)

    def __delitem__(self, key):
        raise self.InvalidOperation('Delete impossible in RingBuffer')

    def __iter__(self):
        for i in range(0, self._count):
            yield self[i]


def cid_from_name(account, ref):
    h = sha256()
    for v in [account, '\0', ref]:
        h.update(v.encode())
    return h.hexdigest().upper()


def fix_ranges(ranges, length):
    if length is None or not ranges or ranges == []:
        return None
    result = []
    for r in ranges:
        start, end = r
        if start is None:
            if end == 0:
                # bytes=-0
                continue
            elif end >= length:
                # all content must be returned
                result.append((0, length-1))
            else:
                result.append((length - end, length-1))
            continue
        if end is None:
            if start < length:
                result.append((start, length-1))
            else:
                # skip
                continue
        elif start < length:
            result.append((start, min(end, length-1)))

    return result


def request_id():
    """Build a 128-bit request id string"""
    return "%04X%028X" % (os.getpid(),
                          getrandbits(112))


class GeneratorIO(RawIOBase):
    """
    Make a file-like object from a generator.
    `gen` is the generator to read.
    `sub_generator` is a boolean telling that the generator
    yields sequences of bytes instead of bytes.
    """

    def __init__(self, gen, sub_generator=True):
        self.generator = self._wrap(gen)
        self._sub_gen = sub_generator

    def _wrap(self, gen):
        """
        Wrap the provided generator so it yields bytes
        instead of sequences of bytes
        """
        for part in gen:
            if part:
                if self._sub_gen:
                    try:
                        for byte in part:
                            yield byte
                    except TypeError:
                        # The yielded elements do not support iteration
                        # thus we will disable it
                        self._sub_gen = False
                        yield part
                else:
                    yield part
            else:
                raise StopIteration

    def readable(self):
        return True

    def read(self, size=None):
        if size is not None:
            return "".join(islice(self.generator, size))
        return "".join(self.generator)

    def readinto(self, b):  # pylint: disable=invalid-name
        read_len = len(b)
        read_data = self.read(read_len)
        b[0:len(read_data)] = read_data
        return len(read_data)

    def __iter__(self):
        for chunk in self.generator:
            yield chunk


def group_chunk_errors(chunk_err_iter):
    errors = dict()
    for chunk, err in chunk_err_iter:
        err_list = errors.get(err) or list()
        err_list.append(chunk)
        errors[err] = err_list
    return errors


def depaginate(func, item_key=None, listing_key=None, marker_key=None,
               *args, **kwargs):
    """
    Yield items from the lists returned by the repetitive calls
    to `func(*args, **kwargs)`. For each call (except the first),
    the marker is taken from the last element returned by the previous
    call (unless `marker_key` is provided).

    :param item_key: an accessor to the actual item that should be yielded,
        applied on each element of the listing
    :param listing_key: an accessor to the actual listing, applied
        on the result of `func(*args, **kwargs)`
    :param marker_key: an accessor to the next marker from the previous
        listing, applied on the result of `func(*args, **kwargs)`
    """
    if not item_key:
        # pylint: disable=function-redefined, missing-docstring
        def item_key(item):
            return item
    if not listing_key:
        # pylint: disable=function-redefined, missing-docstring
        def listing_key(listing):
            return listing
    if not marker_key:
        # pylint: disable=function-redefined, missing-docstring
        def marker_key(listing):
            return listing[-1]

    raw_listing = func(*args, **kwargs)
    listing = listing_key(raw_listing)
    for item in listing:
        yield item_key(item)

    while listing:
        kwargs['marker'] = marker_key(raw_listing)
        raw_listing = func(*args, **kwargs)
        listing = listing_key(raw_listing)
        if listing:
            for item in listing:
                yield item_key(item)


__MONOTONIC_TIME = None


def monotonic_time():
    """Get the monotonic time as float seconds"""
    global __MONOTONIC_TIME
    if __MONOTONIC_TIME is None:
        from ctypes import CDLL, c_int64
        try:
            liboiocore = CDLL('liboiocore.so.0')
            oio_ext_monotonic_time = liboiocore.oio_ext_monotonic_time
            oio_ext_monotonic_time.restype = c_int64

            def _monotonic_time():
                return oio_ext_monotonic_time() / 1000000.0

            __MONOTONIC_TIME = _monotonic_time
        except OSError as exc:
            from sys import stderr
            from time import time
            print >>stderr, "Failed to load oio_ext_monotonic_time(): %s" % exc
            __MONOTONIC_TIME = time

    return __MONOTONIC_TIME()
