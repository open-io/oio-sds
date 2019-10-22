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

import os
import grp
import pwd
import fcntl
from collections import OrderedDict
from hashlib import sha256
from random import getrandbits
from io import RawIOBase
from itertools import islice
from codecs import getdecoder, getencoder
from urllib import quote as _quote
from oio.common.exceptions import OioException, DeadlineReached, ServiceBusy


try:
    import multiprocessing
    CPU_COUNT = multiprocessing.cpu_count() or 1
except (ImportError, NotImplementedError):
    CPU_COUNT = 1


utf8_decoder = getdecoder('utf-8')
utf8_encoder = getencoder('utf-8')


def quote(value, safe='/'):
    if isinstance(value, unicode):
        (value, _len) = utf8_encoder(value, 'replace')
    (valid_utf8_str, _len) = utf8_decoder(value, 'replace')
    return _quote(valid_utf8_str.encode('utf-8'), safe)


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
    """
    Yield paths of all regular files under `volume_path`.
    """
    for root, _dirs, files in os.walk(volume_path):
        for name in files:
            yield os.path.join(root, name)


def statfs(volume):
    """
    :param volume: path to the mount point to get stats from.
    :returns: the free space ratio.
    :rtype: `float`
    """
    st = os.statvfs(volume)
    free_inodes = st.f_ffree
    total_inodes = st.f_files
    free_blocks = st.f_bavail
    total_blocks = st.f_blocks
    if total_inodes > 0:
        inode_ratio = float(free_inodes)/float(total_inodes)
    else:
        inode_ratio = 1
    if total_blocks > 0:
        block_ratio = float(free_blocks)/float(total_blocks)
    else:
        block_ratio = 1
    return min(inode_ratio, block_ratio)


class CacheDict(OrderedDict):
    """
    OrderedDict subclass which holds a limited number of items.
    """

    def __init__(self, size=262144):
        super(CacheDict, self).__init__()
        self.size = size

    def __setitem__(self, key, value):
        super(CacheDict, self).__setitem__(key, value)
        self._check_size()

    def _check_size(self):
        while len(self) > self.size:
            self.popitem(last=False)


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
        raise TypeError('Delete impossible in RingBuffer')

    def __iter__(self):
        for i in xrange(0, self._count):
            yield self[i]


def cid_from_name(account, ref):
    """
    Compute a container ID from an account and a reference name.
    """
    hash_ = sha256()
    for v in [account, '\0', ref]:
        if isinstance(v, unicode):
            v = v.encode('utf-8')
        hash_.update(v)
    return hash_.hexdigest().upper()


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


def request_id(prefix=''):
    """
    Build a 128-bit request id string.

    :param prefix: optional prefix to the request id.
    """
    pref_bits = min(112, len(prefix) * 4)
    rand_bits = 112 - pref_bits
    return "%s%04X%0*X" % (prefix, os.getpid(),
                           rand_bits/4, getrandbits(rand_bits))


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
    """
    Group errors in a dictionary of lists.
    The keys are errors, the values are lists of chunk IDs.
    """
    errors = dict()
    for chunk, err in chunk_err_iter:
        err_list = errors.get(err) or list()
        err_list.append(chunk)
        errors[err] = err_list
    return errors


def depaginate(func, item_key=None, listing_key=None, marker_key=None,
               truncated_key=None, attempts=1, *args, **kwargs):
    """
    Yield items from the lists returned by the repetitive calls
    to `func(*args, **kwargs)`. For each call (except the first),
    the marker is taken from the last element returned by the previous
    call (unless `marker_key` is provided). The listing stops after
    an empty listing is returned (unless `truncated_key` is provided).

    :param item_key: an accessor to the actual item that should be yielded,
        applied on each element of the listing
    :param listing_key: an accessor to the actual listing, applied
        on the result of `func(*args, **kwargs)`
    :param marker_key: an accessor to the next marker from the previous
        listing, applied on the result of `func(*args, **kwargs)`
    :param truncated_key: an accessor telling if the listing is truncated,
        applied on the result of `func(*args, **kwargs)`
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
    if not truncated_key:
        # pylint: disable=function-redefined, missing-docstring
        def truncated_key(listing):
            return bool(listing_key(listing))

    for i in range(attempts):
        try:
            raw_listing = func(*args, **kwargs)
            break
        except ServiceBusy:
            if i >= attempts - 1:
                raise
    listing = listing_key(raw_listing)
    for item in listing:
        yield item_key(item)

    while truncated_key(raw_listing):
        kwargs['marker'] = marker_key(raw_listing)
        for i in range(attempts):
            try:
                raw_listing = func(*args, **kwargs)
                break
            except ServiceBusy:
                if i >= attempts - 1:
                    raise
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


def deadline_to_timeout(deadline, check=False):
    """Convert a deadline (`float` seconds) to a timeout (`float` seconds)"""
    dl_to = deadline - monotonic_time()
    if check and dl_to <= 0.0:
        raise DeadlineReached()
    return dl_to


def timeout_to_deadline(timeout, now=None):
    """Convert a timeout (`float` seconds) to a deadline (`float` seconds)."""
    if now is None:
        now = monotonic_time()
    return now + timeout


def set_deadline_from_read_timeout(kwargs, force=False):
    """
    Compute a deadline from a read timeout, and set it in a keyword
    argument dictionary if there is none (or `force` is set).
    """
    to = kwargs.get('read_timeout')
    if to is not None and (force or 'deadline' not in kwargs):
        kwargs['deadline'] = timeout_to_deadline(to)
