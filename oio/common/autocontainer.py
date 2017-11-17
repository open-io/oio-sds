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

import re
from six import string_types
from itertools import takewhile
from ctypes import CDLL, c_char_p, c_uint, create_string_buffer


# Python's int() raises an exception if the string has non-digit
# characters at the end, while libc's strtoll just stops parsing.
def strtoll(val, base=10):
    """Mimics libc's strtoll function"""
    return int("".join(takewhile(str.isdigit, val)), base)


class ContainerBuilder(object):
    """Base class for container name builders."""
    def __init__(self, **_kwargs):
        pass

    def __call__(self, path):
        return str(path)

    def alternatives(self, path):
        """Generate all alternatives for the provided content path."""
        yield self(path)
        raise StopIteration

    def verify(self, name):
        """Verify that `name` is an autocontainer"""
        return isinstance(name, string_types)


class HashedContainerBuilder(ContainerBuilder):
    """
    Build a container name from a SHA256 of the content path.
    Only the first (most significant) bits will be considered to generate
    the final prefix.
    """

    def __init__(self, offset=0, size=None, bits=15, **_kwargs):
        self.offset = offset
        self.size = size
        self.bits = bits
        self.lib = None
        self.func = None

        # Maximum number of bits of the hexadecimal representation
        bitlength = (((self.bits - 1) // 4) + 1) * 4
        # Maximum value of the hexadecimal representation
        self.mask = (2 ** bitlength) - (2 ** (bitlength - self.bits))

    def __str__(self):
        return '{0}(bits={1},offset={2},size={3})'.format(
                self.__class__.__name__, self.bits, self.offset, self.size)

    def __call__(self, path):
        if self.lib is None:
            self.lib = CDLL('liboiocore.so.0')
            self.func = self.lib.oio_str_autocontainer
            self.func.argtypes = [c_char_p, c_uint, c_char_p, c_uint]
            self.func.restype = c_char_p

        src = path[self.offset:]
        srclen = len(src)
        if self.size and self.size < len(src):
            srclen = self.size
        tmp = create_string_buffer(65)
        out = self.func(src, srclen, tmp, self.bits)
        return str(out)

    def verify(self, name):
        """Verify that `name` is an autocontainer"""
        try:
            integer = int(name, base=16)
            # Verify there are no bits outside the valid range
            return (integer & ~self.mask) == 0
        except ValueError:
            return False


class AutocontainerBuilder(ContainerBuilder):
    """
    Build a container name from the integer conversion
    of a user provided path and a clever mask.

    `path` is expected to be something like
    "video/ABC/DEF/xxxxxxxxxFEDCBAxxxxxxxxxx_nomdufichier"
    """

    def __init__(self, offset=0, size=None, mask=0xFFFFFFFFFF0000FF,
                 base=16, con_format="%016X", **_kwargs):
        self.offset = offset
        self.size = size
        self.mask = mask
        self.base = base
        self.format = con_format

    def __call__(self, path):
        if self.size:
            flat_path = path[self.offset:self.offset+self.size]
        else:
            flat_path = path[self.offset:]
        flat_path = flat_path.replace("/", "")
        int_part = strtoll(flat_path)
        return self.format % (int_part & self.mask)

    def verify(self, name):
        """Verify that `name` is an autocontainer"""
        try:
            integer = int(name, base=16)
            return (self.format % integer) == name
        except ValueError:
            return False


class RegexContainerBuilder(object):
    """
    Build a container name from a regular expression applied on a user
    provided path. Use a concatenation of all matching groups as the
    container name if no custom builder provided.

    :param patterns: regular expressions with at least one capture group
    :type patterns: `str` or iterable of `str`
    """

    def __init__(self, patterns, builder=ContainerBuilder, **kwargs):
        if isinstance(patterns, string_types):
            patterns = (patterns, )
        if not patterns:
            raise ValueError("You must provide at least one pattern")
        self.patterns = list()
        for pattern in patterns:
            if not isinstance(pattern, re._pattern_type):
                pattern = re.compile(pattern)
                if pattern.groups < 1:
                    raise ValueError(
                        "Expression %s does not contain any capture group")
            self.patterns.append(pattern)
        self.builder = builder(**kwargs)

    def __call__(self, path):
        for pattern in self.patterns:
            match = pattern.search(path)
            if match:
                return self.builder(''.join(match.groups()))
        raise ValueError("'%s' does not match any configured patterns" % path)

    def alternatives(self, path):
        """
        Generate all alternatives for the provided path,
        in case it matches several patterns.
        """

        for pattern in self.patterns:
            match = pattern.search(path)
            if match:
                yield self.builder(''.join(match.groups()))
        raise StopIteration

    def verify(self, name):
        return self.builder.verify(name)
