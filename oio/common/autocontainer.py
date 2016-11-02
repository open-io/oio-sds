# Copyright (C) 2016 OpenIO SAS

# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# You should have received a copy of the GNU Lesser General Public
# License along with this library.


from itertools import takewhile
from ctypes import CDLL, c_char_p, c_uint, create_string_buffer


# Python's int() raises an exception if the string has non-digit
# characters at the end, while libc's strtoll just stops parsing.
def strtoll(val, base=10):
    """Mimics libc's strtoll function"""
    return int("".join(takewhile(str.isdigit, val)), base)


class HashedContainerBuilder(object):
    """
    Build a container name from a SHA256 of the content path.
    Only the first bits will be considered to generte the final prefix.
    """

    def __init__(self, offset=0, size=None, bits=15, **_kwargs):
        self.offset = offset
        self.size = size
        self.bits = bits
        self.lib = None
        self.func = None

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


class AutocontainerBuilder(object):
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
