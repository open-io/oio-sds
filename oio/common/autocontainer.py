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


# Python's int() raises an exception if the string has non-digit
# characters at the end, while libc's strtoll just stops parsing.
def strtoll(val, base=10):
    """Mimics libc's strtoll function"""
    return int("".join(takewhile(str.isdigit, val)), base)


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
