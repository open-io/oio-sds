# Copyright (C) 2017 OpenIO SAS, as part of OpenIO SDS
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

from oio.common.green import datetime, time


TIMESTAMP_FORMAT = "%016.05f"


class Timestamp(object):
    def __init__(self, timestamp=None):
        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = float(timestamp)
            # More than year 1000000?! We got microseconds.
            if self.timestamp > 31494784780800.0:
                self.timestamp /= 1000000.0

    def __repr__(self):
        return self.normal

    def __float__(self):
        return self.timestamp

    def __int__(self):
        return int(self.timestamp)

    def __nonzero__(self):
        return bool(self.timestamp)

    @property
    def normal(self):
        return TIMESTAMP_FORMAT % self.timestamp

    def __eq__(self, other):
        if not isinstance(other, Timestamp):
            other = Timestamp(other)
        return self.timestamp == other.timestamp

    def __ne__(self, other):
        if not isinstance(other, Timestamp):
            other = Timestamp(other)
        return self.timestamp != other.timestamp

    def __cmp__(self, other):
        if not isinstance(other, Timestamp):
            other = Timestamp(other)
        return cmp(self.timestamp, other.timestamp)

    @property
    def isoformat(self):
        t = float(self.normal)
        return datetime.utcfromtimestamp(t).isoformat()
