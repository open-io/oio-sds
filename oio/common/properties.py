# Copyright (C) 2025 OVH SAS
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


import json


class RestoreProperty:
    __slots__ = [
        "days",
        "expiry_date",
        "ongoing",
        "request_date",
        "tier",
    ]

    def __init__(self):
        self.ongoing = False
        self.tier = None
        self.days = 0
        self.expiry_date = None
        self.request_date = None

    def dump(self):
        return json.dumps(
            {
                slot: getattr(self, slot)
                for slot in self.__slots__
                if getattr(self, slot) is not None
            },
            separators=(",", ":"),
        )

    @classmethod
    def load(cls, data):
        content = json.loads(data)
        prop = cls()
        for slot in cls.__slots__:
            setattr(prop, slot, content.get(slot))
        return prop
