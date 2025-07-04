# Copyright (C) 2015-2018 OpenIO SAS, as part of OpenIO SDS
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

"""
OpenIO SDS Python API.

Basic object storage example:

    >>> from oio import ObjectStorageApi
    >>> api = ObjectStorageApi(namespace="OPENIO")
    >>> api.object_create("myaccount", "mycontainer", "/etc/magic")
    ([{u'url': u'http://127.0.0.1:6008/DEADBEEFCAFEBABE1EE7',
       u'score': 65,
       u'hash': '8de4989188593b0419d387099c9e9872',
       u'pos': '0',
       u'size': 113}],
     113,
     '8de4989188593b0419d387099c9e9872')
"""

import importlib
import importlib.metadata
import sys


class ObjectStorageApi(object):
    oio = importlib.import_module("oio")
    object_storage = None
    __doc__ = oio.__doc__

    @property
    def ObjectStorageApi(self):  # pylint: disable=invalid-name
        if not self.__class__.object_storage:
            self.__class__.object_storage = importlib.import_module(
                "oio.api.object_storage"
            )
        return self.__class__.object_storage.ObjectStorageApi

    def __getattr__(self, name):
        return getattr(self.__class__.oio, name)


__version__ = __canonical_version__ = importlib.metadata.version("oio")

sys.modules[__name__] = ObjectStorageApi()
__all__ = ["ObjectStorageApi"]
