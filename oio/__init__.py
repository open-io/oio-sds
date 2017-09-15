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

See help("oio.api.object_storage.ObjectStorageApi")

"""


import pkg_resources
import importlib


class LazyLoader(object):
    """
    See help("oio.api.object_storage.ObjectStorageApi")
    """

    def __init__(self, module, name=None):
        self.mod_name = module
        self.class_name = name
        self.value = None

    def __ensure_value(self):
        if self.value is None:
            mod = importlib.import_module(self.mod_name)
            if self.class_name:
                self.value = getattr(mod, self.class_name)
            else:
                self.value = mod

    def __getattr__(self, name):
        self.__ensure_value()
        return getattr(self.value, name)

    def __call__(self, *args, **kwargs):
        self.__ensure_value()
        return self.value(*args, **kwargs)


ObjectStorageApi = LazyLoader("oio.api.object_storage", "ObjectStorageApi")

try:
    __version__ = __canonical_version__ = pkg_resources.get_provider(
        pkg_resources.Requirement.parse('oio')).version
except pkg_resources.DistributionNotFound:
    import pbr.version
    _version_info = pbr.version.VersionInfo('oio')
    __version__ = _version_info.release_string()
    __canonical_version = _version_info.version_string()

__all__ = ["ObjectStorageApi"]
