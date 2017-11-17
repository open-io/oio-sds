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

import sys
from oio.common import exceptions


EC_SEGMENT_SIZE = 1048576


ec_type_to_pyeclib_type = {
    'isa_l_rs_vand': 'isa_l_rs_vand',
    'jerasure_rs_vand': 'jerasure_rs_vand',
    'jerasure_rs_cauchy': 'jerasure_rs_cauchy',
    'shss': 'shss',
    'liberasurecode_rs_vand': 'liberasurecode_rs_vand'
}


def parse_chunk_method(chunk_method):
    param_list = dict()
    if '/' in chunk_method:
        chunk_method, params = chunk_method.split('/', 1)
        params = params.split(',')
        if len(params) >= 1:
            for param in params:
                param = param.lstrip()
                if '=' in param:
                    k, v = param.split('=', 1)
                    param_list[k] = v
                elif param:
                    param_list[param] = "1"
    return chunk_method, param_list


def guess_storage_method(url):
    if url.startswith('b2') or url.startswith('backblaze'):
        return 'backblaze'
    elif url.startswith('kine'):
        return 'kplain'
    else:
        return 'plain'


class StorageMethods(object):
    def __init__(self, methods):
        self.index = methods
        self.cache = {}

    def load(self, chunk_method, **kwargs):
        method = self.cache.get(chunk_method)
        if method:
            return method
        try:
            storage_method, params = parse_chunk_method(chunk_method)
            cls = self.index[storage_method]
        except Exception as exc:
            raise exceptions.InvalidStorageMethod(str(exc)).with_traceback(
                sys.exc_info()[2])
        params.update(kwargs)
        self.cache[chunk_method] = cls.build(params)
        self.cache[chunk_method].type = storage_method
        return self.cache[chunk_method]


class StorageMethod(object):
    def __init__(self, name, ec=False, backblaze=False):
        self._name = name
        self._ec = ec
        self._backblaze = backblaze
        self.type = None

    @property
    def name(self):
        return self._name

    @property
    def ec(self):
        return self._ec

    @property
    def backblaze(self):
        return self._backblaze


class ReplicatedStorageMethod(StorageMethod):
    def __init__(self, name, nb_copy):
        super(ReplicatedStorageMethod, self).__init__(name=name)

        try:
            self._nb_copy = int(nb_copy)
        except (TypeError, ValueError):
            raise exceptions.InvalidStorageMethod('Invalid %r nb_copy' %
                                                  nb_copy)
        self._quorum = (self._nb_copy + 1) // 2

    @classmethod
    def build(cls, params):
        nb_copy = params.pop('nb_copy', 1)
        return cls('repli', nb_copy)

    @property
    def quorum(self):
        return self._quorum

    @property
    def nb_copy(self):
        return self._nb_copy


class ECStorageMethod(StorageMethod):
    def __init__(self, name, ec_segment_size, ec_type, ec_nb_data,
                 ec_nb_parity):
        super(ECStorageMethod, self).__init__(name=name, ec=True)

        try:
            self._ec_nb_data = int(ec_nb_data)
        except (TypeError, ValueError):
            raise exceptions.InvalidStorageMethod('Invalid %r ec_nb_data' %
                                                  ec_nb_data)

        try:
            self._ec_nb_parity = int(ec_nb_parity)
        except (TypeError, ValueError):
            raise exceptions.InvalidStorageMethod('Invalid %r ec_nb_parity' %
                                                  ec_nb_parity)

        self._ec_segment_size = ec_segment_size
        self._ec_type = ec_type

        from pyeclib.ec_iface import ECDriver
        self.driver = ECDriver(k=ec_nb_data, m=ec_nb_parity,
                               ec_type=ec_type_to_pyeclib_type[ec_type])
        self._ec_quorum_size = \
            self._ec_nb_data + self.driver.min_parity_fragments_needed()

    @property
    def quorum(self):
        return self._ec_quorum_size

    @classmethod
    def build(cls, params):
        ec_nb_data = params.pop('k')
        ec_nb_parity = params.pop('m')
        ec_type = params.pop('algo')
        return cls('ec', ec_segment_size=EC_SEGMENT_SIZE,
                   ec_type=ec_type, ec_nb_data=ec_nb_data,
                   ec_nb_parity=ec_nb_parity)

    @property
    def ec_type(self):
        return self._ec_type

    @property
    def ec_nb_data(self):
        return self._ec_nb_data

    @property
    def ec_nb_parity(self):
        return self._ec_nb_parity

    @property
    def ec_segment_size(self):
        return self._ec_segment_size

    @property
    def ec_fragment_size(self):
        return self.driver.get_segment_info(
            self.ec_segment_size, self.ec_segment_size)['fragment_size']


class BackblazeStorageMethod(StorageMethod):
    def __init__(self, name, account_id, bucket_name):
        super(BackblazeStorageMethod, self).__init__(name=name, backblaze=True)
        self._account_id = account_id
        self._bucket_name = bucket_name

    @classmethod
    def build(cls, params):
        account_id = params.pop('account_id')
        bucket_name = params.pop('bucket_name')
        return cls('backblaze', account_id, bucket_name)

    @property
    def account_id(self):
        return self._account_id

    @property
    def bucket_name(self):
        return self._bucket_name


def load_methods():
    global _STORAGE_METHODS
    methods = {'plain': ReplicatedStorageMethod,
               'ec': ECStorageMethod,
               'backblaze': BackblazeStorageMethod}
    _STORAGE_METHODS = StorageMethods(methods)


class StorageMethodLoad(object):
    def __getattribute__(self, name):
        return getattr(_STORAGE_METHODS, name)


_STORAGE_METHODS = None
load_methods()
STORAGE_METHODS = StorageMethodLoad()
