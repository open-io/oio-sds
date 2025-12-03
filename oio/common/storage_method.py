# Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2020-2025 OVH SAS
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

from oio.common import exceptions

try:
    from pyeclib.ec_iface import ECDriver, ECDriverError
except ImportError as err:
    EC_MSG = f"Erasure coding not available: {err}"

    class ECDriverError(RuntimeError):
        pass

    class ECDriver:
        """Dummy wrapper for ECDriver, when erasure-coding is not available."""

        def __init__(self, *_args, **_kwargs):
            raise ECDriverError(EC_MSG)


EC_SEGMENT_SIZE = 1048576


def parse_chunk_method(chunk_method):
    """
    Split a "packed" chunk method description into the chunk method type
    and a dictionary of parameters.
    """
    param_list = {}
    if "/" in chunk_method:
        chunk_method, params = chunk_method.split("/", 1)
        params = params.split(",")
        if len(params) >= 1:
            for param in params:
                param = param.lstrip()
                if "=" in param:
                    k, v = param.split("=", 1)
                    param_list[k] = v
                elif param:
                    param_list[param] = "1"
    return chunk_method, param_list


def unparse_chunk_method(chunk_method, params):
    """
    Generate a "packed" version of a chunk method and its parameters.
    """
    return (
        chunk_method + "/" + ",".join(f"{k}={params[k]}" for k in sorted(params.keys()))
    )


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
            raise exceptions.InvalidStorageMethod(str(exc)) from exc
        params.update(kwargs)
        self.cache[chunk_method] = cls.build(params)
        self.cache[chunk_method].type = storage_method
        return self.cache[chunk_method]


class StorageMethod(object):
    """
    Hold parameters telling how an object is chunked, replicated, checksummed...
    """

    def __init__(self, name, ec=False, **kwargs):
        self._name = name
        self._ec = ec
        self.type = None
        self._params = kwargs

    @property
    def name(self):
        return self._name

    @property
    def ec(self):
        return self._ec

    @property
    def quorum(self):
        raise NotImplementedError

    @property
    def expected_chunks(self):
        raise NotImplementedError

    @property
    def min_chunks_to_read(self):
        raise NotImplementedError

    def to_chunk_method(self):
        """
        Serialize this to a chunk_method string.
        """
        return unparse_chunk_method("ec" if self.ec else "plain", self.params)

    @property
    def params(self):
        """
        Get the dictionary of parameters of the chunk method.
        """
        return self._params

    def fix_missing_checksum_algo(
        self, chunk_checksum_algo="blake3", object_checksum_algo="md5"
    ):
        """
        Set the chunk checksum algorithm and the object checksum algorithm
        in case they are not already present in the storage method.
        """
        self.params.setdefault("cca", chunk_checksum_algo)
        self.params.setdefault("oca", object_checksum_algo)


class ReplicatedStorageMethod(StorageMethod):
    def __init__(self, name, nb_copy, **kwargs):
        super().__init__(name=name, **kwargs)

        try:
            self._params["nb_copy"] = int(nb_copy)
        except (TypeError, ValueError) as exc:
            raise exceptions.InvalidStorageMethod(f"Invalid {nb_copy} nb_copy") from exc
        self._quorum = (self.nb_copy + 1) // 2

    @classmethod
    def build(cls, params):
        nb_copy = params.pop("nb_copy", 1)
        return cls("repli", nb_copy, **params)

    @property
    def quorum(self):
        return self._quorum

    @property
    def expected_chunks(self):
        return self.params["nb_copy"]

    @property
    def min_chunks_to_read(self):
        return 1

    @property
    def nb_copy(self):
        return self.params["nb_copy"]


class ECStorageMethod(StorageMethod):
    def __init__(
        self,
        name,
        ec_segment_size,
        ec_type,
        ec_nb_data,
        ec_nb_parity,
        checksum_type="none",
        **kwargs,
    ):
        super().__init__(name=name, ec=True, **kwargs)

        try:
            self.params["k"] = int(ec_nb_data)
        except (TypeError, ValueError) as exc:
            raise exceptions.InvalidStorageMethod(
                f"Invalid value {ec_nb_data!r} for ec_nb_data"
            ) from exc

        try:
            self.params["m"] = int(ec_nb_parity)
        except (TypeError, ValueError) as exc:
            raise exceptions.InvalidStorageMethod(
                f"Invalid value {ec_nb_parity!r} for ec_nb_parity"
            ) from exc

        self._ec_segment_size = ec_segment_size
        self.params["algo"] = ec_type

        try:
            self.driver = ECDriver(
                k=ec_nb_data,
                m=ec_nb_parity,
                ec_type=ec_type,
                chksum_type=checksum_type,  # Not a typo
            )
        except ECDriverError as exc:
            msg = (
                f"'{ec_type}' ({exc.__class__.__name__}: {exc}) "
                "Check erasure code packages."
            )
            raise exceptions.InvalidStorageMethod(msg) from exc
        self._ec_quorum_size = (
            self.ec_nb_data + self.driver.min_parity_fragments_needed()
        )

    @classmethod
    def build(cls, params):
        ec_nb_data = params.pop("k")
        ec_nb_parity = params.pop("m")
        ec_type = params.pop("algo")
        return cls(
            "ec",
            ec_segment_size=EC_SEGMENT_SIZE,
            ec_type=ec_type,
            ec_nb_data=ec_nb_data,
            ec_nb_parity=ec_nb_parity,
            **params,
        )

    @property
    def quorum(self):
        return self._ec_quorum_size

    @property
    def expected_chunks(self):
        return self.params["k"] + self.params["m"]

    @property
    def min_chunks_to_read(self):
        return self.params["k"]

    @property
    def ec_type(self):
        return self.params["algo"]

    @property
    def ec_nb_data(self):
        return self.params["k"]

    @property
    def ec_nb_parity(self):
        return self.params["m"]

    @property
    def ec_segment_size(self):
        return self._ec_segment_size

    @property
    def ec_fragment_size(self):
        return self.driver.get_segment_info(self.ec_segment_size, self.ec_segment_size)[
            "fragment_size"
        ]


def load_methods():
    global _STORAGE_METHODS
    methods = {"plain": ReplicatedStorageMethod, "ec": ECStorageMethod}
    _STORAGE_METHODS = StorageMethods(methods)


class StorageMethodLoad(object):
    def __getattribute__(self, name):
        return getattr(_STORAGE_METHODS, name)


_STORAGE_METHODS = None
load_methods()
STORAGE_METHODS = StorageMethodLoad()
