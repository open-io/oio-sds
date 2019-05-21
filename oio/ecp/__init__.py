# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
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

from os import read
from ctypes import CDLL, c_int, c_void_p, py_object


__author__ = "jfsmig"


# Prepare the env
_lib = CDLL('liboioecp.so.0')
_lib.ecp_job_init.argtypes = (c_int, c_int, c_int)
_lib.ecp_job_init.restype = c_void_p
_lib.ecp_job_fd.argtypes = (c_void_p,)
_lib.ecp_job_fd.restype = c_int
_lib.ecp_job_status.argtypes = (c_void_p,)
_lib.ecp_job_status.restype = c_int
_lib.ecp_job_encode.argtypes = (c_void_p,)
_lib.ecp_job_decode.argtypes = (c_void_p,)
_lib.ecp_job_close.argtypes = (c_void_p,)
_lib.ecp_job_set_original.argtypes = (c_void_p, c_void_p, c_int)
_lib.ecp_job_get_fragments.argtypes = (c_void_p, )
_lib.ecp_job_get_fragments.restype = py_object


# Export one variable per algorithm
algo_LIBERASURECODE_RS_VAND = c_int.in_dll(_lib, "algo_LIBERASURECODE_RS_VAND")
algo_JERASURE_RS_VAND = c_int.in_dll(_lib, "algo_JERASURE_RS_VAND")
algo_JERASURE_RS_CAUCHY = c_int.in_dll(_lib, "algo_JERASURE_RS_CAUCHY")
algo_ISA_L_RS_VAND = c_int.in_dll(_lib, "algo_ISA_L_RS_VAND")
algo_ISA_L_RS_CAUCHY = c_int.in_dll(_lib, "algo_ISA_L_RS_CAUCHY")
algo_SHSS = c_int.in_dll(_lib, "algo_SHSS")
algo_LIBPHAZR = c_int.in_dll(_lib, "algo_LIBPHAZR")


def encode(algo, k, m, data):
    """
    Apply the given EC algorithm and return the fragments.
    """
    job = _lib.ecp_job_init(algo, k, m)
    _lib.ecp_job_set_original(job, data, len(data))
    try:
        _lib.ecp_job_encode(job)
        fd = _lib.ecp_job_fd(job)
        read(fd, 8)
        if 0 == _lib.ecp_job_status(job):
            return _lib.ecp_job_get_fragments(job)
        raise Exception("EC encode failure")
    finally:
        _lib.ecp_job_close(job)


class ECDriver(object):
    """Mimic the pyeclib driver interface"""

    def __init__(self, k=1, m=1, ec_type=None):
        self.k = k
        self.m = m
        self.algo = ec_type

    def min_parity_fragments_needed(self):
        return 0

    def get_segment_info(self, size, _ignored):
        # return {"fragment_size": 0}
        raise Exception("NYI")

    def encode(self, data):
        return encode(self.algo, k, m, data)

    def decode(self, fragments):
        raise Exception("NYI")

    def reconstruct(self, fragments, missing):
        raise Exception("NYI")
