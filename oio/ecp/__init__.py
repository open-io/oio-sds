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

import errno
from os import read
import eventlet

from ctypes import CDLL, c_int, c_void_p, py_object

try:
    from pyeclib.ec_iface import ECDriver, ECDriverError
except ImportError as err:
    EC_MSG = "Erasure coding not available: %s" % err

    class ECDriverError(RuntimeError):
        pass

    class ECDriver(object):
        """Dummy wrapper for ECDriver, when erasure-coding is not available."""
        def __init__(self, *_args, **_kwargs):
            raise ECDriverError(EC_MSG)


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


def _raise_errcode(err):
    raise Exception("EC encode failure")


def encode(algo, k, m, data):
    """
    Apply the given EC algorithm and return the fragments.
    But do not block the current thread doing it
    """
    job = _lib.ecp_job_init(algo, k, m)
    _lib.ecp_job_set_original(job, data, len(data))
    try:
        _lib.ecp_job_encode(job)
        fd = _lib.ecp_job_fd(job)
        done = False
        # Loop until the non-blocking FD, loop until we have errno=EAGAIN
        while not done:
            # create a listener on fd and swithc to another greenlet
            eventlet.hubs.trampoline(fd, read=True)
            try:
                if len(read(fd, 8)):
                    done = True
            except OSError as ex:
                if ex.errno == errno.EAGAIN:
                    continue
                raise
        rc = _lib.ecp_job_status(job)
        if 0 == rc:
            return _lib.ecp_job_get_fragments(job)
        _raise_errcode(rc)
    finally:
        _lib.ecp_job_close(job)


class OioEcDriver(ECDriver):
    """Mimic the pyeclib driver interface"""

    def __init__(self, **kwargs):
        super(OioEcDriver, self).__init__(**kwargs)

    def encode(self, data):
        return encode(self.ec_type.value, self.k, self.m, data)
