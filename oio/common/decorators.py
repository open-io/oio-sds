# Copyright (C) 2017-2019 OpenIO SAS, as part of OpenIO SDS
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

from functools import wraps
from oio.common.constants import REQID_HEADER
from oio.common.utils import request_id, set_deadline_from_read_timeout
from oio.common.exceptions import NotFound, NoSuchAccount, NoSuchObject, \
    NoSuchContainer, reraise


def ensure_headers(func):
    @wraps(func)
    def ensure_headers_wrapper(*args, **kwargs):
        if kwargs.setdefault('headers', dict()) is None:
            kwargs['headers'] = dict()
        return func(*args, **kwargs)
    return ensure_headers_wrapper


def ensure_request_id(func):
    @wraps(func)
    def ensure_request_id_wrapper(*args, **kwargs):
        headers = kwargs.setdefault('headers', dict())
        # Old style request ID
        if REQID_HEADER not in headers:
            if 'reqid' in kwargs:
                headers[REQID_HEADER] = kwargs.pop('reqid')
            else:
                headers[REQID_HEADER] = request_id()
            kwargs['headers'] = headers
        # New style request ID
        if 'reqid' not in kwargs:
            kwargs['reqid'] = kwargs['headers'][REQID_HEADER]
        return func(*args, **kwargs)
    return ensure_request_id_wrapper


def ensure_request_id2(prefix=''):
    """Ensure the subsequent RPCs will have a request ID."""
    def _ensure_request_id(func):
        @wraps(func)
        def ensure_request_id_wrapper(*args, **kwargs):
            headers = kwargs.setdefault('headers', dict())
            # Old style request ID
            if REQID_HEADER not in headers:
                if 'reqid' in kwargs:
                    headers[REQID_HEADER] = kwargs.pop('reqid')
                else:
                    headers[REQID_HEADER] = request_id(prefix=prefix)
                kwargs['headers'] = headers
            # New style request ID
            if 'reqid' not in kwargs:
                kwargs['reqid'] = kwargs['headers'][REQID_HEADER]
            return func(*args, **kwargs)
        return ensure_request_id_wrapper
    return _ensure_request_id


def handle_account_not_found(fnc):
    @wraps(fnc)
    def _wrapped(self, account=None, *args, **kwargs):
        try:
            return fnc(self, account, *args, **kwargs)
        except NotFound as err:
            err.message = "Account '%s' does not exist." % account
            reraise(NoSuchAccount, err)
    return _wrapped


def handle_container_not_found(fnc):
    @wraps(fnc)
    def _wrapped(self, account, container, *args, **kwargs):
        try:
            return fnc(self, account, container, *args, **kwargs)
        except NotFound as err:
            err.message = "Container '%s' does not exist." % container
            reraise(NoSuchContainer, err)
    return _wrapped


def handle_object_not_found(fnc):
    """
    Catch `oio.common.exceptions.NotFound` exceptions and raise either
    `oio.common.exceptions.NoSuchContainer` or
    `oio.common.exceptions.NoSuchObject` respectively if the container
    is missing or the object is missing.
    """
    @wraps(fnc)
    def _wrapped(self, account, container, obj, *args, **kwargs):
        try:
            return fnc(self, account, container, obj, *args, **kwargs)
        except NotFound as err:
            if err.status in (406, 431):
                err.message = "Container '%s' does not exist." % container
                reraise(NoSuchContainer, err)
            else:
                err.message = "Object '%s' does not exist." % obj
                reraise(NoSuchObject, err)
    return _wrapped


def patch_kwargs(fnc):
    """
    Patch keyword arguments with the ones passed to the class' constructor.
    Compute a deadline if a timeout is provided and there is no deadline
    already. Requires the class to have a `_global_kwargs` member (dict).
    """
    @wraps(fnc)
    def _patch_kwargs(self, *args, **kwargs):
        for argk, argv in self._global_kwargs.items():
            if argk not in kwargs:
                kwargs[argk] = argv
        set_deadline_from_read_timeout(kwargs)
        return fnc(self, *args, **kwargs)
    return _patch_kwargs
