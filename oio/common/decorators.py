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

from functools import wraps
from oio.common.utils import request_id


def ensure_headers(func):
    @wraps(func)
    def ensure_headers_wrapper(*args, **kwargs):
        kwargs['headers'] = kwargs.get('headers') or dict()
        return func(*args, **kwargs)
    return ensure_headers_wrapper


def ensure_request_id(func):
    @wraps(func)
    def ensure_request_id_wrapper(*args, **kwargs):
        headers = kwargs['headers']
        if 'X-oio-req-id' not in headers:
            headers['X-oio-req-id'] = request_id()
        return func(*args, **kwargs)
    return ensure_request_id_wrapper
