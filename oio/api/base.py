# Copyright (C) 2015 OpenIO SAS

# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

from oio.common import exceptions
from oio.common.http import requests
from oio.common.constants import ADMIN_HEADER


class API(object):
    """
    The base class for all API.
    """

    def __init__(self, session=None, endpoint=None, **kwargs):
        super(API, self).__init__()
        if not session:
            session = requests.Session()
        self.session = session
        self.endpoint = endpoint
        self.admin_mode = kwargs.get('admin_mode', False)

    def _request(self, method, url, endpoint=None, session=None, **kwargs):
        if not endpoint:
            endpoint = self.endpoint
        url = '/'.join([endpoint.rstrip('/'), url.lstrip('/')])
        if not session:
            session = self.session
        headers = kwargs.get('headers') or {}
        headers = dict([k, str(headers[k])] for k in headers)
        value_admin = "1" if self.admin_mode else "0"
        headers.update({ADMIN_HEADER: value_admin})
        kwargs['headers'] = headers
        resp = session.request(method, url, **kwargs)
        try:
            body = resp.json()
        except ValueError:
            body = resp.content
        if resp.status_code >= 400:
            raise exceptions.from_response(resp, body)
        return resp, body
