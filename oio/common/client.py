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

from oio.common.utils import get_logger
from oio.common.utils import load_namespace_conf
from oio.common.utils import validate_service_conf
from oio.api.base import HttpApi


class ProxyClient(HttpApi):
    """
    Client directed towards oio-proxy, with logging facility
    """

    def __init__(self, conf, pool_manager=None, request_prefix="",
                 no_ns_in_url=False, endpoint=None, **kwargs):
        """
        :param pool_manager: an optional pool manager that will be reused
        :type pool_manager: `urllib3.PoolManager`
        :param request_prefix: text to insert in between endpoint and
            requested URL
        :type request_prefix: `str`
        :param no_ns_in_url: do not insert namespace name between endpoint
            and `request_prefix`
        :type no_ns_in_url: `bool`
        """
        validate_service_conf(conf)
        self.ns = conf.get('namespace')
        self.conf = conf
        self.logger = get_logger(conf)

        ep_parts = list()
        if endpoint:
            self.proxy_netloc = endpoint[7:]  # skip "http://"
            ep_parts.append(endpoint)
        else:
            ns_conf = load_namespace_conf(self.ns)
            self.proxy_netloc = ns_conf.get('proxy')
            ep_parts.append("http:/")
            ep_parts.append(self.proxy_netloc)

        ep_parts.append("v3.0")
        if not no_ns_in_url:
            ep_parts.append(self.ns)
        if request_prefix:
            ep_parts.append(request_prefix.lstrip('/'))
        super(ProxyClient, self).__init__(endpoint='/'.join(ep_parts),
                                          **kwargs)

    def _direct_request(self, method, url, headers=None,
                        **kwargs):
        if kwargs.get("autocreate"):
            if not headers:
                headers = dict()
            headers["X-oio-action-mode"] = "autocreate"
            kwargs = kwargs.copy()
            kwargs.pop("autocreate")
        return super(ProxyClient, self)._direct_request(
            method, url, headers=headers, **kwargs)
