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


from time import time
from urlparse import urlparse

from oio.common.http_urllib3 import get_pool_manager
from oio.common.logger import get_logger
from oio.conscience.client import ConscienceClient


CACHE_TIMEOUT = 60  # in seconds


class ServiceCache(object):
    """A caching client to rawx services."""

    def __init__(self, conf, pool_manager=None):
        self._cache = dict()
        self.conf = conf
        self.pool_manager = pool_manager or get_pool_manager()
        self._client = ConscienceClient(conf=self.conf,
                                        pool_manager=self.pool_manager)
        self.logger = get_logger(conf)

    def _get_addr(self, item):
        if item in self._cache and self._cache[item]['ts'] < time():
            return self._cache[item]['addr']
        body = self._client.resolve(srv_type='rawx', service_id=item)
        self._cache[item] = {'addr': body['addr'],
                             'ts': time() + CACHE_TIMEOUT}
        return body['addr']

    def resolve(self, url):
        """
        :rtype: return resolved url of a rawx using Service-ID
        """
        # FIXME(mb) some tests doesn't put scheme, should fix tests
        if not url.startswith('http://'):
            url = "http://" + url
        res = urlparse(url)
        if res.port == 80 or res.port is None:
            service_id_or_host = urlparse(url).hostname
            host = self._get_addr(service_id_or_host)
            if host != service_id_or_host:
                url = res.scheme + "://" + host + res.path
                if res.query:
                    url += '?' + res.query
        return url
