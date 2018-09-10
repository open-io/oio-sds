# Copyright (C) 2017-2018 OpenIO SAS, as part of OpenIO SDS
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

from urlparse import urlparse
from eventlet import patcher
from urllib3 import exceptions as urllibexc
from oio.common.exceptions import reraise, \
    OioException, OioNetworkException, OioTimeout


urllib3 = patcher.import_patched('urllib3.__init__')


DEFAULT_POOLSIZE = 32
DEFAULT_RETRIES = 0
DEFAULT_BACKOFF = 0


def get_pool_manager(pool_connections=DEFAULT_POOLSIZE,
                     pool_maxsize=DEFAULT_POOLSIZE,
                     max_retries=DEFAULT_RETRIES,
                     backoff_factor=DEFAULT_BACKOFF):
    """
    Get `urllib3.PoolManager` to manage pools of connections

    :param pool_connections: number of connection pools
    :type pool_connections: `int`
    :param pool_maxsize: number of connections per connection pool
    :type pool_maxsize: `int`
    :param max_retries: number of retries per request
    :type max_retries: `int`
    :param backoff_factor: backoff factor to apply between attemps after
        second try
    :type backoff_factor: `float`

    """
    if max_retries == DEFAULT_RETRIES:
        max_retries = urllib3.Retry(0, read=False)
    else:
        max_retries = urllib3.Retry(total=max_retries,
                                    backoff_factor=backoff_factor)
    return urllib3.PoolManager(num_pools=pool_connections,
                               maxsize=pool_maxsize, retries=max_retries,
                               block=False)


def oio_exception_from_httperror(exc, reqid=None, url=None):
    """
    Convert an HTTPError from urllib3 to an OioException,
    and re-raise it.
    """
    extra_dict = dict()
    if reqid:
        extra_dict['reqid'] = reqid
    if url:
        extra_dict['host'] = urlparse(url).netloc
    extra = ', '.join('%s=%s' % x for x in extra_dict.items())
    if isinstance(exc, urllibexc.MaxRetryError):
        if isinstance(exc.reason, urllibexc.NewConnectionError):
            reraise(OioNetworkException, exc.reason, extra)
        if isinstance(exc.reason, urllibexc.TimeoutError):
            reraise(OioTimeout, exc.reason, extra)
        reraise(OioNetworkException, exc, extra)
    elif isinstance(exc, (urllibexc.ProtocolError,
                          urllibexc.ProxyError,
                          urllibexc.ClosedPoolError)):
        reraise(OioNetworkException, exc, extra)
    elif isinstance(exc, urllibexc.TimeoutError):
        reraise(OioTimeout, exc, extra)
    else:
        reraise(OioException, exc, extra)
