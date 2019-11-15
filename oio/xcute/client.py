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

import sys
import time

from oio.api.base import HttpApi
from oio.common.exceptions import OioException, OioNetworkException
from oio.common.logger import get_logger
from oio.conscience.client import ConscienceClient


class XcuteClient(HttpApi):
    """Simple client API for the xcute service."""

    def __init__(self, conf, endpoint=None, proxy_endpoint=None,
                 refresh_delay=3600.0, logger=None, **kwargs):
        """
        Initialize a client for the xcute service.

        :param conf: dictionary with at least the namespace name
        :type conf: `dict`
        :param endpoint: URL of an xcute service
        :param proxy_endpoint: URL of the proxy
        :param refresh_interval: time between refreshes of the
        xcute service endpoint (if not provided at instantiation)
        :type refresh_interval: `float` seconds
        """
        super(XcuteClient, self).__init__(
            endpoint=endpoint, service_type='xcute-service', **kwargs)
        self.conf = conf
        self.logger = logger or get_logger(self.conf)

        self.conscience = ConscienceClient(conf, endpoint=proxy_endpoint,
                                           logger=self.logger, **kwargs)

        self._refresh_delay = refresh_delay if not self.endpoint else -1.0
        self._last_refresh = 0.0

    def _get_xcute_addr(self, **kwargs):
        """Fetch IP and port of an xcute service from Conscience."""
        acct_instance = self.conscience.next_instance('xcute', **kwargs)
        acct_addr = acct_instance.get('addr')
        return acct_addr

    def _refresh_endpoint(self, now=None, **kwargs):
        """Refresh xcute service endpoint."""
        addr = self._get_xcute_addr(**kwargs)
        self.endpoint = '/'. join(("http:/", addr, "v1.0/xcute"))
        if not now:
            now = time.time()
        self._last_refresh = now

    def _maybe_refresh_endpoint(self, **kwargs):
        """Refresh xcute service endpoint if delay has been reached."""
        if self._refresh_delay >= 0.0 or not self.endpoint:
            now = time.time()
            if now - self._last_refresh > self._refresh_delay:
                try:
                    self._refresh_endpoint(now, **kwargs)
                except OioNetworkException as exc:
                    if not self.endpoint:
                        # Cannot use the previous one
                        raise
                    self.logger.warn(
                            "Failed to refresh xcute endpoint: %s", exc)
                except OioException:
                    if not self.endpoint:
                        # Cannot use the previous one
                        raise
                    self.logger.exception("Failed to refresh xcute endpoint")

    def xcute_request(self, method, action, params=None, **kwargs):
        """Make a request to the xcute service."""
        self._maybe_refresh_endpoint(**kwargs)
        if not params:
            params = dict()
        try:
            resp, body = self._request(method, action, params=params, **kwargs)
        except OioNetworkException as exc:
            exc_info = sys.exc_info()
            if self._refresh_delay >= 0.0:
                self.logger.info(
                    "Refreshing xcute endpoint after error %s", exc)
                try:
                    self._refresh_endpoint(**kwargs)
                except Exception as exc:
                    self.logger.warn("%s", exc)
            raise exc_info[0], exc_info[1], exc_info[2]
        return resp, body

    def job_list(self, orchestrator_id=None, limit=None, marker=None):
        params = {
            'limit': limit,
            'marker': marker
        }
        _, data = self.xcute_request('GET', '/jobs', params=params)
        return data

    def job_create(self, job_type, job_config=None):
        job_info = {
            'type': job_type,
            'config': job_config
        }
        _, data = self.xcute_request('POST', '/jobs', json=job_info)
        return data

    def job_show(self, job_id):
        _, data = self.xcute_request('GET', '/jobs/%s' % job_id)
        return data

    def job_pause(self, job_id):
        self.xcute_request('POST', '/jobs/%s/pause' % job_id)

    def job_resume(self, job_id):
        self.xcute_request('POST', '/jobs/%s/resume' % job_id)

    def job_delete(self, job_id):
        self.xcute_request('DELETE', '/jobs/%s' % job_id)
