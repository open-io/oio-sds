# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2022-2023 OVH SAS
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

from oio.common import exceptions as exc
from oio.common.constants import REQID_HEADER
from oio.common.http_urllib3 import urllibexc
from oio.conscience.checker.base import BaseChecker


class HttpChecker(BaseChecker):
    checker_type = "http"

    def _configure(self):
        for k in ("uri",):
            if k not in self.checker_conf:
                raise exc.ConfigurationException(
                    f'Missing field "{k}" in configuration'
                )

        self.path = self.checker_conf["uri"].lstrip("/")
        self.name = f"{self.name}|{self.path}"
        self.url = "%s:%s%s%s" % (
            self.host,
            self.port,
            "" if self.path.startswith("/") else "/",
            self.path,
        )

    def _check(self, reqid=None):
        resp = None
        try:
            # We have clues that the connection will be reused quickly to get
            # stats, thus we do not explicitly require its closure.
            hdrs = {REQID_HEADER: reqid}
            resp = self.agent.pool_manager.request("GET", self.url, headers=hdrs)
            if resp.status == 200:
                self.last_check_success = True
            else:
                raise Exception(f"({resp.status}) {resp.data.decode('utf-8')}")
        except Exception as err:
            # Avoid spamming the logs
            if self.last_check_success:
                self.logger.warn(
                    "ERROR performing %s check (%s reqid=%s): %s",
                    self.checker_type,
                    self.url,
                    reqid,
                    err,
                )
            self.last_check_success = False
        finally:
            if resp:
                try:
                    # Probably useless since we do not disable preload_content
                    resp.drain_conn()
                    resp.close()
                except urllibexc.HTTPError:
                    pass
            if not self.last_check_success:
                self.logger.warn("%s check failed (reqid=%s)", self.name, reqid)
            return self.last_check_success
