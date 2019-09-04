# Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from oio.common import exceptions as exc
from oio.common.constants import REQID_HEADER
from oio.common.http_urllib3 import urllibexc
from oio.common.utils import request_id
from oio.conscience.checker.base import BaseChecker


class HttpChecker(BaseChecker):
    checker_type = 'http'

    def _configure(self):
        for k in ('uri', ):
            if k not in self.checker_conf:
                raise exc.ConfigurationException(
                    'Missing field "%s" in configuration' % k)

        self.path = self.checker_conf['uri'].lstrip('/')
        self.name = '%s|%s' % (self.name, self.path)
        self.url = '%s:%s%s%s' % (self.host, self.port,
                                  '' if self.path.startswith('/') else '/',
                                  self.path)

    def _check(self):
        resp = None
        try:
            # We have clues that the connection will be reused quickly to get
            # stats, thus we do not explicitely require its closure.
            hdrs = {REQID_HEADER: request_id('chk-')}
            resp = self.agent.pool_manager.request("GET", self.url,
                                                   headers=hdrs)
            if resp.status == 200:
                self.last_check_success = True
            else:
                raise Exception("status code != 200: %s" % resp.status)
        except Exception as err:
            # Avoid spamming the logs
            if self.last_check_success:
                self.logger.warn('ERROR performing %s check (%s): %s',
                                 self.checker_type, self.url, err)
            self.last_check_success = False
        finally:
            if resp:
                try:
                    resp.close()
                except urllibexc.HTTPError:
                    pass
            if not self.last_check_success:
                self.logger.warn('%s check failed', self.name)
            return self.last_check_success
