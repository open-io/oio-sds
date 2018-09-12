# Copyright (C) 2015-2018 OpenIO SAS, as part of OpenIO SDS
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
from oio.common.http_urllib3 import urllibexc
from oio.conscience.checker.base import BaseChecker


class HttpChecker(BaseChecker):
    name = 'http'

    def configure(self):
        for k in ['host', 'port', 'uri']:
            if k not in self.checker_conf:
                raise exc.ConfigurationException(
                    'Missing field "%s" in configuration' % k)

        self.host = self.checker_conf['host']
        self.port = self.checker_conf['port']
        self.path = self.checker_conf['uri']
        self.name = '%s|http|%s|%s|%s' % \
            (self.srv_type, self.host, self.port, self.path)
        self.url = '%s:%s/%s' % (self.host, self.port, self.path)

    def check(self):
        success = False
        resp = None
        try:
            # We have clues that the connection will be reused quickly to get
            # stats, thus we do not explicitely require its closure.
            resp = self.agent.pool_manager.request("GET", self.url)
            if resp.status == 200:
                success = True
            else:
                raise Exception("status code != 200: %s" % resp.status)
        except Exception as e:
            self.logger.warn('ERROR performing http check (%s): %s',
                             self.url, e)
        finally:
            if resp:
                try:
                    resp.close()
                except urllibexc.HTTPError:
                    pass
            if not success:
                self.logger.warn('%s check failed', self.name)
            return success
