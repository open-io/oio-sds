# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
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

from eventlet import Timeout
from oio.common.utils import float_value, RingBuffer


class BaseChecker(object):
    """Base class for all service checkers"""

    def __init__(self, agent, checker_conf, logger):
        self.agent = agent
        self.checker_conf = checker_conf
        self.logger = logger
        self.timeout = float_value(checker_conf.get('timeout'), 5.0)
        self.rise = checker_conf['rise']
        self.fall = checker_conf['fall']
        self.results = RingBuffer(max([self.rise, self.fall]))
        self.name = checker_conf.get('name')
        self.srv_type = agent.service['type']
        self.last_result = None
        self.configure()

    def configure(self):
        """Configuration handle"""
        pass

    def service_status(self):
        """Do the check and set `last_result` accordingly"""
        result = False
        try:
            with Timeout(self.timeout):
                result = self.check()
        except Timeout as e:
            self.logger.warn('check timed out')
        except Exception as e:
            self.logger.warn('check failed: %s', str(e.message))

        if self.last_result is None:
            self.last_result = result
            for _i in range(0, self.results.size):
                self.results.append(result)
            self.logger.info('%s first check returned %s', self.name, result)

        self.results.append(result)
        if not any(self.results[-self.fall:]):
            if self.last_result:
                self.logger.info(
                    '%s status is now down after %d failures', self.name,
                    self.fall)
                self.last_result = False
        if all(self.results[-self.rise:]):
            if not self.last_result:
                self.logger.info(
                    '%s status is now up after %d successes', self.name,
                    self.rise)
                self.last_result = True
        return self.last_result

    def check(self):
        """Actually do the service check"""
        return False
