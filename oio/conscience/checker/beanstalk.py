# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
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
from oio.event.beanstalk import Beanstalk, ConnectionError
from oio.conscience.checker.base import BaseChecker


class BeanstalkChecker(BaseChecker):
    name = 'beanstalkd'

    def configure(self):
        for k in ('host', 'port'):
            if k not in self.checker_conf:
                raise exc.ConfigurationException(
                    'Missing field "%s" in configuration' % k)
        self.__beanstalk = None
        self.host = self.checker_conf['host']
        self.port = int(self.checker_conf['port'])

    @property
    def beanstalk(self):
        if self.__beanstalk is None:
            self.__beanstalk = Beanstalk(self.host, self.port)
        return self.__beanstalk

    def check(self):
        result = False
        try:
            self.beanstalk.stats()
            result = True
        except ConnectionError as e:
            self.logger.warn(
                'ERROR connection lost to beanstalk (%s:%d) %s',
                self.host, self.port, e)
            self.__beanstalk = None
        except Exception as e:
            self.logger.warn('ERROR performing beanstalk check (%s:%s): %s',
                             self.host, self.port, e)
        finally:
            return result
