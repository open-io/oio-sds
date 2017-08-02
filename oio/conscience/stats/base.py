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


class BaseStat(object):
    """Base class for all service stat"""

    def __init__(self, agent, stat_conf, logger):
        self.agent = agent
        self.stat_conf = stat_conf
        self.logger = logger
        self.configure()

    def configure(self):
        """Configuration handle"""
        pass

    def stat(self):
        """Actually do the service stat"""
        return {}
