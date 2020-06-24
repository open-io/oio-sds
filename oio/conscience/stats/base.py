# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
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


class BaseStat(object):
    """Base class for all service statistics collectors."""

    def __init__(self, agent, stat_conf, logger):
        self.agent = agent
        self.stat_conf = stat_conf
        self.logger = logger
        self.configure()

    def configure(self):
        """Configure the statistics collector."""
        pass

    def get_stats(self):
        """Actually collect the service statistics."""
        raise NotImplementedError()
