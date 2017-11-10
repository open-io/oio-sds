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

from logging import getLogger

LOG = getLogger(__name__)

API_NAME = 'directory'


class DirectoryClientCli(object):
    def __init__(self, namespace, **kwargs):
        self.conf = {'namespace': namespace}
        self.conf.update(kwargs)
        self._cluster = None
        self._rdir_lb = None
        self._meta0 = None

    @property
    def cluster(self):
        if not self._cluster:
            from oio.conscience.client import ConscienceClient
            self._cluster = ConscienceClient(self.conf)
        return self._cluster

    @property
    def rdir_lb(self):
        if not self._rdir_lb:
            from oio.rdir.client import RdirDispatcher
            self._rdir_lb = RdirDispatcher(self.conf)
        return self._rdir_lb

    @property
    def meta0(self):
        if not self._meta0:
            from oio.directory.meta0 import Meta0Client
            self._meta0 = Meta0Client(self.conf)
        return self._meta0


def make_client(instance):
    """
    Build a DirectoryClientCli that will be added as "directory"
    field of `instance`.

    :param instance: an instance of ClientManager
    :returns: an instance of DirectoryClientCli
    """
    client = DirectoryClientCli(
        **instance.cli_conf()
    )
    return client
