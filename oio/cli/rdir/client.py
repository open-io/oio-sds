# Copyright (C) 2018 OpenIO SAS, as part of OpenIO SDS
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

API_NAME = 'rdir'


# Could be useful later on if we want to have access to RdirClient too
# and maybe other stuff.
class RdirClientCli(object):

    def __init__(self, namespace, **kwargs):
        self.conf = {'namespace': namespace}
        self.conf.update(kwargs)
        self._rdir_lb = None

    @property
    def rdir_lb(self):
        if not self._rdir_lb:
            from oio.rdir.client import RdirDispatcher
            self._rdir_lb = RdirDispatcher(self.conf)
        return self._rdir_lb


def make_client(instance):
    """
    Build an RdirClientCli that will be added as "rdir"
    field of `instance`.

    :param instance: an instance of ClientManager
    :returns: an instance of VolumeClientCli
    """
    client = RdirClientCli(
        **instance.cli_conf()
    )
    return client
