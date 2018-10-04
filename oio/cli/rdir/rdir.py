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
from cliff import lister
from oio.cli.volume.volume import BootstrapVolume
from oio.cli.common.clientmanager import get_plugin_module


def _format_assignments(service_providers, service_type):
    """Prepare the list of results for display"""
    # FIXME: Copypasta from RDIR/RAWX assignment, possible factorization?
    results = list()
    for service_provider in service_providers:
        rdir = service_provider.get('rdir', {'addr': 'n/a', 'tags': {}})
        results.append(
            (rdir['tags'].get('tag.service_id') or rdir['addr'],
             service_provider['tags'].get('tag.service_id') or
             service_provider['addr'],
             rdir['tags'].get('tag.loc'),
             service_provider['tags'].get('tag.loc')))
    results.sort()
    columns = ('RDIR', 'META2', 'RDIR location', 'META2 location')
    return columns, results


class BootstrapMeta2(lister.Lister):
    """Assign an rdir service to all meta2"""

    log = getLogger(__name__ + '.BootstrapMeta2')

    def __init__(self, *args, **kwargs):
        super(BootstrapMeta2, self).__init__(*args, **kwargs)
        self.error = None

    def get_parser(self, prog_name):
        parser = super(BootstrapMeta2, self).get_parser(prog_name)
        parser.add_argument(
            '--max-per-rdir',
            metavar='<N>',
            type=int,
            help="Maximum number of databases per rdir service")
        return parser

    def take_action(self, parsed_args):
        from oio.common.exceptions import OioException
        try:
            all_meta2 = self.app.client_manager.rdir.rdir_lb.assign_all_meta2(
                parsed_args.max_per_rdir,
                connection_timeout=30.0, read_timeout=90.0
            )
        except OioException as exc:
            self.log.warn("Failed to assign all META2 servers: %s", exc)
            self.error = exc
            all_meta2, _ = \
                self.app.client_manager.rdir.rdir_lb.get_assignments_generic(
                    "meta2",
                    connection_timeout=30.0,
                    read_timeout=90.0
                )
        return _format_assignments(all_meta2, "meta2")


class BootstrapRawx(BootstrapVolume):
    log = getLogger(__name__ + '.BootstrapRawx')

    def __init__(self, *args, **kwargs):
        super(BootstrapRawx, self).__init__(*args, **kwargs)
        self.error = None
        # MONKEY PAAAAAATCH ! (But not really)
        # Yes I'm very aware this is illegal and jail worthy.
        get_plugin_module('oio.cli.volume.client')
