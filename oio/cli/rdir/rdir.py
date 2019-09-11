# Copyright (C) 2018-2019 OpenIO SAS, as part of OpenIO SDS
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
from six import iteritems

from oio.cli import Lister
from oio.common.exceptions import OioException


def _format_assignments(all_services, svc_col_title='Rawx'):
    """Prepare the list of results for display"""
    # Possible improvement: if we do not sort by rdir,
    # we can yield results instead of building a list.
    results = list()
    for svc in all_services:
        rdir = svc.get('rdir', {'addr': 'n/a', 'tags': {}})
        results.append(
            (rdir['tags'].get('tag.service_id') or rdir['addr'],
             svc['tags'].get('tag.service_id') or svc['addr'],
             rdir['tags'].get('tag.loc'),
             svc['tags'].get('tag.loc')))
    results.sort()
    columns = ('Rdir', svc_col_title,
               'Rdir location', '%s location' % svc_col_title)
    return columns, results


class RdirBootstrap(Lister):
    """Assign an rdir services"""

    log = getLogger(__name__ + '.RdirBootstrap')

    def get_parser(self, prog_name):
        parser = super(RdirBootstrap, self).get_parser(prog_name)
        parser.add_argument(
            'service_type',
            help="Which service type to assign rdir to.")
        parser.add_argument(
            '--max-per-rdir',
            metavar='<N>',
            type=int,
            help="Maximum number of databases per rdir service.")
        parser.add_argument(
            '--min-dist',
            metavar='<N>',
            type=int,
            help=("Minimum required distance between any service and "
                  "its assigned rdir service."))
        return parser

    def take_action(self, parsed_args):
        dispatcher = self.app.client_manager.rdir_dispatcher
        try:
            all_services = dispatcher.assign_services(
                parsed_args.service_type, parsed_args.max_per_rdir,
                min_dist=parsed_args.min_dist,
                connection_timeout=30.0, read_timeout=90.0)
        except OioException as exc:
            self.success = False
            self.log.warn('Failed to assign all %s services: %s',
                          parsed_args.service_type, exc)
            all_services, _ = dispatcher.get_assignments(
                parsed_args.service_type, connection_timeout=30.0,
                read_timeout=90.0)
        return _format_assignments(all_services,
                                   parsed_args.service_type.capitalize())


class RdirAssignments(Lister):
    """Display which rdir service is linked to each other service"""

    log = getLogger(__name__ + '.DisplayVolumeAssignation')

    def get_parser(self, prog_name):
        parser = super(RdirAssignments, self).get_parser(prog_name)
        parser.add_argument(
            'service_type',
            help="Which service type to diplay rdir assignments")
        parser.add_argument(
            '--aggregated',
            action="store_true",
            help="Display an aggregation of the assignation")
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        all_services, all_rdir = \
            self.app.client_manager.rdir_dispatcher.get_assignments(
                parsed_args.service_type,
                connection_timeout=30.0, read_timeout=90.0)

        results = list()
        if not parsed_args.aggregated:
            columns, results = _format_assignments(
                all_services, parsed_args.service_type.capitalize())
        else:
            dummy_rdir = {"addr": "n/a", "tags": {}}
            rdir_by_id = dict()
            for svc in all_services:
                rdir = svc.get('rdir', dummy_rdir)
                rdir_id = rdir['tags'].get('tag.service_id') or rdir['addr']
                rdir_by_id[rdir_id] = rdir
                managed_svc = rdir.get('managed_svc') or list()
                svc_id = svc['tags'].get('tag.service_id') or svc['addr']
                managed_svc.append(svc_id)
                rdir['managed_svc'] = managed_svc
            for rdir in all_rdir:
                rdir_id = rdir['tags'].get('tag.service_id') or rdir['addr']
                if rdir_id not in rdir_by_id:
                    rdir['managed_svc'] = list()
                    rdir_by_id[rdir_id] = rdir
            for addr, rdir in iteritems(rdir_by_id):
                results.append((addr,
                                len(rdir['managed_svc']),
                                ' '.join(rdir['managed_svc'])))
            results.sort()
            columns = ('Rdir', 'Number of bases', 'Bases')
        return columns, results
