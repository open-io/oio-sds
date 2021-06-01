# Copyright (C) 2018-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021 OVH SAS
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

from logging import getLogger
from six import iteritems

from oio.cli import Lister
from oio.common.exceptions import OioException
from oio.rdir.client import DEFAULT_RDIR_REPLICAS


def _format_assignments(all_services, svc_col_title='Rawx'):
    """Prepare the list of results for display"""
    # Possible improvement: if we do not sort by rdir,
    # we can yield results instead of building a list.
    results = list()
    for svc in all_services:
        rdirs = svc.get('rdir', [{'addr': 'n/a', 'tags': {}}])
        joined_ids = ','.join((r['tags'].get('tag.service_id') or r['addr'])
                              for r in rdirs)
        joined_loc = ','.join(r['tags'].get('tag.loc')
                              for r in rdirs)
        results.append(
            (svc['tags'].get('tag.service_id') or svc['addr'],
             joined_ids,
             svc['tags'].get('tag.loc'),
             joined_loc))

    results.sort()
    columns = (svc_col_title, 'Rdir',
               '%s location' % svc_col_title, 'Rdir location')
    return columns, results


class RdirBootstrap(Lister):
    """Assign rdir services"""

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
        parser.add_argument(
            '--replicas',
            metavar='<N>',
            type=int,
            default=DEFAULT_RDIR_REPLICAS,
            help="Number of rdir replication per service.")
        parser.add_argument(
            '--service-id',
            metavar='<service-id>',
            help="Assign an rdir only for this service ID.")
        parser.add_argument(
            '--dry-run', action='store_true',
            help='Display actions but do nothing.')
        return parser

    def take_action(self, parsed_args):
        dispatcher = self.app.client_manager.rdir_dispatcher
        try:
            all_services = dispatcher.assign_services(
                parsed_args.service_type,
                max_per_rdir=parsed_args.max_per_rdir,
                min_dist=parsed_args.min_dist,
                replicas=parsed_args.replicas,
                service_id=parsed_args.service_id,
                dry_run=parsed_args.dry_run,
                connection_timeout=30.0, read_timeout=90.0)
        except OioException as exc:
            self.success = False
            self.log.warning('Failed to assign all %s services: %s',
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
            dummy_rdir = [{"addr": {"n/a"}, "tags": {}}]
            rdir_by_id = dict()
            managed_svc = dict()

            for svc in all_services:
                rdirs = svc.get('rdir', dummy_rdir)
                for rdir in rdirs:
                    rdir_id = rdir['tags'].get('tag.service_id') or \
                              rdir['addr']
                    rdir_by_id[rdir_id] = rdir
                    svc_id = svc['tags'].get('tag.service_id') or svc['addr']
                    try:
                        managed_svc[rdir_id].append(svc_id)
                    except KeyError:
                        managed_svc[rdir_id] = [svc_id]
            for rdir in all_rdir:
                rdir_id = rdir['tags'].get('tag.service_id') or rdir['addr']
                if rdir_id not in rdir_by_id:
                    managed_svc[rdir_id] = list()
                    rdir_by_id[rdir_id] = rdir
            for addr, rdir in iteritems(rdir_by_id):
                results.append((addr,
                                len(managed_svc[addr]),
                                ' '.join(managed_svc[addr])))
            results.sort()
            columns = ('Rdir', 'Number of bases', 'Bases')
        return columns, results


class RdirReassign(Lister):
    """
    Reassign rdir services.

    This command does not copy the old databases to the new host, neither
    removes them.

    You can either use the dry-run mode, copy the database to the suggested
    host, then force the assignment with 'openio reference force --replace'.
    Or use the standard mode and let the crawlers reindex everything into
    the new host.
    """

    log = getLogger(__name__ + '.RdirReassign')

    def get_parser(self, prog_name):
        parser = super(RdirReassign, self).get_parser(prog_name)
        parser.add_argument(
            'service_type',
            help="Which service type to assign rdir to.")
        parser.add_argument(
            'rdir_id',
            help="ID of an rdir service to be replaced.")
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
        parser.add_argument(
            '--replicas',
            metavar='<N>',
            type=int,
            default=DEFAULT_RDIR_REPLICAS,
            help="Number of rdir(s) per service.")
        parser.add_argument(
            '--service-id',
            metavar='<service-id>',
            help="Assign an rdir only for this service ID.")
        parser.add_argument(
            '--dry-run', action='store_true',
            help='Display actions but do nothing.')
        return parser

    def take_action(self, parsed_args):
        dispatcher = self.app.client_manager.rdir_dispatcher
        try:
            all_services = dispatcher.assign_services(
                parsed_args.service_type,
                reassign=parsed_args.rdir_id,
                service_id=parsed_args.service_id,
                max_per_rdir=parsed_args.max_per_rdir,
                min_dist=parsed_args.min_dist,
                replicas=parsed_args.replicas,
                dry_run=parsed_args.dry_run,
                connection_timeout=30.0, read_timeout=90.0)
        except OioException as exc:
            self.success = False
            self.log.warning('Failed to assign all %s services: %s',
                             parsed_args.service_type, exc)
            all_services, _ = dispatcher.get_assignments(
                parsed_args.service_type, connection_timeout=30.0,
                read_timeout=90.0)
        return _format_assignments(all_services,
                                   parsed_args.service_type.capitalize())
