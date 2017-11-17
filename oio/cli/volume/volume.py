# Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
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

from oio.cli import Lister, ShowOne
from oio.cli.rdir.rdir import _format_assignments
from oio.common.exceptions import OioException


class ShowAdminVolume(ShowOne):
    """
    Show information about a volume, like the last incident date,
    or the presence of a lock on the volume.

    An empty output means there is no lock and incident on the volume.
    """

    log = getLogger(__name__ + '.ShowAdminVolume')

    def get_parser(self, prog_name):
        parser = super(ShowAdminVolume, self).get_parser(prog_name)
        parser.add_argument(
            'volume',
            metavar='<volume>',
            help='ID of the rawx service')
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        output = list()
        output.append(('volume', parsed_args.volume))
        data = self.app.client_manager.volume.volume_admin_show(
            volume=parsed_args.volume)
        for k, v in sorted(iteritems(data)):
            output.append((k, v))
        return list(zip(*output))


class ClearAdminVolume(Lister):
    """Clear volume incident date."""

    log = getLogger(__name__ + '.ClearAdminVolume')

    def get_parser(self, prog_name):
        parser = super(ClearAdminVolume, self).get_parser(prog_name)
        parser.add_argument(
            'volumes',
            metavar='<volumes>',
            nargs='+',
            help='IDs of the rawx services',
        )
        parser.add_argument(
            '--all',
            dest='clear_all',
            default=False,
            help="Clear all chunks entries",
            action='store_true'
        )
        parser.add_argument(
            '--before-incident',
            dest='before_incident',
            default=False,
            help="Clear all chunks entries before incident date",
            action='store_true'
        )
        parser.add_argument(
            '--repair',
            dest='repair',
            default=False,
            help="Repair all chunks entries",
            action='store_true'
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        volumes = parsed_args.volumes

        results = list()
        for volume in volumes:
            try:
                resp_body = self.app.client_manager.volume.volume_admin_clear(
                        volume, clear_all=parsed_args.clear_all,
                        before_incident=parsed_args.before_incident,
                        repair=parsed_args.repair)
                results.append((volume, True, resp_body))
            except OioException as exc:
                self.success = False
                results.append((volume, False, exc))
        columns = ('Volume', 'Success', 'Message')
        return columns, results


class ShowVolume(ShowOne):
    """
    Show various volume information, like number of indexed chunks,
    and names of containers having chunks on this volume.
    """

    log = getLogger(__name__ + '.ShowVolume')

    def get_parser(self, prog_name):
        parser = super(ShowVolume, self).get_parser(prog_name)
        parser.add_argument(
            'volume',
            metavar='<volume>',
            help='ID of the rawx service',
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        data = self.app.client_manager.volume.volume_show(
            volume=parsed_args.volume, read_timeout=60.0
        )
        return list(zip(*sorted(data.items())))


class IncidentAdminVolume(Lister):
    """Declare an incident on the specified volume."""

    log = getLogger(__name__ + '.IncidentAdminVolume')

    def get_parser(self, prog_name):
        parser = super(IncidentAdminVolume, self).get_parser(prog_name)
        parser.add_argument(
            'volumes',
            metavar='<volumes>',
            nargs='+',
            help='IDs of the rawx services',
        )
        parser.add_argument(
            '--date',
            metavar='<key>',
            default=[],
            type=int,
            action='append',
            help='Incident date to set (seconds since Epoch)')
        return parser

    def take_action(self, parsed_args):
        from time import time

        self.log.debug('take_action(%s)', parsed_args)

        volumes = parsed_args.volumes
        dates = parsed_args.date

        results = list()
        for volume in volumes:
            date = dates.pop(0) if dates else int(time())
            self.app.client_manager.volume.volume_admin_incident(
                    volume, date)
            results.append((volume, date))
        columns = ('Volume', 'Date')
        return columns, results


class LockAdminVolume(Lister):
    """
    Lock the specified volumes.
    Useful to prevent several rebuilders to work on the same volume.
    """

    log = getLogger(__name__ + '.LockAdminVolume')

    def get_parser(self, prog_name):
        parser = super(LockAdminVolume, self).get_parser(prog_name)
        parser.add_argument(
            'volumes',
            metavar='<volumes>',
            nargs='+',
            help='IDs of the rawx services')
        parser.add_argument(
            '--key',
            metavar='<key>',
            required=True,
            help='Identifier of what is locking the volume')
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        volumes = parsed_args.volumes
        key = parsed_args.key

        results = list()
        for volume in volumes:
            self.app.client_manager.volume.volume_admin_lock(
                volume, key)
            results.append((volume, True))
        columns = ('Volume', 'Success')
        return columns, results


class UnlockAdminVolume(Lister):
    """Unlock the specified volumes."""

    log = getLogger(__name__ + '.UnlockAdminVolume')

    def get_parser(self, prog_name):
        parser = super(UnlockAdminVolume, self).get_parser(prog_name)
        parser.add_argument(
            'volumes',
            metavar='<volumes>',
            nargs='+',
            help='IDs of the rawx services')
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        volumes = parsed_args.volumes

        results = list()
        for volume in volumes:
            self.app.client_manager.volume.volume_admin_unlock(
                volume)
            results.append((volume, True))
        columns = ('Volume', 'Success')
        return columns, results


class BootstrapVolume(Lister):
    """
    Assign an rdir service to all rawx.
    Deprecated, prefer using 'openio rdir bootstrap rawx'.
    """

    log = getLogger(__name__ + '.BootstrapVolume')

    def get_parser(self, prog_name):
        parser = super(BootstrapVolume, self).get_parser(prog_name)
        parser.add_argument(
            '--max-per-rdir',
            metavar='<N>',
            type=int,
            help="Maximum number of databases per rdir service")
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        self.log.warn("Deprecated, prefer using 'openio rdir bootstrap rawx'.")

        try:
            all_rawx = self.app.client_manager.volume.rdir_lb.assign_all_rawx(
                    parsed_args.max_per_rdir,
                    connection_timeout=30.0, read_timeout=90.0)
        except OioException as exc:
            self.success = False
            self.log.warn("Failed to assign all rawx: %s", exc)
            all_rawx, _ = \
                self.app.client_manager.volume.rdir_lb.get_assignments(
                        'rawx', connection_timeout=30.0, read_timeout=90.0)

        columns, results = _format_assignments(all_rawx, 'Rawx')
        return columns, results


class DisplayVolumeAssignation(Lister):
    """
    Display which rdir service is linked to each rawx service.
    Deprecated, prefer using 'openio rdir assignments rawx'.
    """

    log = getLogger(__name__ + '.DisplayVolumeAssignation')

    def get_parser(self, prog_name):
        parser = super(DisplayVolumeAssignation, self).get_parser(prog_name)
        parser.add_argument(
            '--aggregated',
            action="store_true",
            help="Display an aggregation of the assignment")
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        self.log.warn(
            "Deprecated, prefer using 'openio rdir assignments rawx'.")

        all_rawx, all_rdir = \
            self.app.client_manager.volume.rdir_lb.get_assignments(
                    'rawx', connection_timeout=30.0, read_timeout=90.0)

        results = list()
        if not parsed_args.aggregated:
            columns, results = _format_assignments(all_rawx, 'Rawx')
        else:
            dummy_rdir = {"addr": "n/a", "tags": {}}
            rdir_by_id = dict()
            for rawx in all_rawx:
                rdir = rawx.get('rdir', dummy_rdir)
                rdir_id = rdir['tags'].get('tag.service_id') or rdir['addr']
                rdir_by_id[rdir_id] = rdir
                managed_rawx = rdir.get('managed_rawx') or list()
                rawx_id = rawx['tags'].get('tag.service_id') or rawx['addr']
                managed_rawx.append(rawx_id)
                rdir['managed_rawx'] = managed_rawx
            for rdir in all_rdir:
                rdir_id = rdir['tags'].get('tag.service_id') or rdir['addr']
                if rdir_id not in rdir_by_id:
                    rdir['managed_rawx'] = list()
                    rdir_by_id[rdir_id] = rdir
            for addr, rdir in iteritems(rdir_by_id):
                results.append((addr,
                                len(rdir['managed_rawx']),
                                ' '.join(rdir['managed_rawx'])))
            results.sort()
            columns = ('Rdir', 'Number of bases', 'Bases')
        return columns, results
