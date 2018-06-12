# Copyright (C) 2015-2018 OpenIO SAS, as part of OpenIO SDS
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
from cliff import lister, show


class ShowAdminVolume(show.ShowOne):
    """
    Show information about a volume, especially the last incident date.
    """

    log = getLogger(__name__ + '.ShowAdminVolume')

    def get_parser(self, prog_name):
        parser = super(ShowAdminVolume, self).get_parser(prog_name)
        parser.add_argument(
            'volume',
            metavar='<volume>',
            help='IP:PORT of the rawx service')
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        output = list()
        output.append(('volume', parsed_args.volume))
        data = self.app.client_manager.volume.volume_admin_show(
            volume=parsed_args.volume)
        for k, v in sorted(data.iteritems()):
            output.append((k, v))
        return zip(*output)


class ClearAdminVolume(lister.Lister):
    """Clear admin volume"""

    log = getLogger(__name__ + '.ClearAdminVolume')

    def get_parser(self, prog_name):
        parser = super(ClearAdminVolume, self).get_parser(prog_name)
        parser.add_argument(
            'volumes',
            metavar='<volumes>',
            nargs='+',
            help='IP:PORT of the rawx services',
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        volumes = parsed_args.volumes

        results = list()
        for volume in volumes:
            self.app.client_manager.volume.volume_admin_clear(
                    volume)
            results.append((volume, True))
        columns = ('Volume', 'Success')
        return columns, results


class ShowVolume(show.ShowOne):
    """Show volume"""

    log = getLogger(__name__ + '.ShowVolume')

    def get_parser(self, prog_name):
        parser = super(ShowVolume, self).get_parser(prog_name)
        parser.add_argument(
            'volume',
            metavar='<volume>',
            help='IP:PORT of the rawx service',
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        data = self.app.client_manager.volume.volume_show(
            volume=parsed_args.volume
        )
        return zip(*sorted(data.iteritems()))


class IncidentAdminVolume(lister.Lister):
    """Set incident on Volume"""

    log = getLogger(__name__ + '.IncidentAdminVolume')

    def get_parser(self, prog_name):
        parser = super(IncidentAdminVolume, self).get_parser(prog_name)
        parser.add_argument(
            'volumes',
            metavar='<volumes>',
            nargs='+',
            help='IP:PORT of the rawx services',
        )
        parser.add_argument(
            '--date',
            metavar='<key>',
            default=[],
            type=int,
            action='append',
            help='Incident date to set (seconds)')
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


class LockAdminVolume(lister.Lister):
    """Lock Volume"""

    log = getLogger(__name__ + '.LockAdminVolume')

    def get_parser(self, prog_name):
        parser = super(LockAdminVolume, self).get_parser(prog_name)
        parser.add_argument(
            'volumes',
            metavar='<volumes>',
            nargs='+',
            help='IP:PORT of the rawx services')
        parser.add_argument(
            '--key',
            metavar='<key>',
            required=True,
            help='Lock key')
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


class UnlockAdminVolume(lister.Lister):
    """Unlock Volume"""

    log = getLogger(__name__ + '.UnlockAdminVolume')

    def get_parser(self, prog_name):
        parser = super(UnlockAdminVolume, self).get_parser(prog_name)
        parser.add_argument(
            'volumes',
            metavar='<volumes>',
            nargs='+',
            help='IP:PORT of the rawx services')
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


def _format_assignation(all_rawx):
    """Prepare the list of results for display"""
    # Possible improvement: if we do not sort by rdir,
    # we can yield results instead of building a list.
    results = list()
    for rawx in all_rawx:
        rdir = rawx.get('rdir', {'addr': 'n/a', 'tags': {}})
        results.append(
            (rdir['tags'].get('tag.service_id') or rdir['addr'],
             rawx['tags'].get('tag.service_id') or rawx['addr'],
             rdir['tags'].get('tag.loc'),
             rawx['tags'].get('tag.loc')))
    results.sort()
    columns = ('Rdir', 'Rawx', 'Rdir location', 'Rawx location')
    return columns, results


class BootstrapVolume(lister.Lister):
    """Assign an rdir service to all rawx"""

    log = getLogger(__name__ + '.BootstrapVolume')

    def __init__(self, *args, **kwargs):
        super(BootstrapVolume, self).__init__(*args, **kwargs)
        self.error = None

    def get_parser(self, prog_name):
        parser = super(BootstrapVolume, self).get_parser(prog_name)
        parser.add_argument(
            '--max-per-rdir',
            metavar='<N>',
            type=int,
            help="Maximum number of databases per rdir service")
        return parser

    def take_action(self, parsed_args):
        from oio.common.exceptions import OioException

        self.log.debug('take_action(%s)', parsed_args)

        try:
            all_rawx = self.app.client_manager.volume.rdir_lb.assign_all_rawx(
                    parsed_args.max_per_rdir,
                    connection_timeout=30.0, read_timeout=90.0)
        except OioException as exc:
            self.log.warn("Failed to assign all rawx: %s", exc)
            self.error = exc
            all_rawx, _ = \
                self.app.client_manager.volume.rdir_lb.get_assignation(
                        connection_timeout=30.0, read_timeout=90.0)

        columns, results = _format_assignation(all_rawx)
        # FIXME(FVE): return 1 if self.error
        return columns, results


class DisplayVolumeAssignation(lister.Lister):
    """Display which rdir service is linked to each rawx service"""

    log = getLogger(__name__ + '.DisplayVolumeAssignation')

    def get_parser(self, prog_name):
        parser = super(DisplayVolumeAssignation, self).get_parser(prog_name)
        parser.add_argument(
            '--aggregated',
            action="store_true",
            help="Display an aggregation of the assignation")
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        all_rawx, all_rdir = \
            self.app.client_manager.volume.rdir_lb.get_assignation(
                    connection_timeout=30.0, read_timeout=90.0)

        results = list()
        if not parsed_args.aggregated:
            columns, results = _format_assignation(all_rawx)
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
            for addr, rdir in rdir_by_id.iteritems():
                results.append((addr,
                                len(rdir['managed_rawx']),
                                ' '.join(rdir['managed_rawx'])))
            results.sort()
            columns = ('Rdir', 'Number of bases', 'Bases')
        return columns, results
