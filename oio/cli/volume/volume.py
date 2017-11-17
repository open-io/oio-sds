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

from six import iteritems
from logging import getLogger
from cliff import lister, show


class ShowAdminVolume(show.ShowOne):
    """Show admin volume"""

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
        for k, v in sorted(iteritems(data)):
            output.append((k, v))
        return list(zip(*output))


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
        return list(zip(*sorted(data.items())))


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


class BootstrapVolume(lister.Lister):
    """Assign an rdir service to all rawx"""

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
        from oio.common.exceptions import ClientException

        self.log.debug('take_action(%s)', parsed_args)

        try:
            all_rawx = self.app.client_manager.volume.rdir_lb.assign_all_rawx(
                    parsed_args.max_per_rdir)
        except ClientException as exc:
            if exc.status != 481:
                raise
            self.log.warn("Failed to assign all rawx: %s", exc)
            all_rawx, _ = \
                self.app.client_manager.volume.rdir_lb.get_assignation()

        results = list()
        for rawx in all_rawx:
            rdir = rawx.get('rdir', {"addr": "n/a", "tags": {}})
            results.append((rdir['addr'],
                            rawx['addr'],
                            rdir['tags'].get('tag.loc'),
                            rawx['tags'].get('tag.loc')))
        results.sort()
        columns = ('Rdir', 'Rawx', 'Rdir location', 'Rawx location')
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
            self.app.client_manager.volume.rdir_lb.get_assignation()

        results = list()
        if not parsed_args.aggregated:
            for rawx in all_rawx:
                rdir = rawx.get('rdir', {"addr": "n/a", "tags": {}})
                results.append((rdir['addr'],
                                rawx['addr'],
                                rdir['tags'].get('tag.loc'),
                                rawx['tags'].get('tag.loc')))
            results.sort()
            columns = ('Rdir', 'Rawx', 'Rdir location', 'Rawx location')
        else:
            dummy_rdir = {"addr": "n/a", "tags": {}}
            rdir_by_addr = dict()
            for rawx in all_rawx:
                rdir = rawx.get('rdir', dummy_rdir)
                rdir_by_addr[rdir["addr"]] = rdir
                managed_rawx = rdir.get('managed_rawx') or list()
                managed_rawx.append(rawx['addr'])
                rdir['managed_rawx'] = managed_rawx
            for rdir in all_rdir:
                if rdir['addr'] not in rdir_by_addr:
                    rdir['managed_rawx'] = list()
                    rdir_by_addr[rdir["addr"]] = rdir
            for addr, rdir in iteritems(rdir_by_addr):
                results.append((addr,
                                len(rdir['managed_rawx']),
                                ' '.join(rdir['managed_rawx'])))
            results.sort()
            columns = ('Rdir', 'Number of bases', 'Bases')
        return columns, results
