import logging
import time

from cliff import lister
from cliff import show


class ShowAdminVolume(show.ShowOne):
    """Show admin volume"""

    log = logging.getLogger(__name__ + '.ShowAdminVolume')

    def get_parser(self, prog_name):
        parser = super(ShowAdminVolume, self).get_parser(prog_name)
        parser.add_argument(
            'volume',
            metavar='<volume>',
            help='Volume to show')
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        output = list()
        output.append(('volume', parsed_args.volume))
        data = self.app.client_manager.storage_internal.volume_admin_show(
            volume=parsed_args.volume)
        for k, v in sorted(data.iteritems()):
            output.append((k, v))
        return zip(*output)


class ClearAdminVolume(lister.Lister):
    """Clear admin volume"""

    log = logging.getLogger(__name__ + '.ClearAdminVolume')

    def get_parser(self, prog_name):
        parser = super(ClearAdminVolume, self).get_parser(prog_name)
        parser.add_argument(
            'volumes',
            metavar='<volumes>',
            nargs='+',
            help='Volume(s) to clear',
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        volumes = parsed_args.volumes

        results = list()
        for volume in volumes:
            self.app.client_manager.storage_internal.volume_admin_clear(
                    volume)
            results.append((volume, True))
        columns = ('Volume', 'Success')
        return columns, results


class ShowVolume(show.ShowOne):
    """Show volume"""

    log = logging.getLogger(__name__ + '.ShowVolume')

    def get_parser(self, prog_name):
        parser = super(ShowVolume, self).get_parser(prog_name)
        parser.add_argument(
            'volume',
            metavar='<volume>',
            help='Volume to show',
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        data = self.app.client_manager.storage_internal.volume_show(
            volume=parsed_args.volume
        )
        return zip(*sorted(data.iteritems()))


class IncidentAdminVolume(lister.Lister):
    """Set incident on Volume"""

    log = logging.getLogger(__name__ + '.IncidentAdminVolume')

    def get_parser(self, prog_name):
        parser = super(IncidentAdminVolume, self).get_parser(prog_name)
        parser.add_argument(
            'volumes',
            metavar='<volumes>',
            nargs='+',
            help='Volume(s) to set incident on',
        )
        parser.add_argument(
            '--date',
            metavar='<key>',
            default=[],
            action='append',
            help='Incident date to set')
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        volumes = parsed_args.volumes
        dates = parsed_args.date

        results = list()
        for volume in volumes:
            date = dates.pop(0) if dates else int(time.time())
            self.app.client_manager.storage_internal.volume_admin_incident(
                    volume, date)
            results.append((volume, date))
        columns = ('Volume', 'Date')
        return columns, results


class LockAdminVolume(lister.Lister):
    """Lock Volume"""

    log = logging.getLogger(__name__ + '.LockAdminVolume')

    def get_parser(self, prog_name):
        parser = super(LockAdminVolume, self).get_parser(prog_name)
        parser.add_argument(
            'volumes',
            metavar='<volumes>',
            nargs='+',
            help='Volume(s) to lock')
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
            self.app.client_manager.storage_internal.volume_admin_lock(
                volume, key)
            results.append((volume, True))
        columns = ('Volume', 'Success')
        return columns, results


class UnlockAdminVolume(lister.Lister):
    """Unlock Volume"""

    log = logging.getLogger(__name__ + '.UnlockAdminVolume')

    def get_parser(self, prog_name):
        parser = super(UnlockAdminVolume, self).get_parser(prog_name)
        parser.add_argument(
            'volumes',
            metavar='<volumes>',
            nargs='+',
            help='Volume(s) to unlock')
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        volumes = parsed_args.volumes

        results = list()
        for volume in volumes:
            self.app.client_manager.storage_internal.volume_admin_unlock(
                volume)
            results.append((volume, True))
        columns = ('Volume', 'Success')
        return columns, results
