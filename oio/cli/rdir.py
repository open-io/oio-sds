import logging

from cliff import show


class DumpVolume(show.ShowOne):
    """Dump volume"""

    log = logging.getLogger(__name__ + '.DumpVolume')

    def get_parser(self, prog_name):
        parser = super(DumpVolume, self).get_parser(prog_name)
        parser.add_argument(
            'volume',
            metavar='<volume>',
            help='Volume to dump',
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        data = self.app.client_manager.storage_internal.volume_dump(
            volume=parsed_args.volume
        )
        return zip(*sorted(data.iteritems()))
