import logging

from cliff import show


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
