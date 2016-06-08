import logging

from cliff import show


class StatsEvents(show.ShowOne):
    """Stats events"""

    log = logging.getLogger(__name__ + '.StatsEvents')

    def get_parser(self, prog_name):
        parser = super(StatsEvents, self).get_parser(prog_name)
        parser.add_argument(
            '--tube',
            metavar='<tube>',
            help='Tube name')
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        data = self.app.client_manager.admin.event_stats(
            parsed_args.tube)
        return zip(*sorted(data.iteritems()))
