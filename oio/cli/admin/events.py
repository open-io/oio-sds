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


class EventsExhume(show.ShowOne):
    """
    Exhume (replay) events that have been buried.
    """

    log = logging.getLogger(__name__ + '.EventsExhume')

    def get_parser(self, prog_name):
        parser = super(EventsExhume, self).get_parser(prog_name)
        parser.add_argument(
            '--tube',
            default="oio",
            help='Name of the tube to interact with (defaults to "oio")')
        parser.add_argument(
            '--limit',
            type=int,
            default=1000,
            help='Maximum number of events to exhume (defaults to 1000)')
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        count = self.app.client_manager.admin.event.exhume(parsed_args.limit,
                                                           parsed_args.tube)
        return [("Exhumed",), (count,)]
