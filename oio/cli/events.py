import logging

from cliff import show


class StatsEvents(show.ShowOne):
    """Stats events"""

    log = logging.getLogger(__name__ + '.StatsEvents')

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        data = self.app.client_manager.storage_internal.event_stats()
        return zip(*sorted(data.iteritems()))
