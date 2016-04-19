"""Meta0 actions for the 'openio' CLI"""

import logging

from cliff.command import Command
from oio.directory.meta0 import PrefixMapping


class Meta0Cmd(Command):
    """Base class for meta0 subcommands"""

    log = logging.getLogger(__name__ + '.Meta0')

    def get_parser(self, prog_name):
        parser = super(Meta0Cmd, self).get_parser(prog_name)
        parser.add_argument('--replicas', metavar='<N>', dest='replicas',
                            type=int, default=3,
                            help='Set the number of replicas')
        parser.add_argument('ns', metavar='<NAMESPACE>',
                            help='Namespace name')
        return parser

    def get_prefix_mapping(self, parsed_args):
        return PrefixMapping(parsed_args.ns, replicas=parsed_args.replicas,
                             logger=self.log)


class Meta0Init(Meta0Cmd):
    """Initialize the meta0"""

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        mapping = self.get_prefix_mapping(parsed_args)

        # Bootstrap with the 'random' strategy, then rebalance with the
        # 'less_prefixes' strategy to ensure the same number of prefixes
        # per meta1. This is faster than bootstrapping directly with the
        # 'less_prefixes' strategy.
        mapping.bootstrap()
        mapping.rebalance()
        # Now save the mapping.
        mapping.force()


class Meta0List(Meta0Cmd):
    """List the content of the meta0"""

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        mapping = self.get_prefix_mapping(parsed_args)
        mapping.load()
        print mapping.to_json()


class Meta0Rebalance(Meta0Cmd):
    """Rebalance the container prefixes over all the available meta1"""

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        mapping = self.get_prefix_mapping(parsed_args)
        mapping.load()
        mapping.rebalance()
        mapping.force()


class Meta0Decommission(Meta0Cmd):
    """Decommission a Meta1 service"""

    def get_parser(self, prog_name):
        parser = super(Meta0Decommission, self).get_parser(prog_name)
        parser.add_argument('addr', metavar='<ADDR>',
                            help='Address of service to decommission')
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        mapping = self.get_prefix_mapping(parsed_args)
        mapping.load()
        mapping.decommission(parsed_args.addr)
        mapping.force()
