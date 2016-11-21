import logging
import time

from cliff.command import Command
from oio.directory.meta0 import PrefixMapping


class DirectoryCmd(Command):
    """Base class for directory subcommands"""

    log = logging.getLogger(__name__ + '.Directory')

    def get_parser(self, prog_name):
        parser = super(DirectoryCmd, self).get_parser(prog_name)
        parser.add_argument('--replicas', metavar='<N>', dest='replicas',
                            type=int, default=3,
                            help='Set the number of replicas')
        return parser

    def get_prefix_mapping(self, parsed_args):
        meta0_client = self.app.client_manager.admin.meta0
        conscience_client = self.app.client_manager.admin.cluster
        digits = self.app.client_manager.get_meta1_digits()
        return PrefixMapping(meta0_client, conscience_client,
                             replicas=parsed_args.replicas,
                             digits=digits,
                             logger=self.log)


class DirectoryInit(DirectoryCmd):
    """Initialize the directory"""

    def get_parser(self, prog_name):
        parser = super(DirectoryInit, self).get_parser(prog_name)
        parser.add_argument('--no-rdir',
                            dest='rdir',
                            action='store_false',
                            default=True,
                            help='Do not assign rdir services to rawx services'
                            )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        mapping = self.get_prefix_mapping(parsed_args)

        # Bootstrap with the 'random' strategy, then rebalance with the
        # 'less_prefixes' strategy to ensure the same number of prefixes
        # per meta1. This is faster than bootstrapping directly with the
        # 'less_prefixes' strategy.
        self.log.info("Computing meta1 prefix mapping...")
        mapping.bootstrap()
        self.log.info("Equilibrating...")
        mapping.rebalance()
        self.log.info("Saving...")
        mapping.force()
        if parsed_args.rdir:
            self.log.info("Assigning rdir services to rawx services...")
            time.sleep(5)  # Let meta1 fetch the list of managed bases
            self.app.client_manager.admin.volume.assign_all_rawx()
        self.log.info("Done")


class DirectoryList(DirectoryCmd):
    """List the content of the directory"""

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        mapping = self.get_prefix_mapping(parsed_args)
        mapping.load()
        print mapping.to_json()


class DirectoryRebalance(DirectoryCmd):
    """Rebalance the container prefixes"""

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        mapping = self.get_prefix_mapping(parsed_args)
        mapping.load()
        mapping.rebalance()
        mapping.force()


class DirectoryDecommission(DirectoryCmd):
    """Decommission a Meta1 service"""

    def get_parser(self, prog_name):
        parser = super(DirectoryDecommission, self).get_parser(prog_name)
        parser.add_argument('addr', metavar='<ADDR>',
                            help='Address of service to decommission')
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        mapping = self.get_prefix_mapping(parsed_args)
        mapping.load()
        mapping.decommission(parsed_args.addr)
        mapping.force()
