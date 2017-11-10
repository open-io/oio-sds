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

from logging import getLogger
from cliff.command import Command
from oio.common.exceptions import ServiceUnavailable


class DirectoryCmd(Command):
    """Base class for directory subcommands"""

    log = getLogger(__name__ + '.Directory')

    def get_parser(self, prog_name):
        parser = super(DirectoryCmd, self).get_parser(prog_name)
        parser.add_argument('--replicas', metavar='<N>', dest='replicas',
                            type=int, default=3,
                            help='Set the number of replicas (3 by default)')
        parser.add_argument('--min-dist', type=int, default=1,
                            help="Minimum distance between replicas")
        return parser

    def get_prefix_mapping(self, parsed_args):
        from oio.directory.meta0 import PrefixMapping

        meta0_client = self.app.client_manager.admin.meta0
        conscience_client = self.app.client_manager.admin.cluster
        digits = self.app.client_manager.get_meta1_digits()
        return PrefixMapping(meta0_client, conscience_client,
                             replicas=parsed_args.replicas,
                             digits=digits,
                             min_dist=parsed_args.min_dist,
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
        parser.add_argument('--force',
                            action='store_true',
                            help="Do the bootstrap even if already done")
        parser.add_argument(
            '--check',
            action='store_true',
            help="Check that all prefixes have the right number of replicas")
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        mapping = self.get_prefix_mapping(parsed_args)
        mapping.load()

        # Bootstrap with the 'random' strategy, then rebalance with the
        # 'less_prefixes' strategy to ensure the same number of prefixes
        # per meta1. This is faster than bootstrapping directly with the
        # 'less_prefixes' strategy.
        if not mapping or parsed_args.force:
            self.log.info("Computing meta1 prefix mapping...")
            mapping.bootstrap()
        else:
            self.log.info("Meta1 prefix mapping already initialized")

        self.log.info("Equilibrating...")
        mapping.rebalance()

        checked = not parsed_args.check
        if not checked:
            self.log.info("Checking...")
            checked = mapping.check_replicas()

        if checked:
            self.log.info("Saving...")
            mapping.force(connection_timeout=10.0, read_timeout=60.0)

        if parsed_args.rdir:
            from time import sleep

            self.log.info("Assigning rdir services to rawx services...")
            max_attempts = 3
            for i in range(max_attempts):
                sleep(5 + i)
                try:
                    self.app.client_manager.admin.rdir_lb.assign_all_rawx()
                except ServiceUnavailable as e:
                    if i < (max_attempts - 1):
                        self.log.info("Retrying because of %s", e)
                        continue
                    raise

        if checked:
            self.log.info("Done")
        else:
            self.log.warn("Errors encountered")
            raise Exception("Bad meta1 prefix mapping")


class DirectoryList(DirectoryCmd):
    """
    List the content of the directory as a JSON object.

    WARNING: output is >2MB.
    """

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
