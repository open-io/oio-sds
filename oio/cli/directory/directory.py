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
        parser.add_argument(
            '--meta0-timeout', metavar='<SECONDS>', type=float, default=30.0,
            help="Timeout for meta0-related operations (30.0s by default)")
        return parser

    def get_prefix_mapping(self, parsed_args):
        from oio.directory.meta0 import PrefixMapping

        meta0_client = self.app.client_manager.directory.meta0
        conscience_client = self.app.client_manager.directory.cluster
        digits = self.app.client_manager.meta1_digits
        return PrefixMapping(meta0_client, conscience_client,
                             replicas=parsed_args.replicas,
                             digits=digits,
                             min_dist=parsed_args.min_dist,
                             logger=self.log)


class DirectoryInit(DirectoryCmd):
    """
    Initialize the service directory.
    Distribute database prefixes among meta1 services and fill the meta0.
    Also assign one rdir service for each rawx service.
    """

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

    def _assign_meta1(self, parsed_args):
        mapping = self.get_prefix_mapping(parsed_args)
        mapping.load(read_timeout=parsed_args.meta0_timeout)

        if mapping and not parsed_args.force:
            self.log.info("Meta1 prefix mapping already initialized")
            if not parsed_args.check:
                return True
            self.log.info("Checking...")
            return mapping.check_replicas()

        # Bootstrap with the 'random' strategy, then rebalance with the
        # 'less_prefixes' strategy to ensure the same number of prefixes
        # per meta1. This is faster than bootstrapping directly with the
        # 'less_prefixes' strategy.
        checked = False
        for i in range(3):
            self.log.info("Computing meta1 prefix mapping (pass %d)", i)
            mapping.bootstrap()

            self.log.info("Equilibrating...")
            mapping.rebalance()

            if parsed_args.check:
                self.log.info("Checking...")
                checked = mapping.check_replicas()
            else:
                checked = True

            if checked:
                break

        if checked:
            self.log.info("Saving...")
            mapping.apply(connection_timeout=5.0,
                          read_timeout=parsed_args.meta0_timeout)
        else:
            raise Exception("Failed to initialize prefix mapping")
        return checked

    def _assign_rdir(self):
        from time import sleep

        self.log.info("Assigning rdir services to rawx services...")
        max_attempts = 3
        for i in range(max_attempts):
            sleep(5 + i)
            try:
                self.app.client_manager.directory.rdir_lb.assign_all_rawx()
            except ServiceUnavailable as e:
                if i < (max_attempts - 1):
                    self.log.info("Retrying because of %s", e)
                    continue
                raise

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        checked = self._assign_meta1(parsed_args)
        if parsed_args.rdir:
            self._assign_rdir()

        if checked:
            self.log.info("Done")
        else:
            self.log.warn("Errors encountered")
            raise Exception("Bad meta1 prefix mapping")


class DirectoryList(DirectoryCmd):
    """
    List the content of meta0 database as a JSON object.

    WARNING: output is >2MB.
    """

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        mapping = self.get_prefix_mapping(parsed_args)
        mapping.load(read_timeout=parsed_args.meta0_timeout)
        print(mapping.to_json())


class DirectoryRebalance(DirectoryCmd):
    """Rebalance the container prefixes."""

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        mapping = self.get_prefix_mapping(parsed_args)
        mapping.load(read_timeout=parsed_args.meta0_timeout)
        moved = mapping.rebalance()
        mapping.apply(moved, read_timeout=parsed_args.meta0_timeout)
        self.log.info("Moved %s", moved)


class DirectoryDecommission(DirectoryCmd):
    """Decommission a Meta1 service (or only some bases)."""

    def get_parser(self, prog_name):
        parser = super(DirectoryDecommission, self).get_parser(prog_name)
        parser.add_argument('addr', metavar='<ADDR>',
                            help='Address of service to decommission')
        parser.add_argument('base', metavar='<BASE>', nargs='*',
                            help="Name of bases to decommission")
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        mapping = self.get_prefix_mapping(parsed_args)
        mapping.load(read_timeout=parsed_args.meta0_timeout)
        moved = mapping.decommission(parsed_args.addr,
                                     bases_to_remove=parsed_args.base)
        mapping.apply(moved, read_timeout=parsed_args.meta0_timeout)
        self.log.info("Moved %s", moved)
