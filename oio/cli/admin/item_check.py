# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
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


from cliff import lister

from oio.cli.admin.common import AccountCommandMixin, ContainerCommandMixin, \
    ObjectCommandMixin, ChunkCommandMixin
from oio.crawler.integrity import Checker, Target, DEFAULT_DEPTH


class ItemCheckCommand(lister.Lister):
    """
    Various parameters that apply to all check commands.
    """

    columns = ('Type', 'Item', 'Status', 'Errors')
    success = True
    checker = None

    @property
    def logger(self):
        return self.app.client_manager.logger

    def get_parser(self, prog_name):
        parser = super(ItemCheckCommand, self).get_parser(prog_name)
        parser.add_argument(
            '--attempts',
            type=int,
            default=1,
            help="Number of attempts for listing requests (default: 1)."
        )
        parser.add_argument(
            '--checksum',
            action='store_true',
            help=("Perform checksum comparisons.")
        )

        parser.add_argument(
            '--concurrency', '--workers', type=int,
            default=30,
            help="Number of concurrent checks (default: 30)."
        )
        parser.add_argument(
            '-o', '--output',
            help=("Output file. Will contain elements in error. "
                  "Can later be passed to stdin of the legacy "
                  "oio-crawler-integrity to re-check only these elements.")
        )
        parser.add_argument(
            '--output-for-chunk-rebuild',
            help=("Write chunk errors in a file with a format "
                  "suitable as 'openio-admin chunk rebuild' input.")
        )
        return parser

    def _take_action(self, parsed_args):
        raise NotImplementedError()

    def take_action(self, parsed_args):
        self.logger.debug('take_action(%s)', parsed_args)

        self.checker = Checker(
            self.app.options.ns,
            concurrency=parsed_args.concurrency,
            error_file=parsed_args.output,
            rebuild_file=parsed_args.output_for_chunk_rebuild,
            request_attempts=parsed_args.attempts,
            check_hash=parsed_args.checksum,
            logger=self.logger)

        return self.columns, self._take_action(parsed_args)

    def _format_results(self):
        for res in self.checker.run():
            if not res.has_errors:
                status = 'OK'
                yield (res.type, repr(res), status, str(None))
            else:
                self.success = False
                status = 'error'
                yield (res.type, repr(res),
                       status, res.latest_error_result().errors_to_str())

    def run(self, parsed_args):
        super(ItemCheckCommand, self).run(parsed_args)
        if not self.success:
            return 1


class RecursiveCheckCommand(ItemCheckCommand):
    """ItemCheckCommand with additional parameters to control recursion."""

    def get_parser(self, prog_name):
        parser = super(RecursiveCheckCommand, self).get_parser(prog_name)
        parser.add_argument(
            '--depth', '--max-depth',
            type=int,
            default=DEFAULT_DEPTH,
            help=("How deep to recurse. 0 means do not recurse. "
                  "N > 0 means recurse N levels below the specified item type "
                  "(namespace -> account -> container -> object -> chunk, "
                  "default: %d)." % DEFAULT_DEPTH)
        )
        return parser


class AccountCheck(AccountCommandMixin, RecursiveCheckCommand):
    """
    Check an account for problems.
    """

    def get_parser(self, prog_name):
        parser = super(AccountCheck, self).get_parser(prog_name)
        AccountCommandMixin.patch_parser(self, parser)
        return parser

    def _take_action(self, parsed_args):
        for acct in parsed_args.accounts:
            target = Target(acct)
            self.checker.check(target, parsed_args.depth)
        return self._format_results()

    def take_action(self, parsed_args):
        AccountCommandMixin.check_and_load_parsed_args(
            self, self.app, parsed_args)
        return super(AccountCheck, self).take_action(parsed_args)


class ContainerCheck(ContainerCommandMixin, RecursiveCheckCommand):
    """
    Check a container for problems.

    Quick checks on the account owning
    the container will also be performed.
    """

    def get_parser(self, prog_name):
        parser = super(ContainerCheck, self).get_parser(prog_name)
        ContainerCommandMixin.patch_parser(self, parser)
        return parser

    def _take_action(self, parsed_args):
        containers = self.resolve_containers(self.app, parsed_args, no_id=True)
        for account, container_name, _ in containers:
            target = Target(account, container_name)
            self.checker.check(target, parsed_args.depth)
        return self._format_results()

    def take_action(self, parsed_args):
        ContainerCommandMixin.check_and_load_parsed_args(
            self, self.app, parsed_args)
        return super(ContainerCheck, self).take_action(parsed_args)


class ObjectCheck(ObjectCommandMixin, RecursiveCheckCommand):
    """
    Check an object for problems.

    Quick checks on the account and the container
    owning the object will also be performed.
    """

    def get_parser(self, prog_name):
        parser = super(ObjectCheck, self).get_parser(prog_name)
        ObjectCommandMixin.patch_parser(self, parser)
        return parser

    def _take_action(self, parsed_args):
        account, _, objects = self.resolve_objects(self.app, parsed_args)
        for container, obj_name, version in objects:
            target = Target(account, container, obj_name, version=version)
            self.checker.check(target, parsed_args.depth)
        return self._format_results()

    def take_action(self, parsed_args):
        ObjectCommandMixin.check_and_load_parsed_args(
            self, self.app, parsed_args)
        return super(ObjectCheck, self).take_action(parsed_args)


class ChunkCheck(ChunkCommandMixin, ItemCheckCommand):
    """
    Check a chunk for problems.

    Quick checks on the account, the container
    and the object owning the chunk will also be performed.
    """

    def get_parser(self, prog_name):
        parser = super(ChunkCheck, self).get_parser(prog_name)
        ChunkCommandMixin.patch_parser(self, parser)
        return parser

    def _take_action(self, parsed_args):
        for chunk in parsed_args.chunks:
            target = Target(self.app.options.account, chunk=chunk)
            self.checker.check(target)
        return self._format_results()

    def take_action(self, parsed_args):
        ChunkCommandMixin.check_and_load_parsed_args(
            self, self.app, parsed_args)
        return super(ChunkCheck, self).take_action(parsed_args)
