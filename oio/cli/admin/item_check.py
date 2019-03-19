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

from oio.cli.admin.common import ContainerCommandMixin, ObjectCommandMixin
from oio.crawler.integrity import Checker, Target


class CheckCommandMixin(object):
    """
    Various parameters that apply to all check commands.
    """

    columns = ('Type', 'Item', 'Status', 'Errors')

    def build_checker(self, parsed_args):
        """Build an instance of Checker."""
        checker = Checker(
            self.app.options.ns,
            concurrency=parsed_args.concurrency,
            error_file=parsed_args.output,
            rebuild_file=parsed_args.output_for_blob_rebuilder,
            request_attempts=parsed_args.attempts,
        )
        return checker

    def patch_parser(self, parser):
        parser.add_argument(
            '--attempts',
            type=int,
            default=1,
            help="Number of attempts for listing requests (default: 1)."
        )
        # TODO(FVE): implement chunk checksums
        # parser.add_argument(
        #     '--checksum',
        #     action='store_true',
        #     help=("Perform checksum comparisons. This requires downloading "
        #           "data from rawx services.")
        # )
        parser.add_argument(
            '--depth', '--max-depth',
            type=int,
            default=5,
            help=("How deep to recurse. 0 means do not recurse. "
                  "N > 0 means recurse N levels below the specified item type "
                  "(namespace -> account -> container -> object -> chunk, "
                  "default: 5).")
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
            '--output-for-blob-rebuilder',
            help=("Write chunk errors in a file with a format "
                  "suitable as oio-blob-rebuilder input.")
        )

    def _format_results(self, checker):
        for res in checker.run():
            yield (res.target.type, repr(res.target),
                   res.health, res.errors_to_str())

    def format_results(self, checker):
        return self.__class__.columns, self._format_results(checker)


class AccountCheck(CheckCommandMixin, lister.Lister):
    """
    Check an account for problems.
    """
    base_level = 4

    def get_parser(self, prog_name):
        parser = super(AccountCheck, self).get_parser(prog_name)
        self.patch_parser(parser)

        parser.add_argument(
            'accounts',
            nargs='*',
            metavar='<account_name>',
            help='Name of the account to check.'
        )
        return parser

    def take_action(self, parsed_args):
        super(AccountCheck, self).take_action(parsed_args)
        # FIXME(FVE): use parsed_args.depth
        checker = self.build_checker(parsed_args)
        if not parsed_args.accounts:
            parsed_args.accounts = [self.app.options.account]
        for acct in parsed_args.accounts:
            target = Target(acct)
            checker.check(target, parsed_args.depth)
        return self.format_results(checker)


class ContainerCheck(ContainerCommandMixin, CheckCommandMixin, lister.Lister):
    """
    Check a container for problems. Quick checks on the account owning
    the container will also be performed.
    """
    base_level = 3

    def get_parser(self, prog_name):
        parser = super(ContainerCheck, self).get_parser(prog_name)
        CheckCommandMixin.patch_parser(self, parser)
        ContainerCommandMixin.patch_parser(self, parser)
        return parser

    def take_action(self, parsed_args):
        super(ContainerCheck, self).take_action(parsed_args)
        checker = self.build_checker(parsed_args)
        for ct in parsed_args.containers:
            target = Target(self.app.options.account, ct)
            checker.check(target, parsed_args.depth)
        return self.format_results(checker)


class ObjectCheck(ObjectCommandMixin, CheckCommandMixin, lister.Lister):
    """
    Check an object for problems. Quick checks on the account and the container
    owning the object will also be performed.
    """
    base_level = 2

    def get_parser(self, prog_name):
        parser = super(ObjectCheck, self).get_parser(prog_name)
        CheckCommandMixin.patch_parser(self, parser)
        ObjectCommandMixin.patch_parser(self, parser)
        return parser

    def take_action(self, parsed_args):
        super(ObjectCheck, self).take_action(parsed_args)
        checker = self.build_checker(parsed_args)
        for obj in parsed_args.objects:
            target = Target(self.app.options.account, parsed_args.container,
                            obj, version=parsed_args.object_version)
            checker.check(target, parsed_args.depth)
        return self.format_results(checker)


class ChunkCheck(CheckCommandMixin, lister.Lister):
    """
    Check a chunk for problems. Quick checks on the account, the container
    and the object owning the chunk will also be performed.
    """
    base_level = 0

    def get_parser(self, prog_name):
        parser = super(ChunkCheck, self).get_parser(prog_name)
        self.patch_parser(parser)

        parser.add_argument(
            'chunks',
            metavar='<chunk_url>',
            nargs='+',
            help='URL to the chunk to check.'
        )
        return parser

    def take_action(self, parsed_args):
        super(ChunkCheck, self).take_action(parsed_args)
        checker = self.build_checker(parsed_args)
        for chunk in parsed_args.chunks:
            target = Target(self.app.options.account, chunk=chunk)
            checker.check(target, parsed_args.depth)
        return self.format_results(checker)
