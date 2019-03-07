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

from oio.crawler.integrity import Checker, Target


class CheckCommandMixin(object):
    """
    Various parameters that apply to all check commands.
    """

    columns = ('Type', 'Item', 'Status', 'Errors')

    def build_checker(self, parsed_args):
        """Build an instance of Checker."""
        # TODO(FVE): when Checker is refactored, review the list of
        # parameters we should pass.
        checker = Checker(self.app.options.ns)
        return checker

    def patch_parser(self, parser):
        parser.add_argument(
            '--depth',
            type=int,
            default=0,
            help=("How deep to recurse. 0 means do not recurse. "
                  "N > 0 means recurse N levels below the specified item type,"
                  " from namespace to chunk.")
        )
        parser.add_argument(
            '--checksum',
            action='store_true',
            help=("Perform checksum comparisons. This requires downloading "
                  "data from rawx services.")
        )

    def _format_results(self, checker):
        for res in checker.wait():
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
            checker.check(target)
        return self.format_results(checker)


class ContainerCheck(CheckCommandMixin, lister.Lister):
    """
    Check a container for problems.
    """
    base_level = 3

    def get_parser(self, prog_name):
        parser = super(ContainerCheck, self).get_parser(prog_name)
        self.patch_parser(parser)

        parser.add_argument(
            'containers',
            nargs='+',
            metavar='<container_name>',
            help='Name of the container to check.'
        )
        return parser

    def take_action(self, parsed_args):
        super(ContainerCheck, self).take_action(parsed_args)
        checker = self.build_checker(parsed_args)
        for ct in parsed_args.containers:
            target = Target(self.app.options.account, ct)
            checker.check(target)
        return self.format_results(checker)


class ObjectCheck(CheckCommandMixin, lister.Lister):
    """
    Check an object for problems.
    """
    base_level = 2

    def get_parser(self, prog_name):
        parser = super(ObjectCheck, self).get_parser(prog_name)
        self.patch_parser(parser)

        parser.add_argument(
            'container',
            metavar='<container_name>',
            help='Name of the container holding the object.'
        )
        parser.add_argument(
            'objects',
            metavar='<object_name>',
            nargs='+',
            help='Name of the object to check.'
        )
        parser.add_argument(
            '--object-version',
            metavar='<version>',
            help=("Version of the object to check. Works when only one "
                  "object is specified on command line.")
        )
        return parser

    def take_action(self, parsed_args):
        super(ObjectCheck, self).take_action(parsed_args)
        checker = self.build_checker(parsed_args)
        for obj in parsed_args.objects:
            target = Target(self.app.options.account, parsed_args.container,
                            obj, parsed_args.object_version)
            checker.check(target)
        return self.format_results(checker)


class ChunkCheck(CheckCommandMixin, lister.Lister):
    """
    Check a chunk for problems.
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
            checker.check(target)
        return self.format_results(checker)
