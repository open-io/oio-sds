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


class AccountCommandMixin(object):
    """
    Add account-related argmuments to a cliff command.
    """

    def patch_parser(self, parser):
        parser.add_argument(
            'accounts',
            nargs='*',
            metavar='<account_name>',
            help='Name of the account to work on.'
        )


class ContainerCommandMixin(object):
    """
    Add container-related argmuments to a cliff command.
    """

    def patch_parser(self, parser):
        parser.add_argument(
            'containers',
            nargs='+',
            metavar='<container_name>',
            help='Name of the container to work on.'
        )
        parser.add_argument(
            '--cid',
            action='store_true',
            dest='is_cid',
            help="Interpret <container_name> as a container ID",
        )


class ObjectCommandMixin(object):
    """
    Add object-related argmuments to a cliff command.
    """

    def patch_parser(self, parser):
        parser.add_argument(
            'container',
            metavar='<container_name>',
            nargs='?',
            help=("Name or cid of the container to interact with.\n" +
                  "Optional if --auto is specified.")
        )
        parser.add_argument(
            'objects',
            metavar='<object_name>',
            nargs='*',
            help='Name of the object to work on.'
        )
        parser.add_argument(
            '--object-version',
            metavar='<version>',
            help=("Version of the object to work on. Can be used when only "
                  "one object is specified on command line.")
        )
        parser.add_argument(
            '--auto',
            action="store_true",
            help=("Auto-generate the container name according to the " +
                  "'flat_*' namespace parameters (<container> is ignored)."),
        )
        parser.add_argument(
            '--flat-bits',
            type=int,
            help="Number of bits for flat-NS computation",
        )
        parser.add_argument(
            '--cid',
            action='store_true',
            dest='is_cid',
            help="Interpret <container_name> as a container ID",
        )

    # TODO(FVE): merge with oio.cli.object.object.ContainerCommandMixin
    def take_action(self, parsed_args):
        if not parsed_args.container and not parsed_args.auto:
            from argparse import ArgumentError
            raise ArgumentError(parsed_args.container,
                                "Missing value for container_name or --auto")
        # If we are generating the container name automatically,
        # the first object name is in the container variable.
        if parsed_args.auto:
            parsed_args.objects.append(parsed_args.container)
        if parsed_args.flat_bits:
            self.app.client_manager.flatns_set_bits(parsed_args.flat_bits)
        if not parsed_args.objects:
            from argparse import ArgumentError
            raise ArgumentError(None,
                                "Missing value for object_name")
