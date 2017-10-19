# Copyright (C) 2017 OpenIO SAS, as part of OpenIO SDS
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

"""Lifecycle-related commands"""

from logging import getLogger
from cliff import command, lister
from oio.container.lifecycle import ContainerLifecycle, LIFECYCLE_PROPERTY_KEY


class LifecycleApply(lister.Lister):
    """Synchronously apply lifecycle rules."""

    log = getLogger(__name__ + '.LifecycleApply')

    def get_parser(self, prog_name):
        parser = super(LifecycleApply, self).get_parser(prog_name)
        parser.add_argument(
            'container',
            metavar='<container>',
            help='Container on which to apply lifecycle rules'
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        lc = ContainerLifecycle(self.app.client_manager.storage,
                                self.app.client_manager.account,
                                parsed_args.container,
                                self.log)
        if not lc.load():
            raise Exception(
                "No lifecycle configuration for container %s in account %s" %
                (parsed_args.container, self.app.client_manager.account))
        raw_res = lc.execute()
        columns = ('Name', 'Version', 'Rule', 'Action', 'Result')
        res = ((x[0]['name'], x[0]['version'], x[1], x[2], x[3])
               for x in raw_res)
        return columns, res


class LifecycleSet(command.Command):
    """Set container lifecycle configuration."""

    log = getLogger(__name__ + '.LifecycleSet')

    def get_parser(self, prog_name):
        parser = super(LifecycleSet, self).get_parser(prog_name)
        parser.add_argument(
            'container',
            metavar='<container>',
            help='Container whose lifecycle configuration to set'
        )
        parser.add_argument(
            'configuration',
            metavar='<configuration>',
            help='Lifecycle configuration'
        )
        parser.add_argument(
            '--from-file',
            action='store_true',
            help='Consider <configuration> as a path to a file'
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        if parsed_args.from_file:
            with open(parsed_args.configuration, 'r') as file_:
                conf = file_.read()
        else:
            conf = parsed_args.configuration

        props = {LIFECYCLE_PROPERTY_KEY: conf}
        self.app.client_manager.storage.container_set_properties(
            self.app.client_manager.account,
            parsed_args.container,
            properties=props
        )


class LifecycleGet(command.Command):
    """Get container lifecycle configuration."""

    log = getLogger(__name__ + '.LifecycleGet')

    def get_parser(self, prog_name):
        parser = super(LifecycleGet, self).get_parser(prog_name)
        parser.add_argument(
            'container',
            metavar='<container>',
            help='Container whose lifecycle configuration to get'
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        md = self.app.client_manager.storage.container_get_properties(
            self.app.client_manager.account,
            parsed_args.container
        )
        self.app.stdout.write(md['properties'].get(LIFECYCLE_PROPERTY_KEY, ''))
