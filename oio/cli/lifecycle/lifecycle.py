# Copyright (C) 2017-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2022 OVH SAS
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

"""Lifecycle-related commands"""


from logging import getLogger

from oio.cli import Command, Lister
from oio.common.exceptions import LifecycleNotFound
from oio.container.lifecycle import etree, ContainerLifecycle


class LifecycleApply(Lister):
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
        lc = ContainerLifecycle(
            self.app.client_manager.storage, self.app.client_manager.account,
            parsed_args.container, logger=self.log)
        if not lc.load():
            raise LifecycleNotFound(
                "No lifecycle configuration for container %s in account %s" %
                (parsed_args.container, self.app.client_manager.account))
        raw_res = lc.execute()
        columns = ('Name', 'Version', 'Rule', 'Action', 'Result')
        res = ((x[0]['name'], x[0]['version'], x[1], x[2], x[3])
               for x in raw_res)
        return columns, res


class LifecycleSet(Command):
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

        lc = ContainerLifecycle(self.app.client_manager.storage,
                                self.app.client_manager.account,
                                parsed_args.container,
                                self.log)
        lc.load_xml(conf)
        lc.save()


class LifecycleGet(Command):
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
        lc = ContainerLifecycle(self.app.client_manager.storage,
                                self.app.client_manager.account,
                                parsed_args.container,
                                self.log)
        xml = lc.get_configuration()
        if xml is None:
            raise LifecycleNotFound(
                "No lifecycle configuration for container %s in account %s" %
                (parsed_args.container, self.app.client_manager.account))
        tree = etree.fromstring(xml)
        text = etree.tostring(tree, pretty_print=True,
                              encoding='utf-8').decode('utf-8')
        self.app.stdout.write(text)
