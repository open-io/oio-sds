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

from oio.cli.admin.common import ContainerCommandMixin
from oio.directory.meta2 import Meta2Database


class ItemMoveCommand(lister.Lister):
    """
    Various parameters that apply to all move commands.
    """

    columns = None
    success = True

    @property
    def logger(self):
        return self.app.client_manager.logger

    def _take_action(self, parsed_args):
        raise NotImplementedError()

    def take_action(self, parsed_args):
        self.logger.debug('take_action(%s)', parsed_args)

        return self.columns, self._take_action(parsed_args)

    def run(self, parsed_args):
        super(ItemMoveCommand, self).run(parsed_args)
        if not self.success:
            return 1


class ContainerMove(ContainerCommandMixin, ItemMoveCommand):
    """
    Move a container from source service to destination service.
    If the destination service isn't set,
    a destination service is automatically selected.
    """

    columns = ('Container', 'Base', 'Source', 'Destination', 'Status',
               'Errors')

    def get_parser(self, prog_name):
        parser = super(ContainerMove, self).get_parser(prog_name)
        ContainerCommandMixin.patch_parser(self, parser)
        parser.add_argument(
            '--src',
            metavar='<service_id>',
            required=True,
            help='ID of the source service',
        )
        parser.add_argument(
            '--dst',
            metavar='<service_id>',
            help='ID of the destination service',
        )
        return parser

    def _take_action(self, parsed_args):
        containers = self.resolve_containers(self.app, parsed_args)
        meta2 = Meta2Database(self.app.client_manager.client_conf,
                              logger=self.logger)
        for _, container_name, container_id in containers:
            moved = meta2.move(container_id, parsed_args.src,
                               dst=parsed_args.dst)
            for res in moved:
                if res['err'] is None:
                    status = 'OK'
                else:
                    self.success = False
                    status = 'error'
                yield (container_name, res['base'], res['src'], res['dst'],
                       status, res['err'])

    def take_action(self, parsed_args):
        ContainerCommandMixin.check_and_load_parsed_args(
            self, self.app, parsed_args)
        return super(ContainerMove, self).take_action(parsed_args)
