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
from logging import getLogger

from oio.cli.admin.common import ContainerCommandMixin
from oio.common.utils import cid_from_name
from oio.directory.meta2 import Meta2Database


class ItemMoveCommandMixin(object):
    """
    Various parameters that apply to all move commands.
    """

    def patch_parser(self, parser):
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


class ContainerMove(ContainerCommandMixin, ItemMoveCommandMixin,
                    lister.Lister):
    """
    Move a container from source service to destination service.
    If the destination service isn't set,
    a destination service is automatically selected.
    """

    log = getLogger(__name__ + '.ContainerMove')

    def get_parser(self, prog_name):
        parser = super(ContainerMove, self).get_parser(prog_name)
        ContainerCommandMixin.patch_parser(self, parser)
        ItemMoveCommandMixin.patch_parser(self, parser)
        return parser

    def _run(self, parsed_args):
        meta2 = Meta2Database(self.app.client_manager.client_conf,
                              logger=self.log)
        for container in parsed_args.containers:
            cid = cid_from_name(self.app.options.account, container)
            moved = meta2.move(cid, parsed_args.src, dst=parsed_args.dst)
            if moved is None:
                continue
            for res in moved:
                res['container'] = container
                yield res

    def _format_results(self, moved):
        if moved is None:
            return
        for res in moved:
            if res['err'] is None:
                status = 'OK'
            else:
                status = 'KO'
            yield (res['container'], res['base'], res['src'], res['dst'],
                   status, res['err'])

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        columns = ('Container', 'Base', 'Source', 'Destination', 'Status',
                   'Message')
        return columns, self._format_results(self._run(parsed_args))
