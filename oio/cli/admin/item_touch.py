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


class ItemTouchCommand(lister.Lister):
    """
    Various parameters that apply to all check commands.
    """

    columns = ('Container', 'Status')

    def get_parser(self, prog_name):
        parser = super(ItemTouchCommand, self).get_parser(prog_name)
        parser.add_argument(
            '--recompute',
            dest='recompute',
            default=False,
            help='Recompute the statistics of the specified container',
            action="store_true"
        )
        return parser


class ContainerTouch(ContainerCommandMixin, ItemTouchCommand):
    """
    Touch an object container, triggers asynchronous treatments on it.
    """

    def get_parser(self, prog_name):
        parser = super(ContainerTouch, self).get_parser(prog_name)
        self.patch_parser(parser)
        return parser

    def touch(self, container, is_cid, recompute):
        kwargs = {'cid': container if is_cid else None,
                  'recompute': recompute}
        self.app.client_manager.storage.container_touch(
            self.app.client_manager.account,
            container if not is_cid else None,
            **kwargs)

    def do(self, parsed_args):
        for container in parsed_args.containers:
            try:
                self.touch(container, parsed_args.is_cid,
                           parsed_args.recompute)
                yield (container, "ok")
            except Exception as err:
                yield (container, str(err))

    def take_action(self, parsed_args):
        super(ContainerTouch, self).take_action(parsed_args)
        return self.columns, self.do(parsed_args)
