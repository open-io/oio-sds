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


from oio.content.repairer import ContentRepairer
from oio.cli.admin.common import ObjectCommandMixin


class ItemRepairCommand(lister.Lister):
    """
    Various parameters that apply to all repair commands.
    """

    log = None
    columns = None
    repairer_class = None
    repairer = None
    conf = dict()

    def get_parser(self, prog_name):
        parser = super(ItemRepairCommand, self).get_parser(prog_name)
        parser.add_argument(
            '--report-interval', type=int,
            help='Report interval in seconds. '
                 '(default=%d)' % self.repairer_class.DEFAULT_REPORT_INTERVAL)

        parser.add_argument(
            '--workers', type=int,
            help='Number of workers. '
                 '(default=%d)' % self.repairer_class.DEFAULT_WORKERS
        )
        parser.add_argument(
            '--items-per-second', type=int,
            help='Max items per second. '
                 '(default=%d)'
            % self.repairer_class.DEFAULT_ITEM_PER_SECOND
        )
        return parser

    def _take_action(self, parsed_args):
        raise NotImplementedError()

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        self.conf.update(self.app.client_manager.client_conf)
        self.conf['report_interval'] = parsed_args.report_interval
        self.conf['workers'] = parsed_args.workers
        self.conf['items_per_second'] = parsed_args.items_per_second

        return self.columns, self._take_action(parsed_args)

    def run(self, parsed_args):
        super(ItemRepairCommand, self).run(parsed_args)
        if not self.repairer.is_success():
            return 1


class ObjectRepair(ObjectCommandMixin, ItemRepairCommand):
    """
    Repair an object by following these steps:
    rebuild all missing, lost or corrupt chunks ;
    update the counters for the account service.
    """

    log = getLogger(__name__ + '.ObjectRepair')
    columns = ('Object', 'Status')
    repairer_class = ContentRepairer

    def get_parser(self, prog_name):
        parser = super(ObjectRepair, self).get_parser(prog_name)
        self.patch_parser(parser)
        return parser

    def _take_action(self, parsed_args):
        if parsed_args.is_cid:
            account, container = self.app.client_manager.storage.resolve_cid(
                parsed_args.container)
        else:
            account = self.app.options.account
            container = parsed_args.container

        objects = list()
        for obj_name in parsed_args.objects:
            obj = dict()
            obj['namespace'] = self.app.options.ns
            obj['account'] = account
            obj['container'] = container
            obj['name'] = obj_name
            obj['version'] = parsed_args.object_version
            objects.append(obj)

        self.repairer = ContentRepairer(
            self.conf, objects=objects, logger=self.log)
        self.repairer.prepare_local_dispatcher()

        for item, _, error in self.repairer.run():
            if error is None:
                status = 'OK'
            else:
                status = error
            yield (self.repairer.string_from_item(item), status)

    def take_action(self, parsed_args):
        ObjectCommandMixin.take_action(self, parsed_args)
        return ItemRepairCommand.take_action(self, parsed_args)
