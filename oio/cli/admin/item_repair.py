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

from oio.account.rebuilder import AccountRebuilder
from oio.container.repairer import ContainerRepairer
from oio.content.repairer import ContentRepairer
from oio.cli.admin.common import AccountCommandMixin, ContainerCommandMixin, \
    ObjectCommandMixin, ToolCommandMixin


class ItemRepairCommand(ToolCommandMixin, lister.Lister):
    """
    Various parameters that apply to all repair commands.
    """

    columns = None
    repairer = None

    @property
    def logger(self):
        return self.app.client_manager.logger

    def get_parser(self, prog_name):
        parser = super(ItemRepairCommand, self).get_parser(prog_name)
        ToolCommandMixin.patch_parser(self, parser)
        return parser

    def _take_action(self, parsed_args):
        raise NotImplementedError()

    def take_action(self, parsed_args):
        ToolCommandMixin.check_and_load_parsed_args(
            self, self.app, parsed_args)
        self.logger.debug('take_action(%s)', parsed_args)

        return self.columns, self._take_action(parsed_args)

    def run(self, parsed_args):
        super(ItemRepairCommand, self).run(parsed_args)
        if not self.repairer.is_success():
            return 1


class AccountRepair(AccountCommandMixin, ItemRepairCommand):
    """
    Repair a account.

    The steps of the repair:
    recompute the counter of this account ;
    refresh the counter of all containers in this account.
    """

    tool_class = AccountRebuilder
    columns = ('Entry', 'Status', 'Errors')

    def get_parser(self, prog_name):
        parser = super(AccountRepair, self).get_parser(prog_name)
        AccountCommandMixin.patch_parser(self, parser)
        return parser

    def _take_action(self, parsed_args):
        accounts = list()
        for account_name in parsed_args.accounts:
            account = dict()
            account['namespace'] = self.app.options.ns
            account['account'] = account_name
            accounts.append(account)

        self.repairer = AccountRebuilder(
            self.tool_conf, accounts=accounts, logger=self.logger)
        self.repairer.prepare_local_dispatcher()

        for item, _, error in self.repairer.run():
            if error is None:
                status = 'OK'
            else:
                status = 'error'
            yield (self.repairer.string_from_item(item), status, error)

    def take_action(self, parsed_args):
        AccountCommandMixin.check_and_load_parsed_args(
            self, self.app, parsed_args)
        return super(AccountRepair, self).take_action(parsed_args)


class ContainerRepair(ContainerCommandMixin, ItemRepairCommand):
    """
    Repair a container.

    The steps of the repair:
    rebuild all missing, lost bases ;
    synchronize its bases ;
    update the counters for the account service.
    """

    tool_class = ContainerRepairer
    columns = ('Container', 'Status', 'Errors')

    def get_parser(self, prog_name):
        parser = super(ContainerRepair, self).get_parser(prog_name)
        ContainerCommandMixin.patch_parser(self, parser)

        parser.add_argument(
            '--no-rebuild-bases', action='store_false', dest='rebuild_bases',
            help='Don\'t rebuild the missing, lost bases. '
                 '(default=%s)'
            % (not self.tool_class.DEFAULT_REBUILD_BASES))
        parser.add_argument(
            '--no-sync-bases', action='store_false', dest='sync_bases',
            help='Don\'t synchronize its bases. '
                 '(default=%s)'
            % (not self.tool_class.DEFAULT_SYNC_BASES))
        parser.add_argument(
            '--no-update-account', action='store_false', dest='update_account',
            help='Don\'t update the counters for the account service. '
                 '(default=%s)'
            % (not self.tool_class.DEFAULT_UPDATE_ACCOUNT))
        return parser

    def _take_action(self, parsed_args):
        self.tool_conf['rebuild_bases'] = parsed_args.rebuild_bases
        self.tool_conf['sync_bases'] = parsed_args.sync_bases
        self.tool_conf['update_account'] = parsed_args.update_account

        containers = self.resolve_containers(self.app, parsed_args, no_id=True)
        containers_to_repair = list()
        for account, container_name, _ in containers:
            container = dict()
            container['namespace'] = self.app.options.ns
            container['account'] = account
            container['container'] = container_name
            containers_to_repair.append(container)

        self.repairer = ContainerRepairer(
            self.tool_conf, containers=containers_to_repair,
            logger=self.logger)
        self.repairer.prepare_local_dispatcher()

        for item, _, error in self.repairer.run():
            if error is None:
                status = 'OK'
            else:
                status = 'error'
            yield (self.repairer.string_from_item(item), status, error)

    def take_action(self, parsed_args):
        ContainerCommandMixin.check_and_load_parsed_args(
            self, self.app, parsed_args)
        return super(ContainerRepair, self).take_action(parsed_args)


class ObjectRepair(ObjectCommandMixin, ItemRepairCommand):
    """
    Repair an object.

    The steps of the repair:
    rebuild all missing, lost or corrupt chunks ;
    update the counters for the account service.
    """

    tool_class = ContentRepairer
    columns = ('Object', 'Status', 'Errors')

    def get_parser(self, prog_name):
        parser = super(ObjectRepair, self).get_parser(prog_name)
        ObjectCommandMixin.patch_parser(self, parser)
        return parser

    def _take_action(self, parsed_args):
        account, _, objects = self.resolve_objects(self.app, parsed_args)
        objects_to_repair = list()
        for container, obj_name, version in objects:
            obj = dict()
            obj['namespace'] = self.app.options.ns
            obj['account'] = account
            obj['container'] = container
            obj['name'] = obj_name
            obj['version'] = version
            objects_to_repair.append(obj)

        self.repairer = ContentRepairer(
            self.tool_conf, objects=objects_to_repair,
            logger=self.logger)
        self.repairer.prepare_local_dispatcher()

        for item, _, error in self.repairer.run():
            if error is None:
                status = 'OK'
            else:
                status = 'error'
            yield (self.repairer.string_from_item(item), status, error)

    def take_action(self, parsed_args):
        ObjectCommandMixin.check_and_load_parsed_args(
            self, self.app, parsed_args)
        return super(ObjectRepair, self).take_action(parsed_args)
