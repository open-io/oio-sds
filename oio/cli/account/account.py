# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
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

from logging import getLogger
from cliff import command, show, lister


class ShowAccount(show.ShowOne):
    """Show account"""

    log = getLogger(__name__ + '.ShowAccount')

    def get_parser(self, prog_name):
        parser = super(ShowAccount, self).get_parser(prog_name)
        parser.add_argument(
            'account',
            metavar='<account>',
            help='Account to update',
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        data = self.app.client_manager.storage.account_show(
            account=parsed_args.account
        )
        data['account'] = data['id']
        del data['id']
        if parsed_args.formatter == 'table':
            from oio.common.easy_value import convert_size

            data['ctime'] = int(float(data.get('ctime', 0)))
            data['bytes'] = convert_size(int(data.get('bytes', 0)), unit="B")
            data['objects'] = convert_size(int(data.get('objects', 0)))
        return list(zip(*sorted(data.items())))


class DeleteAccount(command.Command):
    """Delete account"""

    log = getLogger(__name__ + '.DeleteAccount')

    def get_parser(self, prog_name):
        parser = super(DeleteAccount, self).get_parser(prog_name)
        parser.add_argument(
            'accounts',
            metavar='<account>',
            nargs='+',
            help='Account(s) to delete'
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        for account in parsed_args.accounts:
            self.app.client_manager.storage.account_delete(
                account=account
            )


class CreateAccount(lister.Lister):
    """Create account"""

    log = getLogger(__name__ + '.CreateAccount')

    def get_parser(self, prog_name):
        parser = super(CreateAccount, self).get_parser(prog_name)
        parser.add_argument(
            'accounts',
            metavar='<account>',
            nargs='+',
            help='Account(s) to create'
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        results = []
        for account in parsed_args.accounts:
            result = self.app.client_manager.storage.account_create(
                account=account)
            results.append((account, result))

        return ('Name', 'Created'), (r for r in results)


class SetAccount(command.Command):
    """Set account properties"""

    log = getLogger(__name__ + '.SetAccount')

    def get_parser(self, prog_name):
        from oio.cli.common.utils import KeyValueAction

        parser = super(SetAccount, self).get_parser(prog_name)
        parser.add_argument(
            'account',
            metavar='<account>',
            help='Account to modify',
        )
        parser.add_argument(
            '-p',
            '--property',
            metavar='<key=value>',
            action=KeyValueAction,
            help='Property to add/update for this account'
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        self.app.client_manager.storage.account_set_properties(
            account=parsed_args.account,
            properties=parsed_args.property
        )


class UnsetAccount(command.Command):
    """Unset account properties"""

    log = getLogger(__name__ + '.UnsetAccount')

    def get_parser(self, prog_name):
        parser = super(UnsetAccount, self).get_parser(prog_name)
        parser.add_argument(
            'account',
            metavar='<account>',
            help='Account to modify',
        )
        parser.add_argument(
            '--property',
            metavar='<key>',
            action='append',
            default=[],
            help='Property to delete from account',
            required=True
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        self.app.client_manager.storage.account_del_properties(
            account=parsed_args.account,
            properties=parsed_args.property
        )


class ListAccounts(lister.Lister):
    """List accounts of the namespace"""

    log = getLogger(__name__ + '.ListAccount')

    def get_parser(self, prog_name):
        from oio.cli.common.utils import ValueFormatStoreTrueAction

        parser = super(ListAccounts, self).get_parser(prog_name)
        parser.add_argument(
            '--stats', '--long',
            dest='long_listing',
            default=False,
            help=("Display account statistics "
                  "(and set output format to 'value')"),
            action=ValueFormatStoreTrueAction
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        account_list = self.app.client_manager.storage.account_list()

        if parsed_args.long_listing:
            def _get_account_stats(accounts):
                for account in accounts:
                    data = self.app.client_manager.storage.account_show(
                        account=account
                    )
                    yield (data['id'], data['bytes'], data['containers'],
                           data['objects'], data['ctime'], data['metadata'])

            columns = ('Name', 'bytes', 'containers', 'objects', 'ctime',
                       'metadata')
            return columns, _get_account_stats(account_list)

        column = ('Name',)
        return column, ((e,) for e in account_list)


class RefreshAccount(command.Command):
    """ Refresh counters of an account and all its containers """

    log = getLogger(__name__ + '.RefreshAccount')

    def get_parser(self, prog_name):
        from oio.cli.common.utils import ValueFormatStoreTrueAction

        parser = super(RefreshAccount, self).get_parser(prog_name)
        parser.add_argument(
            'account',
            nargs='?',
            metavar='<account>',
            help='Account to refresh'
        )
        parser.add_argument(
            '--all',
            dest='all_accounts',
            help='Refresh all accounts (<account> is ignored)',
            action=ValueFormatStoreTrueAction
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        if parsed_args.all_accounts:
            self.app.client_manager.storage.account_refresh()
        elif parsed_args.account is not None:
            self.app.client_manager.storage.account_refresh(
                account=parsed_args.account)
        else:
            from argparse import ArgumentError
            raise ArgumentError(parsed_args.account,
                                "Missing value for account or --all")


class FlushAccount(command.Command):
    """ Flush account by emptying the list of its containers """

    log = getLogger(__name__ + '.FlushAccount')

    def get_parser(self, prog_name):
        parser = super(FlushAccount, self).get_parser(prog_name)
        parser.add_argument(
            'account',
            metavar='<account>',
            help='Account to flush'
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        self.app.client_manager.storage.account_flush(
            account=parsed_args.account
        )
