import logging
from cliff import command
from cliff import show
from cliff import lister
from oio.cli.utils import KeyValueAction


class ShowAccount(show.ShowOne):
    """Show account"""

    log = logging.getLogger(__name__ + '.ShowAccount')

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
        return zip(*sorted(data.iteritems()))


class DeleteAccount(command.Command):
    """Delete account"""

    log = logging.getLogger(__name__ + '.DeleteAccount')

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

    log = logging.getLogger(__name__ + '.CreateAccount')

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

        columns = ('Name', 'Created')
        l = (r for r in results)
        return columns, l


class SetAccount(command.Command):
    """Set account properties"""

    log = logging.getLogger(__name__ + '.SetAccount')

    def get_parser(self, prog_name):
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

    log = logging.getLogger(__name__ + '.UnsetAccount')

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

    log = logging.getLogger(__name__ + '.ListAccount')

    def get_parser(self, prog_name):
        parser = super(ListAccounts, self).get_parser(prog_name)
        parser.add_argument(
            '--stats', '--long',
            dest='long_listing',
            default=False,
            help=("Display account statistics "
                  "(slow,  we recommend 'csv' or 'value' output formats)"),
            action="store_true"
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
