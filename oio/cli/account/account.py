# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2022 OVH SAS
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

from logging import getLogger

from oio.cli import Command, Lister, ShowOne
from oio.common.utils import depaginate, request_id


class ShowAccount(ShowOne):
    """Show account"""

    log = getLogger(__name__ + ".ShowAccount")

    def get_parser(self, prog_name):
        parser = super(ShowAccount, self).get_parser(prog_name)
        parser.add_argument(
            "account",
            metavar="<account>",
            help="Account to update",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        data = self.app.client_manager.storage.account_show(account=parsed_args.account)
        data["account"] = data["id"]
        del data["id"]
        if parsed_args.formatter == "table":
            from oio.common.easy_value import convert_size

            data["ctime"] = int(float(data.get("ctime", 0)))
            data["bytes"] = convert_size(int(data.get("bytes", 0)), unit="B")
            data["objects"] = convert_size(int(data.get("objects", 0)))
        return list(zip(*sorted(data.items())))


class DeleteAccount(Command):
    """Delete account"""

    log = getLogger(__name__ + ".DeleteAccount")

    def get_parser(self, prog_name):
        parser = super(DeleteAccount, self).get_parser(prog_name)
        parser.add_argument(
            "accounts", metavar="<account>", nargs="+", help="Account(s) to delete"
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        for account in parsed_args.accounts:
            self.app.client_manager.storage.account_delete(account=account)


class CreateAccount(Lister):
    """Create account"""

    log = getLogger(__name__ + ".CreateAccount")

    def get_parser(self, prog_name):
        parser = super(CreateAccount, self).get_parser(prog_name)
        parser.add_argument(
            "accounts", metavar="<account>", nargs="+", help="Account(s) to create"
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        results = []
        for account in parsed_args.accounts:
            result = self.app.client_manager.storage.account_create(account=account)
            results.append((account, result))

        return ("Name", "Created"), (r for r in results)


class SetAccount(Command):
    """Set account properties."""

    log = getLogger(__name__ + ".SetAccount")

    def get_parser(self, prog_name):
        from oio.cli.common.utils import KeyValueAction

        parser = super(SetAccount, self).get_parser(prog_name)
        parser.add_argument(
            "account",
            metavar="<account>",
            help="Account to modify",
        )
        parser.add_argument(
            "-p",
            "--property",
            metavar="<key=value>",
            action=KeyValueAction,
            help="Property to add/update to this account",
        )
        parser.add_argument(
            "--max-buckets",
            metavar="<n>",
            type=int,
            help="Set the maximum number of buckets per account.",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        if parsed_args.property is None:
            properties = {}
        else:
            properties = parsed_args.property.copy()
        if parsed_args.max_buckets is not None:
            properties["max-buckets"] = str(parsed_args.max_buckets)
        if not properties:
            ValueError("No property")

        self.app.client_manager.storage.account_set_properties(
            account=parsed_args.account, properties=properties
        )


class UnsetAccount(Command):
    """Unset account properties."""

    log = getLogger(__name__ + ".UnsetAccount")

    def get_parser(self, prog_name):
        parser = super(UnsetAccount, self).get_parser(prog_name)
        parser.add_argument(
            "account",
            metavar="<account>",
            help="Account to modify",
        )
        parser.add_argument(
            "-p",
            "--property",
            metavar="<key>",
            action="append",
            default=[],
            help="Property to delete from account",
        )
        parser.add_argument(
            "--max-buckets",
            action="store_true",
            help="Reset the maximum number of buckets per account.",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        if parsed_args.property is None:
            properties = []
        else:
            properties = parsed_args.property.copy()
        if parsed_args.max_buckets:
            properties.append("max-buckets")
        if not properties:
            ValueError("No property")

        self.app.client_manager.storage.account_del_properties(
            account=parsed_args.account, properties=properties
        )


class ListAccounts(Lister):
    """List accounts of the namespace"""

    log = getLogger(__name__ + ".ListAccount")

    def get_parser(self, prog_name):
        from oio.cli.common.utils import ValueFormatStoreTrueAction

        parser = super(ListAccounts, self).get_parser(prog_name)
        parser.add_argument(
            "--prefix", metavar="<prefix>", help="Filter list using <prefix>"
        )
        parser.add_argument("--marker", metavar="<marker>", help="Marker for paging")
        parser.add_argument(
            "--end-marker", metavar="<end-marker>", help="End marker for paging"
        )
        parser.add_argument(
            "--limit", metavar="<limit>", help="Limit the number of accounts returned"
        )
        parser.add_argument(
            "--no-paging",
            "--full",
            dest="full_listing",
            default=False,
            help="List all accounts without paging (and set output format to 'value')",
            action=ValueFormatStoreTrueAction,
        )
        parser.add_argument(
            "--stats",
            "--long",
            dest="long_listing",
            help="Display account statistics",
            action="store_true",
        )
        parser.add_argument(
            "--sharding-accounts",
            help="Display sharding accounts (hidden by default)",
            action="store_true",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        kwargs = {"reqid": request_id(prefix="CLI-ACCOUNT-")}
        if parsed_args.prefix:
            kwargs["prefix"] = parsed_args.prefix
        if parsed_args.marker:
            kwargs["marker"] = parsed_args.marker
        if parsed_args.end_marker:
            kwargs["end_marker"] = parsed_args.end_marker
        if parsed_args.limit:
            kwargs["limit"] = parsed_args.limit
        if parsed_args.long_listing:
            kwargs["stats"] = parsed_args.long_listing
        if parsed_args.sharding_accounts:
            kwargs["sharding_accounts"] = parsed_args.sharding_accounts

        acct_client = self.app.client_manager.storage.account

        if parsed_args.full_listing:
            listing = depaginate(
                acct_client.account_list,
                listing_key=lambda x: x["listing"],
                marker_key=lambda x: x["next_marker"],
                truncated_key=lambda x: x["truncated"],
                **kwargs
            )
        else:
            meta = acct_client.account_list(**kwargs)
            listing = meta["listing"]

        if parsed_args.long_listing:
            columns = (
                "Name",
                "Buckets",
                "Containers",
                "Shards",
                "Objects",
                "Bytes",
                "Ctime",
                "Mtime",
                "Metadata",
            )
            res = (
                (
                    v["id"],
                    v["buckets"],
                    v["containers"],
                    v.get("shards", 0),
                    v["objects"],
                    v["bytes"],
                    v["ctime"],
                    v["mtime"],
                    v["metadata"],
                )
                for v in listing
            )
        else:
            columns = ("Name",)
            res = ((v["id"],) for v in listing)
        return columns, res


class RefreshAccount(Command):
    """Refresh counters of an account and all its containers."""

    log = getLogger(__name__ + ".RefreshAccount")

    def get_parser(self, prog_name):
        from oio.cli.common.utils import ValueFormatStoreTrueAction

        parser = super(RefreshAccount, self).get_parser(prog_name)
        parser.add_argument(
            "account", nargs="?", metavar="<account>", help="Account to refresh"
        )
        parser.add_argument(
            "--all",
            dest="all_accounts",
            help="Refresh all accounts (<account> is ignored)",
            action=ValueFormatStoreTrueAction,
        )
        parser.add_argument(
            "--recompute",
            dest="recompute",
            help="Recompute statistics of every account containers",
            default=False,
            action=ValueFormatStoreTrueAction,
        )
        parser.add_argument(
            "--touch",
            dest="touch",
            help="Refresh all account containers",
            default=False,
            action=ValueFormatStoreTrueAction,
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        if parsed_args.all_accounts:
            self.app.client_manager.storage.account_refresh(
                recompute=parsed_args.recompute,
                container_refresh=parsed_args.touch or parsed_args.recompute,
            )
        elif parsed_args.account is not None:
            self.app.client_manager.storage.account_refresh(
                account=parsed_args.account,
                recompute=parsed_args.recompute,
                container_refresh=parsed_args.touch or parsed_args.recompute,
            )
        else:
            from argparse import ArgumentError

            raise ArgumentError(
                parsed_args.account, "Missing value for account or --all"
            )


class RecomputeAccount(Command):
    """Recompute all account service metrics."""

    log = getLogger(__name__ + ".RecomputeAccount")

    def take_action(self, parsed_args):
        self.log.debug("take action(%s)", parsed_args)

        self.app.client_manager.storage.account_metrics.metrics_recompute()


class FlushAccount(Command):
    """Flush account by emptying the list of its containers."""

    log = getLogger(__name__ + ".FlushAccount")

    def get_parser(self, prog_name):
        parser = super(FlushAccount, self).get_parser(prog_name)
        parser.add_argument("account", metavar="<account>", help="Account to flush")
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        self.app.client_manager.storage.account_flush(account=parsed_args.account)
