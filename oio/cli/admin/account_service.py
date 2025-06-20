# Copyright (C) 2022-2025 OVH SAS
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

from oio.account.cleaner import AccountServiceCleaner
from oio.cli import ShowOne
from oio.common.easy_value import boolean_value
from oio.common.exceptions import CommandError


class AccountServiceClean(ShowOne):
    """
    Delete (in account service) all containers and buckets belonging
    to this cluster that no longer exist.
    """

    @property
    def logger(self):
        return self.app.client_manager.logger

    def get_parser(self, prog_name):
        parser = super(AccountServiceClean, self).get_parser(prog_name)
        parser.add_argument(
            "--bucket",
            help="The name of the bucket to clean",
        )
        parser.add_argument(
            "--no-dry-run",
            dest="dry_run",
            default=True,
            action="store_false",
            help="Disable dry-run mode",
        )
        parser.add_argument(
            "--force",
            dest="force",
            default=False,
            action="store_true",
            help="Skip confirmation",
        )
        return parser

    def take_action(self, parsed_args):
        self.logger.debug("take_action(%s)", parsed_args)
        reqid = self.app.request_id()

        if not parsed_args.dry_run and not parsed_args.force:
            input_text = input(
                "Please note that this command will delete data in "
                "the account service.\nAre you sure you want to continue? "
                "[No/yes] "
            )
            if not boolean_value(input_text, default=False):
                return (
                    ("success", "deleted-containers", "released-buckets"),
                    ("Aborted", 0, 0),
                )

        try:
            account = self.app.client_manager.account
        except CommandError:
            account = None
        cleaner = AccountServiceCleaner(
            self.app.client_manager.namespace,
            account=account,
            bucket=parsed_args.bucket,
            dry_run=parsed_args.dry_run,
            logger=self.logger,
        )
        self.success = cleaner.run(reqid=reqid)
        if self.success:
            if cleaner.deleted_containers > 0:
                self.error_code = 2
            elif cleaner.deleted_buckets > 0:
                self.error_code = 3
        return (
            (
                "dry-run",
                "success",
                "deleted-containers",
                "deleted-buckets",
                "excess-volume",
            ),
            (
                parsed_args.dry_run,
                cleaner.success,
                cleaner.deleted_containers,
                cleaner.deleted_buckets,
                cleaner.excess_volume,
            ),
        )
