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

from oio.account.cleaner import AccountServiceCleaner
from oio.cli import ShowOne


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
            '--no-dry-run',
            dest='dry_run',
            default=True,
            action='store_false',
            help='Report action that should be taken')
        return parser

    def take_action(self, parsed_args):
        self.logger.debug('take_action(%s)', parsed_args)

        if not parsed_args.dry_run:
            input_text = input(
                'Please note that this command will delete data in '
                'the account service.\nAre you sure you want to continue? '
                '[No/yes] ')
            if input_text.lower() != 'yes':
                return (('success', 'deleted-containers', 'released-buckets'),
                        ('Aborted', 0, 0))

        cleaner = AccountServiceCleaner(
            self.app.client_manager.namespace, dry_run=parsed_args.dry_run,
            logger=self.logger)
        self.success = cleaner.run()
        return (('success', 'deleted-containers', 'released-buckets'),
                (self.success, cleaner.deleted_containers,
                 cleaner.released_buckets))
