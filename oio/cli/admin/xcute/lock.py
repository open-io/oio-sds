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

from operator import itemgetter

from oio.cli import Lister, ShowOne
from oio.cli.admin.xcute import XcuteCommand


class LockList(XcuteCommand, Lister):
    """
    List all locks.
    """

    columns = ('Lock', 'Job ID')

    def _take_action(self, parsed_args):
        locks = self.xcute.lock_list()
        for lock in locks:
            yield itemgetter('lock', 'job_id')(lock)

    def take_action(self, parsed_args):
        self.logger.debug('take_action(%s)', parsed_args)

        return self.columns, self._take_action(parsed_args)


class LockShow(XcuteCommand, ShowOne):
    """
    Get all information about one lock.
    """

    def get_parser(self, prog_name):
        parser = super(LockShow, self).get_parser(prog_name)
        parser.add_argument(
            'lock',
            metavar='<lock>',
            help=("Lock to show"))
        return parser

    def take_action(self, parsed_args):
        self.logger.debug('take_action(%s)', parsed_args)

        lock_info = self.xcute.lock_show(parsed_args.lock)

        return [('lock', 'job_id'), itemgetter('lock', 'job_id')(lock_info)]
