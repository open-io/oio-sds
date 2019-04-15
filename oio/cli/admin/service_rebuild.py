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

from oio.rebuilder.meta1_rebuilder import Meta1Rebuilder
from oio.rebuilder.meta2_rebuilder import Meta2Rebuilder


class ServiceRebuildCommand(lister.Lister):
    """
    Various parameters that apply to all rebuild commands.
    """

    def get_parser(self, prog_name):
        parser = super(ServiceRebuildCommand, self).get_parser(prog_name)
        parser.add_argument(
            '--workers',
            type=int,
            default=1,
            help="Number of workers."
        )
        parser.add_argument(
            '--items-per-second',
            type=int,
            default=30,
            help="Max items per second per worker (30)."
        )
        ifile_help = "Read container IDs from this file instead of redis. " \
                     "Each line should contain one container ID."
        parser.add_argument('--input-file', nargs='?',
                            help=ifile_help)
        # TODO(mbo): instead of using file, we should support args
        return parser

    def get_conf(self, parsed_args):
        conf = {}
        conf['namespace'] = self.app.options.ns
        conf['workers'] = parsed_args.workers
        conf['items_per_second'] = parsed_args.items_per_second
        return conf

    @property
    def logger(self):
        return self.app.client_manager.logger

    def take_action(self, parsed_args):
        conf = self.get_conf(parsed_args)

        meta1_rebuilder = self.METHOD(conf, self.logger,
                                      input_file=parsed_args.input_file)
        if meta1_rebuilder.rebuilder_pass():
            status = 'Done'
        else:
            status = 'Error'
        return ('Status', ), ((status, ), )


class Meta1Rebuild(ServiceRebuildCommand):
    """
    Rebuild meta1 databases by setting 'last_rebuild' property in admin table,
    thus triggering a replication.And print the failed container IDs.
    """
    METHOD = Meta1Rebuilder


class Meta2Rebuild(ServiceRebuildCommand):
    """
    Rebuild meta2 databases by setting 'last_rebuild'
    property in admin table, thus triggering a replication.
    And print the failed container IDs.
    """
    METHOD = Meta2Rebuilder
