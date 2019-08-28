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


class ContainerVacuum(ContainerCommandMixin, lister.Lister):
    """
    Vacuum (defragment) a database.

    Execute the operation on the master service, then
    resynchronize the database on the slaves.
    """

    columns = ('Container', 'Status')

    def get_parser(self, prog_name):
        parser = super(ContainerVacuum, self).get_parser(prog_name)
        ContainerCommandMixin.patch_parser(self, parser)
        return parser

    def _take_action(self, parsed_args):
        admin = self.app.client_manager.admin
        if parsed_args.is_cid:
            for cid in parsed_args.containers:
                try:
                    admin.vacuum_base("meta2", cid=cid,
                                      reqid=self.app.request_id())
                    yield cid, "OK"
                except Exception as err:
                    yield cid, str(err)
        else:
            for cname in parsed_args.containers:
                try:
                    admin.vacuum_base("meta2",
                                      account=self.app.options.account,
                                      reference=cname,
                                      reqid=self.app.request_id())
                    yield cname, "OK"
                except Exception as err:
                    yield cname, str(err)

    def take_action(self, parsed_args):
        ContainerCommandMixin.check_and_load_parsed_args(
            self, self.app, parsed_args)
        return self.columns, self._take_action(parsed_args)
