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

from oio.cli.admin.common import MultipleServicesCommandMixin


class DecacheCommand(MultipleServicesCommandMixin, lister.Lister):
    """
    Base class for all decache commands.
    """

    columns = ('Id', 'Status', 'Errors')
    success = True

    @property
    def logger(self):
        return self.app.client_manager.logger

    @property
    def admin(self):
        """Get an instance of AdminClient."""
        return self.app.client_manager.admin

    def get_parser(self, prog_name):
        parser = super(DecacheCommand, self).get_parser(prog_name)
        MultipleServicesCommandMixin.patch_parser(self, parser)
        return parser

    def decache_services(self, services):
        """Send a decache request to each specified service."""
        raise NotImplementedError()

    def take_action(self, parsed_args):
        MultipleServicesCommandMixin.check_and_load_parsed_args(
            self, self.app, parsed_args)
        self.logger.debug('take_action(%s)', parsed_args)

        return self.columns, self.decache_services(parsed_args.services)

    def run(self, parsed_args):
        super(DecacheCommand, self).run(parsed_args)
        if not self.success:
            return 1


class ProxyDecache(DecacheCommand):
    """Flush the cache of a proxy service."""

    service_type = 'oioproxy'

    def decache_services(self, services):
        for srv in services:
            try:
                self.admin.proxy_flush_cache(proxy_netloc=srv)
                yield srv, 'OK', None
            except Exception as err:
                self.success = False
                yield srv, 'error', err


class SqliterepoDecacheCommand(DecacheCommand):
    """Flush the cache of an sqliterepo-based service."""

    def decache_services(self, services):
        for srv in services:
            try:
                self.admin.service_flush_cache(srv)
                yield srv, 'OK', None
            except Exception as err:
                self.success = False
                yield srv, 'error', err


class Meta1Decache(SqliterepoDecacheCommand):
    """Flush the cache of a meta1 service."""
    service_type = 'meta1'


class Meta2Decache(SqliterepoDecacheCommand):
    """Flush the cache of a meta2 service."""
    service_type = 'meta2'
