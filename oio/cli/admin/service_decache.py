# Copyright (C) 2019-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2023 OVH SAS
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

from cliff import lister

from oio.cli.admin.common import MultipleServicesCommandMixin
from oio.common.configuration import load_namespace_conf


class DecacheCommand(MultipleServicesCommandMixin, lister.Lister):
    """
    Base class for all decache commands.
    """

    columns = ("Id", "Status", "Errors")
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

    def decache_services(self, services, _args):
        """Send a decache request to each specified service."""
        raise NotImplementedError()

    def take_action(self, parsed_args):
        self.check_and_load_parsed_args(self.app, parsed_args)
        self.logger.debug("take_action(%s)", parsed_args)

        return self.columns, self.decache_services(parsed_args.services, parsed_args)

    def run(self, parsed_args):
        super(DecacheCommand, self).run(parsed_args)
        if not self.success:
            return 1


class ProxyDecache(DecacheCommand):
    """Flush the cache of a proxy service."""

    service_type = "oioproxy"

    def get_parser(self, prog_name):
        parser = super(ProxyDecache, self).get_parser(prog_name)
        parser.add_argument(
            "--high",
            action="store_false",
            dest="low",
            help=(
                'Flush the "high" cache only, i.e. the list of all meta0 '
                "services and the prefix/meta1 association "
                "(content of meta0 DB)."
            ),
        )
        parser.add_argument(
            "--low",
            action="store_false",
            dest="high",
            help=(
                'Flush the "low" cache only, i.e. the reference/service '
                "association (content of meta1 DB)."
            ),
        )
        return parser

    def decache_services(self, services, args):
        if not (args.high or args.low):
            args.high = args.low = True
        reqid = self.app.request_id()
        for srv in services:
            try:
                self.admin.proxy_flush_cache(
                    proxy_netloc=srv, reqid=reqid, high=args.high, low=args.low
                )
                yield srv, "OK", None
            except Exception as err:
                self.success = False
                yield srv, "error", err


class SqliterepoDecacheCommand(DecacheCommand):
    """Flush the cache of an sqliterepo-based service."""

    def decache_services(self, services, _args):
        reqid = self.app.request_id()
        for srv in services:
            try:
                self.admin.service_flush_cache(srv, reqid=reqid)
                yield srv, "OK", None
            except Exception as err:
                self.success = False
                yield srv, "error", err


class Meta1Decache(SqliterepoDecacheCommand):
    """Flush the cache of a meta1 service."""

    service_type = "meta1"


class Meta2Decache(SqliterepoDecacheCommand):
    """Flush the cache of a meta2 service."""

    service_type = "meta2"


class ReleaseMemoryBase(DecacheCommand):
    """Ask a service to release memory."""

    def decache_services(self, services, args):
        reqid = self.app.request_id()
        for srv in services:
            try:
                self.admin.service_release_memory(svc_id=srv, reqid=reqid)
                yield srv, "OK", None
            except Exception as err:
                self.success = False
                yield srv, "error", err


class ConscienceReleaseMemory(ReleaseMemoryBase):
    service_type = "conscience"

    def check_and_load_parsed_args(self, app, parsed_args):
        # Cannot use the default implementation since conscience services
        # are not registered.
        if not parsed_args.services:
            conf = load_namespace_conf(app.client_manager.namespace)
            parsed_args.services = conf["conscience"].split(",")


class Meta0ReleaseMemory(ReleaseMemoryBase):
    service_type = "meta0"


class Meta1ReleaseMemory(ReleaseMemoryBase):
    service_type = "meta1"


class Meta2ReleaseMemory(ReleaseMemoryBase):
    service_type = "meta2"
