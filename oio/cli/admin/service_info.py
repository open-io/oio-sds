# Copyright (C) 2019-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2024 OVH SAS
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


from cliff import show

from oio.cli import flat_dict_from_dict
from oio.cli.admin.common import SingleServiceCommandMixin


class ServiceInfo(SingleServiceCommandMixin, show.ShowOne):
    """
    Get all information from the specified service.

    Works on all services using ASN.1 protocol except conscience
    (meta0, meta1, meta2), plus rawx and rdir.
    """

    @property
    def logger(self):
        return self.app.client_manager.logger

    def get_parser(self, prog_name):
        parser = super(ServiceInfo, self).get_parser(prog_name)
        SingleServiceCommandMixin.patch_parser(self, parser)
        return parser

    def take_action(self, parsed_args):
        SingleServiceCommandMixin.check_and_load_parsed_args(
            self, self.app, parsed_args
        )
        svc_type, *_ = self.cmd_name.split(" ")
        self.logger.debug("take_action(%s)", parsed_args)
        self.logger.debug("service type: %s", svc_type)

        conf = self.app.client_manager.admin.service_get_info(
            parsed_args.service, svc_type=svc_type
        )
        return zip(*sorted(flat_dict_from_dict(parsed_args, conf).items()))
