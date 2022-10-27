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

from oio.cli import flat_dict_from_dict
from oio.cli.admin.common import SingleServiceCommandMixin
from oio.cli.admin.xcute import ShowOne, XcuteCommand
from oio.xcute.jobs.rdir_decommissionner import RdirDecommissionJob


class RdirDecommission(SingleServiceCommandMixin, XcuteCommand, ShowOne):
    """
    Decommission all bases hosted on an rdir service, for the specified
    service type (rawx, meta2).
    """

    JOB_CLASS = RdirDecommissionJob

    def get_parser(self, prog_name):
        parser = super(RdirDecommission, self).get_parser(prog_name)
        SingleServiceCommandMixin.patch_parser(self, parser)

        parser.add_argument(
            "--service_type",
            choices=["all"] + RdirDecommissionJob.ALLOWED_SERVICE_TYPES,
            default="all",
            help="Which hosted service type to work on.",
        )
        parser.add_argument(
            "--min-dist",
            metavar="<N>",
            type=int,
            help=(
                "Minimum required distance between any service and "
                "its assigned rdir service."
            ),
        )
        parser.add_argument(
            "--replicas",
            metavar="<N>",
            type=int,
            default=RdirDecommissionJob.DEFAULT_REPLICAS,
            help="Number of rdir replicas per hosted service.",
        )
        parser.add_argument(
            "--dry-run", action="store_true", help="Display actions but do nothing."
        )

        return parser

    def get_job_config(self, parsed_args):
        job_params = {
            "service_id": parsed_args.service,
            "dry_run": parsed_args.dry_run,
            "min_dist": parsed_args.min_dist,
            "replicas": parsed_args.replicas,
        }
        if parsed_args.service_type == "all":
            job_params["service_types"] = RdirDecommissionJob.ALLOWED_SERVICE_TYPES
        else:
            job_params["service_types"] = [parsed_args.service_type]
        return {"params": job_params}

    def take_action(self, parsed_args):
        self.logger.debug("take_action(%s)", parsed_args)

        job_config = self.get_job_config(parsed_args)
        job_info = self.xcute.job_create(self.JOB_CLASS.JOB_TYPE, job_config=job_config)
        return zip(*sorted(flat_dict_from_dict(parsed_args, job_info).items()))
