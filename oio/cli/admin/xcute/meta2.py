# Copyright (C) 2019-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2023-2024 OVH SAS
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

from oio.cli.admin.common import SingleServiceCommandMixin
from oio.cli.admin.xcute import XcuteJobStartCommand, XcuteRdirCommand
from oio.xcute.jobs.meta2_decommissioner import Meta2DecommissionJob
from oio.xcute.jobs.meta2_rebuilder import Meta2RebuildJob
from oio.xcute.jobs.meta2_relocator import Meta2RelocationJob


class Meta2Relocate(XcuteJobStartCommand):
    """
    Analyze all containers of the local region,
    and move those who don't match the location constraints.
    """

    JOB_CLASS = Meta2RelocationJob

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        parser.add_argument(
            "--account-marker",
            help="Start analyzing containers from this account",
        )
        parser.add_argument(
            "--analyze-only",
            action="store_true",
            help="Display actions but do nothing.",
        )
        parser.add_argument(
            "--bases-per-second",
            type=int,
            help=(
                "Max bases per second. "
                f"(default={self.JOB_CLASS.DEFAULT_TASKS_PER_SECOND})"
            ),
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help=(
                "Do not relocate databases, "
                "but still try to find potential destinations."
            ),
        )
        return parser

    def get_job_config(self, parsed_args):
        job_params = {
            "account_marker": parsed_args.account_marker,
            "analyze_only": parsed_args.analyze_only,
            "dry_run": parsed_args.dry_run,
        }
        return {"tasks_per_second": parsed_args.bases_per_second, "params": job_params}


class Meta2Rebuild(SingleServiceCommandMixin, XcuteRdirCommand):
    """
    [BETA] Rebuild bases that were on the specified service.
    """

    JOB_CLASS = Meta2RebuildJob

    def get_parser(self, prog_name):
        parser = super(Meta2Rebuild, self).get_parser(prog_name)
        SingleServiceCommandMixin.patch_parser(self, parser)

        parser.add_argument(
            "--bases-per-second",
            type=int,
            help="Max bases per second. (default=%d)"
            % self.JOB_CLASS.DEFAULT_TASKS_PER_SECOND,
        )

        return parser

    def get_job_config(self, parsed_args):
        job_params = {
            "service_id": parsed_args.service,
            "rdir_fetch_limit": parsed_args.rdir_fetch_limit,
            "rdir_timeout": parsed_args.rdir_timeout,
        }
        return {"tasks_per_second": parsed_args.bases_per_second, "params": job_params}


class Meta2Decommission(SingleServiceCommandMixin, XcuteRdirCommand):
    """
    [BETA] Decommission a meta2 service.
    """

    JOB_CLASS = Meta2DecommissionJob

    def get_parser(self, prog_name):
        parser = super(Meta2Decommission, self).get_parser(prog_name)
        SingleServiceCommandMixin.patch_parser(self, parser)

        parser.add_argument(
            "--bases-per-second",
            type=int,
            help="Max bases per second. (default=%d)"
            % self.JOB_CLASS.DEFAULT_TASKS_PER_SECOND,
        )
        parser.add_argument(
            "--decommission-percentage",
            type=int,
            default=100 - self.JOB_CLASS.DEFAULT_USAGE_TARGET,
            help=(
                "Percentage of databases to decommission (default=%d)."
                % (100 - self.JOB_CLASS.DEFAULT_USAGE_TARGET)
            ),
        )
        parser.add_argument(
            "--dst", metavar="<service_id>", help="ID of the destination meta2."
        )

        return parser

    def get_job_config(self, parsed_args):
        job_params = {
            "service_id": parsed_args.service,
            "dst": parsed_args.dst,
            "rdir_fetch_limit": parsed_args.rdir_fetch_limit,
            "rdir_timeout": parsed_args.rdir_timeout,
            # We kept "usage_target" for the sake of code factorization
            "usage_target": 100 - parsed_args.decommission_percentage,
        }
        return {"tasks_per_second": parsed_args.bases_per_second, "params": job_params}
