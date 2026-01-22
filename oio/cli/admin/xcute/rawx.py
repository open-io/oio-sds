# Copyright (C) 2019-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2026 OVH SAS
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
from oio.common.easy_value import boolean_value
from oio.xcute.jobs.blob_mover import RawxDecommissionJob
from oio.xcute.jobs.blob_rebuilder import RawxRebuildJob


class RawxRebuild(SingleServiceCommandMixin, XcuteRdirCommand):
    """
    Rebuild chunks that were on the specified service.
    It is necessary to declare an incident (with 'openio volume admin
    incident') before running this command.
    """

    JOB_CLASS = RawxRebuildJob

    def get_parser(self, prog_name):
        parser = super(RawxRebuild, self).get_parser(prog_name)
        SingleServiceCommandMixin.patch_parser(self, parser)

        parser.add_argument(
            "--chunks-per-second",
            type=int,
            help="Max chunks per second. (default=%d)"
            % self.JOB_CLASS.DEFAULT_TASKS_PER_SECOND,
        )
        parser.add_argument(
            "--rawx-timeout",
            type=float,
            help="Timeout for rawx operations, in seconds. (default=%f)"
            % self.JOB_CLASS.DEFAULT_RAWX_TIMEOUT,
        )
        parser.add_argument(
            "--dry-run", action="store_true", help="Display actions but do nothing."
        )
        parser.add_argument(
            "--delete-faulty-chunks",
            action="store_true",
            help=(
                "Try to delete faulty chunks after they have been "
                "rebuilt elsewhere. This option is useful if the chunks "
                "you are rebuilding are not actually missing but are "
                "corrupted."
            ),
        )
        parser.add_argument(
            "--allow-frozen-container",
            action="store_true",
            help="Deprecated",
        )
        parser.add_argument(
            "--not-same-rawx",
            action="store_true",
            help=(
                "Prevent rebuilt rawx to be considered as destination rawx candidate"
            ),
        )
        parser.add_argument(
            "--read-all-available-sources",
            action="store_true",
            help="For objects using erasure-coding, connect to all apparently "
            "available chunks, to have backups in case one of them is "
            "silently corrupt.",
        )
        parser.add_argument(
            "--use-incident-date",
            action="store_true",
            help=(
                "Use the incident date set in the rdir associated to the rawx. "
                "Only chunks prior to this date will be rebuilt. "
                "Be aware that crawlers may automatically index chunks. "
                '(see "openio volume admin show").'
            ),
        )
        parser.add_argument(
            "--set-incident-date",
            action="store_true",
            help=(
                "Set a new incident date to rebuild from the current date. "
                'If "--use-incident-date" is set, the already existing incident '
                'date will be used (see "openio volume admin show"). '
                'Override the "--use-incident-date" parameter.'
            ),
        )
        parser.add_argument(
            "--set-specific-incident-date",
            type=int,
            help=(
                "Set a specific incident date to rebuild from this date "
                "(seconds since Epoch). "
                'Override the "--use-incident-date" and '
                '"--set-incident-date" parameters.'
            ),
        )

        return parser

    def get_job_config(self, parsed_args):
        job_params = {
            "service_id": parsed_args.service,
            "rdir_fetch_limit": parsed_args.rdir_fetch_limit,
            "rdir_timeout": parsed_args.rdir_timeout,
            "rawx_timeout": parsed_args.rawx_timeout,
            "dry_run": parsed_args.dry_run,
            "allow_same_rawx": not parsed_args.not_same_rawx,
            "read_all_available_sources": parsed_args.read_all_available_sources,
            "try_chunk_delete": parsed_args.delete_faulty_chunks,
            "use_incident_date": parsed_args.use_incident_date,
            "set_incident_date": parsed_args.set_incident_date,
            "set_specific_incident_date": parsed_args.set_specific_incident_date,
        }
        return {"tasks_per_second": parsed_args.chunks_per_second, "params": job_params}


class RawxDecommission(SingleServiceCommandMixin, XcuteJobStartCommand):
    """
    Decommission the specified service.
    All chunks matching the size constraints
    will be moved to others services.
    /!\\ WARNING /!\\ The specified service must be available.
    If it's not, please use the command "openio-admin xcute rawx rebuild".
    """

    JOB_CLASS = RawxDecommissionJob

    def get_parser(self, prog_name):
        parser = super(RawxDecommission, self).get_parser(prog_name)
        SingleServiceCommandMixin.patch_parser(self, parser)

        parser.add_argument(
            "--chunks-per-second",
            type=int,
            help="Max chunks per second. (default=%d)"
            % self.JOB_CLASS.DEFAULT_TASKS_PER_SECOND,
        )
        parser.add_argument(
            "--rawx-timeout",
            type=float,
            help="Timeout for rawx operations, in seconds. (default=%f)"
            % self.JOB_CLASS.DEFAULT_RAWX_TIMEOUT,
        )
        parser.add_argument(
            "--rawx-list-limit",
            type=int,
            help=(
                "Maximum number of entries returned in each rawx response. (default=%d)"
            )
            % self.JOB_CLASS.DEFAULT_RAWX_LIST_LIMIT,
        )
        parser.add_argument(
            "--min-chunk-size",
            type=int,
            help="Only move chunks larger than the given size.",
        )
        parser.add_argument(
            "--max-chunk-size",
            type=int,
            help="Only move chunks smaller than the given size.",
        )
        parser.add_argument(
            "--buffer-size",
            type=int,
            help=(
                "Chunk reader buffer size "
                + f"(default={self.JOB_CLASS.DEFAULT_BUFFER_SIZE}). "
                + "If the value is negative or zero, the readings will start "
                + "small and increase over time."
            ),
        )
        parser.add_argument(
            "--excluded-rawx",
            help=(
                "List of rawx (comma-separated) to exclude from possible "
                + 'destinations. The list can include "auto" '
                + "to exclude all rawx whose usage is already higher "
                + 'than "usage target".'
            ),
        )
        parser.add_argument(
            "--process-locally",
            metavar="yes/no",
            type=boolean_value,
            help=(
                "If true, all sent tasks will be processed only by the source server "
                + "using a dedicated topic ({xcute-job-topic}-{host-ip-address}) "
                + f"(default={self.JOB_CLASS.PROCESS_LOCALLY})."
            ),
        )
        parser.add_argument(
            "--rebuild-on-read-failure",
            metavar="yes/no",
            type=boolean_value,
            default=self.JOB_CLASS.REBUILD_ON_READ_FAILURE,
            help=(
                "If True, rebuild event is emitted for the unrecoverable chunk"
                + " (default=%f)" % self.JOB_CLASS.REBUILD_ON_READ_FAILURE
            ),
        )
        parser.add_argument(
            "--usage-target",
            type=float,
            default=self.JOB_CLASS.DEFAULT_USAGE_TARGET,
            help="Target percentage of volume usage. (default=%f)"
            % self.JOB_CLASS.DEFAULT_USAGE_TARGET,
        )
        parser.add_argument(
            "--usage-check-interval",
            type=float,
            help="Interval between disk usage check in seconds. (default=%f)"
            % self.JOB_CLASS.DEFAULT_USAGE_CHECK_INTERVAL,
        )

        return parser

    def get_job_config(self, parsed_args):
        job_params = {
            "service_id": parsed_args.service,
            "rawx_list_limit": parsed_args.rawx_list_limit,
            "rawx_timeout": parsed_args.rawx_timeout,
            "min_chunk_size": parsed_args.min_chunk_size,
            "max_chunk_size": parsed_args.max_chunk_size,
            "buffer_size": parsed_args.buffer_size,
            "excluded_rawx": parsed_args.excluded_rawx,
            "process_locally": parsed_args.process_locally,
            "rebuild_on_read_failure": parsed_args.rebuild_on_read_failure,
            "usage_target": parsed_args.usage_target,
            "usage_check_interval": parsed_args.usage_check_interval,
        }
        return {"tasks_per_second": parsed_args.chunks_per_second, "params": job_params}
