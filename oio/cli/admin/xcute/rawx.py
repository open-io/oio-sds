# Copyright (C) 2019-2020 OpenIO SAS, as part of OpenIO SDS
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

from oio.cli.admin.common import SingleServiceCommandMixin
from oio.cli.admin.xcute import XcuteRdirCommand
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
            '--chunks-per-second', type=int,
            help='Max chunks per second. '
                 '(default=%d)'
                 % self.JOB_CLASS.DEFAULT_TASKS_PER_SECOND)
        parser.add_argument(
            '--rawx-timeout', type=float,
            help='Timeout for rawx operations, in seconds. (default=%f)'
                 % self.JOB_CLASS.DEFAULT_RAWX_TIMEOUT)
        parser.add_argument(
            '--dry-run', action='store_true',
            help='Display actions but do nothing.')
        parser.add_argument(
            '--delete-faulty-chunks', action='store_true',
            help='Try to delete faulty chunks after they have been '
                 'rebuilt elsewhere. This option is useful if the chunks '
                 'you are rebuilding are not actually missing but are '
                 'corrupted.')
        parser.add_argument(
            '--allow-frozen-container', action='store_true',
            help='Allow rebuilding a chunk in a frozen container.')
        parser.add_argument(
            '--set-incident-date', action='store_true',
            help='Set a new incident date to rebuild from the current date. '
                 'Otherwise, the already existing incident date will be used '
                 '(see "openio volume admin show").')
        parser.add_argument(
            '--set-specific-incident-date', type=int,
            help='Set a specific incident date to rebuild from this date '
                 '(seconds since Epoch). '
                 'Override the "--set-incident-date" parameter.')

        return parser

    def get_job_config(self, parsed_args):
        job_params = {
            'service_id': parsed_args.service,
            'rdir_fetch_limit': parsed_args.rdir_fetch_limit,
            'rdir_timeout': parsed_args.rdir_timeout,
            'rawx_timeout': parsed_args.rawx_timeout,
            'dry_run': parsed_args.dry_run,
            'try_chunk_delete': parsed_args.delete_faulty_chunks,
            'allow_frozen_container': parsed_args.allow_frozen_container,
            'set_incident_date': parsed_args.set_incident_date,
            'set_specific_incident_date':
                parsed_args.set_specific_incident_date
        }
        return {
            'tasks_per_second': parsed_args.chunks_per_second,
            'params': job_params
        }


class RawxDecommission(SingleServiceCommandMixin, XcuteRdirCommand):
    """
    Decommission the specified service.
    All chunks matching the size constraints
    will be moved on the others services.
    """

    JOB_CLASS = RawxDecommissionJob

    def get_parser(self, prog_name):
        parser = super(RawxDecommission, self).get_parser(prog_name)
        SingleServiceCommandMixin.patch_parser(self, parser)

        parser.add_argument(
            '--chunks-per-second', type=int,
            help='Max chunks per second. '
                 '(default=%d)'
                 % self.JOB_CLASS.DEFAULT_TASKS_PER_SECOND)
        parser.add_argument(
            '--rawx-timeout', type=float,
            help='Timeout for rawx operations, in seconds. (default=%f)'
                 % self.JOB_CLASS.DEFAULT_RAWX_TIMEOUT)
        parser.add_argument(
            '--min-chunk-size', type=int,
            help='Only move chunks larger than the given size.')
        parser.add_argument(
            '--max-chunk-size', type=int,
            help='Only move chunks smaller than the given size.')
        parser.add_argument(
            '--excluded-rawx',
            help='List of rawx not to use to move the chunks.')
        parser.add_argument(
            '--usage-target', type=float,
            help='Target percentage of volume usage. (default=%f)'
                 % self.JOB_CLASS.DEFAULT_USAGE_TARGET)
        parser.add_argument(
            '--usage-check-interval', type=float,
            help='Interval between disk usage check in seconds. (default=%f)'
                 % self.JOB_CLASS.DEFAULT_USAGE_CHECK_INTERVAL)

        return parser

    def get_job_config(self, parsed_args):
        job_params = {
            'service_id': parsed_args.service,
            'rdir_fetch_limit': parsed_args.rdir_fetch_limit,
            'rdir_timeout': parsed_args.rdir_timeout,
            'rawx_timeout': parsed_args.rawx_timeout,
            'min_chunk_size': parsed_args.min_chunk_size,
            'max_chunk_size': parsed_args.max_chunk_size,
            'excluded_rawx': parsed_args.excluded_rawx,
            'usage_target': parsed_args.usage_target,
            'usage_check_interval': parsed_args.usage_check_interval
        }
        return {
            'tasks_per_second': parsed_args.chunks_per_second,
            'params': job_params
        }
