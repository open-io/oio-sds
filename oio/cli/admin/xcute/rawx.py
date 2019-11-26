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

from oio.cli import ShowOne, flat_dict_from_dict
from oio.cli.admin.common import SingleServiceCommandMixin
from oio.xcute.jobs.blob_mover import RawxDecommissionJob
from oio.xcute.jobs.blob_rebuilder import RawxRebuildJob


class RawxRebuild(SingleServiceCommandMixin, ShowOne):
    """
    Rebuild chunks that were on the specified service.
    It is necessary to declare an incident (with 'openio volume admin
    incident') before running this command.
    """

    @property
    def logger(self):
        return self.app.client_manager.logger

    @property
    def xcute(self):
        return self.app.client_manager.xcute_client

    def get_parser(self, prog_name):
        parser = super(RawxRebuild, self).get_parser(prog_name)
        SingleServiceCommandMixin.patch_parser(self, parser)

        parser.add_argument(
            '--chunks-per-second', type=int,
            help='Max chunks per second. '
                 '(default=%d)'
                 % RawxRebuildJob.DEFAULT_TASKS_PER_SECOND)
        parser.add_argument(
            '--rdir-fetch-limit', type=int,
            help='Maximum number of entries returned in each rdir response. '
                 '(default=%d)'
            % RawxRebuildJob.DEFAULT_RDIR_FETCH_LIMIT)
        parser.add_argument(
            '--rdir-timeout', type=float,
            help='Timeout for rdir operations, in seconds. (default=%f)'
                 % RawxRebuildJob.DEFAULT_RDIR_TIMEOUT)
        parser.add_argument(
            '--rawx-timeout', type=float,
            help='Timeout for rawx operations, in seconds. (default=%f)'
                 % RawxRebuildJob.DEFAULT_RAWX_TIMEOUT)
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

        return parser

    def take_action(self, parsed_args):
        SingleServiceCommandMixin.check_and_load_parsed_args(
            self, self.app, parsed_args)
        self.logger.debug('take_action(%s)', parsed_args)

        job_params = {
            'service_id': parsed_args.service,
            'rdir_fetch_limit': parsed_args.rdir_fetch_limit,
            'rdir_timeout': parsed_args.rdir_timeout,
            'rawx_timeout': parsed_args.rawx_timeout,
            'dry_run': parsed_args.dry_run,
            'try_chunk_delete': parsed_args.delete_faulty_chunks,
            'allow_frozen_container': parsed_args.allow_frozen_container
        }
        job_config = {
            'tasks_per_second': parsed_args.chunks_per_second,
            'params': job_params
        }
        job_info = self.xcute.job_create(
            RawxRebuildJob.JOB_TYPE, job_config=job_config)
        return zip(*sorted(
            flat_dict_from_dict(parsed_args, job_info).items()))


class RawxDecommission(SingleServiceCommandMixin, ShowOne):
    """
    Decommission the specified service.
    All chunks will be moved on the others services.
    """

    @property
    def logger(self):
        return self.app.client_manager.logger

    @property
    def xcute(self):
        return self.app.client_manager.xcute_client

    def get_parser(self, prog_name):
        parser = super(RawxDecommission, self).get_parser(prog_name)
        SingleServiceCommandMixin.patch_parser(self, parser)

        parser.add_argument(
            '--chunks-per-second', type=int,
            help='Max chunks per second. '
                 '(default=%d)'
                 % RawxDecommissionJob.DEFAULT_TASKS_PER_SECOND)
        parser.add_argument(
            '--rdir-fetch-limit', type=int,
            help='Maximum number of entries returned in each rdir response. '
                 '(default=%d)'
                 % RawxDecommissionJob.DEFAULT_RDIR_FETCH_LIMIT)
        parser.add_argument(
            '--rdir-timeout', type=float,
            help='Timeout for rdir operations, in seconds. (default=%f)'
                 % RawxDecommissionJob.DEFAULT_RDIR_TIMEOUT)
        parser.add_argument(
            '--rawx-timeout', type=float,
            help='Timeout for rawx operations, in seconds. (default=%f)'
                 % RawxDecommissionJob.DEFAULT_RAWX_TIMEOUT)
        parser.add_argument(
            '--min-chunk-size', type=int,
            help='Only move chunks larger than the given size.')
        parser.add_argument(
            '--max-chunk-size', type=int,
            help='Only move chunks smaller than the given size.')
        parser.add_argument(
            '--excluded-rawx',
            help="List of rawx not to use to move the chunks.")

        return parser

    def take_action(self, parsed_args):
        SingleServiceCommandMixin.check_and_load_parsed_args(
            self, self.app, parsed_args)
        self.logger.debug('take_action(%s)', parsed_args)

        job_params = {
            'service_id': parsed_args.service,
            'rdir_fetch_limit': parsed_args.rdir_fetch_limit,
            'rdir_timeout': parsed_args.rdir_timeout,
            'rawx_timeout': parsed_args.rawx_timeout,
            'min_chunk_size': parsed_args.min_chunk_size,
            'max_chunk_size': parsed_args.max_chunk_size,
            'excluded_rawx': parsed_args.excluded_rawx
        }
        job_config = {
            'tasks_per_second': parsed_args.chunks_per_second,
            'params': job_params
        }
        job_info = self.xcute.job_create(
            RawxDecommissionJob.JOB_TYPE, job_config=job_config)
        return zip(*sorted(
            flat_dict_from_dict(parsed_args, job_info).items()))
