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
from oio.xcute.jobs.mover import RawxDecommissionJob


class RawxDecommission(MultipleServicesCommandMixin, lister.Lister):

    columns = ('Service ID', 'Job ID')

    @property
    def logger(self):
        return self.app.client_manager.logger

    @property
    def xcute(self):
        return self.app.client_manager.xcute_client

    def get_parser(self, prog_name):
        parser = super(RawxDecommission, self).get_parser(prog_name)
        MultipleServicesCommandMixin.patch_parser(self, parser)

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

    def _take_action(self, parsed_args):
        job_params = {
            'rdir_fetch_limit': parsed_args.rdir_fetch_limit,
            'rdir_timeout': parsed_args.rdir_timeout,
            'rawx_timeout': parsed_args.rawx_timeout,
            'min_chunk_size': parsed_args.min_chunk_size,
            'max_chunk_size': parsed_args.max_chunk_size,
            'excluded_rawx': parsed_args.excluded_rawx
        }

        for service_id in parsed_args.services:
            job_params['service_id'] = service_id
            try:
                job_info_ = self.xcute.job_create(
                    RawxDecommissionJob.JOB_TYPE, job_params=job_params)
                res = job_info_['job.id']
            except Exception as exc:
                res = str(exc)
            yield (service_id, res)

    def take_action(self, parsed_args):
        MultipleServicesCommandMixin.check_and_load_parsed_args(
            self, self.app, parsed_args)
        return (self.columns, self._take_action(parsed_args))
