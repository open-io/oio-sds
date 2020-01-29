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
from oio.xcute.jobs.container_mover import ContainerMoveJob
from oio.xcute.jobs.meta2_rebuilder import Meta2RebuildJob


class Meta2Rebuild(SingleServiceCommandMixin, ShowOne):
    """
    Rebuild containers that were on the specified service.
    """

    @property
    def logger(self):
        return self.app.client_manager.logger

    @property
    def xcute(self):
        return self.app.client_manager.xcute_client

    def get_parser(self, prog_name):
        parser = super(Meta2Rebuild, self).get_parser(prog_name)
        SingleServiceCommandMixin.patch_parser(self, parser)

        parser.add_argument(
            '--containers-per-second', type=int,
            help='Max chunks per second. '
                 '(default=%d)'
                 % Meta2RebuildJob.DEFAULT_TASKS_PER_SECOND)
        parser.add_argument(
            '--rdir-fetch-limit', type=int,
            help='Maximum number of entries returned in each rdir response. '
                 '(default=%d)'
            % Meta2RebuildJob.DEFAULT_RDIR_FETCH_LIMIT)

        return parser

    def take_action(self, parsed_args):
        SingleServiceCommandMixin.check_and_load_parsed_args(
            self, self.app, parsed_args)
        self.logger.debug('take_action(%s)', parsed_args)

        job_params = {
            'service_id': parsed_args.service,
            'rdir_fetch_limit': parsed_args.rdir_fetch_limit,
        }
        job_config = {
            'tasks_per_second': parsed_args.containers_per_second,
            'params': job_params
        }
        job_info = self.xcute.job_create(
            Meta2RebuildJob.JOB_TYPE, job_config=job_config)
        return zip(*sorted(
            flat_dict_from_dict(parsed_args, job_info).items()))


class Meta2Decommission(SingleServiceCommandMixin, ShowOne):
    """
    Move the specified meta2.
    """

    @property
    def logger(self):
        return self.app.client_manager.logger

    @property
    def xcute(self):
        return self.app.client_manager.xcute_client

    def get_parser(self, prog_name):
        parser = super(Meta2Decommission, self).get_parser(prog_name)
        SingleServiceCommandMixin.patch_parser(self, parser)

        parser.add_argument(
            '--containers-per-second', type=int,
            help='Max containers per second. '
                 '(default=%d)'
                 % ContainerMoveJob.DEFAULT_TASKS_PER_SECOND)
        parser.add_argument(
            '--dst',
            metavar='<service_id>',
            help='ID of the destination meta2.')

        return parser

    def take_action(self, parsed_args):
        self.logger.debug('take_action(%s)', parsed_args)

        job_params = {
            'service_id': parsed_args.service,
            'dst': parsed_args.dst,
        }
        job_config = {
            'tasks_per_second': parsed_args.containers_per_second,
            'params': job_params
        }
        job_info = self.xcute.job_create(
            ContainerMoveJob.JOB_TYPE, job_config=job_config)
        return zip(*sorted(
            flat_dict_from_dict(parsed_args, job_info).items()))
