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

from oio.cli import ShowOne, flat_dict_from_dict


class XcuteCommand(object):

    @property
    def logger(self):
        return self.app.client_manager.logger

    @property
    def xcute(self):
        return self.app.client_manager.xcute_client


class XcuteRdirCommand(XcuteCommand, ShowOne):
    """
    Class holding rdir-related parameters.
    """

    JOB_CLASS = None

    def get_parser(self, prog_name):
        parser = super(XcuteRdirCommand, self).get_parser(prog_name)

        parser.add_argument(
            '--rdir-fetch-limit', type=int,
            help='Maximum number of entries returned in each rdir response. '
                 '(default=%d)'
            % self.JOB_CLASS.DEFAULT_RDIR_FETCH_LIMIT)
        parser.add_argument(
            '--rdir-timeout', type=float,
            help='Timeout for rdir operations, in seconds. (default=%f)'
                 % self.JOB_CLASS.DEFAULT_RDIR_TIMEOUT)

        return parser

    def get_job_config(self, parsed_args):
        raise NotImplementedError()

    def take_action(self, parsed_args):
        self.logger.debug('take_action(%s)', parsed_args)

        job_config = self.get_job_config(parsed_args)
        job_info = self.xcute.job_create(
            self.JOB_CLASS.JOB_TYPE, job_config=job_config)
        return zip(*sorted(
            flat_dict_from_dict(parsed_args, job_info).items()))
