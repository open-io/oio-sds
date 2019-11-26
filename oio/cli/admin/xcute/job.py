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

from oio.cli import Lister, ShowOne, flat_dict_from_dict
from oio.cli.admin.xcute import XcuteCommand


class JobList(XcuteCommand, Lister):
    """
    List all jobs
    """

    columns = ('ID', 'Status', 'Type', 'ctime', 'mtime')

    def _take_action(self, parsed_args):
        jobs = self.xcute.job_list()
        for job_info in jobs:
            job_main_info = job_info['job']
            yield (job_main_info['id'], job_main_info['status'],
                   job_main_info['type'], job_main_info['ctime'],
                   job_main_info['mtime'])

    def take_action(self, parsed_args):
        self.logger.debug('take_action(%s)', parsed_args)

        return self.columns, self._take_action(parsed_args)


class JobShow(XcuteCommand, ShowOne):
    """
    Get all informations about the job
    """

    def get_parser(self, prog_name):
        parser = super(JobShow, self).get_parser(prog_name)
        parser.add_argument(
            'job_id',
            metavar='<job_id>',
            help=("Job ID to show"))
        return parser

    def take_action(self, parsed_args):
        self.logger.debug('take_action(%s)', parsed_args)

        job_info = self.xcute.job_show(parsed_args.job_id)
        return zip(*sorted(
            flat_dict_from_dict(parsed_args, job_info).items()))


class JobPause(XcuteCommand, Lister):
    """
    Pause the jobs
    """

    columns = ('ID', 'Paused')

    def get_parser(self, prog_name):
        parser = super(JobPause, self).get_parser(prog_name)
        parser.add_argument(
            'job_ids',
            nargs='+',
            metavar='<job_id>',
            help=("Job IDs to pause"))
        return parser

    def _take_action(self, parsed_args):
        for job_id in parsed_args.job_ids:
            paused = True
            try:
                self.xcute.job_pause(job_id)
            except Exception as exc:
                self.logger.error('Failed to paused job %s: %s',
                                  job_id, exc)
                paused = False
            yield (job_id, paused)

    def take_action(self, parsed_args):
        self.logger.debug('take_action(%s)', parsed_args)

        return self.columns, self._take_action(parsed_args)


class JobResume(XcuteCommand, Lister):
    """
    Resume the jobs
    """

    columns = ('ID', 'Resumed')

    def get_parser(self, prog_name):
        parser = super(JobResume, self).get_parser(prog_name)
        parser.add_argument(
            'job_ids',
            nargs='+',
            metavar='<job_id>',
            help=("Job IDs to resume"))
        return parser

    def _take_action(self, parsed_args):
        for job_id in parsed_args.job_ids:
            resumed = True
            try:
                self.xcute.job_resume(job_id)
            except Exception as exc:
                self.logger.error('Failed to resumed job %s: %s',
                                  job_id, exc)
                resumed = False
            yield (job_id, resumed)

    def take_action(self, parsed_args):
        self.logger.debug('take_action(%s)', parsed_args)

        return self.columns, self._take_action(parsed_args)


class JobDelete(XcuteCommand, Lister):
    """
    Delete all informations about the jobs
    """

    columns = ('ID', 'Deleted')

    def get_parser(self, prog_name):
        parser = super(JobDelete, self).get_parser(prog_name)
        parser.add_argument(
            'job_ids',
            nargs='+',
            metavar='<job_id>',
            help=("Job IDs to delete"))
        return parser

    def _take_action(self, parsed_args):
        for job_id in parsed_args.job_ids:
            deleted = True
            try:
                self.xcute.job_delete(job_id)
            except Exception as exc:
                self.logger.error('Failed to deleted job %s: %s',
                                  job_id, exc)
                deleted = False
            yield (job_id, deleted)

    def take_action(self, parsed_args):
        self.logger.debug('take_action(%s)', parsed_args)

        return self.columns, self._take_action(parsed_args)
