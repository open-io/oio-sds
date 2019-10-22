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


from oio.cli import Lister, ShowOne
from oio.xcute.common.backend import XcuteBackend


conf = dict()
conf['redis_host'] = '127.0.0.1:6379'


class JobCommand(object):

    _backend = None

    @property
    def logger(self):
        return self.app.client_manager.logger

    @property
    def backend(self):
        if self._backend is None:
            self._backend = XcuteBackend(conf)
        return self._backend


class JobList(JobCommand, Lister):
    """
    List all jobs
    """

    columns = ('ID', 'Status', 'Type', 'ctime', 'mtime')

    def _take_action(self, parsed_args):
        jobs = self.backend.list_jobs()
        for job in jobs:
            yield (job['job_id'], job['status'], job['job_type'],
                   job['ctime'], job['mtime'])

    def take_action(self, parsed_args):
        self.logger.debug('take_action(%s)', parsed_args)

        return self.columns, self._take_action(parsed_args)


class JobShow(JobCommand, ShowOne):
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

        return zip(*sorted(self.backend.get_job_info(
            parsed_args.job_id).items()))


class JobPause():
    pass


class JobResume():
    pass


class JobDelete(JobCommand, Lister):
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
            help=("Job ID to show"))
        return parser

    def _take_action(self, parsed_args):
        for job_id in parsed_args.job_ids:
            deleted = True
            try:
                self.backend.delete_job(job_id)
            except Exception as exc:
                self.logger.error('Failed to deleted job %s: %s',
                                  job_id, exc)
                deleted = False
            yield (job_id, deleted)

    def take_action(self, parsed_args):
        self.logger.debug('take_action(%s)', parsed_args)

        return self.columns, self._take_action(parsed_args)
