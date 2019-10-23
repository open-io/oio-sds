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

import signal
from datetime import datetime

from oio.cli import Command, Lister, ShowOne
from oio.xcute.common.manager import XcuteManager


class JobCommand(object):

    _manager = None

    @property
    def logger(self):
        return self.app.client_manager.logger

    @property
    def manager(self):
        if self._manager is None:
            self._manager = XcuteManager()
        return self._manager


class JobList(JobCommand, Lister):
    """
    List all jobs
    """

    columns = ('ID', 'Status', 'Type', 'ctime', 'mtime')

    def _take_action(self, parsed_args):
        jobs = self.manager.list_jobs()
        for job in jobs:
            yield (job['job_id'], job['status'], job['job_type'],
                   datetime.utcfromtimestamp(float(job['ctime'])),
                   datetime.utcfromtimestamp(float(job['mtime'])))

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

        job = self.manager.show_job(parsed_args.job_id)
        job['ctime'] = datetime.utcfromtimestamp(float(job['ctime']))
        job['mtime'] = datetime.utcfromtimestamp(float(job['mtime']))
        return zip(*sorted(job.items()))


class JobPause():
    pass


class JobResume(JobCommand, Command):
    """
    Resume the job
    """

    def get_parser(self, prog_name):
        parser = super(JobResume, self).get_parser(prog_name)
        parser.add_argument(
            'job_id',
            metavar='<job_id>',
            help=("Job ID to resume"))
        return parser

    def take_action(self, parsed_args):
        self.logger.debug('take_action(%s)', parsed_args)

        job = self.manager.resume_job(parsed_args.job_id)

        def exit_gracefully(signum, frame):
            job.exit_gracefully()

        signal.signal(signal.SIGINT, exit_gracefully)
        signal.signal(signal.SIGTERM, exit_gracefully)

        job.run()
        self.success = job.success


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
            help=("Job IDs to delete"))
        return parser

    def _take_action(self, parsed_args):
        for job_id in parsed_args.job_ids:
            deleted = True
            try:
                self.manager.delete_job(job_id)
            except Exception as exc:
                self.logger.error('Failed to deleted job %s: %s',
                                  job_id, exc)
                deleted = False
            yield (job_id, deleted)

    def take_action(self, parsed_args):
        self.logger.debug('take_action(%s)', parsed_args)

        return self.columns, self._take_action(parsed_args)


class JobGetConfig(JobCommand, ShowOne):
    """
    Get configuration of the job
    """

    def get_parser(self, prog_name):
        parser = super(JobGetConfig, self).get_parser(prog_name)
        parser.add_argument(
            'job_id',
            metavar='<job_id>',
            help=("Job ID to use"))
        return parser

    def take_action(self, parsed_args):
        self.logger.debug('take_action(%s)', parsed_args)

        return zip(*sorted(
            self.manager.get_job_config(parsed_args.job_id).items()))
