# Copyright (C) 2019-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021 OVH SAS
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

from datetime import datetime

from oio.cli import Lister, ShowOne, flat_dict_from_dict
from oio.cli.admin.xcute import XcuteCommand
from oio.cli.common.utils import KeyValueAction
from oio.xcute.common.job import XcuteJobStatus
from oio.xcute.jobs import JOB_TYPES


class JobList(XcuteCommand, Lister):
    """
    List all jobs.
    """

    columns = ('ID', 'Status', 'Type', 'Lock', 'Progress')

    def get_parser(self, prog_name):
        parser = super(JobList, self).get_parser(prog_name)
        parser.add_argument(
            '--date',
            help='Filter jobs with the specified job date '
                 '(%%Y-%%m-%%dT%%H:%%M:%%S)')
        parser.add_argument(
            '--status',
            choices=XcuteJobStatus.ALL,
            help='Filter jobs with the specified job status')
        parser.add_argument(
            '--type',
            choices=JOB_TYPES.keys(),
            help='Filter jobs with the specified job type')
        parser.add_argument(
            '--lock',
            help='Filter jobs with the specified job lock (wildcards allowed)')
        return parser

    def _take_action(self, parsed_args):
        prefix = None
        if parsed_args.date:
            datetime_input_format = ''
            datetime_output_format = ''
            datetime_info_split = parsed_args.date.split('T', 1)
            date_info_split = datetime_info_split[0].split('-', 2)
            if len(date_info_split) > 0:
                datetime_input_format += '%Y'
                datetime_output_format += '%Y'
            if len(date_info_split) > 1:
                datetime_input_format += '-%m'
                datetime_output_format += '%m'
            if len(date_info_split) > 2:
                datetime_input_format += '-%d'
                datetime_output_format += '%d'
            if len(datetime_info_split) > 1:
                if len(date_info_split) != 3:
                    raise ValueError('Wrong date format')
                time_info_split = datetime_info_split[1].split(':', 2)
                if len(time_info_split) > 0:
                    datetime_input_format += 'T%H'
                    datetime_output_format += '%H'
                if len(time_info_split) > 1:
                    datetime_input_format += ':%M'
                    datetime_output_format += '%M'
                if len(time_info_split) > 2:
                    datetime_input_format += ':%S'
                    datetime_output_format += '%S'
            try:
                job_date = datetime.strptime(parsed_args.date,
                                             datetime_input_format)
            except ValueError:
                raise ValueError('Wrong date format')
            prefix = job_date.strftime(datetime_output_format)

        jobs = self.xcute.job_list(
            prefix=prefix, job_status=parsed_args.status,
            job_type=parsed_args.type, job_lock=parsed_args.lock)
        for job_info in jobs:
            job_main_info = job_info['job']
            job_tasks = job_info['tasks']
            try:
                progress = job_tasks['processed'] * 100. / job_tasks['total']
            except ZeroDivisionError:
                if job_tasks['is_total_temp']:
                    progress = 0.
                else:
                    progress = 100.
            yield (job_main_info['id'], job_main_info['status'],
                   job_main_info['type'], job_main_info.get('lock'),
                   '%.2f%%' % progress)

    def take_action(self, parsed_args):
        self.logger.debug('take_action(%s)', parsed_args)

        return self.columns, self._take_action(parsed_args)


class JobShow(XcuteCommand, ShowOne):
    """
    Get all information about the job.
    """

    def get_parser(self, prog_name):
        parser = super(JobShow, self).get_parser(prog_name)
        parser.add_argument(
            'job_id',
            metavar='<job_id>',
            help=('ID of the job to show'))
        parser.add_argument(
            '--raw',
            action='store_true',
            help='Display raw information')
        return parser

    def take_action(self, parsed_args):
        self.logger.debug('take_action(%s)', parsed_args)

        job_info = self.xcute.job_show(parsed_args.job_id)

        if not parsed_args.raw:
            job_main_info = job_info['job']
            duration = job_main_info['mtime'] - job_main_info['ctime']
            job_main_info['duration'] = duration

            job_tasks = job_info['tasks']
            try:
                sent_percent = job_tasks['sent'] * 100. / job_tasks['total']
            except ZeroDivisionError:
                if job_tasks['is_total_temp']:
                    sent_percent = 0.
                else:
                    sent_percent = 100.
            job_tasks['sent_percent'] = sent_percent
            job_tasks['processed_per_second'] = \
                job_tasks['processed'] / (duration or 0.00001)
            try:
                processed_percent = \
                    job_tasks['processed'] * 100. / job_tasks['total']
            except ZeroDivisionError:
                if job_tasks['is_total_temp']:
                    processed_percent = 0.
                else:
                    processed_percent = 100.
            job_tasks['processed_percent'] = processed_percent

            if parsed_args.formatter == 'table':
                if not job_tasks['all_sent']:
                    if job_tasks['is_total_temp']:
                        total_state = 'estimating'
                    else:
                        total_state = 'estimated'
                    job_tasks['total'] = "%d (%s)" % (
                        job_tasks['total'], total_state)

            job_info.pop('orchestrator', None)
            job_main_info.pop('request_pause', None)
            job_tasks.pop('all_sent', None)
            job_tasks.pop('last_sent', None)
            job_tasks.pop('is_total_temp', None)
            job_tasks.pop('total_marker', None)

        return zip(*sorted(
            flat_dict_from_dict(parsed_args, job_info).items()))


class JobPause(XcuteCommand, Lister):
    """
    Pause the jobs.
    """

    columns = ('ID', 'Paused')

    def get_parser(self, prog_name):
        parser = super(JobPause, self).get_parser(prog_name)
        parser.add_argument(
            'job_ids',
            nargs='+',
            metavar='<job_id>',
            help=('IDs of the job to pause'))
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
    Resume the jobs.
    """

    columns = ('ID', 'Resumed')

    def get_parser(self, prog_name):
        parser = super(JobResume, self).get_parser(prog_name)
        parser.add_argument(
            'job_ids',
            nargs='+',
            metavar='<job_id>',
            help=('IDs of the job to to resume'))
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


class JobUpdate(XcuteCommand, ShowOne):
    """
    Update job configuration.
    """

    def get_parser(self, prog_name):
        parser = super(JobUpdate, self).get_parser(prog_name)
        parser.add_argument(
            'job_id',
            metavar='<job_id>',
            help=('ID of the job to update.'))
        parser.add_argument(
            '--tasks-per-second', type=int,
            help='Max tasks per second.')
        parser.add_argument(
            '--tasks-batch-size', type=int,
            help='Max tasks batch size.')
        parser.add_argument(
            '-p', '--param',
            dest='params',
            metavar='<key=value>',
            action=KeyValueAction,
            help='Configuration parameter to update'
        )
        return parser

    def take_action(self, parsed_args):
        self.logger.debug('take_action(%s)', parsed_args)

        job_config = dict()
        if parsed_args.tasks_per_second is not None:
            job_config['tasks_per_second'] = parsed_args.tasks_per_second
        if parsed_args.tasks_batch_size is not None:
            job_config['tasks_batch_size'] = parsed_args.tasks_batch_size
        if parsed_args.params is not None:
            job_config['params'] = parsed_args.params
        new_job_config = self.xcute.job_update(parsed_args.job_id, job_config)

        return zip(*sorted(
            flat_dict_from_dict(parsed_args, new_job_config).items()))


class JobDelete(XcuteCommand, Lister):
    """
    Delete all information about the jobs.
    """

    columns = ('ID', 'Deleted')

    def get_parser(self, prog_name):
        parser = super(JobDelete, self).get_parser(prog_name)
        parser.add_argument(
            'job_ids',
            nargs='+',
            metavar='<job_id>',
            help=('IDs of the job to delete'))
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
