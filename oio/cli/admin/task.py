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


class TaskCommand(object):

    _backend = None

    @property
    def logger(self):
        return self.app.client_manager.logger

    @property
    def backend(self):
        if self._backend is None:
            self._backend = XcuteBackend(conf)
        return self._backend


class TaskList(TaskCommand, Lister):
    """
    List all tasks
    """

    columns = ('ID', 'Status', 'Type', 'ctime', 'mtime')

    def _take_action(self, parsed_args):
        tasks = self.backend.list_tasks()
        for task in tasks:
            yield (task['task_id'], task['status'], task['task_type'],
                   task['ctime'], task['mtime'])

    def take_action(self, parsed_args):
        self.logger.debug('take_action(%s)', parsed_args)

        return self.columns, self._take_action(parsed_args)


class TaskShow(TaskCommand, ShowOne):
    """
    Get all informations about the task
    """

    def get_parser(self, prog_name):
        parser = super(TaskShow, self).get_parser(prog_name)
        parser.add_argument(
            'task_id',
            metavar='<task_id>',
            help=("Task ID to show"))
        return parser

    def take_action(self, parsed_args):
        self.logger.debug('take_action(%s)', parsed_args)

        return zip(*sorted(self.backend.get_task_info(
            parsed_args.task_id).items()))


class TaskPause():
    pass


class TaskResume():
    pass


class TaskDelete(TaskCommand, Lister):
    """
    Delete all informations about the tasks
    """

    columns = ('ID', 'Deleted')

    def get_parser(self, prog_name):
        parser = super(TaskDelete, self).get_parser(prog_name)
        parser.add_argument(
            'task_ids',
            nargs='+',
            metavar='<task_id>',
            help=("Task ID to show"))
        return parser

    def _take_action(self, parsed_args):
        for task_id in parsed_args.task_ids:
            deleted = True
            try:
                self.backend.delete_task(task_id)
            except Exception as exc:
                self.logger.error('Failed to deleted task %s: %s',
                                  task_id, exc)
                deleted = False
            yield (task_id, deleted)

    def take_action(self, parsed_args):
        self.logger.debug('take_action(%s)', parsed_args)

        return self.columns, self._take_action(parsed_args)
