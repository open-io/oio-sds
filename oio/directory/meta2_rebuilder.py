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


from datetime import datetime

from oio.common.easy_value import int_value
from oio.common.tool import Tool, ToolWorker
from oio.rdir.client import RdirClient
from oio.directory.admin import AdminClient
from oio.directory.meta2 import Meta2Database


class Meta2Rebuilder(Tool):
    """
    Rebuild meta2 databases.
    """

    DEFAULT_RDIR_FETCH_LIMIT = 100

    def __init__(self, conf, input_file=None, service_id=None, **kwargs):
        super(Meta2Rebuilder, self).__init__(conf, **kwargs)

        # input
        self.input_file = input_file
        self.meta2_id = service_id

        # rawx/rdir
        self.rdir_client = RdirClient(self.conf, logger=self.logger)
        self.rdir_fetch_limit = int_value(
            self.conf.get('rdir_fetch_limit'), self.DEFAULT_RDIR_FETCH_LIMIT)

    @staticmethod
    def string_from_item(item):
        namespace, container_id = item
        return '%s|%s' % (namespace, container_id)

    def _fetch_items_from_input_file(self):
        with open(self.input_file, 'r') as ifile:
            for line in ifile:
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue

                container_id = stripped
                yield self.namespace, container_id

    def _fetch_items_from_meta2_id(self):
        containers = self.rdir_client.meta2_index_fetch_all(self.meta2_id)
        for container in containers:
            yield self.namespace, container['container_id']

    def _fetch_items(self):
        if self.input_file:
            return self._fetch_items_from_input_file()
        if self.meta2_id:
            return self._fetch_items_from_meta2_id()

        def _empty_generator():
            return
            yield  # pylint: disable=unreachable
        return _empty_generator()

    def _get_report(self, status, end_time, counters):
        references_processed, total_references_processed, \
            errors, total_errors = counters
        time_since_last_report = (end_time - self.last_report) or 0.00001
        total_time = (end_time - self.start_time) or 0.00001
        report = (
            '%(status)s '
            'last_report=%(last_report)s %(time_since_last_report).2fs '
            'references=%(references)d %(references_rate).2f/s '
            'errors=%(errors)d %(errors_rate).2f%% '
            'start_time=%(start_time)s %(total_time).2fs '
            'total_references='
            '%(total_references)d %(total_references_rate).2f/s '
            'total_errors=%(total_errors)d %(total_errors_rate).2f%%' % {
                'status': status,
                'last_report': datetime.fromtimestamp(
                    int(self.last_report)).isoformat(),
                'time_since_last_report': time_since_last_report,
                'references': references_processed,
                'references_rate':
                    references_processed / time_since_last_report,
                'errors': errors,
                'errors_rate': 100 * errors / float(references_processed or 1),
                'start_time': datetime.fromtimestamp(
                    int(self.start_time)).isoformat(),
                'total_time': total_time,
                'total_references': total_references_processed,
                'total_references_rate':
                    total_references_processed / total_time,
                'total_errors': total_errors,
                'total_errors_rate':
                    100 * total_errors / float(total_references_processed or 1)
                })
        if self.total_expected_items is not None:
            progress = 100 * total_references_processed / \
                float(self.total_expected_items or 1)
            report += ' progress=%d/%d %.2f%%' % \
                (total_references_processed, self.total_expected_items,
                 progress)
        return report

    def create_worker(self, queue_workers, queue_reply):
        return ContentRepairerWorker(self, queue_workers, queue_reply)

    def _load_total_expected_items(self):
        pass


class ContentRepairerWorker(ToolWorker):

    def __init__(self, tool, queue_workers, queue_reply):
        super(ContentRepairerWorker, self).__init__(
            tool, queue_workers, queue_reply)

        self.admin_client = AdminClient(self.conf, logger=self.logger)
        self.meta2_database = Meta2Database(self.conf, logger=self.logger)

    def _process_item(self, item):
        namespace, container_id = item
        if namespace != self.tool.namespace:
            raise ValueError('Invalid namespace (actual=%s, expected=%s)' % (
                namespace, self.tool.namespace))

        self.logger.debug('Rebuilding %s', self.tool.string_from_item(item))
        errors = list()
        for res in self.meta2_database.rebuild(container_id):
            if res['err']:
                errors.append('%s: %s' % (res['base'], res['err']))
        if errors:
            raise Exception(errors)

        data = self.admin_client.election_sync(
            service_type='meta2', cid=container_id)
        for host, info in data.items():
            if info['status']['status'] not in (200, 301):
                errors.append('%s (%d): %s' % (
                    host, info['status']['status'], info['status']['message']))
        if errors:
            raise Exception(errors)
