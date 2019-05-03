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

from oio.common.easy_value import true_value
from oio.common.tool import Tool, ToolWorker
from oio.common.utils import cid_from_name
from oio.container.client import ContainerClient
from oio.directory.admin import AdminClient
from oio.directory.meta2 import Meta2Database


class ContainerRepairer(Tool):
    """
    Repair containers.
    """

    DEFAULT_REBUILD_BASES = True
    DEFAULT_SYNC_BASES = True
    DEFAULT_UPDATE_ACCOUNT = True

    def __init__(self, conf, containers=None, **kwargs):
        super(ContainerRepairer, self).__init__(conf, **kwargs)

        # input
        self.containers = containers

    @staticmethod
    def string_from_item(item):
        namespace, account, container = item
        return '%s|%s|%s' % (
            namespace, account, container)

    def _fetch_items_from_containers(self):
        for obj in self.containers:
            namespace = obj['namespace']
            account = obj['account']
            container = obj['container']
            yield namespace, account, container

    def _fetch_items(self):
        if self.containers:
            return self._fetch_items_from_containers()

        def _empty_generator():
            return
            yield  # pylint: disable=unreachable
        return _empty_generator()

    def _get_report(self, status, end_time, counters):
        containers_processed, total_containers_processed, \
            errors, total_errors = counters
        time_since_last_report = (end_time - self.last_report) or 0.00001
        total_time = (end_time - self.start_time) or 0.00001
        report = (
            '%(status)s '
            'last_report=%(last_report)s %(time_since_last_report).2fs '
            'containers=%(containers)d %(containers_rate).2f/s '
            'errors=%(errors)d %(errors_rate).2f%% '
            'start_time=%(start_time)s %(total_time).2fs '
            'total_containers='
            '%(total_containers)d %(total_containers_rate).2f/s '
            'total_errors=%(total_errors)d %(total_errors_rate).2f%%' % {
                'status': status,
                'last_report': datetime.fromtimestamp(
                    int(self.last_report)).isoformat(),
                'time_since_last_report': time_since_last_report,
                'containers': containers_processed,
                'containers_rate':
                    containers_processed / time_since_last_report,
                'errors': errors,
                'errors_rate': 100 * errors / float(containers_processed or 1),
                'start_time': datetime.fromtimestamp(
                    int(self.start_time)).isoformat(),
                'total_time': total_time,
                'total_containers': total_containers_processed,
                'total_containers_rate':
                    total_containers_processed / total_time,
                'total_errors': total_errors,
                'total_errors_rate':
                    100 * total_errors / float(total_containers_processed or 1)
                })
        if self.total_expected_items is not None:
            progress = 100 * total_containers_processed / \
                float(self.total_expected_items or 1)
            report += ' progress=%d/%d %.2f%%' % \
                (total_containers_processed, self.total_expected_items,
                 progress)
        return report

    def create_worker(self, queue_workers, queue_reply):
        return ContainerRepairerWorker(self, queue_workers, queue_reply)

    def _load_total_expected_items(self):
        if self.containers and isinstance(self.containers, list):
            self.total_expected_items = len(self.containers)


class ContainerRepairerWorker(ToolWorker):

    def __init__(self, tool, queue_workers, queue_reply):
        super(ContainerRepairerWorker, self).__init__(
            tool, queue_workers, queue_reply)

        self.rebuild_bases = true_value(self.tool.conf.get(
            'rebuild_bases', self.tool.DEFAULT_REBUILD_BASES))
        self.sync_bases = true_value(self.tool.conf.get(
            'sync_bases', self.tool.DEFAULT_SYNC_BASES))
        self.update_account = true_value(self.tool.conf.get(
            'update_account', self.tool.DEFAULT_UPDATE_ACCOUNT))

        self.admin_client = AdminClient(self.conf, logger=self.logger)
        self.container_client = ContainerClient(self.conf, logger=self.logger)
        self.meta2_database = Meta2Database(self.conf, logger=self.logger)

    def _process_item(self, item):
        namespace, account, container = item
        if namespace != self.tool.namespace:
            raise ValueError('Invalid namespace (actual=%s, expected=%s)' % (
                namespace, self.tool.namespace))

        errors = list()

        if self.rebuild_bases:
            cid = cid_from_name(account, container)
            for res in self.meta2_database.rebuild(cid):
                if res['err']:
                    errors.append('%s: %s' % (res['base'], res['err']))
            if errors:
                raise Exception(errors)

        if self.sync_bases:
            data = self.admin_client.election_sync(
                service_type='meta2', account=account, reference=container)
            for host, info in data.items():
                if info['status']['status'] not in (200, 301):
                    errors.append('%s (%d): %s' % (
                        host, info['status']['status'],
                        info['status']['message']))
            if errors:
                raise Exception(errors)

        if self.update_account:
            self.container_client.container_touch(
                account=account, reference=container)
