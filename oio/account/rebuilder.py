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

from oio import ObjectStorageApi
from oio.account.client import AccountClient
from oio.common.green import eventlet
from oio.common.tool import Tool, ToolWorker


class AccountRebuilder(Tool):
    """
    Rebuild the account services.
    """

    def __init__(self, conf, accounts=None, **kwargs):
        super(AccountRebuilder, self).__init__(conf, **kwargs)
        self._accounts_to_refresh = set()
        self._accounts_refreshed = eventlet.Queue()

        # input
        self.accounts = accounts

        self.account_client = AccountClient(self.conf, logger=self.logger)

    @staticmethod
    def string_from_item(item):
        namespace, account, container = item
        if container is None:
            return '%s|%s' % (namespace, account)
        return '%s|%s|%s' % (namespace, account, container)

    def _fetch_items_from_accounts(self):
        for obj in self.accounts:
            namespace = obj['namespace']
            account = obj['account']
            item = namespace, account, None
            yield item

    def _fetch_items_from_all_accounts(self):
        try:
            accounts = self.account_client.account_list()
            for account in accounts:
                item = self.namespace, account, None
                yield item
        except Exception as exc:
            self.success = False
            self.logger.error('Failed to list accounts: %s', exc)

    def _fetch_items(self):
        if self.accounts:
            items = self._fetch_items_from_accounts()
        else:
            items = self._fetch_items_from_all_accounts()
        for item in items:
            self._accounts_to_refresh.add(item)
            yield item

        while True:
            if not self._accounts_to_refresh:
                break
            item = self._accounts_refreshed.get()
            namespace, account, error = item
            self._accounts_to_refresh.remove((namespace, account, None))
            if error:
                continue
            try:
                containers = self.account_client.container_list(account)
                for container in containers["listing"]:
                    yield namespace, account, container[0]
            except Exception as exc:
                self.success = False
                self.logger.error('Failed to list containers (account=%s): %s',
                                  account, exc)

    def _get_report(self, status, end_time, counters):
        entries_processed, total_entries_processed, \
            errors, total_errors = counters
        time_since_last_report = (end_time - self.last_report) or 0.00001
        total_time = (end_time - self.start_time) or 0.00001
        report = (
            '%(status)s '
            'last_report=%(last_report)s %(time_since_last_report).2fs '
            'entries=%(entries)d %(entries_rate).2f/s '
            'errors=%(errors)d %(errors_rate).2f%% '
            'start_time=%(start_time)s %(total_time).2fs '
            'total_entries=%(total_entries)d %(total_entries_rate).2f/s '
            'total_errors=%(total_errors)d %(total_errors_rate).2f%%' % {
                'status': status,
                'last_report': datetime.fromtimestamp(
                    int(self.last_report)).isoformat(),
                'time_since_last_report': time_since_last_report,
                'entries': entries_processed,
                'entries_rate': entries_processed / time_since_last_report,
                'errors': errors,
                'errors_rate': 100 * errors / float(entries_processed or 1),
                'start_time': datetime.fromtimestamp(
                    int(self.start_time)).isoformat(),
                'total_time': total_time,
                'total_entries': total_entries_processed,
                'total_entries_rate': total_entries_processed / total_time,
                'total_errors': total_errors,
                'total_errors_rate':
                    100 * total_errors / float(total_entries_processed or 1)
                })
        if self.total_expected_items is not None:
            progress = 100 * total_entries_processed / \
                float(self.total_expected_items or 1)
            report += ' progress=%d/%d %.2f%%' % \
                (total_entries_processed, self.total_expected_items, progress)
        return report

    def create_worker(self, queue_workers, queue_reply):
        return AccountRebuilderWorker(self, queue_workers, queue_reply)

    def _load_total_expected_items(self):
        if self.accounts and isinstance(self.accounts, list):
            self.total_expected_items = len(self.accounts)

    def run(self):
        tasks_res = super(AccountRebuilder, self).run()
        for task_res in tasks_res:
            item, _, error = task_res
            namespace, account, container = item
            if container is None:
                self._accounts_refreshed.put((namespace, account, error))
            yield task_res


class AccountRebuilderWorker(ToolWorker):

    def __init__(self, tool, queue_workers, queue_reply):
        super(AccountRebuilderWorker, self).__init__(
            tool, queue_workers, queue_reply)

        self.api = ObjectStorageApi(self.tool.namespace, logger=self.logger)

    def _process_item(self, item):
        namespace, account, container = item
        if namespace != self.tool.namespace:
            raise ValueError('Invalid namespace (actual=%s, expected=%s)' % (
                namespace, self.tool.namespace))

        if container is None:
            self.api.account.account_refresh(account)
        else:
            self.api.container_refresh(account, container)
