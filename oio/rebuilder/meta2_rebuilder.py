# Copyright (C) 2018 OpenIO SAS, as part of OpenIO SDS
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

from oio.common.utils import cid_from_name
from oio.rebuilder.meta_rebuilder import MetaRebuilder, MetaRebuilderWorker


class Meta2Rebuilder(MetaRebuilder):

    def __init__(self, conf, logger, **kwargs):
        super(Meta2Rebuilder, self).__init__(conf, logger, None, **kwargs)

    def _create_worker(self, **kwargs):
        return Meta2RebuilderWorker(self, **kwargs)

    def _fill_queue(self, queue, **kwargs):
        if self._fill_queue_from_file(queue, **kwargs):
            return

        accounts = self.api.account_list()
        for account in accounts:
            containers = self._full_container_list(account)
            for container in containers:
                cid = cid_from_name(account, container[0])
                queue.put(cid)
            if not self.running:
                break

    def _item_to_string(self, cid, **kwargs):
        return 'reference %s' % cid

    def _get_report(self, status, end_time, counters, **kwargs):
        references_processed, errors, total_references_processed, \
            total_errors = counters
        time_since_last_report = (end_time - self.last_report) or 0.00001
        total_time = (end_time - self.start_time) or 0.00001
        return ('%(status)s volume=%(volume)s '
                'last_report=%(last_report)s %(time_since_last_report).2fs '
                'references=%(references)d %(references_rate).2f/s '
                'errors=%(errors)d %(errors_rate).2f%% '
                'start_time=%(start_time)s %(total_time).2fs '
                'total_references=%(total_references)d '
                '%(total_references_rate).2f/s '
                'total_errors=%(total_errors)d %(total_errors_rate).2f%%' % {
                    'status': status,
                    'volume': self.volume,
                    'last_report': datetime.fromtimestamp(
                        int(self.last_report)).isoformat(),
                    'time_since_last_report': time_since_last_report,
                    'references': references_processed,
                    'references_rate':
                        references_processed / time_since_last_report,
                    'errors': errors,
                    'errors_rate':
                        100 * errors / float(references_processed or 1),
                    'start_time': datetime.fromtimestamp(
                        int(self.start_time)).isoformat(),
                    'total_time': total_time,
                    'total_references': total_references_processed,
                    'total_references_rate':
                        total_references_processed / total_time,
                    'total_errors': total_errors,
                    'total_errors_rate': 100 * total_errors /
                        float(total_references_processed or 1)
                })


class Meta2RebuilderWorker(MetaRebuilderWorker):

    def __init__(self, rebuilder, max_attempts=5, **kwargs):
        super(Meta2RebuilderWorker, self).__init__(rebuilder, 'meta2',
                                                   **kwargs)
