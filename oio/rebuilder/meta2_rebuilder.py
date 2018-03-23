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
        super(Meta2Rebuilder, self).__init__(conf, logger, **kwargs)

    def _create_worker(self, **kwargs):
        return Meta2RebuilderWorker(self.conf, self.logger, **kwargs)

    def _fill_queue(self, queue, **kwargs):
        accounts = self.api.account_list()
        for account in accounts:
            containers = self._full_container_list(account)
            for container in containers:
                cid = cid_from_name(account, container[0])
                queue.put(cid)

    def _get_report(self, start_time, passes, errors,
                    total_references_processed, rebuilder_time, end_time,
                    elapsed, info, **kwargs):
        return ('DONE '
                'started=%(start_time)s '
                'ended=%(end_time)s '
                'passes=%(passes)d '
                'elapsed=%(elapsed).02f '
                'errors=%(errors)d '
                'meta2_references=%(references)d %(rate).2f/s '
                'elapsed=%(rebuilder_time).2f '
                '(rebuilder: %(success_rate).2f%%)' % {
                    'start_time': datetime.fromtimestamp(
                        int(start_time)).isoformat(),
                    'end_time': datetime.fromtimestamp(
                        int(end_time)).isoformat(),
                    'passes': passes,
                    'elapsed': elapsed,
                    'errors': errors,
                    'references': total_references_processed,
                    'rate': total_references_processed / elapsed,
                    'rebuilder_time': rebuilder_time,
                    'success_rate':
                        100 * ((total_references_processed - errors) /
                               float(total_references_processed or 1))
                })


class Meta2RebuilderWorker(MetaRebuilderWorker):

    def __init__(self, conf, logger, max_attempts=5, **kwargs):
        super(Meta2RebuilderWorker, self).__init__(conf, logger, 'meta2',
                                                   **kwargs)

    def _get_report(self, num, start_time, report_time, now, **kwargs):
        return ('RUN '
                'worker=%(num)d '
                'started=%(start_time)s '
                'passes=%(passes)d '
                'errors=%(errors)d '
                'meta2_references=%(references)d %(rate).2f/s '
                'elapsed=%(total).2f '
                '(rebuilder: %(success_rate).2f%%)' % {
                    'num': num,
                    'start_time': datetime.fromtimestamp(
                        int(report_time)).isoformat(),
                    'passes': self.passes,
                    'errors': self.errors,
                    'references': self.total_items_processed,
                    'rate': self.passes / (now - report_time),
                    'total': (now - start_time),
                    'rebuilder_time': self.rebuilder_time,
                    'success_rate':
                        100 * ((self.total_items_processed - self.errors) /
                               float(self.total_items_processed or 1))
                })
