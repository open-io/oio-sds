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

from oio.common.configuration import load_namespace_conf
from oio.common.utils import cid_from_name
from oio.conscience.client import ConscienceClient
from oio.rebuilder.meta_rebuilder import MetaRebuilder, MetaRebuilderWorker


class Meta1Rebuilder(MetaRebuilder):

    def __init__(self, conf, logger, **kwargs):
        super(Meta1Rebuilder, self).__init__(conf, logger, **kwargs)
        self.conscience = ConscienceClient(self.conf, logger=self.logger)
        sds_conf = load_namespace_conf(self.conf['namespace']) or {}
        self.meta1_digits = int(sds_conf.get('meta1_digits', 4))

    def _create_worker(self, **kwargs):
        return Meta1RebuilderWorker(self.conf, self.logger, **kwargs)

    def _fill_queue(self, queue, **kwargs):
        if self._fill_queue_from_file(queue, **kwargs):
            return

        prefixes = set()

        rawx_services = self.conscience.all_services('rawx')
        for rawx in rawx_services:
            cid = cid_from_name('_RDIR', rawx['addr'])
            prefix = cid[:self.meta1_digits]
            if prefix not in prefixes:
                queue.put(prefix.ljust(64, '0'))
                prefixes.add(prefix)

        accounts = self.api.account_list()
        for account in accounts:
            containers = self._full_container_list(account)
            for container in containers:
                cid = cid_from_name(account, container[0])
                prefix = cid[:self.meta1_digits]
                if prefix not in prefixes:
                    queue.put(prefix.ljust(64, '0'))
                    prefixes.add(prefix)

    def _get_report(self, start_time, end_time, passes, errors,
                    waiting_time, rebuilder_time, elapsed,
                    total_prefixes_processed, info,
                    **kwargs):
        return ('DONE '
                'started=%(start_time)s '
                'ended=%(end_time)s '
                'elapsed=%(elapsed).2f '
                'passes=%(passes)d '
                'errors=%(errors)d '
                'meta1_prefixes=%(prefixes)d %(rate).2f/s '
                'waiting_time=%(waiting_time).2f '
                'rebuilder_time=%(rebuilder_time).2f '
                '(rebuilder: %(success_rate).2f%%)' % {
                    'start_time': datetime.fromtimestamp(
                        int(start_time)).isoformat(),
                    'end_time': datetime.fromtimestamp(
                        int(end_time)).isoformat(),
                    'elapsed': elapsed,
                    'passes': passes,
                    'errors': errors,
                    'prefixes': total_prefixes_processed,
                    'rate': total_prefixes_processed / elapsed,
                    'rebuilder_time': rebuilder_time,
                    'waiting_time': waiting_time,
                    'success_rate':
                        100 * ((total_prefixes_processed - errors) /
                               float(total_prefixes_processed or 1))
                })


class Meta1RebuilderWorker(MetaRebuilderWorker):

    def __init__(self, conf, logger, **kwargs):
        super(Meta1RebuilderWorker, self).__init__(conf, logger, 'meta1',
                                                   **kwargs)

    def _get_report(self, num, start_time, end_time, total_time, report_time,
                    **kwargs):
        return ('RUN '
                'worker=%(num)d '
                'started=%(start_time)s '
                'passes=%(passes)d '
                'errors=%(errors)d '
                'meta1_prefixes=%(prefixes)d %(rate).2f/s '
                'waiting_time=%(waiting_time).2f '
                'rebuilder_time=%(rebuilder_time).2f '
                'total_time=%(total_time).2f '
                '(rebuilder: %(success_rate).2f%%)' % {
                    'num': num,
                    'start_time': datetime.fromtimestamp(
                        int(report_time)).isoformat(),
                    'passes': self.passes,
                    'errors': self.errors,
                    'prefixes': self.total_items_processed,
                    'rate': self.passes / (end_time - report_time),
                    'waiting_time': self.waiting_time,
                    'rebuilder_time': self.rebuilder_time,
                    'total_time': (end_time - start_time),
                    'success_rate':
                        100 * ((self.total_items_processed - self.errors) /
                               float(self.total_items_processed or 1))
                })
