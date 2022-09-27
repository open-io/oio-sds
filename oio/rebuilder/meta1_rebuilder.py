# Copyright (C) 2018-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2022 OVH SAS
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

from oio.common.configuration import load_namespace_conf
from oio.common.utils import cid_from_name, depaginate
from oio.conscience.client import ConscienceClient
from oio.rebuilder.meta_rebuilder import MetaRebuilder, MetaRebuilderWorker


class Meta1Rebuilder(MetaRebuilder):

    def __init__(self, conf, logger, **kwargs):
        super(Meta1Rebuilder, self).__init__(conf, logger, None, **kwargs)
        self.conscience = ConscienceClient(self.conf, logger=self.logger)
        sds_conf = load_namespace_conf(self.conf['namespace']) or {}
        self.meta1_digits = int(sds_conf.get('ns.meta1_digits',
                                             sds_conf.get('meta1_digits', 4)))

    def _create_worker(self, **kwargs):
        return Meta1RebuilderWorker(self, **kwargs)

    def _fill_queue(self, queue, **kwargs):
        if self._fill_queue_from_file(queue, **kwargs):
            return

        prefixes = set()

        # Build the list of meta1 databases hosting technical references
        hosted_services = (self.conscience.all_services('rawx')
                           + self.conscience.all_services('meta2'))
        for svc in hosted_services:
            service_id = svc['tags'].get('tag.service_id', svc['addr'])
            cid = cid_from_name('_RDIR', service_id)
            prefix = cid[:self.meta1_digits]
            if prefix not in prefixes:
                queue.put(prefix.ljust(64, '0'))
                prefixes.add(prefix)

        # Build the list of meta1 databases hosting container references
        accounts = depaginate(
            self.api.account.account_list,
            listing_key=lambda x: x['listing'],
            item_key=lambda x: x['id'],
            marker_key=lambda x: x['next_marker'],
            truncated_key=lambda x: x['truncated'],
            sharding_accounts=True)
        for account in accounts:
            containers = depaginate(
                self.api.account.container_list,
                listing_key=lambda x: x['listing'],
                item_key=lambda x: x[0],
                marker_key=lambda x: x['next_marker'],
                truncated_key=lambda x: x['truncated'],
                account=account,
                region=self.api.account.region)
            for container in containers:
                cid = cid_from_name(account, container)
                prefix = cid[:self.meta1_digits]
                if prefix not in prefixes:
                    queue.put(prefix.ljust(64, '0'))
                    prefixes.add(prefix)
            if not self.running:
                break

    def _item_to_string(self, prefix, **kwargs):
        return 'prefix %s' % prefix

    def _get_report(self, status, end_time, counters, **kwargs):
        prefixes_processed, errors, total_prefixes_processed, \
            total_errors = counters
        time_since_last_report = (end_time - self.last_report) or 0.00001
        total_time = (end_time - self.start_time) or 0.00001
        return ('%(status)s volume=%(volume)s '
                'last_report=%(last_report)s %(time_since_last_report).2fs '
                'prefixes=%(prefixes)d %(prefixes_rate).2f/s '
                'errors=%(errors)d %(errors_rate).2f%% '
                'start_time=%(start_time)s %(total_time).2fs '
                'total_prefixes=%(total_prefixes)d '
                '%(total_prefixes_rate).2f/s '
                'total_errors=%(total_errors)d %(total_errors_rate).2f%%' % {
                    'status': status,
                    'volume': self.volume,
                    'last_report': datetime.fromtimestamp(
                        int(self.last_report)).isoformat(),
                    'time_since_last_report': time_since_last_report,
                    'prefixes': prefixes_processed,
                    'prefixes_rate':
                        prefixes_processed / time_since_last_report,
                    'errors': errors,
                    'errors_rate':
                        100 * errors / float(prefixes_processed or 1),
                    'start_time': datetime.fromtimestamp(
                        int(self.start_time)).isoformat(),
                    'total_time': total_time,
                    'total_prefixes': total_prefixes_processed,
                    'total_prefixes_rate':
                        total_prefixes_processed / total_time,
                    'total_errors': total_errors,
                    'total_errors_rate': 100 * total_errors /
                        float(total_prefixes_processed or 1)
                })


class Meta1RebuilderWorker(MetaRebuilderWorker):

    def __init__(self, rebuilder, **kwargs):
        super(Meta1RebuilderWorker, self).__init__(rebuilder, 'meta1',
                                                   **kwargs)
