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


import time
import sys

from oio import ObjectStorageApi
from oio.common.exceptions import NotFound, ServiceBusy
from oio.common.client import ProxyClient
from oio.rebuilder.rebuilder import Rebuilder, RebuilderWorker


class MetaRebuilder(Rebuilder):
    """
    Abstract class for directory rebuilders.
    """

    def __init__(self, conf, logger, **kwargs):
        super(MetaRebuilder, self).__init__(conf, logger, **kwargs)
        self.api = ObjectStorageApi(self.conf['namespace'], logger=self.logger)

    def _fill_queue_from_file(self, queue, **kwargs):
        if self.input_file is None:
            return False
        with open(self.input_file, 'r') as ifile:
            for line in ifile:
                stripped = line.strip()
                if stripped and not stripped.startswith('#'):
                    queue.put(stripped)
        return True

    def _full_container_list(self, account, **kwargs):
        listing = self.api.container_list(account, **kwargs)
        for element in listing:
            yield element

        while listing:
            kwargs['marker'] = listing[-1][0]
            listing = self.api.container_list(account, **kwargs)
            if listing:
                for element in listing:
                    yield element

    def _init_info(self, **kwargs):
        return None

    def _compute_info(self, worker, info, **kwargs):
        return None


class MetaRebuilderWorker(RebuilderWorker):

    def __init__(self, conf, logger, type_, max_attempts=5, **kwargs):
        super(MetaRebuilderWorker, self).__init__(conf, logger, **kwargs)
        self.type = type_
        self.max_attempts = max_attempts
        self.proxy_client = ProxyClient(
            self.conf, request_prefix='/admin', logger=self.logger)

    def _rebuild_one(self, cid, **kwargs):
        attempts = 0
        while True:
            attempts += 1
            params = {'cid': cid, 'type': self.type}
            try:
                properties = {'properties': {'sys.last_rebuild':
                                             str(int(time.time()))}}
                # Setting a property will trigger a database replication
                self.proxy_client._request('POST', '/set_properties',
                                           params=params, json=properties)
                self.passes += 1
                break
            except Exception as err:
                if attempts < self.max_attempts:
                    if isinstance(err, NotFound):
                        try:
                            self.proxy_client._request('POST', '/leave',
                                                       params=params)
                        except Exception:
                            pass
                        continue
                    if isinstance(err, ServiceBusy):
                        time.sleep(attempts * 0.5)
                        continue
                self.logger.error('ERROR while rebuilding %s: %s', cid, err)
                self.errors += 1
                sys.stdout.write(cid+'\n')
                break
