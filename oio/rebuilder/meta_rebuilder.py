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

import time
import sys

from oio import ObjectStorageApi
from oio.common.exceptions import NotFound, OioException, OioTimeout, \
    ServiceBusy, from_multi_responses
from oio.directory.admin import AdminClient
from oio.rebuilder.rebuilder import Rebuilder, RebuilderWorker


class MetaRebuilder(Rebuilder):
    """
    Abstract class for directory rebuilders.
    """

    def __init__(self, conf, logger, volume, **kwargs):
        super(MetaRebuilder, self).__init__(conf, logger, volume, **kwargs)
        self.api = ObjectStorageApi(self.namespace, logger=self.logger,
                                    **kwargs)

    def _fill_queue_from_file(self, queue, **kwargs):
        if self.input_file is None:
            return False
        with open(self.input_file, 'r') as ifile:
            for line in ifile:
                stripped = line.strip()
                if stripped and not stripped.startswith('#'):
                    queue.put(stripped)
                if not self.running:
                    break
        return True


class MetaRebuilderWorker(RebuilderWorker):

    def __init__(self, rebuilder, type_, max_attempts=5, **kwargs):
        super(MetaRebuilderWorker, self).__init__(rebuilder, **kwargs)
        self.type = type_
        self.max_attempts = max_attempts
        self.admin_client = AdminClient(self.conf, logger=self.logger)

    def _rebuild_one(self, cid, **kwargs):
        missing_base = False
        for attempts in range(self.max_attempts):
            try:
                if not missing_base:
                    # Check if the bases exist
                    try:
                        data = self.admin_client.has_base(self.type, cid=cid)
                        from_multi_responses(data)
                    except OioException as exc:
                        self.logger.warning(
                            'Missing base(s) for %s: %s', cid, exc)
                        missing_base = True

                if missing_base:
                    data = self.admin_client.election_leave(self.type, cid=cid)
                    from_multi_responses(data)
                    # TODO(adu): use self.admin_client.election_sync
                    # Setting a property will trigger a database replication
                    properties = {'sys.last_rebuild': str(int(time.time()))}
                    self.admin_client.set_properties(self.type, cid=cid,
                                                     properties=properties)
                break
            except Exception as err:
                if attempts < self.max_attempts - 1:
                    if isinstance(err, NotFound):
                        self.logger.warn('%s: %s', cid, err)
                        continue
                    if isinstance(err, OioTimeout) \
                            or isinstance(err, ServiceBusy):
                        self.logger.warn('%s: %s', cid, err)
                        time.sleep(attempts * 0.5)
                        continue
                self.logger.error('ERROR while rebuilding %s: %s', cid, err)
                sys.stdout.write(cid + '\n')
                break
