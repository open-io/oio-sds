# Copyright (C) 2015 OpenIO, original work as part of
# OpenIO Software Defined Storage
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

import os
import plyvel

from oio.common.exceptions import ServerException
from oio.common.utils import json


# FIXME this class is not thread-safe (see _get_db, push) but it works fine
# with the default gunicorn sync worker and with only one worker.
# Only one process can open a leveldb DB so if we want to use several workers,
# we need to close/open db each time.
# In multithreaded environement, the push function needs transaction to update
# an entry in a consistent manner.
class RdirBackend(object):
    def __init__(self, conf):
        self.db_path = conf.get('db_path')
        self.dbs = {}
        if not os.path.exists(self.db_path):
            os.makedirs(self.db_path)

    def _get_db(self, volume):
        try:
            db = self.dbs[volume]
        except KeyError:
            self.dbs[volume] = plyvel.DB("%s/%s" % (self.db_path, volume),
                                         create_if_missing=True)
            db = self.dbs[volume]
        return db

    def _get_db_chunk(self, volume):
        return self._get_db(volume).prefixed_db("chunk|")

    def _get_db_admin(self, volume):
        return self._get_db(volume).prefixed_db("admin|")

    def chunk_push(self, volume, container, content, chunk,
                   mtime=None, rtime=None):
        # TODO replace content_path with content_id when available in git
        key = "%s|%s|%s" % (container, content, chunk)

        value = self._get_db_chunk(volume).get(key.encode('utf8'))
        if value is not None:
            value = json.loads(value)
        else:
            value = dict()

        if mtime is not None:
            value['mtime'] = mtime
        if rtime is not None:
            value['rtime'] = rtime

        if value.get('mtime') is None:  # not consistent
            raise ServerException("mtime is mandatory")

        value = json.dumps(value)

        self._get_db_chunk(volume).put(key.encode('utf8'),
                                       value.encode('utf8'))

    def chunk_delete(self, volume, container, content, chunk):
        # TODO replace content_path with content_id when available in git
        key = "%s|%s|%s" % (container, content, chunk)

        self._get_db_chunk(volume).delete(key.encode('utf8'))

    def chunk_fetch(self, volume, start_after=None, limit=None,
                    ignore_rebuilt=False):
        result = dict()

        if start_after is not None:
            start_after = start_after.encode('utf8')

        db_iter = self._get_db_chunk(volume).iterator(
            start=start_after,
            include_start=False)
        count = 0
        for key, value in db_iter:
            if limit is not None and count >= limit:
                break
            data = json.loads(value)
            if data.get('rtime') is not None and ignore_rebuilt:
                continue
            result[key] = data
            count += 1
        return result

    def chunk_rebuild_status(self, volume):
        total_chunks = 0
        total_chunks_rebuilt = 0
        containers = dict()
        for key, value in self._get_db_chunk(volume):
            total_chunks += 1

            container, content, chunk = key.split('|')
            try:
                containers[container]['total'] += 1
            except KeyError:
                containers[container] = {'total': 1, 'rebuilt': 0}

            data = json.loads(value)
            rtime = data.get('rtime')
            if rtime is not None:
                total_chunks_rebuilt += 1
                containers[container]['rebuilt'] += 1

        result = {
            'chunk': {
                'total': total_chunks,
                'rebuilt': total_chunks_rebuilt
            },
            'container': containers
        }
        return result

    def status(self):
        opened_db_count = len(self.dbs)
        status = {'opened_db_count': opened_db_count}
        return status
