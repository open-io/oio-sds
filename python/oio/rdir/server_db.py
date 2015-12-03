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
from oio.common.exceptions import ServerException
from oio.common.utils import json
from plyvel import DB


# FIXME this class is not thread-safe (see _get_db, push, lock) but it
# works fine with the default gunicorn sync worker and with only one worker.
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

    def _get_db(self, volume_id):
        try:
            db = self.dbs[volume_id]
        except KeyError:
            path = "%s/%s" % (self.db_path, volume_id)
            self.dbs[volume_id] = DB(path, create_if_missing=True)
            db = self.dbs[volume_id]
        return db

    def _get_db_chunk(self, volume_id):
        return self._get_db(volume_id).prefixed_db("chunk|")

    def _get_db_admin(self, volume_id):
        return self._get_db(volume_id).prefixed_db("admin|")

    def chunk_push(self, volume_id,
                   container_id, content_id, chunk_id, **data):
        key = "%s|%s|%s" % (container_id, content_id, chunk_id)

        value = self._get_db_chunk(volume_id).get(key.encode('utf8'))
        if value is not None:
            value = json.loads(value)
        else:
            value = dict()

        for k, v in data.iteritems():
            value[k] = v

        if 'mtime' not in value:  # not consistent
            if 'rtime' in value:
                # In functionnal test, we can encounter the case where rebuild
                # update (rtime) arrives before creation update (first mtime)
                value['mtime'] = value['rtime']
            else:
                raise ServerException("mtime is mandatory")

        value = json.dumps(value)

        self._get_db_chunk(volume_id).put(key.encode('utf8'),
                                          value.encode('utf8'))

    def chunk_delete(self, volume_id, container_id, content_id, chunk_id):
        key = "%s|%s|%s" % (container_id, content_id, chunk_id)

        self._get_db_chunk(volume_id).delete(key.encode('utf8'))

    def chunk_fetch(self, volume_id, start_after=None,
                    limit=None, rebuild=False):
        result = []

        if start_after is not None:
            start_after = start_after.encode('utf8')

        incident_date = self.admin_get_incident_date(volume_id)
        if rebuild and incident_date is None:
            # No incident date set so no chunks needs to be rebuild
            return result

        db_iter = self._get_db_chunk(volume_id).iterator(
            start=start_after,
            include_start=False)
        count = 0
        for key, value in db_iter:
            if limit is not None and count >= limit:
                break
            data = json.loads(value)
            if rebuild:
                if data.get('rtime'):
                    continue  # already rebuilt
                mtime = data.get('mtime')
                if int(mtime) > incident_date:
                    continue  # chunk pushed after the incident
            result.append((key, data))
            count += 1
        return result

    def chunk_status(self, volume_id):
        total_chunks = 0
        total_chunks_rebuilt = 0
        incident_date = self.admin_get_incident_date(volume_id)
        containers = dict()
        for key, value in self._get_db_chunk(volume_id):
            total_chunks += 1

            container, content, chunk = key.split('|')
            try:
                containers[container]['total'] += 1
            except KeyError:
                containers[container] = {'total': 1}
                if incident_date is not None:
                    containers[container]['rebuilt'] = 0

            data = json.loads(value)
            rtime = data.get('rtime')
            if rtime is not None:
                total_chunks_rebuilt += 1
                containers[container]['rebuilt'] += 1

        result = {
            'chunk': {'total': total_chunks},
            'container': containers
        }
        if incident_date is not None:
            result['rebuild'] = {'incident_date': incident_date}
            result['chunk']['rebuilt'] = total_chunks_rebuilt
        return result

    def admin_set_incident_date(self, volume_id, date):
        self._get_db_admin(volume_id).put('incident_date', str(date))

    def admin_get_incident_date(self, volume_id):
        ret = self._get_db_admin(volume_id).get('incident_date')
        if ret is None:
            return None
        return int(ret)

    def admin_clear(self, volume_id, clear_all):
        db = self._get_db_chunk(volume_id)
        count = 0
        for key, value in db:
            if not clear_all:
                data = json.loads(value)
            if clear_all or 'rtime' in data:
                count += 1
                db.delete(key)
        self._get_db_admin(volume_id).delete('incident_date')
        return count

    def admin_lock(self, volume_id, who):
        ret = self._get_db_admin(volume_id).get('lock')
        if ret is not None:
            return ret  # already locked

        self._get_db_admin(volume_id).put('lock', who.encode('utf8'))
        return None

    def admin_unlock(self, volume_id):
        self._get_db_admin(volume_id).delete('lock')

    def admin_show(self, volume_id):
        result = {}
        for key, value in self._get_db_admin(volume_id):
            result[key] = value
        return result

    def status(self):
        opened_db_count = len(self.dbs)
        status = {'opened_db_count': opened_db_count}
        return status
