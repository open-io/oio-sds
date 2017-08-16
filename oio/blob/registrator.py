# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
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


from contextlib import contextmanager
from os.path import basename
from time import clock as now

from oio.common.utils import paths_gen
from oio.blob.utils import check_volume, read_chunk_metadata
from oio.container.client import ContainerClient
from oio.common.exceptions import Conflict, NotFound


default_report_interval = 60.0


@contextmanager
def lock_volume(path):
    # TODO xattr-lock the volume
    yield
    # TODO xattr-unlock the volume


def meta2bean(volid, meta):
    return {"type": "chunk",
            "id": "http://" + volid + "/" + meta["chunk_id"],
            "hash": meta['chunk_hash'],
            "size": int(meta["chunk_size"]),
            "pos": meta["chunk_pos"],
            "content": meta["content_id"]}


class BlobRegistratorWorker(object):
    def __init__(self, conf, logger, volume):
        self.conf = conf
        self.logger = logger
        self.volume = volume
        self.namespace = self.conf["namespace"]
        self.volume_ns, self.volume_id = check_volume(self.volume)
        c = dict()
        c['namespace'] = self.namespace
        self.client = ContainerClient(c, logger=self.logger)
        self.report_interval = conf.get(
                "report_period", default_report_interval)

        actions = {
                'update': BlobRegistratorWorker._update_chunk,
                'insert': BlobRegistratorWorker._insert_chunk,
                'check': BlobRegistratorWorker._check_chunk,
        }
        self.action = actions[conf.get("action", "check")]

    def pass_with_lock(self):
        with lock_volume(self.volume):
            return self.pass_without_lock()

    def pass_without_lock(self):
        last_report = now()
        count, success, fail = 0, 0, 0
        if self.namespace != self.volume_ns:
            self.logger.warn("Forcing the NS to [%s] (previously [%s])",
                             self.namespace, self.volume_ns)

        self.logger.info("START %s", self.volume)

        paths = paths_gen(self.volume)
        for path in paths:
            # Action
            try:
                with open(path) as f:
                    meta = read_chunk_metadata(f)
                    self.action(self, path, f, meta)
                    success = success + 1
            except NotFound as e:
                fail = fail + 1
                self.logger.info("ORPHAN %s/%s in %s/%s %s",
                                 meta['content_id'], meta['chunk_id'],
                                 meta['container_id'], meta['content_path'],
                                 str(e))
            except Conflict as e:
                fail = fail + 1
                self.logger.info("ALREADY %s/%s in %s/%s %s",
                                 meta['content_id'], meta['chunk_id'],
                                 meta['container_id'], meta['content_path'],
                                 str(e))
            except Exception as e:
                fail = fail + 1
                self.logger.warn("ERROR %s/%s in %s/%s %s",
                                 meta['content_id'], meta['chunk_id'],
                                 meta['container_id'], meta['content_path'],
                                 str(e))
            count = count + 1

            # TODO(jfs): do the throttling

            # periodical reporting
            t = now()
            if t - last_report > self.report_interval:
                self.logger.info("STEP %d ok %d ko %d",
                                 count, success, fail)

        self.logger.info("FINAL %s %d ok %d ko %d",
                         self.volume, count, success, fail)

    def _check_chunk(self, path, f, meta):
        raise Exception("CHECK not yet implemented")

    def _insert_chunk(self, path, f, meta):
        cid = meta['container_id']
        chunkid = basename(path)
        bean = meta2bean(self.volume_id, meta)
        self.client.container_raw_insert(bean, cid=cid)
        self.logger.info("inserted %s/%s in %s/%s",
                         meta['content_id'], chunkid, cid,
                         meta['content_path'])

    def _update_chunk(self, path, f, meta):
        cid = meta['container_id']
        chunkid = basename(path)
        if str(meta['chunk_pos']).startswith('0'):
            if not self.conf['first']:
                self.logger.info("skip %s/%s from %s/%s",
                                 meta['content_id'], chunkid, cid,
                                 meta['content_path'])
                return
        pre = meta2bean(self.volume_id, meta)
        post = meta2bean(self.volume_id, meta)
        self.client.container_raw_update(pre, post, cid=cid)
        self.logger.info("updated %s/%s in %s/%s",
                         meta['content_id'], chunkid, cid,
                         meta['content_path'])
