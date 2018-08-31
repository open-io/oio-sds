# Copyright (C) 2015-2018 OpenIO SAS, as part of OpenIO SDS
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


import json
import time
from datetime import datetime
from socket import gethostname

from oio.common.easy_value import int_value, true_value
from oio.common.exceptions import ContentNotFound, NotFound, OrphanChunk
from oio.content.factory import ContentFactory
from oio.event.beanstalk import Beanstalk, ConnectionError
from oio.rdir.client import RdirClient
from oio.rebuilder.rebuilder import Rebuilder, RebuilderWorker


DEFAULT_REBUILDER_TUBE = 'oio-rebuild'


class BlobRebuilder(Rebuilder):

    def __init__(self, conf, logger, volume, try_chunk_delete=False,
                 beanstalkd_addr=None, **kwargs):
        super(BlobRebuilder, self).__init__(conf, logger, volume, **kwargs)
        # rdir
        self.rdir_client = RdirClient(conf, logger=self.logger)
        self.rdir_fetch_limit = int_value(conf.get('rdir_fetch_limit'), 100)
        # rawx
        self.try_chunk_delete = try_chunk_delete
        # beanstalk
        self.beanstalkd_addr = beanstalkd_addr
        self.beanstalkd_tube = conf.get('beanstalkd_tube',
                                        DEFAULT_REBUILDER_TUBE)
        self.beanstalkd = None
        # counters
        self.bytes_processed = 0
        self.total_bytes_processed = 0

    def _create_worker(self, **kwargs):
        return BlobRebuilderWorker(
            self, try_chunk_delete=self.try_chunk_delete, **kwargs)

    def _fill_queue(self, queue, **kwargs):
        chunks = self._fetch_chunks()
        for chunk in chunks:
            queue.put(chunk)

    def _item_to_string(self, chunk, **kwargs):
        cid, content_id, chunk_id_or_pos, _ = chunk
        return 'chunk %s|%s|%s' % (cid, content_id, chunk_id_or_pos)

    def _get_report(self, status, end_time, counters, **kwargs):
        chunks_processed, bytes_processed, errors, total_chunks_processed, \
            total_bytes_processed, total_errors = counters
        time_since_last_report = (end_time - self.last_report) or 0.00001
        total_time = (end_time - self.start_time) or 0.00001
        return ('%(status)s volume=%(volume)s '
                'last_report=%(last_report)s %(time_since_last_report).2fs '
                'chunks=%(chunks)d %(chunks_rate).2f/s '
                'bytes=%(bytes)d %(bytes_rate).2fB/s '
                'errors=%(errors)d %(errors_rate).2f%% '
                'start_time=%(start_time)s %(total_time).2fs '
                'total_chunks=%(total_chunks)d %(total_chunks_rate).2f/s '
                'total_bytes=%(total_bytes)d %(total_bytes_rate).2fB/s '
                'total_errors=%(total_errors)d %(total_errors_rate).2f%%' % {
                    'status': status,
                    'volume': self.volume,
                    'last_report': datetime.fromtimestamp(
                        int(self.last_report)).isoformat(),
                    'time_since_last_report': time_since_last_report,
                    'chunks': chunks_processed,
                    'chunks_rate': chunks_processed / time_since_last_report,
                    'bytes': bytes_processed,
                    'bytes_rate': bytes_processed / time_since_last_report,
                    'errors': errors,
                    'errors_rate': 100 * errors / float(chunks_processed or 1),
                    'start_time': datetime.fromtimestamp(
                        int(self.start_time)).isoformat(),
                    'total_time': total_time,
                    'total_chunks': total_chunks_processed,
                    'total_chunks_rate': total_chunks_processed / total_time,
                    'total_bytes': total_bytes_processed,
                    'total_bytes_rate': total_bytes_processed / total_time,
                    'total_errors': total_errors,
                    'total_errors_rate':
                        100 * total_errors / float(total_chunks_processed or 1)
                })

    def _update_processed_without_lock(self, bytes_processed, error=None,
                                       **kwargs):
        super(BlobRebuilder, self)._update_processed_without_lock(
            None, error=error, **kwargs)
        if bytes_processed is not None:
            self.bytes_processed += bytes_processed

    def _update_totals_without_lock(self, **kwargs):
        chunks_processed, errors, total_chunks_processed, total_errors = \
            super(BlobRebuilder, self)._update_totals_without_lock(**kwargs)
        bytes_processed = self.bytes_processed
        self.bytes_processed = 0
        self.total_bytes_processed += bytes_processed
        return chunks_processed, bytes_processed, errors, \
            total_chunks_processed, self.total_bytes_processed, total_errors

    def rebuilder_pass(self, **kwargs):
        if self.volume:
            success = False
            self.rdir_client.admin_lock(self.volume,
                                        "rebuilder on %s" % gethostname())
        try:
            success = super(BlobRebuilder, self).rebuilder_pass(**kwargs)
        finally:
            if self.volume:
                self.rdir_client.admin_unlock(self.volume)
        return success

    def _fetch_chunks_from_event(self, job_id, data):
        env = json.loads(data)
        for chunk_id_or_pos in env['data']['missing_chunks']:
            yield [env['url']['id'], env['url']['content'],
                   str(chunk_id_or_pos), None]

    def _connect_to_beanstalk(self):
        self.logger.debug('Connecting to %s', self.beanstalkd_addr)
        self.beanstalkd = Beanstalk.from_url(self.beanstalkd_addr)
        self.logger.debug('Using tube %s', self.beanstalkd_tube)
        self.beanstalkd.use(self.beanstalkd_tube)
        self.beanstalkd.watch(self.beanstalkd_tube)

    def _handle_beanstalk_event(self, conn_error):
        try:
            job_id, data = self.beanstalkd.reserve()
            if conn_error:
                self.logger.warn("beanstalk reconnected")
        except ConnectionError:
            if not conn_error:
                self.logger.warn("beanstalk connection error")
            raise
        try:
            for chunk in self._fetch_chunks_from_event(job_id, data):
                yield chunk
            self.beanstalkd.delete(job_id)
        except Exception:
            self.logger.exception("handling event %s (bury)", job_id)
            self.beanstalkd.bury(job_id)

    def _fetch_chunks_from_beanstalk(self):
        conn_error = False
        while 1:
            try:
                self._connect_to_beanstalk()
                for chunk in self._handle_beanstalk_event(conn_error):
                    conn_error = False
                    yield chunk
            except ConnectionError as exc:
                self.logger.warn('Disconnected: %s', exc)
                if 'Invalid URL' in str(exc):
                    raise
                conn_error = True
                time.sleep(1.0)

    def _fetch_chunks_from_file(self):
        with open(self.input_file, 'r') as ifile:
            for line in ifile:
                stripped = line.strip()
                if stripped and not stripped.startswith('#'):
                    yield stripped.split('|', 3)[:3] + [None]

    def _fetch_chunks(self):
        if self.input_file:
            return self._fetch_chunks_from_file()
        elif self.beanstalkd_addr:
            return self._fetch_chunks_from_beanstalk()
        else:
            return self.rdir_client.chunk_fetch(
                self.volume, limit=self.rdir_fetch_limit, rebuild=True)


class BlobRebuilderWorker(RebuilderWorker):

    def __init__(self, rebuilder, try_chunk_delete=False, **kwargs):
        super(BlobRebuilderWorker, self).__init__(rebuilder, **kwargs)
        self.dry_run = true_value(
            self.rebuilder.conf.get('dry_run', False))
        self.allow_same_rawx = true_value(
            self.rebuilder.conf.get('allow_same_rawx'))
        self.try_chunk_delete = try_chunk_delete
        self.rdir_client = self.rebuilder.rdir_client
        self.content_factory = ContentFactory(self.rebuilder.conf,
                                              logger=self.logger)

    def _rebuild_one(self, chunk, **kwargs):
        container_id, content_id, chunk_id_or_pos, _ = chunk
        if self.dry_run:
            self.dryrun_chunk_rebuild(container_id, content_id,
                                      chunk_id_or_pos)
            return 0
        else:
            return self.chunk_rebuild(container_id, content_id,
                                      chunk_id_or_pos)

    def dryrun_chunk_rebuild(self, container_id, content_id, chunk_id_or_pos):
        self.logger.info("[dryrun] Rebuilding "
                         "container %s, content %s, chunk %s",
                         container_id, content_id, chunk_id_or_pos)

    def chunk_rebuild(self, container_id, content_id, chunk_id_or_pos):
        self.logger.info('Rebuilding (container %s, content %s, chunk %s)',
                         container_id, content_id, chunk_id_or_pos)
        try:
            content = self.content_factory.get(container_id, content_id)
        except ContentNotFound:
            raise OrphanChunk('Content not found: possible orphan chunk')

        chunk_size = 0
        chunk_pos = None
        if len(chunk_id_or_pos) < 32:
            chunk_pos = chunk_id_or_pos
            chunk_id = None
            metapos = int(chunk_pos.split('.', 1)[0])
            chunk_size = content.chunks.filter(metapos=metapos).all()[0].size
        else:
            if '/' in chunk_id_or_pos:
                chunk_id = chunk_id_or_pos.rsplit('/', 1)[-1]
            else:
                chunk_id = chunk_id_or_pos

            chunk = content.chunks.filter(id=chunk_id).one()
            if chunk is None:
                raise OrphanChunk(("Chunk not found in content:"
                                   'possible orphan chunk'))
            elif self.volume and chunk.host != self.volume:
                raise ValueError("Chunk does not belong to this volume")
            chunk_size = chunk.size

        content.rebuild_chunk(chunk_id, allow_same_rawx=self.allow_same_rawx,
                              chunk_pos=chunk_pos)

        if self.try_chunk_delete:
            try:
                content.blob_client.chunk_delete(chunk.url)
                self.logger.info("Chunk %s deleted", chunk.url)
            except NotFound as exc:
                self.logger.debug("Chunk %s: %s", chunk.url, exc)

        # This call does not raise exception if chunk is not referenced
        if chunk_id is not None:
            self.rdir_client.chunk_delete(chunk.host, container_id,
                                          content_id, chunk_id)

        return chunk_size
