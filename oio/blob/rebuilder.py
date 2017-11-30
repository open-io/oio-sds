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


import json
import time
from datetime import datetime
from socket import gethostname

from oio.common.easy_value import int_value, true_value
from oio.common.logger import get_logger
from oio.common.green import ratelimit
from oio.common.exceptions import ContentNotFound, NotFound, OrphanChunk
from oio.content.factory import ContentFactory
from oio.event.beanstalk import Beanstalk, ConnectionError
from oio.rdir.client import RdirClient


class BlobRebuilderWorker(object):
    def __init__(self, conf, logger, volume,
                 input_file=None, try_chunk_delete=False,
                 beanstalkd_addr=None):
        self.conf = conf
        self.logger = logger or get_logger(conf)
        self.volume = volume
        self.run_time = 0
        self.passes = 0
        self.errors = 0
        self.last_reported = 0
        self.chunks_run_time = 0
        self.bytes_running_time = 0
        self.bytes_processed = 0
        self.total_bytes_processed = 0
        self.total_chunks_processed = 0
        self.dry_run = true_value(
            conf.get('dry_run', False))
        self.report_interval = int_value(
            conf.get('report_interval'), 3600)
        self.max_chunks_per_second = int_value(
            conf.get('chunks_per_second'), 30)
        self.max_bytes_per_second = int_value(
            conf.get('bytes_per_second'), 10000000)
        self.rdir_fetch_limit = int_value(
            conf.get('rdir_fetch_limit'), 100)
        self.allow_same_rawx = true_value(
            conf.get('allow_same_rawx'))
        self.input_file = input_file
        self.rdir_client = RdirClient(conf, logger=self.logger)
        self.content_factory = ContentFactory(conf)
        self.try_chunk_delete = try_chunk_delete
        self.beanstalkd_addr = beanstalkd_addr
        self.beanstalkd_tube = conf.get('beanstalkd_tube', 'rebuild')

    def _fetch_chunks_from_event(self, job_id, data):
        env = json.loads(data)
        for chunk_pos in env['data']['missing_chunks']:
            yield [env['url']['id'], env['url']['content'], chunk_pos, None]

    def _handle_beanstalk_event(self, conn_error):
        try:
            job_id, data = self.beanstalk.reserve()
            if conn_error:
                self.logger.warn("beanstalk reconnected")
                conn_error = False
        except ConnectionError:
            if not conn_error:
                self.logger.warn("beanstalk connection error")
                conn_error = True
        try:
            for chunk in self._fetch_chunks_from_event(job_id, data):
                yield chunk
            self.beanstalk.delete(job_id)
        except Exception:
            self.logger.exception("handling event %s (bury)", job_id)
            self.beanstalk.bury(job_id)

    def _fetch_chunks_from_beanstalk(self):
        self.beanstalk = Beanstalk.from_url(self.beanstalkd_addr)
        self.beanstalk.use(self.beanstalkd_tube)
        self.beanstalk.watch(self.beanstalkd_tube)
        conn_error = False
        while 1:
            for chunk in self._handle_beanstalk_event(conn_error):
                yield chunk

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
            return self.rdir_client.chunk_fetch(self.volume,
                                                limit=self.rdir_fetch_limit,
                                                rebuild=True)

    def rebuilder_pass_with_lock(self):
        self.rdir_client.admin_lock(self.volume,
                                    "rebuilder on %s" % gethostname())
        try:
            self.rebuilder_pass()
        finally:
            self.rdir_client.admin_unlock(self.volume)

    def rebuilder_pass(self):
        start_time = report_time = time.time()

        rebuilder_time = 0

        chunks = self._fetch_chunks()
        for cid, content_id, chunk_id_or_pos, _ in chunks:
            loop_time = time.time()
            if self.dry_run:
                self.dryrun_chunk_rebuild(cid, content_id, chunk_id_or_pos)
            else:
                self.safe_chunk_rebuild(cid, content_id, chunk_id_or_pos)

            self.chunks_run_time = ratelimit(
                self.chunks_run_time,
                self.max_chunks_per_second
            )
            self.total_chunks_processed += 1
            now = time.time()

            if now - self.last_reported >= self.report_interval:
                self.logger.info(
                    'RUN  %(volume)s '
                    'started=%(start_time)s '
                    'passes=%(passes)d '
                    'errors=%(errors)d '
                    'chunks=%(nb_chunks)d %(c_rate).2f/s '
                    'bytes=%(nb_bytes)d %(b_rate).2fB/s '
                    'elapsed=%(total).2f '
                    '(rebuilder: %(success_rate).2f%%)' % {
                        'volume': self.volume,
                        'start_time': datetime.fromtimestamp(
                            int(report_time)).isoformat(),
                        'passes': self.passes,
                        'errors': self.errors,
                        'nb_chunks': self.total_chunks_processed,
                        'nb_bytes': self.total_bytes_processed,
                        'c_rate': self.passes / (now - report_time),
                        'b_rate': self.bytes_processed / (now - report_time),
                        'total': (now - start_time),
                        'rebuilder_time': rebuilder_time,
                        'success_rate':
                            100 * ((self.total_chunks_processed - self.errors)
                                   / float(self.total_chunks_processed))
                    }
                )
                report_time = now
                self.passes = 0
                self.bytes_processed = 0
                self.last_reported = now
            rebuilder_time += (now - loop_time)
        end_time = time.time()
        elapsed = (end_time - start_time) or 0.000001
        self.logger.info(
            'DONE %(volume)s '
            'started=%(start_time)s '
            'ended=%(end_time)s '
            'passes=%(passes)d '
            'elapsed=%(elapsed).02f '
            'errors=%(errors)d '
            'chunks=%(nb_chunks)d %(c_rate).2f/s '
            'bytes=%(nb_bytes)d %(b_rate).2fB/s '
            'elapsed=%(rebuilder_time).2f '
            '(rebuilder: %(success_rate).2f%%)' % {
                'volume': self.volume,
                'start_time': datetime.fromtimestamp(
                    int(start_time)).isoformat(),
                'end_time': datetime.fromtimestamp(
                    int(end_time)).isoformat(),
                'passes': self.passes,
                'elapsed': elapsed,
                'errors': self.errors,
                'nb_chunks': self.total_chunks_processed,
                'nb_bytes': self.total_bytes_processed,
                'c_rate': self.total_chunks_processed / elapsed,
                'b_rate': self.total_bytes_processed / elapsed,
                'rebuilder_time': rebuilder_time,
                'success_rate':
                    100 * ((self.total_chunks_processed - self.errors) /
                           float(self.total_chunks_processed or 1))
            }
        )

    def dryrun_chunk_rebuild(self, container_id, content_id, chunk_id_or_pos):
        self.logger.info("[dryrun] Rebuilding "
                         "container %s, content %s, chunk %s",
                         container_id, content_id, chunk_id_or_pos)
        self.passes += 1

    def safe_chunk_rebuild(self, container_id, content_id, chunk_id_or_pos):
        try:
            self.chunk_rebuild(container_id, content_id, chunk_id_or_pos)
        except Exception as e:
            self.errors += 1
            self.logger.error('ERROR while rebuilding chunk %s|%s|%s: %s',
                              container_id, content_id, chunk_id_or_pos, e)

        self.passes += 1

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
                                  "possible orphan chunk"))
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

        self.bytes_processed += chunk_size
        self.total_bytes_processed += chunk_size
