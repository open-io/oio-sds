# Copyright (C) 2015-2017 OpenIO, original work as part of
# OpenIO Software Defined Storage
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
from datetime import datetime
from socket import gethostname

from oio.common import exceptions as exc
from oio.common.utils import get_logger, int_value, true_value
from oio.common.green import ratelimit
from oio.common.exceptions import ContentNotFound, OrphanChunk
from oio.content.factory import ContentFactory
from oio.rdir.client import RdirClient


class BlobRebuilderWorker(object):
    def __init__(self, conf, logger, volume):
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
        self.rdir_client = RdirClient(conf)
        self.content_factory = ContentFactory(conf)

    def rebuilder_pass_with_lock(self):
        self.rdir_client.admin_lock(self.volume,
                                    "rebuilder on %s" % gethostname())
        try:
            self.rebuilder_pass()
        finally:
            self.rdir_client.admin_unlock(self.volume)

    def rebuilder_pass(self):
        start_time = report_time = time.time()

        total_errors = 0
        rebuilder_time = 0

        chunks = self.rdir_client.chunk_fetch(self.volume,
                                              limit=self.rdir_fetch_limit,
                                              rebuild=True)
        for container_id, content_id, chunk_id, data in chunks:
            loop_time = time.time()

            if self.dry_run:
                self.dryrun_chunk_rebuild(container_id, content_id, chunk_id)
            else:
                self.safe_chunk_rebuild(container_id, content_id, chunk_id)

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
                    '(rebuilder: %(rebuilder_rate).2f%%)' % {
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
                        'rebuilder_rate':
                            100.0 * rebuilder_time / float(now - start_time)
                    }
                )
                report_time = now
                total_errors += self.errors
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
            'elapsed=%(elapsed).02f '
            'errors=%(errors)d '
            'chunks=%(nb_chunks)d %(c_rate).2f/s '
            'bytes=%(nb_bytes)d %(b_rate).2fB/s '
            'elapsed=%(rebuilder_time).2f '
            '(rebuilder: %(rebuilder_rate).2f%%)' % {
                'volume': self.volume,
                'start_time': datetime.fromtimestamp(
                    int(start_time)).isoformat(),
                'end_time': datetime.fromtimestamp(
                    int(end_time)).isoformat(),
                'elapsed': elapsed,
                'errors': total_errors + self.errors,
                'nb_chunks': self.total_chunks_processed,
                'nb_bytes': self.total_bytes_processed,
                'c_rate': self.total_chunks_processed / elapsed,
                'b_rate': self.total_bytes_processed / elapsed,
                'rebuilder_time': rebuilder_time,
                'rebuilder_rate': 100.0 * rebuilder_time / float(elapsed)
            }
        )

    def dryrun_chunk_rebuild(self, container_id, content_id, chunk_id):
        self.logger.info("[dryrun] Rebuilding "
                         "container %s, content %s, chunk %s",
                         container_id, content_id, chunk_id)
        self.passes += 1

    def safe_chunk_rebuild(self, container_id, content_id, chunk_id):
        try:
            self.chunk_rebuild(container_id, content_id, chunk_id)
        except Exception as e:
            self.errors += 1
            self.logger.error('ERROR while rebuilding chunk %s|%s|%s) : %s',
                              container_id, content_id, chunk_id, e)

        self.passes += 1

    def chunk_rebuild(self, container_id, content_id, chunk_id):
        self.logger.info('Rebuilding (container %s, content %s, chunk %s)',
                         container_id, content_id, chunk_id)

        try:
            content = self.content_factory.get(container_id, content_id)
        except ContentNotFound:
            raise exc.OrphanChunk('Content not found')

        chunk = content.chunks.filter(id=chunk_id).one()
        if chunk is None:
            raise OrphanChunk("Chunk not found in content")
        chunk_size = chunk.size

        content.rebuild_chunk(chunk_id, allow_same_rawx=self.allow_same_rawx)

        self.rdir_client.chunk_delete(self.volume, container_id, content_id,
                                      chunk_id)

        self.bytes_processed += chunk_size
        self.total_bytes_processed += chunk_size
