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


from contextlib import closing
import hashlib
import time

from oio.blob.utils import check_volume, read_chunk_metadata
from oio.container.client import ContainerClient
from oio.common.daemon import Daemon
from oio.common import exceptions as exc
from oio.common.utils import get_logger, int_value, paths_gen
from oio.common.green import ratelimit


SLEEP_TIME = 30


class BlobAuditorWorker(object):
    def __init__(self, conf, logger, volume):
        self.conf = conf
        self.logger = logger
        self.volume = volume
        self.run_time = 0
        self.passes = 0
        self.errors = 0
        self.orphan_chunks = 0
        self.faulty_chunks = 0
        self.corrupted_chunks = 0
        self.last_reported = 0
        self.chunks_run_time = 0
        self.bytes_running_time = 0
        self.bytes_processed = 0
        self.total_bytes_processed = 0
        self.total_chunks_processed = 0
        self.report_interval = int_value(
            conf.get('report_interval'), 3600)
        self.max_chunks_per_second = int_value(
            conf.get('chunks_per_second'), 30)
        self.max_bytes_per_second = int_value(
            conf.get('bytes_per_second'), 10000000)
        self.container_client = ContainerClient(conf)

    def audit_pass(self):
        self.namespace, self.address = check_volume(self.volume)

        start_time = report_time = time.time()

        total_errors = 0
        total_corrupted = 0
        total_orphans = 0
        total_faulty = 0
        audit_time = 0

        paths = paths_gen(self.volume)

        for path in paths:
            loop_time = time.time()
            self.safe_chunk_audit(path)
            self.chunks_run_time = ratelimit(
                self.chunks_run_time,
                self.max_chunks_per_second
            )
            self.total_chunks_processed += 1
            now = time.time()

            if now - self.last_reported >= self.report_interval:
                self.logger.info(
                    '%(start_time)s '
                    '%(passes)d '
                    '%(corrupted)d '
                    '%(faulty)d '
                    '%(orphans)d '
                    '%(errors)d '
                    '%(c_rate).2f '
                    '%(b_rate).2f '
                    '%(total).2f '
                    '%(audit_time).2f'
                    '%(audit_rate).2f' % {
                        'start_time': time.ctime(report_time),
                        'passes': self.passes,
                        'corrupted': self.corrupted_chunks,
                        'faulty': self.faulty_chunks,
                        'orphans': self.orphan_chunks,
                        'errors': self.errors,
                        'c_rate': self.passes / (now - report_time),
                        'b_rate': self.bytes_processed / (now - report_time),
                        'total': (now - start_time),
                        'audit_time': audit_time,
                        'audit_rate': audit_time / (now - start_time)
                    }
                )
                report_time = now
                total_corrupted += self.corrupted_chunks
                total_orphans += self.orphan_chunks
                total_faulty += self.faulty_chunks
                total_errors += self.errors
                self.passes = 0
                self.corrupted_chunks = 0
                self.orphan_chunks = 0
                self.faulty_chunks = 0
                self.errors = 0
                self.bytes_processed = 0
                self.last_reported = now
            audit_time += (now - loop_time)
        elapsed = (time.time() - start_time) or 0.000001
        self.logger.info(
            '%(elapsed).02f '
            '%(corrupted)d '
            '%(faulty)d '
            '%(orphans)d '
            '%(errors)d '
            '%(chunk_rate).2f '
            '%(bytes_rate).2f '
            '%(audit_time).2f '
            '%(audit_rate).2f' % {
                'elapsed': elapsed,
                'corrupted': total_corrupted + self.corrupted_chunks,
                'faulty': total_faulty + self.faulty_chunks,
                'orphans': total_orphans + self.orphan_chunks,
                'errors': total_errors + self.errors,
                'chunk_rate': self.total_chunks_processed / elapsed,
                'bytes_rate': self.total_bytes_processed / elapsed,
                'audit_time': audit_time,
                'audit_rate': audit_time / elapsed
            }
        )

    def safe_chunk_audit(self, path):
        try:
            self.chunk_audit(path)
        except exc.FaultyChunk as err:
            self.faulty_chunks += 1
            self.logger.error('ERROR faulty chunk %s: %s', path, err)
        except exc.CorruptedChunk as err:
            self.corrupted_chunks += 1
            self.logger.error('ERROR corrupted chunk %s: %s', path, err)
        except exc.OrphanChunk as err:
            self.orphan_chunks += 1
            self.logger.error('ERROR orphan chunk %s: %s', path, err)
        except Exception:
            self.errors += 1
            self.logger.exception('ERROR while auditing chunk %s', path)

        self.passes += 1

    def chunk_audit(self, path):
        with open(path) as f:
            try:
                meta = read_chunk_metadata(f)
            except exc.MissingAttribute as e:
                raise exc.FaultyChunk(
                    'Missing extended attribute %s' % e)
            size = int(meta['chunk_size'])
            md5_checksum = meta['chunk_hash'].lower()
            reader = ChunkReader(f, size, md5_checksum)
            with closing(reader):
                for buf in reader:
                    buf_len = len(buf)
                    self.bytes_running_time = ratelimit(
                        self.bytes_running_time,
                        self.max_bytes_per_second,
                        increment=buf_len)
                    self.bytes_processed += buf_len
                    self.total_bytes_processed += buf_len

            try:
                container_id = meta['container_id']
                content_path = meta['content_path']
                content_attr, data = self.container_client.content_locate(
                    cid=container_id, path=content_path)

                # Check chunk data
                chunk_data = None
                metachunks = set()
                for c in data:
                    if c['url'].endswith(meta['chunk_id']):
                        metachunks.add(c['pos'].split('.', 2)[0])
                        chunk_data = c
                if not chunk_data:
                    raise exc.OrphanChunk('Not found in content')

                if chunk_data['size'] != int(meta['chunk_size']):
                    raise exc.FaultyChunk('Invalid chunk size found')

                if chunk_data['hash'] != meta['chunk_hash']:
                    raise exc.FaultyChunk('Invalid chunk hash found')

                if chunk_data['pos'] != meta['chunk_pos']:
                    raise exc.FaultyChunk('Invalid chunk position found')

            except exc.NotFound:
                raise exc.OrphanChunk('Chunk not found in container')


class BlobAuditor(Daemon):
    def __init__(self, conf, **kwargs):
        super(BlobAuditor, self).__init__(conf)
        self.logger = get_logger(conf)
        volume = conf.get('volume')
        if not volume:
            raise exc.ConfigurationException('No volume specified for auditor')
        self.volume = volume

    def run(self, *args, **kwargs):
        while True:
            try:
                worker = BlobAuditorWorker(self.conf, self.logger, self.volume)
                worker.audit_pass()
            except Exception as e:
                self.logger.exception('ERROR in audit: %s' % e)
            self._sleep()

    def _sleep(self):
        time.sleep(SLEEP_TIME)


class ChunkReader(object):
    def __init__(self, fp, size, md5_checksum):
        self.fp = fp
        self.size = size
        self.md5_checksum = md5_checksum
        self.bytes_read = 0
        self.iter_md5 = None

    def __iter__(self):
        self.iter_md5 = hashlib.md5()
        while True:
            buf = self.fp.read()
            if buf:
                self.iter_md5.update(buf)
                self.bytes_read += len(buf)
                yield buf
            else:
                break

    def close(self):
        if self.fp:
            self.md5_read = self.iter_md5.hexdigest()
            if self.bytes_read != self.size:
                raise exc.FaultyChunk('Invalid size for chunk')

            if self.md5_read != self.md5_checksum:
                raise exc.CorruptedChunk(
                    'checksum does not match %s != %s'
                    % (self.md5_read, self.md5_checksum))
