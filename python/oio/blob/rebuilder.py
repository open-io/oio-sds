import time

from oio.blob.client import BlobClient
from oio.container.client import ContainerClient
from oio.rdir.client import RdirClient
from oio.common.daemon import Daemon
from oio.common import exceptions as exc
from oio.common.utils import get_logger, int_value, ratelimit


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
        self.report_interval = int_value(
            conf.get('report_interval'), 3600)
        self.max_chunks_per_second = int_value(
            conf.get('chunks_per_second'), 30)
        self.max_bytes_per_second = int_value(
            conf.get('bytes_per_second'), 10000000)
        self.rdir_fetch_limit = int_value(
            conf.get('rdir_fetch_limit'), 100)
        self.blob_client = BlobClient()
        self.container_client = ContainerClient(conf)
        self.rdir_client = RdirClient(conf)

    def rebuilder_pass(self):
        start_time = report_time = time.time()

        total_errors = 0
        rebuilder_time = 0

        chunks = self.rdir_client.fetch(self.volume,
                                        limit=self.rdir_fetch_limit)
        for container, content, chunk, data in chunks:
            loop_time = time.time()

            self.safe_chunk_rebuild(container, content, chunk)
            self.rdir_client.chunk_push(self.volume, container, content, chunk,
                                        rtime=int(time.time()))

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
                    '%(errors)d '
                    '%(c_rate).2f '
                    '%(b_rate).2f '
                    '%(total).2f '
                    '%(rebuilder_time).2f'
                    '%(rebuilder_rate).2f' % {
                        'start_time': time.ctime(report_time),
                        'passes': self.passes,
                        'errors': self.errors,
                        'c_rate': self.passes / (now - report_time),
                        'b_rate': self.bytes_processed / (now - report_time),
                        'total': (now - start_time),
                        'rebuilder_time': rebuilder_time,
                        'rebuilder_rate': rebuilder_time / (now - start_time)
                    }
                )
                report_time = now
                total_errors += self.errors
                self.passes = 0
                self.bytes_processed = 0
                self.last_reported = now
            rebuilder_time += (now - loop_time)
        elapsed = (time.time() - start_time) or 0.000001
        self.logger.info(
            '%(elapsed).02f '
            '%(errors)d '
            '%(chunk_rate).2f '
            '%(bytes_rate).2f '
            '%(rebuilder_time).2f '
            '%(rebuilder_rate).2f' % {
                'elapsed': elapsed,
                'errors': total_errors + self.errors,
                'chunk_rate': self.total_chunks_processed / elapsed,
                'bytes_rate': self.total_bytes_processed / elapsed,
                'rebuilder_time': rebuilder_time,
                'rebuilder_rate': rebuilder_time / elapsed
            }
        )

    def safe_chunk_rebuild(self, container, content, chunk):
        self.logger.debug('Rebuilding (container %s, content %s, chunk %s)'
                          % (container, content, chunk))
        try:
            self.chunk_rebuild(container, content, chunk)
        except Exception as e:
            self.errors += 1
            self.logger.error('ERROR while rebuilding chunk %s|%s|%s) : %s',
                              container, content, chunk, e)
        self.passes += 1

    # TODO rain support
    # TODO push chunks anywhere on the grid when container_raw_update fixed
    def chunk_rebuild(self, container, content, chunk):
        current_chunk_url = 'http://%s/%s' % (self.volume, chunk)

        try:
            data = self.container_client.content_show(
                cid=container, path=content)
        except exc.NotFound:
            raise exc.OrphanChunk('Content not found')

        current_chunk = None
        for c in data:
            if c['url'] == current_chunk_url:
                current_chunk = c
                break
        if not current_chunk:
            exc.OrphanChunk('Chunk not found in content')

        duplicate_chunks = []
        for c in data:
            if c['pos'] == current_chunk['pos'] \
                    and c['url'] != current_chunk['url']:
                duplicate_chunks.append(c)
        if len(duplicate_chunks) == 0:
            raise exc.UnrecoverableContent('No copy of missing chunk')

        for src in duplicate_chunks:
            try:
                self.blob_client.chunk_copy(src['url'], current_chunk['url'])
                self.logger.debug('copy chunk from %s to %s',
                                  src['url'], current_chunk['url'])
                break
            except Exception:
                self.logger.debug('Failed to copy chunk from %s to %s',
                                  src['url'], current_chunk['url'])

        self.bytes_processed += current_chunk['size']
        self.total_bytes_processed += current_chunk['size']


class BlobRebuilder(Daemon):
    def __init__(self, conf, **kwargs):
        super(BlobRebuilder, self).__init__(conf)
        self.logger = get_logger(conf)
        volume_id = conf.get('volume_id')
        if not volume_id:
            raise exc.ConfigurationException('No volume specified')
        self.volume_id = volume_id

    def run(self, *args, **kwargs):
        try:
            worker = BlobRebuilderWorker(self.conf,
                                         self.logger, self.volume_id)
            worker.rebuilder_pass()
        except Exception as e:
            self.logger.exception('ERROR in rebuilder: %s' % e)
