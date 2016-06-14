import time

from oio.blob.client import BlobClient
from oio.blob.utils import check_volume, read_chunk_metadata
from oio.common.exceptions import ContentNotFound
from oio.container.client import ContainerClient
from oio.common.daemon import Daemon
from oio.common import exceptions as exc
from oio.common.utils import get_logger, int_value, ratelimit, paths_gen, \
    statfs
from oio.content.factory import ContentFactory

SLEEP_TIME = 30
READ_BUFFER_SIZE = 65535


class BlobMoverWorker(object):
    def __init__(self, conf, logger, volume):
        self.conf = conf
        self.logger = logger or get_logger(conf)
        self.volume = volume
        self.run_time = 0
        self.passes = 0
        self.errors = 0
        self.last_reported = 0
        self.last_usage_check = 0
        self.chunks_run_time = 0
        self.bytes_running_time = 0
        self.bytes_processed = 0
        self.total_bytes_processed = 0
        self.total_chunks_processed = 0
        self.usage_target = int_value(
            conf.get('usage_target'), 0)
        self.usage_check_interval = int_value(
            conf.get('usage_check_interval'), 3600)
        self.report_interval = int_value(
            conf.get('report_interval'), 3600)
        self.max_chunks_per_second = int_value(
            conf.get('chunks_per_second'), 30)
        self.max_bytes_per_second = int_value(
            conf.get('bytes_per_second'), 10000000)
        self.blob_client = BlobClient()
        self.container_client = ContainerClient(conf)
        self.content_factory = ContentFactory(conf)

    def mover_pass(self):
        self.namespace, self.address = check_volume(self.volume)

        start_time = report_time = time.time()

        total_errors = 0
        mover_time = 0

        paths = paths_gen(self.volume)

        for path in paths:
            loop_time = time.time()

            now = time.time()
            if now - self.last_usage_check >= self.usage_check_interval:
                used, total = statfs(self.volume)
                usage = (float(used) / total) * 100
                if usage <= self.usage_target:
                    self.logger.info(
                        'current usage %.2f%%: target reached (%.2f%%)', usage,
                        self.usage_target)
                    self.last_usage_check = now
                    break

            self.safe_chunk_move(path)
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
                    '%(mover_time).2f'
                    '%(mover_rate).2f' % {
                        'start_time': time.ctime(report_time),
                        'passes': self.passes,
                        'errors': self.errors,
                        'c_rate': self.passes / (now - report_time),
                        'b_rate': self.bytes_processed / (now - report_time),
                        'total': (now - start_time),
                        'mover_time': mover_time,
                        'mover_rate': mover_time / (now - start_time)
                    }
                )
                report_time = now
                total_errors += self.errors
                self.passes = 0
                self.bytes_processed = 0
                self.last_reported = now
            mover_time += (now - loop_time)
        elapsed = (time.time() - start_time) or 0.000001
        self.logger.info(
            '%(elapsed).02f '
            '%(errors)d '
            '%(chunk_rate).2f '
            '%(bytes_rate).2f '
            '%(mover_time).2f '
            '%(mover_rate).2f' % {
                'elapsed': elapsed,
                'errors': total_errors + self.errors,
                'chunk_rate': self.total_chunks_processed / elapsed,
                'bytes_rate': self.total_bytes_processed / elapsed,
                'mover_time': mover_time,
                'mover_rate': mover_time / elapsed
            }
        )

    def safe_chunk_move(self, path):
        try:
            self.chunk_move(path)
        except Exception as e:
            self.errors += 1
            self.logger.error('ERROR while moving chunk %s: %s', path, e)
        self.passes += 1

    def load_chunk_metadata(self, path):
        with open(path) as f:
            return read_chunk_metadata(f)

    def chunk_move(self, path):
        meta = self.load_chunk_metadata(path)
        container_id = meta['container_id']
        content_id = meta['content_id']
        chunk_id = meta['chunk_id']
        chunk_url = 'http://%s/%s' % (self.address, meta['chunk_id'])

        try:
            content = self.content_factory.get(container_id, content_id)
        except ContentNotFound:
            raise exc.OrphanChunk('Content not found')

        new_chunk = content.move_chunk(chunk_id)

        self.logger.info(
            'moved chunk %s to %s', chunk_url, new_chunk['url'])


class BlobMover(Daemon):
    def __init__(self, conf, **kwargs):
        super(BlobMover, self).__init__(conf)
        self.logger = get_logger(conf)
        volume = conf.get('volume')
        if not volume:
            raise exc.ConfigurationException('No volume specified for mover')
        self.volume = volume

    def run(self, *args, **kwargs):
        while True:
            try:
                worker = BlobMoverWorker(self.conf, self.logger, self.volume)
                worker.mover_pass()
            except Exception as e:
                self.logger.exception('ERROR in mover: %s' % e)
            self._sleep()

    def _sleep(self):
        time.sleep(SLEEP_TIME)
