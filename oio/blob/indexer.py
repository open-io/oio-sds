import time
from datetime import datetime
from random import random

from oio.blob.utils import check_volume, read_chunk_metadata
from oio.rdir.client import RdirClient
from oio.common.daemon import Daemon
from oio.common import exceptions as exc
from oio.common.utils import get_logger, int_value, paths_gen
from oio.common.green import ratelimit


class BlobIndexer(Daemon):
    def __init__(self, conf, **kwargs):
        super(BlobIndexer, self).__init__(conf)
        self.logger = get_logger(conf)
        volume = conf.get('volume')
        if not volume:
            raise exc.ConfigurationException('No volume specified for indexer')
        self.volume = volume
        self.passes = 0
        self.errors = 0
        self.last_reported = 0
        self.chunks_run_time = 0
        self.total_chunks_processed = 0
        self.interval = int_value(
            conf.get('interval'), 300)
        self.report_interval = int_value(
            conf.get('report_interval'), 3600)
        self.max_chunks_per_second = int_value(
            conf.get('chunks_per_second'), 30)
        self.index_client = RdirClient(conf)
        self.namespace, self.volume_id = check_volume(self.volume)

    def index_pass(self):
        start_time = report_time = time.time()

        total_errors = 0

        paths = paths_gen(self.volume)

        for path in paths:
            self.safe_update_index(path)
            self.chunks_run_time = ratelimit(
                self.chunks_run_time,
                self.max_chunks_per_second
            )
            self.total_chunks_processed += 1
            now = time.time()
            if now - self.last_reported >= self.report_interval:
                self.logger.info(
                    'started=%(start_time)s '
                    'passes=%(passes)d '
                    'errors=%(errors)d '
                    'c_rate=%(c_rate).2f '
                    'total=%(total).2f ' % {
                        'start_time': datetime.fromtimestamp(
                            int(report_time)).isoformat(),
                        'passes': self.passes,
                        'errors': self.errors,
                        'c_rate': self.passes / (now - report_time),
                        'total': (now - start_time)
                    }
                )
                report_time = now
                total_errors += self.errors
                self.passes = 0
                self.errors = 0
                self.last_reported = now
        end_time = time.time()
        elapsed = (end_time - start_time) or 0.000001
        self.logger.info(
            'started=(%start_time)s '
            'ended=(%end_time)s '
            'elapsed=%(elapsed).02f '
            'errors=%(errors)d '
            'chunk/s%(chunk_rate).2f ' % {
                'start_time': datetime.fromtimestamp(
                    int(start_time)).isoformat(),
                'end_time': datetime.fromtimestamp(
                    int(end_time)).isoformat(),
                'elapsed': elapsed,
                'errors': total_errors + self.errors,
                'chunk_rate': self.total_chunks_processed / elapsed
            }
        )
        if elapsed < self.interval:
            time.sleep(self.interval - elapsed)

    def safe_update_index(self, path):
        try:
            self.logger.debug('Updating index: %s', path)
            self.update_index(path)
        except Exception:
            self.errors += 1
            self.logger.exception('ERROR while updating index for chunk %s',
                                  path)
        self.passes += 1

    def update_index(self, path):
        with open(path) as f:
            try:
                meta = read_chunk_metadata(f)
            except exc.MissingAttribute as e:
                raise exc.FaultyChunk(
                    'Missing extended attribute %s' % e)
            data = {'mtime': int(time.time())}
            self.index_client.chunk_push(self.volume_id,
                                         meta['container_id'],
                                         meta['content_id'],
                                         meta['chunk_id'],
                                         **data)

    def run(self, *args, **kwargs):
        time.sleep(random() * self.interval)
        while True:
            try:
                self.index_pass()
            except Exception as e:
                self.logger.exception('ERROR during indexing: %s' % e)
