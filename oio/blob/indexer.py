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
        self.successes = 0
        self.last_reported = 0
        self.chunks_run_time = 0
        self.interval = int_value(
            conf.get('interval'), 300)
        self.report_interval = int_value(
            conf.get('report_interval'), 3600)
        self.max_chunks_per_second = int_value(
            conf.get('chunks_per_second'), 30)
        self.index_client = RdirClient(conf, logger=self.logger)
        self.namespace, self.volume_id = check_volume(self.volume)

    def index_pass(self):

        def safe_update_index(path):
            try:
                self.update_index(path)
                self.successes += 1
                self.logger.debug('Updated %s', path)
            except Exception:
                self.errors += 1
                self.logger.exception('ERROR while updating %s', path)

        def report(tag):
            total = self.errors + self.successes
            now = time.time()
            elapsed = (now - start_time) or 0.000001
            self.logger.info(
                '%(tag)s=%(current_time)s '
                'elapsed=%(elapsed).02f '
                'pass=%(pass)d '
                'errors=%(errors)d '
                'chunks=%(nb_chunks)d %(c_rate).2f/s' % {
                    'tag': tag,
                    'current_time': datetime.fromtimestamp(
                        int(now)).isoformat(),
                    'pass': self.passes,
                    'errors': self.errors,
                    'nb_chunks': total,
                    'c_rate': total / (now - self.last_reported),
                    'elapsed': elapsed
                }
            )
            self.last_reported = now

        start_time = time.time()
        self.last_reported = start_time
        self.errors = 0
        self.successes = 0

        paths = paths_gen(self.volume)
        report('started')
        for path in paths:
            safe_update_index(path)
            self.chunks_run_time = ratelimit(
                self.chunks_run_time,
                self.max_chunks_per_second
            )
            now = time.time()
            if now - self.last_reported >= self.report_interval:
                report('running')
        report('ended')

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
            pre = time.time()
            try:
                self.index_pass()
            except Exception as e:
                self.logger.exception('ERROR during indexing: %s' % e)
            else:
                self.passes += 1
            elapsed = (time.time() - pre) or 0.000001
            if elapsed < self.interval:
                time.sleep(self.interval - elapsed)
