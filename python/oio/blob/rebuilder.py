import time
from socket import gethostname

from oio.blob.client import BlobClient
from oio.common.exceptions import ClientException
from oio.container.client import ContainerClient
from oio.rdir.client import RdirClient
from oio.common import exceptions as exc
from oio.common.utils import get_logger, int_value, ratelimit, true_value


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
        self.blob_client = BlobClient()
        self.container_client = ContainerClient(conf)
        self.rdir_client = RdirClient(conf)

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

    def dryrun_chunk_rebuild(self, container_id, content_id, chunk_id):
        self.logger.info("[dryrun] Rebuilding "
                         "container %s, content %s, chunk %s"
                         % (container_id, content_id, chunk_id))
        self.passes += 1

    def safe_chunk_rebuild(self, container_id, content_id, chunk_id):
        self.logger.info('Rebuilding (container %s, content %s, chunk %s)'
                         % (container_id, content_id, chunk_id))
        try:
            self.chunk_rebuild(container_id, content_id, chunk_id)
        except Exception as e:
            self.errors += 1
            self.logger.error('ERROR while rebuilding chunk %s|%s|%s) : %s',
                              container_id, content_id, chunk_id, e)

        self.passes += 1

    def _meta2_get_chunks_at_pos(self, container_id, content_id, chunk_id):
        current_chunk_url = 'http://%s/%s' % (self.volume, chunk_id)

        try:
            data = self.container_client.content_show(
                cid=container_id, content=content_id)
        except exc.NotFound:
            raise exc.OrphanChunk('Content not found')

        current_chunk = None
        for c in data:
            if c['url'] == current_chunk_url:
                current_chunk = c
                break
        if not current_chunk:
            raise exc.OrphanChunk('Chunk not found in content')

        duplicate_chunks = []
        for c in data:
            if c['pos'] == current_chunk['pos'] \
                    and c['url'] != current_chunk['url']:
                duplicate_chunks.append(c)
        if len(duplicate_chunks) == 0:
            raise exc.UnrecoverableContent('No copy of missing chunk')

        return current_chunk, duplicate_chunks

    def _meta2_get_spare_chunk(self, container_id, content_id, notin, broken):
        spare_data = {'notin': notin,
                      'broken': [broken],
                      'size': 0}
        try:
            spare_resp = self.container_client.content_spare(
                cid=container_id, content=content_id, data=spare_data)
        except ClientException as e:
            raise exc.SpareChunkException('No spare chunk (%s)' % e.message)

        return spare_resp['chunks'][0]

    def _meta2_replace_chunk(self, container_id, content_id,
                             current_chunk, new_chunk):
        old = [{'type': 'chunk',
                'id': current_chunk['url'],
                'hash': current_chunk['hash'],
                'size': current_chunk['size'],
                'pos': current_chunk['pos'],
                'content': content_id}]
        new = [{'type': 'chunk',
                'id': new_chunk['id'],
                'hash': current_chunk['hash'],
                'size': current_chunk['size'],
                'pos': current_chunk['pos'],
                'content': content_id}]
        update_data = {'old': old, 'new': new}

        self.container_client.container_raw_update(
            cid=container_id, data=update_data)

    # TODO rain support
    def chunk_rebuild(self, container_id, content_id, chunk_id):

        current_chunk, duplicate_chunks = self._meta2_get_chunks_at_pos(
            container_id, content_id, chunk_id)

        spare_chunk = self._meta2_get_spare_chunk(
            container_id, content_id, duplicate_chunks, current_chunk)

        uploaded = False
        for src in duplicate_chunks:
            try:
                self.blob_client.chunk_copy(src['url'], spare_chunk['id'])
                self.logger.debug('copy chunk from %s to %s',
                                  src['url'], spare_chunk['id'])
                uploaded = True
                break
            except Exception as e:
                self.logger.debug('Failed to copy chunk from %s to %s: %s',
                                  src['url'], spare_chunk['id'], type(e))
        if not uploaded:
            raise exc.UnrecoverableContent('No copy available '
                                           'of missing chunk')

        self._meta2_replace_chunk(container_id, content_id,
                                  current_chunk, spare_chunk)

        self.rdir_client.chunk_push(self.volume, container_id, content_id,
                                    chunk_id, rtime=int(time.time()))

        self.bytes_processed += current_chunk['size']
        self.total_bytes_processed += current_chunk['size']
