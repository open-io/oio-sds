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

import time
import uuid
from datetime import datetime
from socket import gethostname

from oio.common.json import json
from oio.common.green import eventlet, threading, sleep
from oio.common.easy_value import float_value, int_value, true_value
from oio.common.exceptions import ContentNotFound, NotFound, OrphanChunk, \
    ConfigurationException, OioTimeout, ExplicitBury, OioException, RetryLater
from oio.event.beanstalk import BeanstalkdListener, BeanstalkdSender, \
    BeanstalkError
from oio.content.factory import ContentFactory
from oio.rdir.client import RdirClient
from oio.rebuilder.rebuilder import Rebuilder, RebuilderWorker


DEFAULT_REBUILDER_TUBE = 'oio-rebuild'
DEFAULT_RETRY_DELAY = 3600
DISTRIBUTED_REBUILDER_TIMEOUT = 300


class BlobRebuilder(Rebuilder):
    """
    Rebuild chunks that were on the specified volume.
    """

    def __init__(self, conf, logger, volume, try_chunk_delete=False,
                 beanstalkd_addr=None, **kwargs):
        super(BlobRebuilder, self).__init__(conf, logger, volume, **kwargs)
        # rdir
        self.rdir_client = RdirClient(conf, logger=self.logger)
        self.rdir_fetch_limit = int_value(conf.get('rdir_fetch_limit'), 1000)
        self.rdir_timeout = float_value(conf.get('rdir_timeout'), 60.0)
        self.rdir_shuffle_chunks = true_value(conf.get('rdir_shuffle_chunks'))
        # rawx
        self.try_chunk_delete = try_chunk_delete
        # beanstalk
        if beanstalkd_addr:
            beanstalkd_tube = conf.get('beanstalkd_tube',
                                       DEFAULT_REBUILDER_TUBE)
            self.beanstalkd_listener = BeanstalkdListener(
                beanstalkd_addr, beanstalkd_tube, self.logger, **kwargs)
            self.retryer = BeanstalkdSender(
                beanstalkd_addr, beanstalkd_tube, self.logger, **kwargs)
        else:
            self.beanstalkd_listener = None
            self.retryer = None
        self.retry_delay = int_value(self.conf.get('retry_delay'),
                                     DEFAULT_RETRY_DELAY)
        # counters
        self.bytes_processed = 0
        self.total_bytes_processed = 0
        self.total_expected_chunks = None
        # distributed
        self.distributed = False

    def _create_worker(self, **kwargs):
        return BlobRebuilderWorker(
            self, try_chunk_delete=self.try_chunk_delete, **kwargs)

    def _fill_queue(self, queue, **kwargs):
        chunks = self._fetch_chunks(**kwargs)
        for chunk in chunks:
            queue.put(chunk)

    def _read_retry_queue(self, queue, **kwargs):
        while True:
            # Reschedule jobs we were not able to handle.
            chunk = queue.get()
            if self.retryer:
                sent = False
                while not sent:
                    sent = self.retryer.send_job(
                        self._event_from_broken_chunk(chunk, **kwargs),
                        delay=self.retry_delay)
                    if not sent:
                        sleep(1.0)
                self.retryer.job_done()
            queue.task_done()

    def _item_to_string(self, chunk, **kwargs):
        cid, content_id, chunk_id_or_pos, _ = chunk
        return 'chunk %s|%s|%s' % (cid, content_id, chunk_id_or_pos)

    def _get_report(self, status, end_time, counters, **kwargs):
        chunks_processed, bytes_processed, errors, total_chunks_processed, \
            total_bytes_processed, total_errors = counters
        time_since_last_report = (end_time - self.last_report) or 0.00001
        total_time = (end_time - self.start_time) or 0.00001
        report = (
                '%(status)s volume=%(volume)s '
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
        if self.total_expected_chunks is not None:
            progress = 100 * total_chunks_processed / \
                float(self.total_expected_chunks or 1)
            report += ' progress=%d/%d %.2f%%' % \
                (total_chunks_processed, self.total_expected_chunks, progress)
        return report

    def _update_processed_without_lock(self, bytes_processed, error=None,
                                       increment=1, **kwargs):
        super(BlobRebuilder, self)._update_processed_without_lock(
            None, error=error, increment=increment, **kwargs)
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

    def _rebuilder_pass(self, **kwargs):
        return super(BlobRebuilder, self).rebuilder_pass(**kwargs)

    def _load_expected_chunks(self):
        try:
            info = self.rdir_client.status(self.volume,
                                           timeout=self.rdir_timeout)
            self.total_expected_chunks = info.get(
                    'chunk', dict()).get('to_rebuild', None)
            self.logger.info('Total chunks to rebuild: %d',
                             self.total_expected_chunks)
        except Exception as exc:
            self.logger.warn('Failed to fetch the total chunks to rebuild: %s',
                             exc)

    def rebuilder_pass(self, **kwargs):
        success = False
        if self.volume:
            self.rdir_client.admin_lock(self.volume,
                                        "rebuilder on %s" % gethostname(),
                                        timeout=self.rdir_timeout)
            eventlet.spawn_n(self._load_expected_chunks)
        try:
            success = self._rebuilder_pass(**kwargs)
        finally:
            if self.volume:
                self.rdir_client.admin_unlock(self.volume,
                                              timeout=self.rdir_timeout)
        return success

    def _event_from_broken_chunk(self, chunk, reply=None, **kwargs):
        cid, content_id, chunk_id_or_pos, _ = chunk
        event = {}
        event['when'] = time.time()
        event['event'] = 'storage.content.broken'
        event['data'] = {'missing_chunks': [chunk_id_or_pos]}
        event['url'] = {'ns': self.namespace,
                        'id': cid, 'content': content_id}
        if reply:
            event['reply'] = reply
        return json.dumps(event)

    def _chunks_from_event(self, job_id, data, **kwargs):
        decoded = json.loads(data)
        container_id = decoded['url']['id']
        content_id = decoded['url']['content']
        more = None
        reply = decoded.get('reply', None)  # pylint: disable=no-member
        if reply:
            more = {'reply': reply}
        for chunk_id_or_pos in decoded['data']['missing_chunks']:
            yield [container_id, content_id,
                   str(chunk_id_or_pos), more]

    def _fetch_events_from_beanstalk(self, **kwargs):
        return self.beanstalkd_listener.fetch_jobs(
            self._chunks_from_event, **kwargs)

    def _fetch_chunks_from_file(self, **kwargs):
        with open(self.input_file, 'r') as ifile:
            for line in ifile:
                stripped = line.strip()
                if stripped and not stripped.startswith('#'):
                    yield stripped.split('|', 3)[:3] + [None]

    def _fetch_chunks(self, **kwargs):
        if self.input_file:
            return self._fetch_chunks_from_file(**kwargs)
        if self.beanstalkd_listener and not self.distributed:
            return self._fetch_events_from_beanstalk(**kwargs)
        if self.volume:
            return self.rdir_client.chunk_fetch(
                self.volume, limit=self.rdir_fetch_limit, rebuild=True,
                timeout=self.rdir_timeout, shuffle=self.rdir_shuffle_chunks,
                **kwargs)
        raise ConfigurationException('No source to fetch chunks from')


class DistributedBlobRebuilder(BlobRebuilder):
    """
    Send broken chunk events to a set of beanstalkd queues,
    and wait for responses on a single queue.
    """

    def __init__(self, conf, logger, volume, distributed_addr, **kwargs):
        super(DistributedBlobRebuilder, self).__init__(
            conf, logger, volume, **kwargs)

        if not self.beanstalkd_listener:
            raise ConfigurationException(
                "No beanstalkd to fetch responses from")
        distributed_tube = conf.get('distributed_tube', DEFAULT_REBUILDER_TUBE)
        if self.beanstalkd_listener.tube == distributed_tube:
            raise ConfigurationException(
                "The beanstalkd tubes must be different")

        self.distributed = True
        self.beanstalkd_senders = dict()
        for addr in distributed_addr.split(';'):
            sender = BeanstalkdSender(
                addr, distributed_tube, self.logger, **kwargs)
            self.beanstalkd_senders[sender.addr] = sender
        self.sending = False
        self.rebuilder_id = str(uuid.uuid4())

    def is_finished(self):
        """Tell is all senders have finished to send their events."""
        total_events = 0
        for sender in self.beanstalkd_senders.values():
            total_events += sender.nb_jobs
        return total_events <= 0

    def _rebuilder_pass(self, **kwargs):
        self.start_time = self.last_report = time.time()
        self.log_report('START', force=True)

        reply = {'addr': self.beanstalkd_listener.addr,
                 'tube': self.beanstalkd_listener.tube,
                 'rebuilder_id': self.rebuilder_id}
        # pylint: disable=no-member
        thread = threading.Thread(target=self._distribute_broken_chunks,
                                  args=(reply,), kwargs=kwargs)
        thread.start()

        while thread.is_alive():
            if self.sending:
                break
            else:
                time.sleep(0.1)

        while thread.is_alive() or not self.is_finished():
            try:
                event_info = self.beanstalkd_listener.fetch_job(
                    self._rebuilt_chunk_from_event,
                    timeout=DISTRIBUTED_REBUILDER_TIMEOUT, **kwargs)
                for beanstalkd_addr, chunk, bytes_processed, error \
                        in event_info:
                    self.beanstalkd_senders[beanstalkd_addr].job_done()
                    self.update_processed(
                        chunk, bytes_processed, error=error, **kwargs)
                self.log_report('RUN', **kwargs)
            except OioTimeout:
                self.logger.error("No response for %d seconds",
                                  DISTRIBUTED_REBUILDER_TIMEOUT)
                self.log_report('DONE', force=True)
                return False

        self.log_report('DONE', force=True)
        return self.total_errors == 0

    def _distribute_broken_chunks(self, reply, **kwargs):
        index = 0
        senders = self.beanstalkd_senders.values()
        sender_count = len(senders)

        def _send_broken_chunk(broken_chunk, local_index):
            event = self._event_from_broken_chunk(
                broken_chunk, reply=reply, **kwargs)
            # Send the event with a non-full sender
            while True:
                for _ in range(sender_count):
                    success = senders[local_index].send_job(
                        event, **kwargs)
                    local_index = (local_index + 1) % sender_count
                    if success:
                        return local_index
                time.sleep(5)

        broken_chunks = self._fetch_chunks(**kwargs)
        try:
            index = _send_broken_chunk(next(broken_chunks), index)
            self.sending = True
        except StopIteration:
            return
        for broken_chunk in broken_chunks:
            index = _send_broken_chunk(broken_chunk, index)

    def _rebuilt_chunk_from_event(self, job_id, data, **kwargs):
        # pylint: disable=no-member
        decoded = json.loads(data)
        rebuilder_id = decoded.get('rebuilder_id')
        if rebuilder_id != self.rebuilder_id:
            raise ExplicitBury('Wrong rebuilder ID: %s (expected=%s)'
                               % (rebuilder_id, self.rebuilder_id))
        beanstalkd_addr = decoded['beanstalkd']
        chunk = (decoded['cid'], decoded['content_id'],
                 decoded['chunk_id_or_pos'], None)
        bytes_processed = decoded.get('bytes_processed', None)
        error = decoded.get('error', None)
        yield beanstalkd_addr, chunk, bytes_processed, error


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
        self.sender = None

    def _rebuild_one(self, chunk, **kwargs):
        container_id, content_id, chunk_id_or_pos, _ = chunk
        if self.dry_run:
            self.dryrun_chunk_rebuild(container_id, content_id,
                                      chunk_id_or_pos, **kwargs)
            return 0
        else:
            try:
                return self.chunk_rebuild(container_id, content_id,
                                          chunk_id_or_pos, **kwargs)
            except OioException as exc:
                _, _, _, more = chunk
                # Schedule a retry only if the sender did not set reply address
                # (rebuild CLIs set reply address, meta2 does not).
                if not isinstance(exc, OrphanChunk) \
                        and not more.get('reply', None):
                    raise RetryLater(
                        chunk, 'Cannot rebuild chunk %s: %s' % (
                            self.rebuilder._item_to_string(chunk, **kwargs),
                            exc))
                raise

    def update_processed(self, chunk, bytes_processed, error=None, **kwargs):
        container_id, content_id, chunk_id_or_pos, more = chunk
        if more is not None:
            reply = more.get('reply', None)
            if reply is not None:
                event = {'rebuilder_id': reply['rebuilder_id'],
                         'beanstalkd': self.rebuilder.beanstalkd_listener.addr,
                         'cid': container_id, 'content_id': content_id,
                         'chunk_id_or_pos': chunk_id_or_pos}
                if error is not None:
                    event['error'] = error
                if bytes_processed is not None:
                    event['bytes_processed'] = bytes_processed
                try:
                    if self.sender is None:
                        self.sender = BeanstalkdSender(
                            reply['addr'], reply['tube'], self.logger,
                            **kwargs)
                    elif self.sender.addr != reply['addr'] \
                            or self.sender.addr != reply['tube']:
                        self.sender.close()
                        self.sender = BeanstalkdSender(
                            reply['addr'], reply['tube'], self.logger,
                            **kwargs)

                    self.sender.send_job(json.dumps(event))
                except BeanstalkError as exc:
                    self.logger.warn(
                        'reply failed %s: %s',
                        self.rebuilder._item_to_string(chunk, **kwargs), exc)

        super(BlobRebuilderWorker, self).update_processed(
            chunk, bytes_processed, error=error, **kwargs)

    def dryrun_chunk_rebuild(self, container_id, content_id, chunk_id_or_pos,
                             **kwargs):
        self.logger.info("[dryrun] Rebuilding "
                         "container %s, content %s, chunk %s",
                         container_id, content_id, chunk_id_or_pos)

    def chunk_rebuild(self, container_id, content_id, chunk_id_or_pos,
                      **kwargs):
        """
        Try to find the chunk in the metadata of the specified object,
        then rebuild it.
        """
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
                content.blob_client.chunk_delete(chunk.url, **kwargs)
                self.logger.info("Chunk %s deleted", chunk.url)
            except NotFound as exc:
                self.logger.debug("Chunk %s: %s", chunk.url, exc)

        # This call does not raise exception if chunk is not referenced
        if chunk_id is not None:
            self.rdir_client.chunk_delete(chunk.host, container_id,
                                          content_id, chunk_id, **kwargs)

        return chunk_size
