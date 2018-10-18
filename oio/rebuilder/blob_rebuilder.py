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

from oio.api.base import HttpApi
from oio.common.json import json
from oio.common.green import threading
from oio.common.easy_value import int_value, true_value
from oio.common.exceptions import ContentNotFound, NotFound, OrphanChunk, \
    ConfigurationException, OioTimeout, ExplicitBury
from oio.content.factory import ContentFactory
from oio.event.beanstalk import Beanstalk, BeanstalkError, ConnectionError, \
    ResponseError
from oio.rdir.client import RdirClient
from oio.rebuilder.rebuilder import Rebuilder, RebuilderWorker


DEFAULT_REBUILDER_TUBE = 'oio-rebuild'
DEFAULT_IMPROVER_TUBE = 'oio-improve'
DISTRIBUTED_REBUILDER_TIMEOUT = 300


class BlobRebuilder(Rebuilder):

    def __init__(self, conf, logger, volume, try_chunk_delete=False,
                 beanstalkd_addr=None, **kwargs):
        super(BlobRebuilder, self).__init__(conf, logger, volume, **kwargs)
        self.http = HttpApi(**kwargs)
        # rdir
        self.rdir_client = RdirClient(conf, logger=self.logger)
        self.rdir_fetch_limit = int_value(conf.get('rdir_fetch_limit'), 100)
        # rawx
        self.try_chunk_delete = try_chunk_delete
        # beanstalk
        self.beanstalkd_addr = beanstalkd_addr
        self.beanstalkd_tube = conf.get('beanstalkd_tube',
                                        DEFAULT_REBUILDER_TUBE)
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

    def _rebuilder_pass(self, **kwargs):
        return super(BlobRebuilder, self).rebuilder_pass(**kwargs)

    def rebuilder_pass(self, **kwargs):
        success = False
        if self.volume:
            self.rdir_client.admin_lock(self.volume,
                                        "rebuilder on %s" % gethostname())
            info = self.rdir_client.status(self.volume)
            self.total_expected_chunks = info.get(
                    'chunk', dict()).get('to_rebuild', None)
        try:
            success = self._rebuilder_pass(**kwargs)
        finally:
            if self.volume:
                self.rdir_client.admin_unlock(self.volume)
        return success

    def _event_from_broken_chunk(self, chunk, reply, **kwargs):
        cid, content_id, chunk_id_or_pos, _ = chunk
        event = {}
        event['when'] = time.time()
        event['event'] = 'storage.content.broken'
        event['data'] = {'missing_chunks': [chunk_id_or_pos]}
        event['url'] = {'ns': self.namespace,
                        'id': cid, 'content': content_id}
        event['reply'] = reply
        return json.dumps(event)

    def _chunks_from_event(self, job_id, data, **kwargs):
        decoded = json.loads(data)
        container_id = decoded['url']['id']
        content_id = decoded['url']['content']
        more = None
        reply = decoded.get('reply', None)
        if reply:
            more = {'reply': reply}
        for chunk_id_or_pos in decoded['data']['missing_chunks']:
            yield [container_id, content_id,
                   str(chunk_id_or_pos), more]

    def _fetch_events_from_beanstalk(self, **kwargs):
        beanstalkd = BeanstalkdListener(
            self.beanstalkd_addr, self.beanstalkd_tube, self.logger, **kwargs)
        return beanstalkd.fetch_events(self._chunks_from_event, **kwargs)

    def _fetch_chunks_from_file(self, **kwargs):
        with open(self.input_file, 'r') as ifile:
            for line in ifile:
                stripped = line.strip()
                if stripped and not stripped.startswith('#'):
                    yield stripped.split('|', 3)[:3] + [None]

    def _fetch_chunks(self, **kwargs):
        if self.input_file:
            return self._fetch_chunks_from_file(**kwargs)
        if self.beanstalkd_addr and not self.distributed:
            return self._fetch_events_from_beanstalk(**kwargs)
        if self.volume:
            return self.rdir_client.chunk_fetch(
                self.volume, limit=self.rdir_fetch_limit, rebuild=True,
                **kwargs)
        raise ConfigurationException('No source to fetch chunks from')


class DistributedBlobRebuilder(BlobRebuilder):

    def __init__(self, conf, logger, volume, distributed_addr, **kwargs):
        super(DistributedBlobRebuilder, self).__init__(
            conf, logger, volume, **kwargs)
        self.distributed = True
        self.distributed_addr = distributed_addr
        self.distributed_tube = conf.get('distributed_tube',
                                         DEFAULT_REBUILDER_TUBE)
        self.sending = False
        self.rebuilder_id = str(uuid.uuid4())

        if not self.beanstalkd_addr:
            raise ConfigurationException(
                "No beanstalkd to fetch responses from")
        if self.beanstalkd_tube == self.distributed_tube:
            raise ConfigurationException(
                "The beanstalkd tubes must be different")

    def _rebuilder_pass(self, **kwargs):
        self.start_time = self.last_report = time.time()
        self.log_report('START', force=True)

        listener = BeanstalkdListener(
            self.beanstalkd_addr, self.beanstalkd_tube, self.logger, **kwargs)
        senders = dict()
        for distributed_addr in self.distributed_addr.split(';'):
            senders[distributed_addr] = BeanstalkdSender(
                distributed_addr, self.distributed_tube, self.logger, **kwargs)

        reply = {'addr': self.beanstalkd_addr, 'tube': self.beanstalkd_tube,
                 'rebuilder_id': self.rebuilder_id}
        thread = threading.Thread(target=self._distribute_broken_chunks,
                                  args=(senders, reply), kwargs=kwargs)
        thread.start()

        def is_finish():
            total_events = 0
            for _, sender in senders.iteritems():
                total_events += sender.nb_events
            return total_events <= 0

        while thread.is_alive():
            if self.sending:
                break
            else:
                time.sleep(0.1)

        while thread.is_alive() or not is_finish():
            try:
                event_info = listener.fetch_event(
                    self._rebuilt_chunk_from_event,
                    timeout=DISTRIBUTED_REBUILDER_TIMEOUT, **kwargs)
                for beanstalkd_addr, chunk, bytes_processed, error \
                        in event_info:
                    senders[beanstalkd_addr].event_done()
                    self.update_processed(
                        chunk, bytes_processed, error=error, **kwargs)
            except OioTimeout:
                self.logger.error("No response since %d secondes",
                                  DISTRIBUTED_REBUILDER_TIMEOUT)
                self.log_report('DONE', force=True)
                return False

        self.log_report('DONE', force=True)
        return self.total_errors == 0

    def _distribute_broken_chunks(self, senders, reply, **kwargs):
        index = 0
        senders = senders.values()
        n = len(senders)

        def _send_broken_chunk(broken_chunk, index):
            event = self._event_from_broken_chunk(
                broken_chunk, reply, **kwargs)
            # Send the event with a non-full sender
            while True:
                for _ in range(n):
                    success = senders[index].send_event(
                        event, **kwargs)
                    index = (index + 1) % n
                    if success:
                        return index
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
            return self.chunk_rebuild(container_id, content_id,
                                      chunk_id_or_pos, **kwargs)

    def update_processed(self, chunk, bytes_processed, error=None, **kwargs):
        container_id, content_id, chunk_id_or_pos, more = chunk
        if more is not None:
            reply = more.get('reply', None)
            if reply is not None:
                event = {'rebuilder_id': reply['rebuilder_id'],
                         'beanstalkd': self.rebuilder.beanstalkd_addr,
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

                    self.sender.send_event(json.dumps(event))
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


class Beanstalkd(object):

    def __init__(self, addr, tube, logger, **kwargs):
        if addr is not None and addr.startswith('beanstalk://'):
            addr = addr[12:]
        self.addr = addr
        self.tube = tube
        self.logger = logger
        self.beanstalkd = None
        self.connected = False
        self._connect()
        # Check the connection
        self.beanstalkd.stats_tube(self.tube)

    def _connect(self, **kwargs):
        self.close()
        self.beanstalkd = Beanstalk.from_url('beanstalk://' + self.addr)
        self.beanstalkd.use(self.tube)
        self.beanstalkd.watch(self.tube)
        self.connected = True

    def close(self):
        if self.connected:
            try:
                self.beanstalkd.close()
            except BeanstalkError:
                pass
            self.connected = False


class BeanstalkdListener(Beanstalkd):

    def fetch_event(self, on_event, timeout=None, **kwargs):
        job_id = None
        try:
            if not self.connected:
                self.logger.debug('Connecting to %s using tube %s',
                                  self.addr, self.tube)
                self._connect(**kwargs)
            job_id, data = self.beanstalkd.reserve(timeout=timeout)
            for event_info in on_event(job_id, data, **kwargs):
                yield event_info
            self.beanstalkd.delete(job_id)
            return
        except ConnectionError as exc:
            self.connected = False
            self.logger.warn(
                'Disconnected from %s using tube %s (job=%s): %s',
                self.addr, self.tube, job_id, exc)
            if 'Invalid URL' in str(exc):
                raise
            time.sleep(1.0)
        except ExplicitBury as exc:
            self.logger.warn("Job bury on %s using tube %s (job=%s): %s",
                             self.addr, self.tube, job_id, exc)
        except BeanstalkError as exc:
            if isinstance(exc, ResponseError) and 'TIMED_OUT' in str(exc):
                raise OioTimeout()

            self.logger.exception("ERROR on %s using tube %s (job=%s)",
                                  self.addr, self.tube, job_id)
        except Exception:
            self.logger.exception("ERROR on %s using tube %s (job=%s)",
                                  self.addr, self.tube, job_id)
        if job_id:
            try:
                self.beanstalkd.bury(job_id)
            except BeanstalkError as exc:
                self.logger.error("Could not bury job %s: %s", job_id, exc)

    def fetch_events(self, on_event, **kwargs):
        while True:
            for event_info in self.fetch_event(on_event, **kwargs):
                yield event_info


class BeanstalkdSender(Beanstalkd):

    def __init__(self, addr, tube, logger,
                 threshold=512, limit=1024, **kwargs):
        super(BeanstalkdSender, self).__init__(addr, tube, logger)
        self.threshold = threshold
        self.limit = limit
        self.fill = True
        self.nb_events = 0
        self.lock_nb_events = threading.Lock()

    def send_event(self, event, **kwargs):
        if self.nb_events <= self.threshold:
            self.fill = True
        elif not self.fill or self.nb_events > self.limit:
            return False

        job_id = None
        try:
            if not self.connected:
                self.logger.debug('Connecting to %s using tube %s',
                                  self.addr, self.tube)
                self._connect(**kwargs)

            with self.lock_nb_events:
                job_id = self.beanstalkd.put(event)
                self.nb_events += 1
                if self.nb_events == self.limit:
                    self.fill = False
            return True
        except ConnectionError as exc:
            self.connected = False
            self.logger.warn(
                'Disconnected from %s using tube %s (job=%s): %s',
                self.addr, self.tube, job_id, exc)
            if 'Invalid URL' in str(exc):
                raise
        except Exception:
            self.logger.exception("ERROR on %s using tube %s (job=%s)",
                                  self.addr, self.tube, job_id)
        return False

    def event_done(self):
        with self.lock_nb_events:
            self.nb_events -= 1
