# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
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


from datetime import datetime
from socket import gethostname

from oio.blob.operator import ChunkOperator
from oio.common.easy_value import int_value, true_value
from oio.common.green import time
from oio.common.tool import Tool, ToolWorker
from oio.event.evob import EventTypes
from oio.rdir.client import RdirClient


class BlobRebuilder(Tool):
    """
    Rebuild chunks.
    """

    DEFAULT_BEANSTALKD_WORKER_TUBE = 'oio-rebuild'
    DEFAULT_DISTRIBUTED_BEANSTALKD_WORKER_TUBE = 'oio-rebuild'
    DEFAULT_RDIR_FETCH_LIMIT = 100
    DEFAULT_ALLOW_SAME_RAWX = True
    DEFAULT_TRY_CHUNK_DELETE = False
    DEFAULT_DRY_RUN = False

    def __init__(self, conf,
                 input_file=None, rawx_id=None, **kwargs):
        super(BlobRebuilder, self).__init__(conf, **kwargs)

        # counters
        self.bytes_processed = 0
        self.total_bytes_processed = 0

        # input
        self.input_file = input_file
        self.rawx_id = rawx_id

        # rawx/rdir
        self.rdir_client = RdirClient(self.conf, logger=self.logger)
        self.rdir_fetch_limit = int_value(
            self.conf.get('rdir_fetch_limit'), self.DEFAULT_RDIR_FETCH_LIMIT)

    @staticmethod
    def items_from_task_event(task_event):
        namespace = task_event['url']['ns']
        container_id = task_event['url']['id']
        content_id = task_event['url']['content']
        for chunk_id_or_pos in task_event['data']['missing_chunks']:
            yield namespace, container_id, content_id, str(chunk_id_or_pos)

    @staticmethod
    def task_event_from_item(item):
        namespace, container_id, content_id, chunk_id_or_pos = item
        return \
            {
                'when': time.time(),
                'event': EventTypes.CONTENT_BROKEN,
                'url': {
                    'ns': namespace,
                    'id': container_id,
                    'content': content_id
                },
                'data': {
                    'missing_chunks': [
                        chunk_id_or_pos
                    ]
                }
            }

    @staticmethod
    def tasks_res_from_res_event(res_event):
        namespace = res_event['url']['ns']
        container_id = res_event['url']['id']
        content_id = res_event['url']['content']
        for chunk_rebuilt in res_event['data']['chunks_rebuilt']:
            yield (namespace, container_id, content_id,
                   str(chunk_rebuilt['chunk_id_or_pos'])), \
                chunk_rebuilt['bytes_processed'], chunk_rebuilt['error']

    @staticmethod
    def res_event_from_task_res(task_res):
        item, bytes_processed, error = task_res
        namespace, container_id, content_id, chunk_id_or_pos = item
        return \
            {
                'when': time.time(),
                'event': EventTypes.CONTENT_REBUILT,
                'url': {
                    'ns': namespace,
                    'id': container_id,
                    'content': content_id
                },
                'data': {
                    'chunks_rebuilt': [{
                        'chunk_id_or_pos': chunk_id_or_pos,
                        'bytes_processed': bytes_processed,
                        'error': error
                    }]
                }
            }

    @staticmethod
    def string_from_item(item):
        namespace, container_id, content_id, chunk_id_or_pos = item
        return '%s|%s|%s|%s' % (
            namespace, container_id, content_id, chunk_id_or_pos)

    def _fetch_items_from_input_file(self):
        with open(self.input_file, 'r') as ifile:
            for line in ifile:
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue

                container_id, content_id, chunk_id_or_pos = \
                    stripped.split('|', 3)[:3]
                yield self.namespace, container_id, content_id, \
                    chunk_id_or_pos

    def _fetch_items_from_rawx_id(self):
        lost_chunks = self.rdir_client.chunk_fetch(
            self.rawx_id, limit=self.rdir_fetch_limit, rebuild=True)
        for container_id, content_id, chunk_id, _ in lost_chunks:
            yield self.namespace, container_id, content_id, chunk_id

    def _fetch_items(self):
        if self.input_file:
            return self._fetch_items_from_input_file()
        if self.rawx_id:
            return self._fetch_items_from_rawx_id()

        def _empty_generator():
            return
            yield  # pylint: disable=unreachable
        return _empty_generator()

    def update_counters(self, task_res):
        super(BlobRebuilder, self).update_counters(task_res)
        _, bytes_processed, _ = task_res
        if bytes_processed is not None:
            self.bytes_processed += bytes_processed

    def _update_total_counters(self):
        chunks_processed, total_chunks_processed, errors, total_errors = \
            super(BlobRebuilder, self)._update_total_counters()
        bytes_processed = self.bytes_processed
        self.bytes_processed = 0
        self.total_bytes_processed += bytes_processed
        return chunks_processed, total_chunks_processed, \
            bytes_processed, self.total_bytes_processed, \
            errors, total_errors

    def _get_report(self, status, end_time, counters):
        chunks_processed, total_chunks_processed, \
            bytes_processed, total_bytes_processed, \
            errors, total_errors = counters
        time_since_last_report = (end_time - self.last_report) or 0.00001
        total_time = (end_time - self.start_time) or 0.00001
        report = (
            '%(status)s '
            'last_report=%(last_report)s %(time_since_last_report).2fs '
            'chunks=%(chunks)d %(chunks_rate).2f/s '
            'bytes=%(bytes)d %(bytes_rate).2fB/s '
            'errors=%(errors)d %(errors_rate).2f%% '
            'start_time=%(start_time)s %(total_time).2fs '
            'total_chunks=%(total_chunks)d %(total_chunks_rate).2f/s '
            'total_bytes=%(total_bytes)d %(total_bytes_rate).2fB/s '
            'total_errors=%(total_errors)d %(total_errors_rate).2f%%' % {
                'status': status,
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
        if self.total_expected_items is not None:
            progress = 100 * total_chunks_processed / \
                float(self.total_expected_items or 1)
            report += ' progress=%d/%d %.2f%%' % \
                (total_chunks_processed, self.total_expected_items, progress)
        return report

    def create_worker(self, queue_workers, queue_reply):
        return BlobRebuilderWorker(self, queue_workers, queue_reply)

    def _load_total_expected_items(self):
        if self.rawx_id:
            info = self.rdir_client.status(
                self.rawx_id,
                read_timeout=600)  # FIXME(adu): Reduce the timeout
            self.total_expected_items = info.get(
                'chunk', dict()).get('to_rebuild', None)

    def run(self):
        if self.rawx_id:
            self.rdir_client.admin_lock(
                self.rawx_id, "rebuilder on %s" % gethostname())
        success = super(BlobRebuilder, self).run()
        if self.rawx_id:
            self.rdir_client.admin_unlock(self.rawx_id)
        return success


class BlobRebuilderWorker(ToolWorker):

    def __init__(self, tool, queue_workers, queue_reply):
        super(BlobRebuilderWorker, self).__init__(
            tool, queue_workers, queue_reply)

        self.allow_same_rawx = true_value(self.tool.conf.get(
            'allow_same_rawx', self.tool.DEFAULT_ALLOW_SAME_RAWX))
        self.try_chunk_delete = true_value(self.tool.conf.get(
            'try_chunk_delete', self.tool.DEFAULT_TRY_CHUNK_DELETE))
        self.dry_run = true_value(self.tool.conf.get(
            'dry_run', self.tool.DEFAULT_DRY_RUN))

        self.chunk_operator = ChunkOperator(self.conf, logger=self.logger)

    def _process_item(self, item):
        namespace, container_id, content_id, chunk_id_or_pos = item
        if namespace != self.tool.namespace:
            raise ValueError('Invalid namespace (actual=%s, expected=%s)' % (
                namespace, self.tool.namespace))

        log_rebuilding = 'Rebuilding %s' % self.tool.string_from_item(item)
        if self.dry_run:
            self.logger.debug('[dryrun] %s', log_rebuilding)
            return None

        self.logger.debug(log_rebuilding)
        return self.chunk_operator.rebuild(
            container_id, content_id, chunk_id_or_pos,
            rawx_id=self.tool.rawx_id, try_chunk_delete=self.try_chunk_delete,
            allow_same_rawx=self.allow_same_rawx)
