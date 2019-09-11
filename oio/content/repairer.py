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
from six import iteritems

from oio.api.object_storage import _sort_chunks
from oio.blob.operator import ChunkOperator
from oio.blob.client import BlobClient
from oio.common.exceptions import NotFound, ClientPreconditionFailed
from oio.common.storage_method import STORAGE_METHODS
from oio.common.tool import Tool, ToolWorker
from oio.common.utils import cid_from_name
from oio.container.client import ContainerClient


class ContentRepairer(Tool):
    """
    Repair objects.
    """

    def __init__(self, conf, objects=None, **kwargs):
        super(ContentRepairer, self).__init__(conf, **kwargs)

        # input
        self.objects = objects

    @staticmethod
    def string_from_item(item):
        namespace, account, container, obj_name, version = item
        return '%s|%s|%s|%s|%s' % (
            namespace, account, container, obj_name, version)

    def _fetch_items_from_objects(self):
        for obj in self.objects:
            namespace = obj['namespace']
            account = obj['account']
            container = obj['container']
            obj_name = obj['name']
            version = obj['version']
            yield namespace, account, container, obj_name, version

    def _fetch_items(self):
        if self.objects:
            return self._fetch_items_from_objects()

        def _empty_generator():
            return
            yield  # pylint: disable=unreachable
        return _empty_generator()

    def _get_report(self, status, end_time, counters):
        objects_processed, total_objects_processed, \
            errors, total_errors = counters
        time_since_last_report = (end_time - self.last_report) or 0.00001
        total_time = (end_time - self.start_time) or 0.00001
        report = (
            '%(status)s '
            'last_report=%(last_report)s %(time_since_last_report).2fs '
            'objects=%(objects)d %(objects_rate).2f/s '
            'errors=%(errors)d %(errors_rate).2f%% '
            'start_time=%(start_time)s %(total_time).2fs '
            'total_objects=%(total_objects)d %(total_objects_rate).2f/s '
            'total_errors=%(total_errors)d %(total_errors_rate).2f%%' % {
                'status': status,
                'last_report': datetime.fromtimestamp(
                    int(self.last_report)).isoformat(),
                'time_since_last_report': time_since_last_report,
                'objects': objects_processed,
                'objects_rate': objects_processed / time_since_last_report,
                'errors': errors,
                'errors_rate': 100 * errors / float(objects_processed or 1),
                'start_time': datetime.fromtimestamp(
                    int(self.start_time)).isoformat(),
                'total_time': total_time,
                'total_objects': total_objects_processed,
                'total_objects_rate': total_objects_processed / total_time,
                'total_errors': total_errors,
                'total_errors_rate':
                    100 * total_errors / float(total_objects_processed or 1)
                })
        if self.total_expected_items is not None:
            progress = 100 * total_objects_processed / \
                float(self.total_expected_items or 1)
            report += ' progress=%d/%d %.2f%%' % \
                (total_objects_processed, self.total_expected_items, progress)
        return report

    def create_worker(self, queue_workers, queue_reply):
        return ContentRepairerWorker(self, queue_workers, queue_reply)

    def _load_total_expected_items(self):
        if self.objects and isinstance(self.objects, list):
            self.total_expected_items = len(self.objects)


class ContentRepairerWorker(ToolWorker):

    def __init__(self, tool, queue_workers, queue_reply):
        super(ContentRepairerWorker, self).__init__(
            tool, queue_workers, queue_reply)

        self.chunk_operator = ChunkOperator(self.conf, logger=self.logger)
        self.blob_client = BlobClient(self.conf)
        self.container_client = ContainerClient(self.conf, logger=self.logger)

    def _safe_chunk_rebuild(self, item, content_id, chunk_id_or_pos, **kwargs):
        _, account, container, _, _ = item
        try:
            container_id = cid_from_name(account, container)
            self.chunk_operator.rebuild(
                container_id, content_id, chunk_id_or_pos, **kwargs)
        except Exception as exc:  # pylint: disable=broad-except
            self.logger.error(
                'ERROR when rebuilding chunk %s (%s): %s',
                self.tool.string_from_item(item), chunk_id_or_pos, exc)
            return exc

    def _repair_metachunk(self, item, content_id, stg_met, pos, chunks):
        """
        Check that a metachunk has the right number of chunks.

        :returns: the list (generator) of missing chunks
        """
        exceptions = list()
        required = stg_met.expected_chunks
        if len(chunks) < required:
            if stg_met.ec:
                subs = {x['num'] for x in chunks}
                for sub in range(required):
                    if sub not in subs:
                        exc = self._safe_chunk_rebuild(
                            item, content_id, "%d.%d" % (pos, sub))
                        if exc:
                            exceptions.append(exc)
            else:
                missing_chunks = required - len(chunks)
                for _ in range(missing_chunks):
                    exc = self._safe_chunk_rebuild(
                        item, content_id, pos)
                    if exc:
                        exceptions.append(exc)

        for chunk in chunks:
            try:
                self.blob_client.chunk_head(
                    chunk['url'], xattr=True, check_hash=True)
            except (NotFound, ClientPreconditionFailed) as e:
                kwargs = {'try_chunk_delete':
                          isinstance(e, ClientPreconditionFailed)}
                exc = self._safe_chunk_rebuild(
                    item, content_id, chunk['url'], **kwargs)
                if exc:
                    exceptions.append(exc)
            except Exception as exc:  # pylint: disable=broad-except
                self.logger.error(
                    'ERROR when checking chunk %s (%s): %s',
                    self.tool.string_from_item(item), chunk['url'], exc)
                exceptions.append(exc)

        return exceptions

    def _process_item(self, item):
        namespace, account, container, obj_name, version = item
        if namespace != self.tool.namespace:
            raise ValueError('Invalid namespace (actual=%s, expected=%s)' % (
                namespace, self.tool.namespace))

        obj_meta, chunks = self.container_client.content_locate(
            account=account, reference=container,
            path=obj_name, version=version, properties=False)
        content_id = obj_meta['id']

        exceptions = list()
        stg_met = STORAGE_METHODS.load(obj_meta['chunk_method'])
        chunks_by_pos = _sort_chunks(chunks, stg_met.ec)
        for pos, chunks in iteritems(chunks_by_pos):
            try:
                exceptions += self._repair_metachunk(
                    item, content_id, stg_met, pos, chunks)
            except Exception as exc:  # pylint: disable=broad-except
                self.logger.error('ERROR when repair metachunk %s (%d): %s',
                                  self.tool.string_from_item(item), pos, exc)
                exceptions.append(exc)

        if exceptions:
            raise Exception(exceptions)

        self.container_client.content_touch(
            account=account, reference=container,
            path=obj_name, version=version)
