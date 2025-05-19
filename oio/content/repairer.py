# Copyright (C) 2019-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2025 OVH SAS
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

from collections import defaultdict
from datetime import datetime

from oio.api.object_storage import _sort_chunks
from oio.blob.client import BlobClient
from oio.blob.operator import ChunkOperator
from oio.common.exceptions import (
    ClientPreconditionFailed,
    NotFound,
    OioNetworkException,
    ServiceBusy,
)
from oio.common.storage_method import STORAGE_METHODS
from oio.common.tool import Tool, ToolWorker
from oio.common.utils import cid_from_name, request_id
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
        return "|".join((namespace, account, container, obj_name, str(version)))

    def _fetch_items_from_objects(self):
        for obj in self.objects:
            namespace = obj["namespace"]
            account = obj["account"]
            container = obj["container"]
            obj_name = obj["name"]
            version = obj["version"]
            yield namespace, account, container, obj_name, version

    def _fetch_items(self):
        if self.objects:
            return self._fetch_items_from_objects()

        def _empty_generator():
            return
            yield  # pylint: disable=unreachable

        return _empty_generator()

    def _get_report(self, status, end_time, counters):
        objects_processed, total_objects_processed, errors, total_errors = counters
        time_since_last_report = (end_time - self.last_report) or 0.00001
        total_time = (end_time - self.start_time) or 0.00001
        report = (
            "%(status)s "
            "last_report=%(last_report)s %(time_since_last_report).2fs "
            "objects=%(objects)d %(objects_rate).2f/s "
            "errors=%(errors)d %(errors_rate).2f%% "
            "start_time=%(start_time)s %(total_time).2fs "
            "total_objects=%(total_objects)d %(total_objects_rate).2f/s "
            "total_errors=%(total_errors)d %(total_errors_rate).2f%%"
            % {
                "status": status,
                "last_report": datetime.fromtimestamp(
                    int(self.last_report)
                ).isoformat(),
                "time_since_last_report": time_since_last_report,
                "objects": objects_processed,
                "objects_rate": objects_processed / time_since_last_report,
                "errors": errors,
                "errors_rate": 100 * errors / float(objects_processed or 1),
                "start_time": datetime.fromtimestamp(int(self.start_time)).isoformat(),
                "total_time": total_time,
                "total_objects": total_objects_processed,
                "total_objects_rate": total_objects_processed / total_time,
                "total_errors": total_errors,
                "total_errors_rate": 100
                * total_errors
                / float(total_objects_processed or 1),
            }
        )
        if self.total_expected_items is not None:
            progress = (
                100 * total_objects_processed / float(self.total_expected_items or 1)
            )
            report += " progress=%d/%d %.2f%%" % (
                total_objects_processed,
                self.total_expected_items,
                progress,
            )
        return report

    def create_worker(self, queue_workers, queue_reply):
        return ContentRepairerWorker(self, queue_workers, queue_reply)

    def _load_total_expected_items(self):
        if self.objects and isinstance(self.objects, list):
            self.total_expected_items = len(self.objects)


class ContentRepairerWorker(ToolWorker):
    def __init__(self, tool, queue_workers, queue_reply):
        super(ContentRepairerWorker, self).__init__(tool, queue_workers, queue_reply)

        self.chunk_operator = ChunkOperator(
            self.conf, logger=self.logger, watchdog=self.tool.watchdog
        )
        self.blob_client = BlobClient(
            self.conf, logger=self.logger, watchdog=self.tool.watchdog
        )
        self.container_client = ContainerClient(self.conf, logger=self.logger)

        self.read_all_available_sources = self.conf.get(
            "read_all_available_sources", False
        )
        self.rebuild_on_network_error = self.conf.get("rebuild_on_network_error", False)

    def _safe_chunk_rebuild(
        self, item, content_id, chunk_id_or_pos, path, version, **kwargs
    ):
        _, account, container, _, _ = item
        try:
            container_id = cid_from_name(account, container)
            self.chunk_operator.rebuild(
                container_id=container_id,
                content_id=content_id,
                chunk_id_or_pos=chunk_id_or_pos,
                path=path,
                version=version,
                read_all_available_sources=self.read_all_available_sources,
                **kwargs,
            )
        except Exception as exc:  # pylint: disable=broad-except
            self.logger.error(
                "Error when rebuilding chunk %s (%s): %s",
                self.tool.string_from_item(item),
                chunk_id_or_pos,
                exc,
            )
            return exc

    def _rebuild_missing_positions(
        self,
        item,
        content_id,
        stg_met,
        metachunk_pos,
        chunks,
        path,
        version,
        reqid=None,
    ):
        exceptions = []
        required = stg_met.expected_chunks
        if len(chunks) >= required:
            return exceptions  # Nothing to do

        if stg_met.ec:
            subs = {x["num"] for x in chunks}
            for sub in range(required):
                if sub not in subs:
                    pos = f"{metachunk_pos}.{sub}"
                    exc = self._safe_chunk_rebuild(
                        item=item,
                        content_id=content_id,
                        chunk_id_or_pos=pos,
                        path=path,
                        version=version,
                        reqid=reqid,
                    )
                    if exc:
                        exceptions.append((pos, exc))
        else:
            pos = str(metachunk_pos)
            missing_chunks = required - len(chunks)
            for _ in range(missing_chunks):
                exc = self._safe_chunk_rebuild(
                    item=item,
                    content_id=content_id,
                    chunk_id_or_pos=pos,
                    path=path,
                    version=version,
                    reqid=reqid,
                )
                if exc:
                    exceptions.append((pos, exc))
        return exceptions

    def _remove_and_unref_chunk(
        self,
        item,
        content_id,
        chunk,
        path,
        version,
        reqid=None,
    ):
        _ns, account, container, _, _ = item
        payload = [
            {
                "type": "chunk",
                "id": chunk["url"],
                "hash": chunk["hash"],
                "size": chunk["size"],
                "content": content_id,
                "pos": chunk["pos"],
            }
        ]
        try:
            self.logger.info(
                "Unreferencing %s from %s/%s/%s (reqid=%s)",
                chunk["url"],
                account,
                container,
                path,
                reqid,
            )
            self.container_client.container_raw_delete(
                account,
                container,
                path=path,
                version=version,
                data=payload,
                reqid=reqid,
            )
            self.logger.info("Deleting %s (reqid=%s)", chunk["url"], reqid)
            self.blob_client.chunk_delete(chunk["url"], reqid=reqid)
        except NotFound as err:
            self.logger.debug(
                "Got an error during removal of %s: %s", chunk["url"], err
            )
        except Exception as err:
            self.logger.warning(
                "Failed to delete or unreference %s: %s", chunk["url"], err
            )
            return err
        return None

    def _remove_duplicate_positions(
        self,
        item,
        content_id,
        stg_met,
        metachunk_pos,
        chunks,
        path,
        version,
        reqid=None,
    ):
        """
        Try to remove duplicate chunks at the same position.
        """
        exceptions = []
        required = stg_met.expected_chunks
        if len(chunks) <= required:
            return exceptions  # Nothing to do

        if stg_met.ec:
            by_subpos = defaultdict(list)
            for chunk in chunks:
                by_subpos[chunk["num"]].append(chunk)
            to_delete = []
            for sub, dups in by_subpos.items():
                if len(dups) <= 1:
                    continue
                self.logger.warning(
                    "%d chunks at position %s.%s, expected 1",
                    len(dups),
                    metachunk_pos,
                    sub,
                )
                can_be_kept = [x for x in dups if x.get("is_valid")]
                del_first = [x for x in dups if not x.get("is_valid")]
                if not can_be_kept:
                    self.logger.warning(
                        "No valid chunk at position %s.%s, %d chunks referenced",
                        metachunk_pos,
                        sub,
                        len(dups),
                    )
                elif not del_first:
                    # Chunks are supposed to be sorted by score (decreasing)
                    to_delete.extend(can_be_kept[1:])
                else:
                    # del_first can be shorter than the number of chunks
                    # in excess and we may need a 2nd pass.
                    to_delete.extend(del_first)

        else:  # replication
            # Chunks are supposed to be sorted by score (decreasing)
            to_delete = chunks[required:]

        for chunk in to_delete:
            exc = self._remove_and_unref_chunk(
                item, content_id, chunk, path, version, reqid=reqid
            )
            if exc:
                exceptions.append((chunk["url"], exc))

    def _repair_metachunk(
        self,
        item,
        content_id,
        stg_met,
        metachunk_pos,
        chunks,
        path,
        version,
        reqid=None,
    ):
        """
        Check that a metachunk has the right number of chunks.

        :returns: the list (generator) of missing chunks
        """
        exceptions = self._rebuild_missing_positions(
            item,
            content_id,
            stg_met,
            metachunk_pos,
            chunks,
            path,
            version,
            reqid,
        )

        for chunk in chunks:
            try:
                _chunk_meta = self.blob_client.chunk_head(
                    chunk["url"],
                    xattr=True,
                    verify_checksum=True,
                    reqid=reqid,
                )
                chunk["is_valid"] = True
            except (
                NotFound,
                ClientPreconditionFailed,
                ServiceBusy,  # I/O error
                OioNetworkException,
            ) as exc:
                if (
                    isinstance(exc, OioNetworkException)
                    and not self.rebuild_on_network_error
                ):
                    exceptions.append((chunk["url"], exc))
                    continue
                exc = self._safe_chunk_rebuild(
                    item=item,
                    content_id=content_id,
                    chunk_id_or_pos=chunk["url"],
                    path=path,
                    version=version,
                    try_chunk_delete=isinstance(exc, ClientPreconditionFailed),
                    reqid=reqid,
                )
                if exc:
                    exceptions.append((chunk["url"], exc))
            except Exception as exc:  # pylint: disable=broad-except
                self.logger.error(
                    "Error when checking chunk %s (%s): %s",
                    self.tool.string_from_item(item),
                    chunk["url"],
                    exc,
                )
                exceptions.append((chunk["url"], exc))

        dup_exc = self._remove_duplicate_positions(
            item,
            content_id,
            stg_met,
            metachunk_pos,
            chunks,
            path,
            version,
            reqid=reqid,
        )
        if dup_exc:
            exceptions.extend(dup_exc)

        return exceptions

    def _process_item(self, item):
        reqid = request_id("objrepair-")
        namespace, account, container, obj_name, version = item
        if namespace != self.tool.namespace:
            raise ValueError(
                "Invalid namespace "
                f"(actual={namespace}, expected={self.tool.namespace})"
            )

        obj_meta, chunks = self.container_client.content_locate(
            account=account,
            reference=container,
            path=obj_name,
            version=version,
            properties=False,
            reqid=reqid,
        )
        content_id = obj_meta["id"]
        if version is None:
            version = obj_meta["version"]
            item = (namespace, account, container, obj_name, version)

        exceptions = []
        stg_met = STORAGE_METHODS.load(obj_meta["chunk_method"])
        chunks_by_pos = _sort_chunks(chunks, stg_met.ec, keep_duplicates=True)
        for pos, chunks in chunks_by_pos.items():
            try:
                exceptions += self._repair_metachunk(
                    item=item,
                    content_id=content_id,
                    stg_met=stg_met,
                    metachunk_pos=pos,
                    chunks=chunks,
                    path=obj_name,
                    version=version,
                    reqid=reqid,
                )
            except Exception as exc:  # pylint: disable=broad-except
                self.logger.error(
                    "Error when repairing metachunk %s (%d): %s (reqid=%s)",
                    self.tool.string_from_item(item),
                    pos,
                    exc,
                    reqid,
                )
                exceptions.append(exc)

        if exceptions:
            raise Exception(exceptions)

        self.container_client.content_touch(
            account=account,
            reference=container,
            path=obj_name,
            version=version,
            reqid=reqid,
        )
