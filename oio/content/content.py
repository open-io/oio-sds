# Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2020-2024 OVH SAS
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

import json
import time

from oio.blob.client import BlobClient
from oio.common import exceptions as exc
from oio.common.decorators import ensure_request_id2
from oio.common.exceptions import (
    ObjectUnavailable,
    UnrecoverableContent,
)
from oio.common.fullpath import encode_fullpath
from oio.common.logger import get_logger
from oio.common.storage_functions import (
    RAWX_PERMANENT_ERRORS,
    _get_weighted_random_score,
)
from oio.common.storage_method import STORAGE_METHODS
from oio.container.client import ContainerClient
from oio.content.quality import ensure_better_chunk_qualities, pop_chunk_qualities
from oio.event.evob import EventTypes


def cmp(x, y):
    """cmp function as a workaround for python3"""
    return (x > y) - (x < y)


class Content(object):
    # FIXME: no need for container_id since we have account and container name
    def __init__(
        self,
        conf,
        container_id,
        metadata,
        chunks,
        storage_method,
        account,
        container_name,
        blob_client=None,
        container_client=None,
        logger=None,
    ):
        self.conf = conf
        self.container_id = container_id
        self.metadata = metadata
        self.extra_properties = metadata.get("extra_properties")
        self.chunks = ChunksHelper(chunks)
        self._storage_method = storage_method
        self.logger = logger or get_logger(self.conf)
        self.blob_client = blob_client or BlobClient(conf, logger=self.logger)
        self.container_client = container_client or ContainerClient(
            self.conf, logger=self.logger
        )

        # FIXME: all these may be properties
        self.content_id = self.metadata["id"]
        self.path = self.metadata["name"]
        self.length = int(self.metadata["length"])
        self.version = self.metadata["version"]
        self.checksum = self.metadata["hash"]
        self.chunk_method = self.metadata["chunk_method"]
        self.account = account
        self.container_name = container_name
        if "full_path" in self.metadata:
            self.full_path = metadata["full_path"]
        else:
            self.full_path = encode_fullpath(
                self.account,
                self.container_name,
                self.path,
                self.version,
                self.content_id,
            )

    @property
    def mime_type(self):
        return self.metadata["mime_type"]

    @mime_type.setter
    def mime_type(self, value):
        self.metadata["mime_type"] = value

    @property
    def policy(self):
        return self.metadata["policy"]

    @policy.setter
    def policy(self, value):
        self.metadata["policy"] = value

    @property
    def properties(self):
        return self.metadata.get("properties")

    @properties.setter
    def properties(self, value):
        if not isinstance(value, dict):
            raise ValueError("'value' must be a dict")
        self.metadata["properties"] = value

    @property
    def storage_method(self):
        """
        Get a StorageMethod object loaded from self.chunk_method
        """
        if not self._storage_method:
            self._storage_method = STORAGE_METHODS.load(self.chunk_method)
        return self._storage_method

    def _get_spare_chunk(
        self,
        chunks_notin,
        chunks_broken,
        position,
        max_attempts=3,
        check_quality=False,
        fake_excluded_chunks=None,
        force_fair_constraints=False,
        adjacent_mode=False,
        **kwargs,
    ):
        notin = ChunksHelper(chunks_notin, False).raw()
        broken = ChunksHelper(chunks_broken, False).raw()
        if fake_excluded_chunks:
            for fake_excluded_chunk in fake_excluded_chunks:
                chunk = fake_excluded_chunk.copy()
                chunk["hash"] = broken[0]["hash"]
                chunk["pos"] = broken[0]["pos"]
                chunk["size"] = broken[0]["size"]
                broken.append(chunk)
        spare_data = {
            "notin": notin,
            "broken": broken,
            "force_fair_constraints": force_fair_constraints,
            "adjacent_mode": adjacent_mode,
        }
        last_exc = None
        bal = 0
        for attempt in range(max_attempts):
            try:
                spare_resp = self.container_client.content_spare(
                    cid=self.container_id,
                    path=self.path,
                    version=self.version,
                    data=spare_data,
                    stgpol=self.policy,
                    position=position,
                    **kwargs,
                )
                # Transform list of properties into a dict
                properties = {
                    x["key"]: x["value"] for x in spare_resp.get("properties", {})
                }
                quals = pop_chunk_qualities(properties)
                if check_quality:
                    bal = ensure_better_chunk_qualities(chunks_broken, quals)
                break
            except (exc.ClientException, exc.SpareChunkException) as err:
                self.logger.debug(
                    "Failed to find spare chunk (attempt %d/%d): %s",
                    attempt + 1,
                    max_attempts,
                    err,
                )
                last_exc = err
                # TODO(FVE): exponential backoff?
        else:
            if isinstance(last_exc, exc.SpareChunkException):
                exc.reraise(exc.SpareChunkException, last_exc)
            raise exc.SpareChunkException("No spare chunk: %s" % str(last_exc))

        url_list = []
        for chunk in spare_resp["chunks"]:
            url_list.append(chunk["id"])

        if check_quality:
            self.logger.debug(
                "Found %d spare chunks, that will improve metachunk quality by %d",
                len(url_list),
                bal,
            )

        return url_list, quals

    def _add_raw_chunk(self, current_chunk, url, **kwargs):
        data = {
            "type": "chunk",
            "id": url,
            "hash": current_chunk.checksum,
            "size": current_chunk.size,
            "pos": current_chunk.pos,
            "content": self.content_id,
        }

        # path is required in order to redirect the request to the appropriate
        # shard. version is not required, but we can pass it anyway.
        self.container_client.container_raw_insert(
            data, cid=self.container_id, path=self.path, version=self.version, **kwargs
        )

    def _update_spare_chunk(self, current_chunk, new_url, **kwargs):
        old = {
            "type": "chunk",
            "id": current_chunk.url,
            "hash": current_chunk.checksum,
            "size": current_chunk.size,
            "pos": current_chunk.pos,
            "content": self.content_id,
        }
        new = {
            "type": "chunk",
            "id": new_url,
            "hash": current_chunk.checksum,
            "size": current_chunk.size,
            "pos": current_chunk.pos,
            "content": self.content_id,
        }
        self.container_client.container_raw_update(
            [old],
            [new],
            cid=self.container_id,
            path=self.path,
            version=self.version,
            **kwargs,
        )

    def _generate_sysmeta(self):
        sysmeta = {}
        sysmeta["id"] = self.content_id
        sysmeta["version"] = self.version
        sysmeta["policy"] = self.policy
        sysmeta["mime_type"] = self.mime_type
        sysmeta["chunk_method"] = self.chunk_method
        sysmeta["chunk_size"] = self.metadata["chunk_size"]
        sysmeta["full_path"] = self.full_path
        sysmeta["content_path"] = self.path
        sysmeta["container_id"] = self.container_id
        if self.extra_properties:
            sysmeta["extra_properties"] = self.extra_properties
        return sysmeta

    def _create_object(self, **kwargs):
        data = {"chunks": self.chunks.raw(), "properties": self.properties}
        self.container_client.content_create(
            cid=self.container_id,
            path=self.path,
            content_id=self.content_id,
            stgpol=self.policy,
            size=self.length,
            checksum=self.checksum,
            version=self.version,
            chunk_method=self.chunk_method,
            mime_type=self.mime_type,
            data=data,
            **kwargs,
        )

    def rebuild_chunk(
        self,
        chunk_id,
        service_id=None,
        allow_same_rawx=False,
        chunk_pos=None,
        allow_frozen_container=True,
        reqid=None,
        **kwargs,
    ):
        raise NotImplementedError()

    def create(self, stream, **kwargs):
        raise NotImplementedError()

    def fetch(self):
        raise NotImplementedError()

    def delete(self, **kwargs):
        self.container_client.content_delete(
            cid=self.container_id, path=self.path, **kwargs
        )

    @ensure_request_id2(prefix="move-chunk-")
    def move_chunk(
        self,
        chunk_id,
        service_id=None,
        check_quality=False,
        dry_run=False,
        max_attempts=3,
        cur_items=None,
        force_fair_constraints=True,
        adjacent_mode=False,
        copy_from_duplica=True,
        buffer_size=None,
        async_delete=False,
        **kwargs,
    ):
        """
        Move a chunk to another place. Optionally ensure that the
        new place is an improvement over the current one.
        """
        if isinstance(chunk_id, Chunk):
            current_chunk = chunk_id
            chunk_id = current_chunk.id
            service_id = current_chunk.host
        else:
            candidates = self.chunks.filter(id=chunk_id)
            if len(candidates) > 1:
                if service_id is None:
                    raise exc.ChunkException(
                        f"Several chunks with ID {chunk_id} and no service ID"
                    )
            # Force Check host
            candidates = candidates.filter(host=service_id)
            current_chunk = candidates.one()
        if current_chunk is None or current_chunk not in self.chunks:
            raise exc.OrphanChunk("Chunk not found in content")

        if service_id:
            other_chunks = (
                self.chunks.filter(metapos=current_chunk.metapos)
                .exclude(host=service_id)
                .all()
            )
        else:
            other_chunks = (
                self.chunks.filter(metapos=current_chunk.metapos)
                .exclude(id=chunk_id)
                .all()
            )
        if cur_items:  # If cur_items is defined
            current_chunk.quality["cur_items"] = cur_items
        spare_urls, qualities = self._get_spare_chunk(
            other_chunks,
            [current_chunk],
            position=current_chunk.pos,
            check_quality=check_quality,
            max_attempts=max_attempts,
            force_fair_constraints=force_fair_constraints,
            adjacent_mode=adjacent_mode,
            **kwargs,
        )
        chunks_srcs = [current_chunk]
        if copy_from_duplica:
            # Sort chunks by score to try to copy with higher score.
            # When scores are close together (e.g. [95, 94, 94, 93, 50]),
            # don't always start with the highest element.
            duplicate_chunks = (
                self.chunks.filter(pos=current_chunk.pos)
                .sort(
                    key=lambda chunk: _get_weighted_random_score(chunk.raw()),
                    reverse=True,
                )
                .all()
            )
            # To reduce the load on the rawx to decommission,
            # use one of the rawx with a copy of the chunk to move.
            chunks_srcs = duplicate_chunks

        if dry_run:
            self.logger.info(
                "Dry-run: would copy chunk from %s to %s",
                chunks_srcs[0].url,
                spare_urls[0],
            )
        else:
            perm_errors = []
            temp_errors = []
            for src in chunks_srcs:
                try:
                    self.logger.info(
                        "Copying chunk from %s to %s (reqid=%s)",
                        src.url,
                        spare_urls[0],
                        kwargs.get("reqid"),
                    )
                    # TODO(FVE): retry to copy (max_attempts times)
                    self.blob_client.chunk_copy(
                        src.url,
                        spare_urls[0],
                        chunk_id=chunk_id,
                        fullpath=self.full_path,
                        cid=self.container_id,
                        path=self.path,
                        version=self.version,
                        content_id=self.content_id,
                        buffer_size=buffer_size,
                        **kwargs,
                    )
                    break
                except Exception as err:
                    self.logger.warning(
                        "Failed to copy chunk from %s to %s: %s (reqid=%s)",
                        src.url,
                        spare_urls[0],
                        err,
                        kwargs.get("reqid"),
                    )
                    # When we are moving an EC chunk, we don't analyze other
                    # chunks. Therefore, we can report the error about the one
                    # chunk we just manipulated.
                    if len(chunks_srcs) == 1 and self.storage_method.ec:
                        raise
                    # In case of replication, we will try other chunks. At the
                    # end of the loop, in case of failure, we will report the
                    # situation of the whole object.
                    if isinstance(err, RAWX_PERMANENT_ERRORS):
                        perm_errors.append(err)
                    else:
                        temp_errors.append(err)
            else:
                msg = f"No copy available of chunk to move: {perm_errors + temp_errors}"
                if len(perm_errors) >= len(chunks_srcs):
                    raise UnrecoverableContent(msg)
                raise ObjectUnavailable(msg)
            self._update_spare_chunk(current_chunk, spare_urls[0], **kwargs)

            try:
                if not async_delete:
                    self.blob_client.chunk_delete(current_chunk.url, **kwargs)
                else:
                    service_name = self.blob_client.get_service_name(current_chunk.url)
                    data = json.dumps(
                        {
                            "when": time.time(),
                            "event": EventTypes.CONTENT_DELETED,
                            "url": {
                                "id": self.container_id,
                                "content": self.content_id,
                            },
                            "request_id": kwargs.get("reqid"),
                            "data": [{"id": current_chunk.url, "type": "chunks"}],
                            "service_id": service_name,
                        }
                    )
                    topic = self.blob_client.get_topic_name(service_name)
                    self.blob_client.send(topic=topic, data=data)
            except Exception as err:
                self.logger.warning(
                    "Failed to delete chunk %s: %s (reqid=%s)",
                    current_chunk.url,
                    err,
                    kwargs.get("reqid"),
                )

        current_chunk.url = spare_urls[0]
        current_chunk.quality = qualities[current_chunk.url]

        return current_chunk.raw()

    @ensure_request_id2(prefix="move-chunk-")
    def move_linked_chunk(self, chunk_id, from_url, **kwargs):
        current_chunk = self.chunks.filter(id=chunk_id).one()
        if current_chunk is None:
            raise exc.OrphanChunk("Chunk not found in content")

        _, to_url = self.blob_client.chunk_link(
            from_url, None, self.full_path, **kwargs
        )
        self.logger.debug(
            "link chunk %s from %s to %s (reqid=%s)",
            chunk_id,
            from_url,
            to_url,
            kwargs.get("reqid"),
        )

        self._update_spare_chunk(current_chunk, to_url, **kwargs)

        try:
            self.blob_client.chunk_delete(current_chunk.url, **kwargs)
        except Exception as err:
            self.logger.warn("Failed to delete chunk %s: %s", current_chunk.url, err)

        current_chunk.url = to_url

        return current_chunk.raw()


class Chunk(object):
    def __init__(self, chunk):
        self._data = chunk
        self._pos = chunk["pos"]
        d = self.pos.split(".", 1)
        if len(d) > 1:
            ec = True
            self._metapos = int(d[0])
            self._subpos = int(d[1])
        else:
            self._metapos = int(self._pos)
            ec = False
        self._ec = ec

    @property
    def ec(self):
        return self._ec

    @property
    def url(self):
        return self._data.get("url") or self._data["id"]

    @url.setter
    def url(self, new_url):
        self._data["url"] = new_url
        self._data["real_url"] = new_url

    @property
    def pos(self):
        return self._pos

    @property
    def metapos(self):
        return self._metapos

    @property
    def subpos(self):
        return self._subpos

    @property
    def size(self):
        return self._data["size"]

    @size.setter
    def size(self, new_size):
        self._data["size"] = new_size

    @property
    def id(self):
        return self.url.split("/")[-1]

    @property
    def host(self):
        return self.url.split("/")[2]

    @property
    def checksum(self):
        return self._data["hash"].upper()

    @checksum.setter
    def checksum(self, new_checksum):
        self._data["hash"] = new_checksum

    @property
    def data(self):
        return self._data

    @property
    def imperfections(self):
        """
        List imperfections of this chunk.
        Tell how much the quality of this chunk can be improved.

        :returns: a positive number telling how many criteria can be improved
        (0 if all criteria are met).
        """
        qual = self.quality
        imperfections = list()
        if qual.get("final_slot") != qual.get("expected_slot"):
            imperfections.append(
                "slot %s != %s" % (qual.get("final_slot"), qual.get("expected_slot"))
            )
        if qual["final_dist"] < qual["expected_dist"]:
            imperfections.append(
                "dist %d < %d" % (qual["final_dist"], qual["expected_dist"])
            )
        return imperfections

    @property
    def quality(self):
        """
        Get the "quality" of the chunk, i.e. a dictionary telling how it
        matched the request criteria when it has been selected.
        """
        return self._data.setdefault("quality", {"final_dist": 0, "expected_dist": 1})

    @quality.setter
    def quality(self, value):
        self._data["quality"] = value

    def raw(self):
        return self._data

    def __str__(self):
        return "[Chunk %s (%s)]" % (self.url, self.pos)

    def __repr__(self):
        return str(self)

    def __cmp__(self, other):
        if self.metapos != other.metapos:
            return cmp(self.metapos, other.metapos)

        if not self.ec:
            return cmp(self.id, other.id)

        return cmp(self.subpos, other.subpos)

    def __lt__(self, other):
        return self.__cmp__(other) < 0

    def __le__(self, other):
        return self.__cmp__(other) <= 0

    def __eq__(self, other):
        return self.__cmp__(other) == 0

    def __ne__(self, other):
        return self.__cmp__(other) != 0

    def __ge__(self, other):
        return self.__cmp__(other) >= 0

    def __gt__(self, other):
        return self.__cmp__(other) > 0


class ChunksHelper(object):
    def __init__(self, chunks, raw_chunk=True, sort_key=None, sort_reverse=False):
        if raw_chunk:
            self.chunks = [Chunk(c) for c in chunks]
        else:
            self.chunks = chunks
        if sort_key is not None:
            self.sort_key = sort_key
        else:
            # Some old tests expect chunks to be sorted by chunk ID,
            # for the same position. Starting from version 7.2.0, chunks
            # for the same position can have the same ID, so we must sort
            # them by host (or URL) for the order to be consistent.
            self.sort_key = lambda c: (c.pos, c.id, c.url)
        self.sort_reverse = sort_reverse
        self.chunks.sort(key=self.sort_key, reverse=self.sort_reverse)

    def filter(self, id=None, pos=None, metapos=None, subpos=None, host=None, url=None):
        found = []
        for c in self.chunks:
            if id is not None and c.id != id:
                continue
            if pos is not None and c.pos != str(pos):
                continue
            if metapos is not None and c.metapos != metapos:
                continue
            if subpos is not None and c.subpos != subpos:
                continue
            if host is not None and c.host != host:
                continue
            if url is not None and c.url != url:
                continue
            found.append(c)
        return ChunksHelper(
            found, False, sort_key=self.sort_key, sort_reverse=self.sort_reverse
        )

    def exclude(
        self, id=None, pos=None, metapos=None, subpos=None, host=None, url=None
    ):
        found = []
        for c in self.chunks:
            if id is not None and c.id == id:
                continue
            if pos is not None and c.pos == str(pos):
                continue
            if metapos is not None and c.metapos == metapos:
                continue
            if subpos is not None and c.subpos == subpos:
                continue
            if host is not None and c.host == host:
                continue
            if url is not None and c.url == url:
                continue
            found.append(c)
        return ChunksHelper(
            found, False, sort_key=self.sort_key, sort_reverse=self.sort_reverse
        )

    def sort(self, key=None, reverse=False):
        return ChunksHelper(
            list(self.chunks), False, sort_key=key, sort_reverse=reverse
        )

    def one(self):
        if len(self.chunks) != 1:
            return None
        return self.chunks[0]

    def all(self):
        return self.chunks

    def raw(self):
        res = []
        for c in self.chunks:
            res.append(c.raw())
        return res

    def __len__(self):
        return len(self.chunks)

    def __iter__(self):
        for c in self.chunks:
            yield c

    def __getitem__(self, item):
        return self.chunks[item]
