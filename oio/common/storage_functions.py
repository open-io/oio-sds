# Copyright (C) 2017-2020 OpenIO SAS, as part of OpenIO SDS
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


import random

from oio.api.ec import ECChunkDownloadHandler
from oio.api.io import ChunkReader
from oio.common import exceptions as exc
from oio.common.decorators import ensure_headers
from oio.common.http import http_header_from_ranges

RAWX_PERMANENT_ERRORS = (
    exc.NotFound,  # Chunk does not exist
    exc.ClientPreconditionFailed,  # Chunk has bad size or is corrupt
)


def obj_range_to_meta_chunk_range(obj_start, obj_end, meta_sizes):
    """
    Convert a requested object range into a list of meta_chunk ranges.

    :param meta_sizes: size of all object metachunks. Must be sorted!
    :type meta_sizes: iterable, sorted in ascendant metachunk order.
    :returns: a `dict` of tuples (meta_chunk_start, meta_chunk_end)
        with metachunk positions as keys.

        * meta_chunk_start is the first byte of the meta chunk,
          or None if this is a suffix byte range

        * meta_chunk_end is the last byte of the meta_chunk,
          or None if this is a prefix byte range
    """

    offset = 0
    found_start = False
    found_end = False
    total_size = 0

    for meta_size in meta_sizes:
        total_size += meta_size
    # suffix byte range handling
    if obj_start is None and obj_end is not None:
        obj_start = total_size - min(total_size, obj_end)
        obj_end = total_size - 1

    meta_chunk_ranges = {}
    for pos, meta_size in enumerate(meta_sizes):
        if meta_size <= 0:
            continue
        if found_start:
            meta_chunk_start = 0
        elif obj_start is not None and obj_start >= offset + meta_size:
            offset += meta_size
            continue
        elif obj_start is not None and obj_start < offset + meta_size:
            meta_chunk_start = obj_start - offset
            found_start = True
        else:
            meta_chunk_start = 0
        if obj_end is not None and offset + meta_size > obj_end:
            meta_chunk_end = obj_end - offset
            # found end
            found_end = True
        elif meta_size > 0:
            meta_chunk_end = meta_size - 1
        meta_chunk_ranges[pos] = (meta_chunk_start, meta_chunk_end)
        if found_end:
            break
        offset += meta_size

    return meta_chunk_ranges


def get_meta_ranges(ranges, chunks):
    """
    Convert object ranges to metachunks ranges.

    :returns: a list of dictionaries indexed by metachunk positions
    """
    range_infos = []
    meta_sizes = [chunks[pos][0]["size"] for pos in sorted(chunks.keys())]
    for obj_start, obj_end in ranges:
        meta_ranges = obj_range_to_meta_chunk_range(obj_start, obj_end, meta_sizes)
        range_infos.append(meta_ranges)
    return range_infos


def _get_weighted_random_score(chunk):
    score = chunk.get("score", 0)
    if not score:
        return 0
    if score > 0:
        score += random.randrange(10)
    # else:
    #   Score may be negative if the service is down
    return score


def _sort_chunks(raw_chunks, ec_security, keep_duplicates=False, logger=None):
    """
    Sort a list a chunk objects. In addition to the sort,
    this function adds an "offset" field to each chunk object.

    :type raw_chunks: iterable of `dict`
    :param ec_security: tells the sort algorithm that chunk positions are
        composed (e.g. "0.4").
    :type ec_security: `bool`
    :returns: a `dict` with metachunk positions as keys,
        and `list` of chunk objects as values.
    """
    nums_by_position = {}
    chunks = {}
    for chunk in raw_chunks:
        raw_position = chunk["pos"].split(".")
        position = int(raw_position[0])
        if ec_security:
            num = int(raw_position[1])
            chunk["num"] = int(raw_position[1])
            nums = nums_by_position.setdefault(position, set())
            if num in nums:
                if logger:
                    logger.warning(
                        "Duplicated position (%s) for %s",
                        chunk["pos"],
                        chunk["real_url"],
                    )
                if not keep_duplicates:
                    continue
            nums.add(num)
        chunks_at_position = chunks.setdefault(position, [])
        chunks_at_position.append(chunk)

    # for each position, remove incoherent chunks
    for pos, local_chunks in chunks.items():
        if len(local_chunks) < 2:
            continue
        byhash = {}
        for chunk in local_chunks:
            h = chunk.get("hash")
            if h not in byhash:
                byhash[h] = []
            byhash[h].append(chunk)
        if len(byhash) < 2:
            continue
        # sort by length
        bylength = list(byhash.values())
        bylength.sort(key=len, reverse=True)
        chunks[pos] = bylength[0]

    # Append the 'offset' attribute
    offset = 0
    for pos in sorted(chunks.keys()):
        clist = chunks[pos]
        # When scores are close together (e.g. [95, 94, 94, 93, 50]),
        # don't always start with the highest element.
        clist.sort(key=_get_weighted_random_score, reverse=True)
        for element in clist:
            element["offset"] = offset
        offset += clist[0]["size"]

    return chunks


@ensure_headers
def fetch_stream(chunks, ranges, storage_method, headers=None, **kwargs):
    ranges = ranges or [(None, None)]
    meta_range_list = get_meta_ranges(ranges, chunks)

    for meta_range_dict in meta_range_list:
        for pos in sorted(meta_range_dict.keys()):
            meta_start, meta_end = meta_range_dict[pos]
            if meta_start is not None and meta_end is not None:
                headers["Range"] = http_header_from_ranges((meta_range_dict[pos],))
            reader = ChunkReader(iter(chunks[pos]), None, headers=headers, **kwargs)
            try:
                it = reader.get_iter()
            except RAWX_PERMANENT_ERRORS as err:
                raise exc.UnrecoverableContent(f"Cannot download position {pos}: {err}")
            except Exception as err:
                raise exc.ObjectUnavailable(
                    f"Error while downloading position {pos}: {err}"
                )
            for part in it:
                for dat in part["iter"]:
                    yield dat


@ensure_headers
def fetch_stream_ec(chunks, ranges, storage_method, **kwargs):
    ranges = ranges or [(None, None)]
    meta_range_list = get_meta_ranges(ranges, chunks)
    for meta_range_dict in meta_range_list:
        for pos in sorted(meta_range_dict.keys()):
            meta_start, meta_end = meta_range_dict[pos]
            handler = ECChunkDownloadHandler(
                storage_method, chunks[pos], meta_start, meta_end, **kwargs
            )
            try:
                stream = handler.get_stream()
            except RAWX_PERMANENT_ERRORS as err:
                raise exc.UnrecoverableContent(f"Cannot download position {pos}: {err}")
            except Exception as err:
                raise exc.ObjectUnavailable(
                    f"Error while downloading position {pos}: {err}"
                )
            try:
                for part_info in stream:
                    for dat in part_info["iter"]:
                        yield dat
            finally:
                # This must be done in a finally block to handle the case
                # when the reader does not read until the end of the stream.
                stream.close()
