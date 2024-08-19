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


from collections import Counter
from typing import Any, Iterable, Mapping, Union
from urllib.parse import urlparse

from oio.common import exceptions as exc
from oio.common.json import json
from oio.crawler.rawx.chunk_wrapper import ChunkWrapper


NB_LOCATION_LEVELS = 4
CHUNK_SYSMETA_PREFIX = "__OIO_CHUNK__"


def pop_chunk_qualities(properties):
    """
    Pop chunk quality information from a dictionary of properties.

    :param properties: properties dict.
    """
    qualities = {}
    for k, _ in list(properties.items()):
        if k.startswith(CHUNK_SYSMETA_PREFIX):
            qualities[k[len(CHUNK_SYSMETA_PREFIX) :]] = json.loads(properties.pop(k))

    return qualities


def location_constraint_to_int(max_items: str) -> int:
    """
    Transform a ".+_location_constraint" string into a comparable integer.

    These strings are in the form A.B.C.D, with A representing a number
    of services per datacenter and D representing a number of services per
    storage drive.

    A lower number represents a better selection (fewer services per location).
    """
    return sum(
        256**x * int(y)
        for x, y in enumerate(
            max_items.split(".", NB_LOCATION_LEVELS)[0:NB_LOCATION_LEVELS]
        )
    )


def location_constraint_margin(
    quality: Mapping[str, Any], key: str = "fair_location_constraint"
) -> Iterable[Union[int, bool]]:
    """
    Compute an improvement margin for the number of services per location.

    :param quality: a dict representing the quality of a service selection
    :param key: quality name to be compared with.
    :returns: an integer telling how far from the target is the number of
        services per location. If positive, the selection is better than
        expected, if negative, it can be improved. It return also a boolean
        to tell if were able to make comparison or not.
    """

    if "cur_items" not in quality or key not in quality:
        return 0, False  # Cannot compare
    target = location_constraint_to_int(quality[key])
    if target == 0:
        return 0, False  # Not configured (legacy configuration?)
    cur = location_constraint_to_int(quality["cur_items"])
    return target - cur, True


def compare_chunk_quality(current, candidate):
    """
    Compare the qualities of two chunks.

    :returns: > 0 if the candidate is better quality,
        0 if they are equal, < 0 if the candidate is worse.
    """
    balance = 0

    # Compare distance between chunks.
    balance += candidate.get("final_dist", 1) - current.get("final_dist", 1)
    if "fair_location_constraint" not in current:
        current["fair_location_constraint"] = candidate["fair_location_constraint"]
    # Compare the number of services per location
    current_margin, current_compared = location_constraint_margin(current)
    candidate_margin, candidate_compared = location_constraint_margin(candidate)
    if current_compared and candidate_margin > current_margin:
        balance += 1
    elif not current_compared and candidate_compared and candidate_margin >= 0:
        # if the candidate margin is the last slot available on the host targeted,
        # the candidate margin is equal to zero.
        balance += 1
    elif candidate_margin < current_margin:
        balance -= 1

    # Compare use of fallback mechanisms.
    expected_slot = current.get("expected_slot")
    if (
        current.get("final_slot") != expected_slot
        and candidate.get("final_slot") == expected_slot
    ):
        # The current slot is not the expected one,
        # and the candidate slot is the expected one.
        balance += 1
    elif (
        current.get("final_slot") == expected_slot
        and candidate.get("final_slot") != expected_slot
    ):
        # The current slot is the expected one,
        # but we are proposed to replace it with another one.
        # The final balance may still be positive if the distance
        # has been drastically increased.
        balance -= 1

    return balance


def ensure_better_chunk_qualities(current_chunks, candidates, threshold=1):
    """
    Ensure that the set of spare chunks is really an improvement over
    the set of current chunks, raise SpareChunkException if it is not.
    """
    balance = 0
    for current, candidate in zip(current_chunks, candidates.keys()):
        balance += compare_chunk_quality(current.quality, candidates[candidate])
    if balance < threshold:
        raise exc.SpareChunkException(
            "the spare chunks found would not improve the quality "
            "(balance=%d, threshold=%d)" % (balance, threshold)
        )
    return balance


def format_location(location, levels=NB_LOCATION_LEVELS):
    """
    Format location with dc.rack.server.disk format if needed.

    :param location: location on dc.rack.server.disk format
    :type location: str
    :param levels: expected number of levels
    :type levels: int
    :return: location formatted as (dc, rack, server, disk)
    :rtype: tuple
    """
    length = len(location)
    if length < levels:
        # Complete missing position in chunk location
        levels = levels - length
        for _ in range(levels):
            # For local environments
            location = ("",) + location
    return location[-4:]


def get_distance(loc_1, loc_2):
    """
    Compute the distance between the two locations.

    :param loc_1: first location
    :type loc_1: str
    :param loc_2: second location
    :type loc_2: str
    :return: distance between two location
    :rtype: int
    """
    common = 0
    loc_1 = format_location(tuple(loc_1.split(".")))
    loc_2 = format_location(tuple(loc_2.split(".")))
    for i in range(NB_LOCATION_LEVELS):
        if loc_1[i] != loc_2[i]:
            break
        common += 1
    return NB_LOCATION_LEVELS - common


def count_items_per_loc(loc_list):
    """
    Count items per location, for each location level.

    :param loc_list: a list of location tuples
    """
    counters = Counter()
    for loc in loc_list:
        for level in range(1, NB_LOCATION_LEVELS + 1):
            counters[loc[:level]] += 1
    return counters


def get_current_items(current, rawx_id, all_chunks, rawx_srv_locations, logger=None):
    """
    Calculate current items on the host of the chunk passed in parameters

    :param current: chunk representation or a chunk_id.
    :type current: ChunkWrapper
    :param rawx_id: Rawx id hosting the current chunk
    :type rawx_id: str
    :param all_chunks: list of object chunks
    :type all_chunks: list
    :param rawx_srv_locations: location of all rawx service
    :type rawx_srv_locations: dict
    :param logger: logger instance
    :type logger: Logger
    :return: the current items on the host, e.g: 12.12.4.1
    :rtype: str
    """
    if not current and not rawx_id:
        if logger:
            logger.warning("Cannot calculate current items without chunk id or rawx id")
        return None
    try:
        counters = {}
        # Location of the current chunk
        current_loc = None
        if isinstance(current, ChunkWrapper):
            chunk_id = current.chunk_id
        else:  # Chunk id
            chunk_id = current
        for chunk in all_chunks:
            rawx_srv_id = urlparse(chunk["url"]).netloc
            # Location of the rawx hosting the chunk selected
            location = format_location(rawx_srv_locations[rawx_srv_id])
            if chunk_id and chunk_id in chunk["url"]:
                # Get the location of the chunk
                current_loc = location

            for depth in range(NB_LOCATION_LEVELS):
                # Create a counter for each level
                depth_counter = counters.setdefault(depth, Counter())
                subloc = location[: depth + 1]
                depth_counter[subloc] += 1
        cur_items = []
        if not current_loc and rawx_id:
            current_loc = format_location(rawx_srv_locations[rawx_id])
        for depth in range(NB_LOCATION_LEVELS):
            counter = counters[depth]
            subloc = current_loc[: depth + 1]
            cur_items.append(str(counter[subloc]))
        return ".".join(cur_items)
    except Exception as exception:
        if logger:
            logger.error(
                "Chunk %s: calculate current items quality has failed due to %s",
                chunk_id,
                exception,
            )
    return None
