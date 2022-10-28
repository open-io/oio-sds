# Copyright (C) 2020-2022 OVH SAS
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


from typing import Any, Mapping

from oio.common import exceptions as exc
from oio.common.json import json


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


def max_items_to_int(max_items: str) -> int:
    """
    Transform a ".+_max_items" string into a comparable integer.

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


def max_items_margin(quality: Mapping[str, Any], key: str = "soft_max_items") -> int:
    """
    Compute an improvement margin for the number of services per location.

    :param quality: a dict representing the quality of a service selection
    :param key: max_items quality to be compared with.
    :returns: an integer telling how far from the target is the number of
        services per location. If positive, the selection is better than
        expected, if negative, it can be improved.
    """
    if "cur_items" not in quality or key not in quality:
        return 0  # Cannot compare
    target = max_items_to_int(quality[key])
    if target == 0:
        return 0  # Not configured (legacy configuration?)
    cur = max_items_to_int(quality["cur_items"])
    return target - cur


def compare_chunk_quality(current, candidate):
    """
    Compare the qualities of two chunks.

    :returns: > 0 if the candidate is better quality,
        0 if they are equal, < 0 if the candidate is worse.
    """
    balance = 0

    # Compare distance between chunks.
    balance += candidate.get("final_dist", 1) - current.get("final_dist", 1)

    # Compare the number of services per location
    current_margin = max_items_margin(current)
    candidate_margin = max_items_margin(candidate)
    if candidate_margin > current_margin:
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
