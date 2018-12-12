# Copyright (C) 2015-2018 OpenIO SAS, as part of OpenIO SDS
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

import eventlet

import time
import logging

from datetime import datetime, timedelta

import eventlet.hubs as eventlet_hubs # noqa
from eventlet import sleep, patcher, greenthread # noqa
from eventlet import Queue, Timeout, GreenPile, GreenPool # noqa
from eventlet.green import threading, socket # noqa
from eventlet.green.httplib import HTTPConnection, HTTPResponse, _UNKNOWN # noqa
from eventlet.event import Event # noqa
from eventlet.queue import Empty, LifoQueue # noqa

from oio.common.exceptions import OioException

eventlet.monkey_patch(os=False)

logging.thread = eventlet.green.thread
logging.threading = threading
logging._lock = logging.threading.RLock()


class OioTimeout(Timeout):
    """Wrapper over eventlet.Timeout with better __str__."""

    msg_prefix = ''

    def __str__(self):
        return "%stimeout %s" % (self.__class__.msg_prefix,
                                 super(OioTimeout, self).__str__())


class ConnectionTimeout(OioTimeout):
    msg_prefix = 'Connection '


class SourceReadTimeout(OioTimeout):
    msg_prefix = 'Source read '


class ChunkWriteTimeout(OioTimeout):
    msg_prefix = 'Chunk write '


class ChunkReadTimeout(OioTimeout):
    msg_prefix = 'Chunk read '


def get_hub():
    return 'poll'


def ratelimit(run_time, max_rate, increment=1, rate_buffer=5):
    if max_rate <= 0 or increment <= 0:
        return run_time
    clock_accuracy = 1000.0
    now = time.time() * clock_accuracy
    time_per_request = clock_accuracy * (float(increment) / max_rate)
    if now - run_time > rate_buffer * clock_accuracy:
        run_time = now
    elif run_time - now > time_per_request:
        sleep((run_time - now) / clock_accuracy)
    return run_time + time_per_request


def ratelimit_validate_policy(policy):
    """
    Validate a policy. The following rules are checked:
    - We have a complete partition of 24 hours.
    - Each partition has a positive max_rate
    - Partition starts at 0H and ends at 0H. (Easier to program ..)

    If one of these parameters are not respected, an OioException is thrown.

    An example of a simple policy would be:
    [
        [0, 0, 3],
    ]

    Which would be a policy to have a constant max_rate of 3. A more complex
    policy would be:
    [
        [0, 7, 1],
        [7, 9, 10],
        [9, 15, 200],
        [15, 20, 10],
        [20, 0, 1],
    ]

    :param policy: A dictionary containing the policy that follows the
                  aforementioned description.
    :type dict
    :return:
    """

    def validate_entry(entry_index):
        """
        Validates a single entry of the policy partition

        :param entry_index: Policy entry index
        :return: Whether the partition entry is valid or not.
        """
        if not 0 <= policy[entry_index][0] < 24:
            return False
        # If we're validating a middle record.
        if len(policy) > 1 and entry_index != len(policy) - 1:
            if policy[entry_index][0] > policy[entry_index][1]:
                return False
            if policy[entry_index][1] != policy[entry_index + 1][0]:
                return False
            return True
        # Otherwise we're either validating a single record policy or the last
        # record.
        if policy[entry_index][1] != policy[0][0]:
            return False
        if policy[entry_index][1] != 0:
            return False
        return True

    policy.sort()
    # Check the
    for i in range(len(policy)):
        if not validate_entry(i):
            raise OioException("The given policy isn't valid !")

    return True


def ratelimit_function_next_rate(curr_date, policy):
    """
    Given a current date and a policy, calculate the date at which the next
    rate change is scheduled.

    (Could be useful if the rate limited operation is fast, and as such we
    would want to cache the next rate date so that instead of selecting the
    rate each op, we'd just compare to a timestamp and return a cached value,
    which in the current implementation would make it go from a for loop with
    several comparisons to about a single comparison)

    :param curr_date: The current datetime
    :type curr_date datetime
    :param policy: A list representing a validated policy.
    :return: A second-resolution unix epoch of the next scheduled rate change
    """
    curr_hour = curr_date.hour
    curr_partition = None

    # We have a partition, first occurrence is the only one.
    if len(policy) > 1:
        for partition in policy:
            if partition[0] <= curr_hour <= partition[1]:
                curr_partition = partition
                break
    else:
        curr_partition = policy[0]

    # Reset to an hour resolution
    curr_date = curr_date - timedelta(minutes=curr_date.minute,
                                      seconds=curr_date.second,
                                      microseconds=curr_date.microsecond)

    delta = None
    if curr_partition[1] == 0:
        # Reset to midnight
        curr_date = curr_date - timedelta(hours=curr_date.hour)
        delta = timedelta(days=1)
    else:
        delta = timedelta(hours=curr_partition[1] - curr_hour)

    next_rate_date = curr_date + delta

    # Because Python 2
    return (next_rate_date - datetime(1970, 1, 1)).total_seconds()


def ratelimit_function_curr_rate(curr_date, policy):
    """
    Given a validated policy and a datetime, return the applicable max_rate

    :param curr_date: The current date
    :type curr_date datetime
    :param policy: An array representing a validated policy
    :return: The applicable max_rate (elements per second)
    """
    curr_hour = curr_date.hour
    curr_partition = None
    # We have a partition, first occurrence is the only one.
    if len(policy) > 1:
        for partition in policy:
            if partition[0] <= curr_hour <= partition[1] or \
                    (partition[0] <= curr_hour and partition[1] == 0):
                curr_partition = partition
                break
    else:
        curr_partition = policy[0]

    return curr_partition[2]


def ratelimit_function_build(policy):
    """
    Given a policy, return a customized wrapper around ratelimit for a
    time aware rate limiter.
    :param policy: An array representing a rate limiting policy as described
                    by ratelimit_validate_policy.
    :return: A callable function similar in signature to ratelimit but that
             ignores all parameters other than the first one.
    """
    ratelimit_validate_policy(policy)

    def _ratelimiter(run_time, *args, **kwargs):
        """
        The ratelimit wrapper that takes into account the custom policy, and
        ignores all the other parameters other than run_time
        :param run_time: The last time the operation was executed in seconds.
        """
        curr_date = datetime.today()

        return ratelimit(run_time=run_time,
                         max_rate=ratelimit_function_curr_rate(
                             curr_date=curr_date,
                             policy=_ratelimiter.policy))

    _ratelimiter.policy = policy

    return _ratelimiter


class ContextPool(GreenPool):
    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        for coroutine in list(self.coroutines_running):
            coroutine.kill()
