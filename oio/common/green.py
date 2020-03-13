# Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
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

from six import string_types

import eventlet.hubs as eventlet_hubs # noqa
from eventlet import sleep, patcher, greenthread # noqa
from eventlet import Queue, Timeout, GreenPile, GreenPool # noqa
from eventlet.green import thread, threading, socket # noqa
from eventlet.event import Event # noqa
from eventlet.green.httplib import (HTTPConnection, HTTPSConnection, # noqa
    HTTPResponse, _UNKNOWN) # noqa
from eventlet.queue import Empty, LifoQueue, LightQueue # noqa
from eventlet.semaphore import Semaphore # noqa

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


def eventlet_yield():
    """Swith to another eventlet coroutine."""
    sleep(0)


def get_hub():
    return 'poll'


def ratelimit(run_time, max_rate, increment=1, rate_buffer=5, time_time=None):
    if max_rate <= 0 or increment <= 0:
        return run_time
    clock_accuracy = 1000.0
    now = (time_time or time.time()) * clock_accuracy
    time_per_request = clock_accuracy * (float(increment) / max_rate)
    if now - run_time > rate_buffer * clock_accuracy:
        run_time = now
    elif run_time - now > 0:
        sleep((run_time - now) / clock_accuracy)
    return run_time + time_per_request


def ratelimit_validate_policy(policy):
    """
    Validate a policy. The following rules are checked:
    - Each partition has a positive max_rate.
    - The start date of each partition is 0 or positive.
    - The start date of each partition is lower than 24h.

    An example of a simple policy would be:
    [
        (datetime.timedelta(0), 3),
    ]

    Which would be a policy to have a constant max_rate of 3. A more complex
    policy would be:
    [
        (datetime.timedelta(0, 1800), 10),  #  0h30 to  6h45
        (datetime.timedelta(0, 24300), 2),  #  6h45 to  9h45
        (datetime.timedelta(0, 35100), 5),  #  9h45 to 15h30
        (datetime.timedelta(0, 55800), 3),  # 15h30 to 20h00
        (datetime.timedelta(0, 72000), 8),  # 20h00 to  0h30
    ]

    :param policy: A list containing the policy that follows the
                   aforementioned description.
    :type policy: `list`
    :raises: `ValueError` if one of the rules is not respected.
    """
    if not policy:
        raise ValueError('Policy must contain at least one rate')

    min_time = timedelta(0)
    max_time = timedelta(hours=24)

    for entry in policy:
        if len(entry) < 2:
            raise ValueError('Ratelimit entries must be 2-tuples')
        if entry[0] < min_time:
            raise ValueError('Start time cannot be negative')
        if entry[0] >= max_time:
            raise ValueError('Start time cannot be more than 24 hours')
        if entry[1] < 0:
            raise ValueError('Rate must be zero or positive')

    policy.sort()
    return True


def ratelimit_function_curr_rate(curr_date, policy):
    """
    Given a validated policy and a datetime, return the applicable max_rate

    :param curr_date: The current date
    :type curr_date datetime
    :param policy: An array representing a validated policy
    :return: The applicable max_rate (elements per second)
    """
    curr_partition = policy[-1]
    # We have a partition, first occurrence is the only one.
    if len(policy) > 1:
        for partition in policy:
            if (curr_date - partition[0]).date() < curr_date.date():
                break
            curr_partition = partition
    else:
        curr_partition = policy[0]

    return curr_partition[1]


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
    :type curr_date: `datetime`
    :param policy: A list representing a validated policy.
    :returns: the next scheduled rate and the `datetime` object for the next
              scheduled rate change.
    """
    next_day = False
    for partition in policy:
        curr_partition = partition
        if (curr_date - partition[0]).date() < curr_date.date():
            break
    else:
        curr_partition = policy[0]
        next_day = True
    next_date = datetime(curr_date.year, curr_date.month, curr_date.day)
    next_date += curr_partition[0]
    if next_day:
        next_date += timedelta(days=1)
    return curr_partition[1], next_date


def ratelimit_policy_from_string(policy_str):
    """
    :rtype: `list` of 2-tuples with a `datetime.timedelta` and an integer.
    """
    policy = list()
    if ';' not in policy_str:
        try:
            td = timedelta(0)
            rate = int(policy_str)
        except ValueError as err:
            raise ValueError("Unparseable rate limit '%s': %s" %
                             (policy_str, err))
        policy.append((td, rate))
        return policy
    changes = policy_str.split(';')
    for change in changes:
        try:
            time_str, rate_str = change.split(':', 1)
            hour_str, min_str = time_str.split('h', 1)
            td = timedelta(hours=int(hour_str), minutes=int(min_str))
            rate = int(rate_str)
        except ValueError as err:
            raise ValueError("Unparseable rate change '%s': %s" %
                             (change, err))
        policy.append((td, rate))
    policy.sort()
    return policy


def ratelimit_function_build(policy):
    """
    Given a policy, return a customized wrapper around ratelimit for a
    time aware rate limiter.
    :param policy: An array representing a rate limiting policy as described
                    by ratelimit_validate_policy.
    :return: A callable function similar in signature to ratelimit but that
             ignores all parameters other than the first one.
    """
    if isinstance(policy, string_types):
        policy = ratelimit_policy_from_string(policy)
    ratelimit_validate_policy(policy)

    def _ratelimiter(run_time, _max_rate=None, increment=1, rate_buffer=5):
        """
        The ratelimit wrapper that takes into account the custom policy, and
        ignores all the other parameters other than run_time
        :param run_time: The last time the operation was executed in seconds.
        """
        time_time = time.time()
        curr_date = datetime.fromtimestamp(time_time)

        return ratelimit(run_time,
                         ratelimit_function_curr_rate(
                             curr_date=curr_date,
                             policy=_ratelimiter.policy),
                         increment,
                         rate_buffer,
                         time_time)

    _ratelimiter.policy = policy

    return _ratelimiter


class ContextPool(GreenPool):
    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        for coroutine in list(self.coroutines_running):
            coroutine.kill()
