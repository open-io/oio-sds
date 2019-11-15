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

import eventlet.hubs as eventlet_hubs # noqa
from eventlet import sleep, patcher, greenthread # noqa
from eventlet import Queue, Timeout, GreenPile, GreenPool # noqa
from eventlet.green import threading, socket # noqa
from eventlet.green.httplib import HTTPConnection, HTTPResponse, _UNKNOWN # noqa
from eventlet.event import Event # noqa
from eventlet.queue import Empty, LifoQueue, LightQueue # noqa

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


def ratelimit(run_time, max_rate, increment=1, rate_buffer=5):
    if max_rate <= 0 or increment <= 0:
        return run_time
    clock_accuracy = 1000.0
    now = time.time() * clock_accuracy
    time_per_request = clock_accuracy * (float(increment) / max_rate)
    if now - run_time > rate_buffer * clock_accuracy:
        run_time = now
    elif run_time - now > 0:
        sleep((run_time - now) / clock_accuracy)
    return run_time + time_per_request


class ContextPool(GreenPool):
    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        for coroutine in list(self.coroutines_running):
            coroutine.kill()
