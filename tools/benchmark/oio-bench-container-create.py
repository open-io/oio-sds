#!/usr/bin/env python

# Copyright (C) 2019-2020 OpenIO SAS, as part of OpenIO SDS
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

from __future__ import print_function

import time
from eventlet import sleep
from eventlet.greenpool import GreenPool
from eventlet.queue import LightQueue
from oio import ObjectStorageApi


API = None
POOL = None
RESULTS = None


def create_loop(prefix):
    iteration = 0
    while True:
        name = prefix + str(iteration)
        iteration += 1
        try:
            API.container_create('benchmark', name)
            RESULTS.put(name)
            sleep(0)
        except Exception as err:
            print(err)


def main(threads, delay=2.0, duration=30.0):
    counter = 0
    created = list()
    now = start = checkpoint = time.time()
    POOL.starmap(create_loop, [('%d-' % n, ) for n in range(threads)])
    while now - start < duration:
        res = RESULTS.get()
        counter += 1
        if now - checkpoint > delay:
            print("%d containers in %fs, %f containers per second." % (
                  counter, now - checkpoint, counter / (now - checkpoint)))
            counter = 0
            checkpoint = now
        created.append(res)
        now = time.time()
    for coro in POOL.coroutines_running:
        coro.kill()
    while not RESULTS.empty():
        created.append(RESULTS.get(block=False))
    end = time.time()
    rate = len(created) / (end - start)
    print("End. %d containers created in %fs, %f containers per second." % (
          len(created), end - start, rate))
    print("Cleaning...")
    for _ in POOL.starmap(API.container_delete,
                          [('benchmark', n) for n in created]):
        pass
    POOL.waitall()
    return rate


if __name__ == '__main__':
    import os
    import sys
    THREADS = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    API = ObjectStorageApi(os.getenv('OIO_NS', 'OPENIO'))
    RESULTS = LightQueue(THREADS * 10)
    POOL = GreenPool(THREADS)
    main(THREADS)
