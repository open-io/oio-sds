#!/usr/bin/env python

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

from __future__ import print_function

import time
from eventlet import sleep
from eventlet.greenpool import GreenPool
from eventlet.queue import LightQueue
from oio import ObjectStorageApi


ACCOUNT = None
API = None
POOL = None
RESULTS = None
POLICY = None


def create_loop(container, prefix):
    iteration = 0
    while True:
        name = prefix + str(iteration)
        iteration += 1
        try:
            API.object_create(ACCOUNT, container, obj_name=name, data='',
                              policy=POLICY)
            RESULTS.put((container, name))
            sleep(0)
        except Exception as err:
            print(err)


def main(threads, delay=2.0, duration=30.0):
    counter = 0
    created = list()
    cname = 'benchmark-%d' % int(time.time())
    now = start = checkpoint = time.time()
    POOL.starmap(create_loop,
                 [(cname, '%d-' % n, ) for n in range(threads)])
    while now - start < duration:
        res = RESULTS.get()
        counter += 1
        if now - checkpoint > delay:
            print("%d objects in %fs, %f objects per second." % (
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
    print("End. %d objects created in %fs, %f objects per second." % (
          len(created), end - start, rate))
    print("Cleaning...")
    for _ in POOL.starmap(API.object_delete,
                          [(ACCOUNT, n[0], n[1]) for n in created]):
        pass
    POOL.waitall()
    return rate


def _object_upload(ul_handler, **kwargs):
    ul_chunks = ul_handler.chunk_prep()
    return ul_chunks.next(), 0, 'd41d8cd98f00b204e9800998ecf8427e'


if __name__ == '__main__':
    import os
    import sys
    THREADS = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    POLICY = sys.argv[2] if len(sys.argv) > 2 else 'SINGLE'
    ACCOUNT = os.getenv('OIO_ACCOUNT', 'benchmark')
    API = ObjectStorageApi(os.getenv('OIO_NS', 'OPENIO'))
    API._object_upload = _object_upload
    RESULTS = LightQueue(THREADS * 10)
    POOL = GreenPool(THREADS)
    main(THREADS)
