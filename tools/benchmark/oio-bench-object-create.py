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
from oio.common.utils import depaginate


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


def list_objects(container):
    objects_iter = depaginate(
        API.object_list,
        listing_key=lambda x: x['objects'],
        marker_key=lambda x: x.get('next_marker'),
        truncated_key=lambda x: x['truncated'],
        account=ACCOUNT, container=container,
        limit=5000)
    return [obj['name'] for obj in objects_iter]


def main(threads, delay=5.0, duration=60.0):
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
    print("Listing.")
    start = time.time()
    all_objects = list_objects(cname)
    end = time.time()
    print("Listing %d objects took %fs seconds, %f objects per second." % (
        len(all_objects), end - start, len(all_objects) / (end - start)))
    print("Cleaning...")
    for _ in POOL.starmap(API.object_delete,
                          [(ACCOUNT, cname, obj)
                           for obj in all_objects]):
        pass
    POOL.waitall()
    return rate


def _object_upload(ul_handler, **kwargs):
    ul_chunks = ul_handler.chunk_prep()
    return ul_chunks.next(), 0, 'd41d8cd98f00b204e9800998ecf8427e'


USAGE = """Concurrently create many fake objects in the same container.
The account name is taken from the OIO_ACCOUNT environement variable, the
container name is 'benchmark-' followed by a timestamp.
Does not create chunks, just save chunk addresses.

usage: %s [THREADS [POLICY [DURATION]]]

    THREAD is 1 by default
    POLICY is "SINGLE" by default
    DURATION is 60.0 seconds by default
"""

if __name__ == '__main__':
    import os
    import sys
    if len(sys.argv) > 1 and sys.argv[1] in ('-h', '--help'):
        print(USAGE % sys.argv[0])
        sys.exit(0)
    THREADS = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    POLICY = sys.argv[2] if len(sys.argv) > 2 else 'SINGLE'
    DURATION = float(sys.argv[3]) if len(sys.argv) > 3 else 60.0
    ACCOUNT = os.getenv('OIO_ACCOUNT', 'benchmark')
    API = ObjectStorageApi(os.getenv('OIO_NS', 'OPENIO'))
    API._object_upload = _object_upload
    RESULTS = LightQueue(THREADS * 10)
    POOL = GreenPool(THREADS)
    main(THREADS, duration=DURATION)
