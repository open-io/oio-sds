#!/usr/bin/env python

# Copyright (C) 2020 OpenIO SAS, as part of OpenIO SDS
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
"""
Put pressure on the account service by sending a lot of
account/container/update requests.

1000 (+1) shards will be simulated for each bucket, and will be continuously
updated with pseudorandom values, for 60s. Then they will be cleaned.

Namespace: OIO_NS environment variable or 'OPENIO'.
Account: OIO_ACCOUNT environment variable or 'benchmark'.


usage: %s [processes]

processes: the number of simultaneous processes (with 16 coroutines each).
"""

from __future__ import print_function

import multiprocessing
import time
from eventlet import sleep
from eventlet.greenpool import GreenPool
from eventlet.queue import Empty, LightQueue
from oio.account.client import AccountClient


ACCOUNT = None
DURATION = 60.0
SHARDS = 1000


def create_loop(api, prefix, results):
    iteration = 0
    up_req = {
        'bucket': prefix,
        'objects': 0,
        'bytes': 0,
        'damaged_objects': 0,
        'missing_chunks': 0,
        'mtime': time.time()
    }
    # Create the "main" shard
    try:
        api.container_update(ACCOUNT, prefix, up_req)
        results.put(prefix)
    except Exception as err:
        print(err)

    # Loop on all other shards
    while True:
        name = prefix + '%2F' + str(iteration % SHARDS)
        mtime = time.time()
        iteration += 1
        # Poor man's random
        up_req['objects'] = int(mtime) % iteration
        up_req['bytes'] = up_req['objects'] * 42
        up_req['mtime'] = mtime
        try:
            api.container_update(ACCOUNT, name, up_req)
            results.put(name)
            sleep(0)
        except Exception as err:
            print(err)


def main(myid, queue, concurrency, delay=5.0, duration=DURATION):
    counter = 0
    created = list()
    results = LightQueue(concurrency * 10)
    pool = GreenPool(concurrency)
    api = AccountClient({'namespace': NS}, pool_maxsize=concurrency+1)
    now = start = checkpoint = time.time()
    pool.starmap(create_loop, [(api, 'buck-%d-%d' % (myid, n), results)
                               for n in range(concurrency)])
    while now - start < duration:
        try:
            res = results.get(timeout=delay)
            created.append(res)
            counter += 1
        except Empty:
            pass
        if now - checkpoint > delay:
            print("Proc %d: %d updates in %fs, %f updates per second." % (
                  myid, counter, now - checkpoint,
                  counter / (now - checkpoint)))
            counter = 0
            checkpoint = now
        now = time.time()
    for coro in pool.coroutines_running:
        coro.kill()
    while not results.empty():
        created.append(results.get(block=False))
    end = time.time()
    rate = len(created) / (end - start)
    print("Proc %d: end. %d updates in %fs, %f updates per second." % (
          myid, len(created), end - start, rate))
    time.sleep(2)
    print("Proc %d: cleaning..." % myid)
    del_req = {'dtime': time.time()}
    # Do not delete twice (or an exception is raised)
    uniq_ct = set(created)
    for _ in pool.starmap(api.container_update,
                          [(ACCOUNT, n, del_req) for n in uniq_ct]):
        pass
    pool.waitall()
    queue.put(rate)
    return 0


if __name__ == '__main__':
    import os
    import sys
    if len(sys.argv) > 1:
        if sys.argv[1] in ('-h', '-help', '--help'):
            print(__doc__ % sys.argv[0])
            sys.exit(1)
        else:
            N_PROC = int(sys.argv[1])
    else:
        N_PROC = 1
    COROS = 10
    NS = os.getenv('OIO_NS', 'OPENIO')
    ACCOUNT = os.getenv('OIO_ACCOUNT', 'benchmark')
    QUEUE = multiprocessing.Queue()
    PROCESSES = list()
    for sub in range(N_PROC):
        PROCESSES.append(multiprocessing.Process(
            target=main, args=(sub, QUEUE, COROS)))
    for proc in PROCESSES:
        proc.start()
    RATE = 0
    try:
        for proc in PROCESSES:
            RATE += QUEUE.get(timeout=DURATION*2)
    except Empty:
        pass
    for proc in PROCESSES:
        proc.join()
    print("Overall rate: %f updates per second" % RATE)
