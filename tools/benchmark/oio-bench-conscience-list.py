#!/usr/bin/env python

# Copyright (C) 2024 OVH SAS
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
from oio.common.configuration import load_namespace_conf
from oio.common.utils import request_id


API = None
CS_ADDR = None
POOL = None
RESULTS = None


def list_loop(prefix):
    iteration = 0
    reqid = request_id("csbench-" + prefix)
    while True:
        name = prefix + str(iteration)
        iteration += 1
        try:
            API.conscience.all_services("all", cs=CS_ADDR, reqid=reqid)
            RESULTS.put(name)
            sleep(0)
        except Exception as err:
            print(err)


def main(threads, delay=2.0, duration=60.0):
    counter = 0
    created = []
    now = start = checkpoint = time.monotonic()
    POOL.starmap(list_loop, [("%d-" % n,) for n in range(threads)])
    while now - start < duration:
        res = RESULTS.get()
        counter += 1
        if now - checkpoint > delay:
            print(
                f"{counter} requests in {now - checkpoint:.3f}s, "
                f"{counter / (now - checkpoint):.3f} req/s."
            )
            counter = 0
            checkpoint = now
        created.append(res)
        now = time.monotonic()
    for coro in POOL.coroutines_running:
        coro.kill()
    while not RESULTS.empty():
        created.append(RESULTS.get(block=False))
    end = time.monotonic()
    rate = len(created) / (end - start)
    print(f"End. {len(created)} requests in {end - start:.3f}s, " f"{rate:.3f} req/s.")
    POOL.waitall()
    return rate


if __name__ == "__main__":
    import os
    import sys

    THREADS = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    NS = os.getenv("OIO_NS", "OPENIO")
    NS_CONF = load_namespace_conf(NS)
    CS_ADDR = NS_CONF["conscience"].split(",")[0]
    API = ObjectStorageApi(NS)
    RESULTS = LightQueue(THREADS * 10)
    POOL = GreenPool(THREADS)
    main(THREADS)
