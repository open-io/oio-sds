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

import time
from eventlet import sleep
from eventlet.greenpool import GreenPool
from oio import ObjectStorageApi
from oio.common.configuration import load_namespace_conf
from oio.common.utils import request_id
from oio.directory.admin import AdminClient


API = None
CS_ADDR = None
POOL = None
RESULTS = 0


def list_loop(prefix):
    global RESULTS
    iteration = 0
    reqid = request_id("csbench-" + prefix)
    while True:
        iteration += 1
        try:
            API.conscience.all_services("all", cs=CS_ADDR, reqid=reqid)
            RESULTS += 1
            sleep(0)
        except Exception as err:
            print(err)


def main_loop(threads, delay=2.0, duration=60.0):
    counter = 0
    now = start = checkpoint = time.monotonic()
    POOL.starmap(list_loop, [("%d-" % n,) for n in range(threads)])
    while now - start < duration:
        new_counter = RESULTS
        elapsed = now - checkpoint
        if elapsed > delay:
            diff = new_counter - counter
            print(
                f"{diff} requests in {now - checkpoint:.3f}s, "
                f"{diff / (now - checkpoint):.3f} req/s."
            )
            counter = new_counter
            checkpoint = now
        else:
            sleep(delay - elapsed)
        now = time.monotonic()
    for coro in POOL.coroutines_running:
        coro.kill()
    POOL.waitall()
    end = time.monotonic()
    rate = RESULTS / (end - start)
    print(f"End. {RESULTS} requests in {end - start:.3f}s, " f"{rate:.3f} req/s.")
    return rate


def main(threads, delay=10.0, duration=60.0):
    global API, CS_ADDR
    admin = AdminClient(
        {"namespace": API.namespace}, pôol_manager=API.container.pool_manager
    )
    stats_before = admin.service_get_stats(CS_ADDR)
    update_duration_before = stats_before.get(
        "req.time.hub_update", 0
    ) / stats_before.get("req.hits.hub_update", 1)

    main_loop(threads, delay=delay, duration=duration)

    stats_after = admin.service_get_stats(CS_ADDR)
    if "req.time.hub_update" in stats_after:
        update_duration_after = (
            stats_after.get("req.time.hub_update", 0)
            - stats_before.get("req.time.hub_update", 0)
        ) / (
            stats_after.get("req.hits.hub_update", 1)
            - stats_before.get("req.hits.hub_update", 0)
        )
        print(
            "Inter-conscience update before: "
            f"{update_duration_before:.3f}µs per service"
        )
        print(
            "Inter-conscience update during benchmark: "
            f"{update_duration_after:.3f}µs per service"
        )


if __name__ == "__main__":
    import os
    import sys

    THREADS = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    NS = os.getenv("OIO_NS", "OPENIO")
    NS_CONF = load_namespace_conf(NS)
    CS_ADDR = NS_CONF["conscience"].split(",")[0]
    API = ObjectStorageApi(NS)
    POOL = GreenPool(THREADS)
    main(THREADS)
