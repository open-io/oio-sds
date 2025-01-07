#!/usr/bin/env python

# Copyright (C) 2019-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2023 OVH SAS
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

# parser
import argparse
import os
import time

from eventlet import monkey_patch, sleep
from eventlet.greenpool import GreenPool
from eventlet.queue import LightQueue

from oio import ObjectStorageApi
from oio.common.utils import depaginate

monkey_patch()

# globals
ACCOUNT = None
API = None
POOL = None
RESULTS = None
POLICY = None


def create_loop(container, prefix, obj_count):
    iteration = 0
    while True:
        name = prefix + str(iteration)
        iteration += 1
        if iteration > obj_count > 0:
            break
        try:
            API.object_create(ACCOUNT, container, obj_name=name, data="", policy=POLICY)
            RESULTS.put((container, name))
            sleep(0)
        except Exception as err:
            print(err)


def list_objects(container):
    objects_iter = depaginate(
        API.object_list,
        listing_key=lambda x: x["objects"],
        marker_key=lambda x: x.get("next_marker"),
        truncated_key=lambda x: x["truncated"],
        account=ACCOUNT,
        container=container,
        limit=5000,
    )
    return [obj["name"] for obj in objects_iter]


def compute_meta2_db_size(container):
    container_result = API.container_get_properties(ACCOUNT, container, admin_mode=True)
    page_count = int(container_result["system"]["stats.page_count"])
    page_size = int(container_result["system"]["stats.page_size"])
    meta2_db_size = page_count * page_size
    print(
        "Meta2 database size: %d bytes, page count: %d, page size: %d."
        % (meta2_db_size, page_count, page_size)
    )
    return meta2_db_size


def create_objects_in_period(threads, delay=5.0, duration=60.0, clean=True):
    counter = 0
    created = list()
    cname = "benchmark-%d" % int(time.time())
    now = start = checkpoint = time.time()
    POOL.starmap(create_loop, [(cname, "%d-" % n, 0) for n in range(threads)])
    while now - start < duration:
        res = RESULTS.get()
        counter += 1
        if now - checkpoint > delay:
            print(
                "%d objects in %fs, %f objects per second."
                % (counter, now - checkpoint, counter / (now - checkpoint))
            )
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
    print(
        "End. %d objects created in %fs, %f objects per second."
        % (len(created), end - start, rate)
    )
    print("Listing.")
    start = time.time()
    all_objects = list_objects(cname)
    end = time.time()
    print(
        "Listing %d objects took %fs seconds, %f objects per second."
        % (len(all_objects), end - start, len(all_objects) / (end - start))
    )
    compute_meta2_db_size(cname)
    if clean:
        print("Cleaning...")
        for _ in POOL.starmap(
            API.object_delete, [(ACCOUNT, cname, obj) for obj in all_objects]
        ):
            pass
        POOL.waitall()
    return rate


def create_fixed_number_of_objects(threads, delay=5.0, obj_count=1000, clean=True):
    counter = 0
    created = list()
    cname = "benchmark-%d" % int(time.time())
    quotient, remainder = divmod(obj_count, threads)
    portion_to_generate = list()
    for i in range(threads):
        nb_objects = quotient
        if i < remainder:
            nb_objects += 1
        portion_to_generate.append(nb_objects)

    now = start = checkpoint = time.time()
    POOL.starmap(
        create_loop,
        [(cname, "%d-" % n, portion_to_generate[n]) for n in range(threads)],
    )
    while len(created) < obj_count:
        res = RESULTS.get()
        counter += 1
        if now - checkpoint > delay:
            print(
                "%d objects in %fs, %f objects per second."
                % (counter, now - checkpoint, counter / (now - checkpoint))
            )
            counter = 0
            checkpoint = now
        created.append(res)
        now = time.time()

    end = time.time()
    rate = len(created) / (end - start)
    print(
        "End. %d objects created in %fs, %f objects per second."
        % (len(created), end - start, rate)
    )
    print("Listing.")
    start = time.time()
    all_objects = list_objects(cname)
    end = time.time()
    print(
        "Listing %d objects took %fs seconds, %f objects per second."
        % (len(all_objects), end - start, len(all_objects) / (end - start))
    )
    compute_meta2_db_size(cname)
    if clean:
        print("Cleaning...")
        for _ in POOL.starmap(
            API.object_delete, [(ACCOUNT, cname, obj) for obj in all_objects]
        ):
            pass
        POOL.waitall()
    return rate


def _object_upload(ul_handler, **kwargs):
    ul_chunks = ul_handler.chunk_prep()
    return next(ul_chunks), 0, "d41d8cd98f00b204e9800998ecf8427e"


USAGE = """Concurrently create many fake objects in the same container.
The account name is taken from the OIO_ACCOUNT environement variable, the
container name is 'benchmark-' followed by a timestamp.
Does not create chunks, just save chunk addresses.
"""


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=USAGE)
    parser.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=1,
        help="Number of coroutines to spawn (1 by default).",
    )
    parser.add_argument(
        "-s",
        "--storage-policy",
        "--policy",
        type=str,
        default="SINGLE",
        help='Storage policy of the fake objects ("SINGLE" by default).',
    )
    parser.add_argument(
        "-d",
        "--duration",
        type=float,
        help="Keep generating objects for this duration (60s by default).",
    )
    parser.add_argument(
        "-n",
        "--object-count",
        type=int,
        help="Total number of objects to create (duration will be ignored).",
    )
    parser.add_argument(
        "--do-not-clean",
        action="store_false",
        dest="clean",
        help="Do not clean the container after the benchmark.",
    )

    args = parser.parse_args()

    THREADS = args.concurrency
    POLICY = args.storage_policy
    DURATION = 60.0
    OBJECT_COUNT = 1000

    CREATION_MODE = "duration"
    if args.duration is not None:
        CREATION_MODE = "duration"
        DURATION = args.duration
    if args.object_count is not None:
        CREATION_MODE = "object count"

    ACCOUNT = os.getenv("OIO_ACCOUNT", "benchmark")
    API = ObjectStorageApi(os.getenv("OIO_NS", "OPENIO"))
    API._object_upload = _object_upload
    RESULTS = LightQueue(THREADS * 10)
    POOL = GreenPool(THREADS)

    if CREATION_MODE == "duration":
        print("Creating objects during %f seconds." % DURATION)
        create_objects_in_period(THREADS, duration=DURATION, clean=args.clean)
    else:
        print("Creating %d objects." % args.object_count)
        create_fixed_number_of_objects(
            THREADS, obj_count=args.object_count, clean=args.clean
        )
