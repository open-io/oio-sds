#!/usr/bin/env python2

import sys
import time
import random
from oio.event.consumer import EventTypes
from oio.conscience.client import ConscienceClient
from oio.rdir.client import RdirClient


CHUNK_EVENTS = [EventTypes.CHUNK_DELETED, EventTypes.CHUNK_NEW]


class Harasser(object):
    def __init__(self, ns, max_containers=256, max_contents=256):
        conf = {'namespace': ns}
        self.cs = ConscienceClient(conf)
        self.rdir = RdirClient(conf)
        self.rawx_list = [x['addr'] for x in self.cs.all_services('rawx')]
        self.sent = set()
        self.max_containers = max_containers
        self.max_contents = max_contents
        self.pushed_count = 0
        self.pushed_time = 0
        self.removed_count = 0
        self.removed_time = 0

    def harass_put(self, loops=None):
        if loops is None:
            loops = random.randint(1000, 2000)
        print "Pushing %d fake chunks" % loops
        loop = loops
        count_start_container = random.randrange(2**20)
        count_start_content = random.randrange(2**20)
        start = time.time()
        nb_rawx = len(self.rawx_list)
        while loop > 0:
            args = {'mtime': int(start)}
            # vol_id = random.choice(self.rawx_list)
            # container_id = "%064X" % (random.randrange(self.max_containers))
            # content_id = "%032X" % (random.randrange(self.max_contents))
            vol_id = self.rawx_list[loop % nb_rawx]
            container_id = "%064X" % (loop + count_start_container)
            content_id = "%032X" % (loop + count_start_content)
            chunk_id = "http://%s/%064X" \
                % (vol_id, random.randrange(2**128))
            self.rdir.chunk_push(
                vol_id, container_id, content_id, chunk_id, **args)
            self.sent.add((vol_id, container_id, content_id, chunk_id))
            loop -= 1
        end = time.time()
        self.pushed_count += loops
        self.pushed_time += end-start
        print "%d pushed in %.3fs, %d req/s" \
            % (loops, end-start, loops/(end-start))

    def harass_del(self, min_loops=0):
        min_loops = min(min_loops, len(self.sent))
        loops = random.randint(min_loops, len(self.sent))
        print "Removing %d fake chunks" % loops
        loop = loops
        start = time.time()
        while loop > 0:
            args = self.sent.pop()
            self.rdir.chunk_delete(*args)
            loop -= 1
        end = time.time()
        self.removed_count += loops
        self.removed_time += end-start
        print "%d removed in %.3fs, %d req/s" \
            % (loops, end-start, loops/(end-start))

    def __call__(self):
        try:
            while True:
                self.harass_put()
                self.harass_del()
        except KeyboardInterrupt:
            print "Cleaning..."
            self.harass_del(len(self.sent))
            print "Stats:"
            print "Pushed %d in %.3fs, %d req/s" % (self.pushed_count,
                                                    self.pushed_time,
                                                    self.pushed_count /
                                                    self.pushed_time)
            print "Removed %d in %.3fs, %d req/s" % (self.removed_count,
                                                     self.removed_time,
                                                     self.removed_count /
                                                     self.removed_time)


if __name__ == '__main__':
    if len(sys.argv) > 3:
        HARASS = Harasser(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))
    elif len(sys.argv) > 2:
        HARASS = Harasser(sys.argv[1], int(sys.argv[2]))
    elif len(sys.argv) > 1:
        HARASS = Harasser(sys.argv[1])
    else:
        print "usage: %s NS [NB_CONTAINERS [NB_CONTENTS]]" % sys.argv[0]
        sys.exit(1)
    HARASS()
