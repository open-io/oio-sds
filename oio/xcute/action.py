from random import randint
from oio.conscience.client import ConscienceClient
from oio.directory.client import DirectoryClient
from oio.rdir.client import RdirClient


class Randomizer(object):
    def __call__(self, handle):
        return randint(0, 65536)


class Iterator(object):
    def __init__(self, idx, limit):
        self.idx = idx
        self.limit = limit
    def __call__(self, handle):
        if self.idx >= self.limit:
            raise StopIteration()
        handle.produce(self.idx)
        handle.recurse(Iterator(self.idx+1, self.limit))


class RawxList(object):
    def __init__(self, ns, srvid, start):
        super(RawxList, self).__init__()
        self.ns = ns
        self.srvid = srvid
        self.start = start
        self.limit = 1

    def __call__(self, handle):
        rdir = RdirClient({'namespace': self.ns})
        last = None
        for chunk in rdir.chunk_fetch(self.srvid,
                                      limit=self.limit,
                                      start_after=self.start):
            handle.produce(chunk)
        if last is None:
            raise StopIteration
        handle.recurse(RawxList(self.ns, self.srvid, last))


class SingleBlobMove(object):
    def __init__(self, ns, srvid, chunkid):
        self.ns = ns
        self.srvid = srvid
        self.chunkid = chunkid

    def __call__(self, handle):
        pass


class PageBlobMover(object):
    def __init__(self, ns, srvid, start):
        super(BlobMover, self).__init__()
        self.ns = ns
        self.srvid = srvid
        self.start = start
        self.limit = 1

    def __call__(self, handle):
        rdir = RdirClient({'namespace': self.ns})
        last = None
        for chunk in rdir.chunk_fetch(self.srvid,
                                      limit=self.limit,
                                      start_after=self.start):
            handle.propagate(SingleBlobMove(self.ns, self.srvid, chunk[0]))
        if last is None:
            raise StopIteration
        handle.recurse(RawxList(self.ns, self.srvid, last))
