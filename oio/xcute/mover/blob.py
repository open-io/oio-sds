from oio import xcute
from oio.rdir.client import RdirClient


class SingleBlobMove(object):
    def __init__(self, ns, srvid, chunkid):
        self.ns = ns
        self.srvid = srvid
        self.chunkid = chunkid

    def __call__(self, _handle):
        # TODO(jfs): call the actual blob mover logic
        raise Exception("Not implemented")


class PageBlobMover(object):
    def __init__(self, config):
        super(BlobMover, self).__init__()
        self.ns = kwargs.get("ns")
        self.srvid = kwargs.get("srvid")
        self.start = kwargs.get("marker")
        self.limit = kwargs.get("limit")

    def __call__(self, handle):
        spawned = set()
        client = xcute.ClientAsync(self.ns, handle.source.back_url())
        rdir = RdirClient({'namespace': self.ns})
        for chunk in rdir.chunk_fetch(self.srvid,
                                      limit=self.limit,
                                      start_after=self.start):
            todo = SingleBlobMove(self.ns, self.srvid, chunk['addr'])
            job_id = client.start(None, todo)
            spawned.add(job_id)
        for job_id in spawned:
            client.join(job_id)
