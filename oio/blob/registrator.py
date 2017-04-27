from contextlib import contextmanager

from oio.common.utils import paths_gen
from oio.blob.utils import check_volume, read_chunk_metadata
from oio.container.client import ContainerClient
from oio.common import exceptions as exc


@contextmanager
def lock_volume(path):
    # TODO xattr-lock the volume
    yield
    # TODO xattr-unlock the volume


def meta2bean(volid, meta):
    return {"type": "chunk",
            "id": "http://" + volid + "/" + meta["chunk_id"],
            "hash": meta['chunk_hash'],
            "size": int(meta["chunk_size"]),
            "pos": meta["chunk_pos"],
            "content": meta["content_id"]}


class BlobRegistratorWorker(object):
    def __init__(self, conf, logger, volume):
        self.conf = conf
        self.logger = logger
        self.volume = volume
        self.namespace = self.conf["namespace"]
        self.volume_ns, self.volume_id = check_volume(self.volume)
        c = dict()
        c['namespace'] = self.namespace
        self.client = ContainerClient(c)

    def pass_with_lock(self):
        with lock_volume(self.volume):
            return self.pass_without_lock()

    def pass_without_lock(self):
        if self.namespace != self.volume_ns:
            self.logger.warn("Forcing the NS to [%s] (previously [%s])",
                             self.namespace, self.volume_ns)
        # TODO(jfs): do the startup reporting
        paths = paths_gen(self.volume)
        for path in paths:
            try:
                self._register_chunk(path)
                # TODO(jfs): do the throttling
            except Exception as e:
                self.logger.warn("Faulty chunk found at %s: %s", path, str(e))
            # TODO(jfs): do the periodical reporting
        # TODO(jfs): do the final reporting

    def _register_chunk(self, path):
        with open(path) as f:
            try:
                meta = read_chunk_metadata(f)
                cid = meta['container_id']
                if str(meta['chunk_pos']).startswith('0'):
                    if not self.conf['first']:
                        self.logger.info("skip %s from %s", path, cid)
                        return
                pre = meta2bean(self.volume_id, meta)
                post = meta2bean(self.volume_id, meta)
                self.client.raw_update(pre, post, cid=cid,
                                       path=meta['content_path'])
                self.logger.info("registered %s in %s", path, cid)
            except exc.MissingAttribute as e:
                raise exc.FaultyChunk('Missing extended attribute %s' % e)
