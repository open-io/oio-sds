
from oio.common.utils import paths_gen
from oio.blob.utils import check_volume, read_chunk_metadata
from oio.container.client import ContainerClient
from oio.common import exceptions as exc


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
        self.namespace, self.volume_id = check_volume(self.volume)
        conf = dict()
        conf['namespace'] = self.namespace
        self.client = ContainerClient(conf)

    def pass_with_lock(self):
        with lock_volume(self.volume):
            return self.pass_without_lock()

    def pass_without_lock(self):
        paths = paths_gen(self.volume)
        for path in paths:
            try:
                self._register_chunk(path)
            except Exception as e:
                self.logger.warn("Faulty chunk found at %s: %s", path, str(e))

    def _register_chunk(self, path):
        with open(path) as f:
            try:
                meta = read_chunk_metadata(f)
                self.logger.warn("%s > %s", path, meta)
                pre = meta2bean(self.volume_id, meta)
                post = meta2bean(self.volume_id, meta)
                self.client.raw_update(pre, post,
                                       cid=meta['container_id'],
                                       path=meta['content_path'])
            except exc.MissingAttribute as e:
                raise exc.FaultyChunk('Missing extended attribute %s' % e)
