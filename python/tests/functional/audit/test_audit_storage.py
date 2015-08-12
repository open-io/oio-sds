import unittest
import json
import string
import hashlib
import random

import os
import requests

import xattr
from oio.common.utils import get_logger
from oio.blob.auditor import BlobAuditorWorker
from tests.functional.audit import load_functest_config
from oio.common import exceptions as exc


class TestFeaturesFunctional(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestFeaturesFunctional, self).__init__(*args, **kwargs)
        self._load_config()

    def _load_config(self):

        config = load_functest_config()

        self.test_dir = os.path.expanduser('~/.oio/sds/')
        with open(self.test_dir + 'conf/test.conf') as f:
            self.conf = json.load(f)
        self.namespace = self.conf['namespace']
        self.proxyd = self.conf['proxyd_uri'] + '/v3.0/' + self.namespace
        self.account = self.conf['account']

        self.session = requests.session()

        self.chars = string.ascii_lowercase + string.ascii_uppercase + string.digits
        self.chars_id = string.digits + 'ABCDEF'

        self.addr_ref = self.proxyd + "/reference"
        self.addr_container = self.proxyd + "/container"
        self.addr_content = self.proxyd + "/content"

        self.rawx = 'http://' + self.conf["rawx"][0] + '/'

        self.h = hashlib.new('md5')

        self.auditor = BlobAuditorWorker(config, get_logger(config),
                                         config.get('volume'))

    def rand_generator(self, dictionary, n):

        return ''.join(random.choice(dictionary) for _ in range(n))

    class content_test(object):
        def __init__(self, path, size, id_r, nb_chunks):
            self.path = path
            self.size = size
            self.id_container = id_r
            self.nb_chunks = nb_chunks

    class chunk_test(object):
        def __init__(self, size, id_r, pos, md5):
            self.size = size
            self.id_chunk = id_r
            self.pos = pos
            self.md5 = md5

    def setUp(self):

        super(TestFeaturesFunctional, self).setUp()

        self.ref = self.rand_generator(self.chars, 8)

        self.session.post(self.addr_ref + "/create",
                          params={"acct": self.account, "ref": self.ref})
        self.session.post(self.addr_ref + "/link",
                          params={"type": "meta2", "acct": self.account,
                                  "ref": self.ref})
        self.session.post(self.addr_container + "/create",
                          params={"acct": self.account, "ref": self.ref})

        self.url_rand = self.rand_generator(self.chars_id, 64)

        self.data = self.rand_generator(self.chars, 1280)
        self.h.update(self.data)
        self.hash_rand = self.h.hexdigest().lower()

        self.content = self.content_test(self.rand_generator(self.chars, 6),
                                         len(self.data), self.url_rand, 1)
        self.content.id_container = \
        self.session.get(self.addr_container + "/show",
                         params={"acct": self.account,
                                 "ref": self.ref}).headers[
            "X-oio-container-meta-sys-name"][:64]
        self.chunk = self.chunk_test(self.content.size, self.url_rand, 0,
                                     self.hash_rand)

        self.headers_put = {'X-oio-chunk-meta-content-path': self.content.path,
                            'X-oio-chunk-meta-content-size': self.content.size,
                            'X-oio-chunk-meta-content-chunksnb': self.content.nb_chunks,
                            'X-oio-chunk-meta-container-id': self.content.id_container,
                            'X-oio-chunk-meta-chunk-id': self.chunk.id_chunk,
                            'X-oio-chunk-meta-chunk-size': self.chunk.size,
                            'X-oio-chunk-meta-chunk-pos': self.chunk.pos,
                            'X-oio-chunk-meta-chunk-hash': self.hash_rand}
        self.headers_put_proxy = {'x-oio-content-meta-hash': self.hash_rand,
                                  'x-oio-content-meta-length': self.chunk.size}

        self.chunk_proxy = {"hash": self.chunk.md5, "pos": "0",
                            "size": self.chunk.size,
                            "url": self.rawx + self.chunk.id_chunk}

        self.session.put(self.rawx + self.chunk.id_chunk, data=self.data,
                         headers=self.headers_put)

        self.chunk_path = self.test_dir + 'data/NS-rawx-1/' + self.chunk.id_chunk[
                                                              0:2] + "/" + self.chunk.id_chunk

    def tearDown(self):

        super(TestFeaturesFunctional, self).tearDown()

        for (addr, param) in [(self.addr_content + "/delete",
                               {"acct": self.account, "ref": self.ref,
                                "path": self.content.path}), (
                                  self.addr_container + "/destroy",
                                  {"acct": self.account, "ref": self.ref}), (
                                  self.addr_ref + "/unlink",
                                  {"type": "meta2", "acct": self.account,
                                   "ref": self.ref}), (
                                  self.addr_ref + "/destroy",
                                  {"acct": self.account, "ref": self.ref})]:
            try:
                self.session.post(addr, params=param)
            except Exception:
                pass

        try:
            os.remove(self.chunk_path)
        except Exception:
            pass

        try:
            os.removedirs(
                self.test_dir + 'data/NS-rawx-1/' + self.chunk.id_chunk[0:2])
        except Exception:
            pass

        if not (os.path.isdir(self.test_dir + 'data/NS-rawx-1/')):
            os.makedirs(self.test_dir + 'data/NS-rawx-1/')

    def put_content_proxy(self):

        return self.session.post(self.addr_content + "/create",
                                 headers=self.headers_put_proxy,
                                 data=json.dumps([self.chunk_proxy]),
                                 params={"acct": self.account, "ref": self.ref,
                                         "path": self.content.path})

    def test_optimal_case(self):

        self.put_content_proxy()
        self.auditor.chunk_audit(self.chunk_path)

    def test_deleted_proxy_content(self):

        with self.assertRaises(exc.OrphanChunk):
            self.auditor.chunk_audit(self.chunk_path)

    def test_deleted_proxy_container(self):

        self.session.post(self.addr_container + "/destroy",
                          params={"acct": self.account, "ref": self.ref})

        with self.assertRaises(exc.OrphanChunk):
            self.auditor.chunk_audit(self.chunk_path)

    def test_broken_content_changed_data(self):

        self.put_content_proxy()
        with open(self.chunk_path, "w") as f:
            f.write(self.rand_generator(self.chars, 1280))

        with self.assertRaises(exc.CorruptedChunk):
            self.auditor.chunk_audit(self.chunk_path)

    def test_broken_content_less_data(self):

        self.put_content_proxy()
        with open(self.chunk_path, "w") as f:
            f.write(self.rand_generator(self.chars, 320))

        with self.assertRaises(exc.FaultyChunk):
            self.auditor.chunk_audit(self.chunk_path)

    def test_broken_content_more_data(self):

        self.put_content_proxy()
        with open(self.chunk_path, "a") as f:
            f.write(self.rand_generator(self.chars, 3840))

        with self.assertRaises(exc.FaultyChunk):
            self.auditor.chunk_audit(self.chunk_path)

    def test_xattr_bad_content_nbchunk(self):

        self.put_content_proxy()
        xattr.setxattr(self.chunk_path, 'user.grid.content.nbchunk', '42')

        with self.assertRaises(Exception):
            self.auditor.chunk_audit(self.chunk_path)

    def test_xattr_bad_chunk_size(self):

        self.put_content_proxy()
        xattr.setxattr(self.chunk_path, 'user.grid.chunk.size', '320')

        with self.assertRaises(exc.FaultyChunk):
            self.auditor.chunk_audit(self.chunk_path)

    def test_xattr_bad_chunk_hash(self):

        self.put_content_proxy()
        xattr.setxattr(self.chunk_path, 'user.grid.chunk.hash', 'WRONG_HASH')

        with self.assertRaises(exc.CorruptedChunk):
            self.auditor.chunk_audit(self.chunk_path)

    def test_xattr_bad_content_size(self):

        self.put_content_proxy()
        xattr.setxattr(self.chunk_path, 'user.grid.content.size', '320')

        with self.assertRaises(Exception):
            self.auditor.chunk_audit(self.chunk_path)

    def test_xattr_bad_content_path(self):

        self.put_content_proxy()
        xattr.setxattr(self.chunk_path, 'user.grid.content.path', 'WRONG_PATH')

        with self.assertRaises(exc.OrphanChunk):
            self.auditor.chunk_audit(self.chunk_path)

    def test_xattr_bad_chunk_id(self):

        self.put_content_proxy()
        xattr.setxattr(self.chunk_path, 'user.grid.chunk.id', 'WRONG_ID')

        with self.assertRaises(exc.OrphanChunk):
            self.auditor.chunk_audit(self.chunk_path)

    def test_xattr_bad_content_container(self):

        self.put_content_proxy()
        xattr.setxattr(self.chunk_path, 'user.grid.content.container',
                       'WRONG_CONTAINER')

        with self.assertRaises(exc.ClientException):
            self.auditor.chunk_audit(self.chunk_path)

    def test_xattr_bad_chunk_position(self):

        self.put_content_proxy()
        xattr.setxattr(self.chunk_path, 'user.grid.chunk.position', '42')

        with self.assertRaises(exc.FaultyChunk):
            self.auditor.chunk_audit(self.chunk_path)

    def test_missing_rawx_chunk(self):

        self.put_content_proxy()
        try:
            os.remove(self.chunk_path)
        except Exception:
            pass

        try:
            os.removedirs(
                self.test_dir + 'data/NS-rawx-1/' + self.chunk.id_chunk[0:2])
        except Exception:
            pass

        with self.assertRaises(IOError):
            self.auditor.chunk_audit(self.chunk_path)

    def test_chunk_bad_hash(self):

        data2 = self.rand_generator(self.chars, 320)
        self.h.update(self.data)
        self.hash_rand = self.h.hexdigest().lower()
        self.chunk.md5 = self.hash_rand
        self.chunk_proxy['hash'] = self.chunk.md5
        self.headers_put_proxy['x-oio-content-meta-hash'] = self.chunk.md5
        self.put_content_proxy()

        with self.assertRaises(exc.FaultyChunk):
            self.auditor.chunk_audit(self.chunk_path)

    def test_chunk_bad_length(self):

        self.chunk.size = 320
        self.chunk_proxy['size'] = self.chunk.size
        self.headers_put_proxy['x-oio-content-meta-length'] = self.chunk.size
        self.put_content_proxy()

        with self.assertRaises(exc.FaultyChunk):
            self.auditor.chunk_audit(self.chunk_path)

    def test_chunk_bad_pos(self):

        self.chunk.size = '320'
        self.chunk_proxy['size'] = self.chunk.size
        self.put_content_proxy()

        with self.assertRaises(exc.OrphanChunk):
            self.auditor.chunk_audit(self.chunk_path)

    def test_chunk_bad_url(self):

        self.chunk.id_chunk = 'WRONG_ID'
        self.chunk_proxy['url'] = self.rawx + self.chunk.id_chunk
        self.put_content_proxy()

        with self.assertRaises(exc.OrphanChunk):
            self.auditor.chunk_audit(self.chunk_path)

    def test_content_bad_path(self):

        true_path = self.content.path
        self.content.path = 'BAD_PATH'
        self.put_content_proxy()

        with self.assertRaises(IOError):
            self.auditor.chunk_audit(true_path)
