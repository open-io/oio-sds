import string
import random
import hashlib
import gzip
import os

import requests

import xattr

from tests.utils import BaseTestCase


class FakeContent(object):
    def __init__(self, path, size, id_r, nb_chunks):
        self.path = path
        self.size = size
        self.id_container = id_r
        self.nb_chunks = nb_chunks


class FakeChunk(object):
    def __init__(self, size, id_r, pos, md5):
        self.size = size
        self.chunk_id = id_r
        self.pos = pos
        self.md5 = md5


def rand_generator(self, dictionary, n):
    return ''.join(random.choice(dictionary) for _ in range(n))


class TestBlobFunctional(BaseTestCase):
    def setUp(self):
        super(TestBlobFunctional, self).setUp()
        self.namespace = self.conf['namespace']

        self.rawx = 'http://' + self.conf["rawx"][0] + '/'
        self.session = requests.session()
        self.id_chars = string.digits + 'ABCDEF'

        self.chars = (string.ascii_lowercase + string.ascii_uppercase +
                      string.digits)
        self.chars_id = string.digits + 'ABCDEF'

        self.h = hashlib.new('md5')

        self.content_data = rand_generator(self.chars, 24)
        self.url_rand = rand_generator(self.chars_id, 64)
        self.h.update(self.content_data)
        self.hash_rand = self.h.hexdigest().lower()

        self.content = FakeContent(
            rand_generator(self.chars, 6), len(self.content_data),
            self.url_rand, 1)
        self.chunk = FakeChunk(
            self.content.size, self.url_rand, 0, self.hash_rand)

        self.headers_put = {'X-oio-chunk-meta-content-path': self.content.path,
                            'X-oio-chunk-meta-content-size': self.content.size,
                            'X-oio-chunk-meta-content-chunksnb':
                                self.content.nb_chunks,
                            'X-oio-chunk-meta-container-id':
                                self.content.id_container,
                            'X-oio-chunk-meta-chunk-id': self.chunk.chunk_id,
                            'X-oio-chunk-meta-chunk-size': self.chunk.size,
                            'X-oio-chunk-meta-chunk-pos': self.chunk.pos,
                            'X-oio-chunk-meta-chunk-hash': self.hash_rand}
        self.chunk_path = (self.test_dir + 'data/NS-rawx-1/' +
                           self.chunk.chunk_id[0:2] + "/" +
                           self.chunk.chunk_id)

    def tearDown(self):
        super(TestBlobFunctional, self).tearDown()
        try:
            os.remove(self.chunk_path)
        except Exception:
            pass

        try:
            os.removedirs(
                self.test_dir + 'data/NS-rawx-1/' + self.chunk.chunk_id[0:2])
        except Exception:
            pass

        if not (os.path.isdir(self.test_dir + 'data/NS-rawx-1/')):
            os.makedirs(self.test_dir + 'data/NS-rawx-1/')

    def setup_again(self, length):

        if length == 0:
            self.content_data = ""
        else:
            self.content_data = rand_generator(self.chars, length)

        self.content.size = length
        self.chunk.size = length

        self.h.update(self.content_data)
        self.hash_rand = self.h.hexdigest().lower()
        self.chunk.md5 = self.hash_rand

        self.headers_put = {'X-oio-chunk-meta-content-path': self.content.path,
                            'X-oio-chunk-meta-content-size': self.content.size,
                            'X-oio-chunk-meta-content-chunksnb':
                                self.content.nb_chunks,
                            'X-oio-chunk-meta-container-id':
                                self.content.id_container,
                            'X-oio-chunk-meta-chunk-id': self.chunk.chunk_id,
                            'X-oio-chunk-meta-chunk-size': self.chunk.size,
                            'X-oio-chunk-meta-chunk-pos': self.chunk.pos,
                            'X-oio-chunk-meta-chunk-hash': self.hash_rand}
        self.chunk_path = (self.test_dir + 'data/NS-rawx-1/' +
                           self.chunk.chunk_id[0:2] + "/" +
                           self.chunk.chunk_id)

    def setup_compressed(self, tmpfile, length):

        if length == 0:
            self.content_data = ""
        else:
            self.content_data = rand_generator('data', length)

        gzip.GzipFile(fileobj=tmpfile, mode="wb").write(self.content_data)
        tmpfile.seek(0, 0)

        self.content.size = tmpfile.tell()
        self.chunk.size = self.content.size

        self.h.update(self.content_data)
        self.hash_rand = self.h.hexdigest().lower()
        self.chunk.md5 = self.hash_rand

        self.headers_put = {'X-oio-chunk-meta-content-path': self.content.path,
                            'X-oio-chunk-meta-content-size': self.content.size,
                            'X-oio-chunk-meta-content-chunksnb':
                                self.content.nb_chunks,
                            'X-oio-chunk-meta-container-id':
                                self.content.id_container,
                            'X-oio-chunk-meta-chunk-id': self.chunk.chunk_id,
                            'X-oio-chunk-meta-chunk-size': self.chunk.size,
                            'X-oio-chunk-meta-chunk-pos': self.chunk.pos,
                            'X-oio-chunk-meta-chunk-hash': self.hash_rand,
                            'Transfer_encoding': 'gzip'}
        self.chunk_path = (self.test_dir + 'data/NS-rawx-1/' +
                           self.chunk.chunk_id[0:2] + "/" +
                           self.chunk.chunk_id)

    def init_chunk(self):
        resp = self.session.put(self.rawx + self.chunk.chunk_id,
                                data=self.content_data,
                                headers=self.headers_put)

        return resp

    def test_put(self):

        resp = self.session.put(self.rawx + self.chunk.chunk_id,
                                data=self.content_data,
                                headers=self.headers_put)
        self.assertEqual(resp.status_code, 201)

        with open(self.chunk_path) as f:
            self.chunk_data = f.read()
        self.assertEqual(self.chunk_data, self.content_data)

    def test_put_empty(self):

        self.setup_again(0)

        self.session.put(self.rawx + self.chunk.chunk_id,
                         data=self.content_data,
                         headers=self.headers_put)

        with open(self.chunk_path) as f:
            self.chunk_data = f.read()
        self.assertEqual(self.chunk_data, "")

    def test_put_no_chunk_position(self):

        del self.headers_put['X-oio-chunk-meta-chunk-pos']

        resp = self.init_chunk()
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(os.path.isfile(self.chunk_path), False)

    def test_put_no_chunk_size(self):

        del self.headers_put['X-oio-chunk-meta-chunk-size']

        resp = self.init_chunk()
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(os.path.isfile(self.chunk_path), False)

    def test_put_no_chunk_id(self):

        del self.headers_put['X-oio-chunk-meta-chunk-id']

        resp = self.init_chunk()
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(os.path.isfile(self.chunk_path), False)

    def test_put_no_number_chunks(self):

        del self.headers_put['X-oio-chunk-meta-content-chunksnb']

        resp = self.init_chunk()
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(os.path.isfile(self.chunk_path), False)

    def test_put_no_container_id(self):

        del self.headers_put['X-oio-chunk-meta-container-id']

        resp = self.init_chunk()
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(os.path.isfile(self.chunk_path), False)

    def test_put_no_content_size(self):

        del self.headers_put['X-oio-chunk-meta-content-size']

        resp = self.init_chunk()
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(os.path.isfile(self.chunk_path), False)

    def test_put_no_content_path(self):

        del self.headers_put['X-oio-chunk-meta-content-path']

        resp = self.init_chunk()
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(os.path.isfile(self.chunk_path), False)

    def test_get(self):

        self.init_chunk()

        resp = self.session.get(self.rawx + self.chunk.chunk_id)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content, self.content_data)

    def test_get_empty(self):

        self.setup_again(0)

        self.init_chunk()

        resp = self.session.get(self.rawx + self.chunk.chunk_id)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content, "")

    def test_get_range(self):

        self.init_chunk()

        resp = self.session.get(self.rawx + self.chunk.chunk_id,
                                headers={'Range': 'bytes=5-10'})
        self.assertEqual(resp.status_code, 206)
        self.assertEqual(resp.content, self.content_data[5:11])

    def test_get_range_empty(self):

        self.setup_again(0)

        self.init_chunk()

        resp = self.session.get(self.rawx + self.chunk.chunk_id,
                                headers={'Range': 'bytes=5-10'})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content, "")

    def test_get_range_1M(self):

        self.setup_again(1310720)

        self.init_chunk()

        resp = self.session.get(self.rawx + self.chunk.chunk_id,
                                headers={'Range': 'bytes=5-10005'})
        self.assertEqual(resp.status_code, 206)
        self.assertEqual(resp.content, self.content_data[5:10006])

    def test_get_attr(self):

        self.init_chunk()

        resp = self.session.get(self.rawx + self.chunk.chunk_id).headers
        self.assertEqual(resp["X-oio-chunk-meta-content-path"],
                         self.content.path)
        self.assertEqual(resp["X-oio-chunk-meta-content-size"],
                         str(self.content.size))
        self.assertEqual(resp["X-oio-chunk-meta-content-chunksnb"],
                         str(self.content.nb_chunks))
        self.assertEqual(resp["X-oio-chunk-meta-container-id"],
                         self.content.id_container)
        self.assertEqual(resp["X-oio-chunk-meta-chunk-id"],
                         self.chunk.chunk_id)
        self.assertEqual(resp["X-oio-chunk-meta-chunk-size"],
                         str(self.chunk.size))
        self.assertEqual(resp["X-oio-chunk-meta-chunk-pos"],
                         str(self.chunk.pos))

    def test_check_attr(self):

        self.init_chunk()

        self.assertEqual(
            xattr.getxattr(self.chunk_path, 'user.grid.content.path'),
            self.content.path)
        self.assertEqual(
            xattr.getxattr(self.chunk_path, 'user.grid.content.nbchunk'),
            str(self.content.nb_chunks))
        self.assertEqual(xattr.getxattr(self.chunk_path, 'user.grid.chunk.id'),
                         self.chunk.chunk_id)
        self.assertEqual(
            xattr.getxattr(self.chunk_path, 'user.grid.chunk.size'),
            str(self.chunk.size))
        self.assertEqual(
            xattr.getxattr(self.chunk_path, 'user.grid.content.size'),
            str(self.content.size))
        self.assertEqual(
            xattr.getxattr(self.chunk_path, 'user.grid.chunk.position'),
            str(self.chunk.pos))
        self.assertEqual(
            xattr.getxattr(self.chunk_path, 'user.grid.content.container'),
            self.content.id_container)

    def test_get_hash(self):

        self.init_chunk()
        h = hashlib.new('md5')
        h.update(self.content_data)
        handmade_hash = h.hexdigest().upper()

        resp = self.session.get(self.rawx + self.chunk.chunk_id).headers[
            "X-oio-chunk-meta-chunk-hash"]
        self.assertEqual(resp, handmade_hash)

    def test_put_correct_hash(self):

        h = hashlib.new('md5')
        h.update(self.content_data)
        handmade_hash = h.hexdigest().upper()
        self.headers_put['X-oio-chunk-meta-chunk-hash'] = handmade_hash

        self.init_chunk()

        resp = self.session.get(self.rawx + self.chunk.chunk_id).headers[
            "X-oio-chunk-meta-chunk-hash"]
        self.assertEqual(resp, handmade_hash)

        self.assertEqual(
            xattr.getxattr(self.chunk_path, 'user.grid.chunk.hash'),
            handmade_hash)

    def test_put_wrong_hash(self):

        self.headers_put[
            'X-oio-chunk-meta-chunk-hash'] = '00000000000000000000000000000000'

        self.init_chunk()

        h = hashlib.new('md5')
        h.update(self.content_data)
        handmade_hash = h.hexdigest().upper()

        resp = self.session.get(self.rawx + self.chunk.chunk_id).headers[
            "X-oio-chunk-meta-chunk-hash"]
        self.assertEqual(resp, handmade_hash)

        self.assertEqual(
            xattr.getxattr(self.chunk_path, 'user.grid.chunk.hash'),
            handmade_hash)

    def test_delete(self):

        self.init_chunk()

        resp = self.session.delete(self.rawx + self.chunk.chunk_id)
        self.assertEqual(resp.status_code, 204)

        resp = os.listdir(
            self.test_dir + 'data/NS-rawx-1/' + self.chunk.chunk_id[0:2])
        self.assertEqual(resp, [])
