import unittest
import json
import os
import string
import random
import md5
import gzip
import StringIO
import tempfile

import requests

import xattr

class TestConscienceFunctional(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestConscienceFunctional, self).__init__(*args, **kwargs)
        self._load_config()

    def _load_config(self):
        self.test_dir = os.path.expanduser('~/.oio/sds/')
        with open(self.test_dir + 'conf/test.conf') as f:
	    self.conf = json.load(f)
	self.namespace = self.conf['namespace']

        self.rawx = 'http://' + self.conf["rawx"][0] + '/'
        self.session = requests.session()
        self.id_chars = string.digits + 'ABCDEF'
        self.rand_chars = string.digits + string.ascii_lowercase + string.ascii_uppercase

    def gen_rand(self, r_type, i):
        if r_type == 'id':
            return ''.join(random.choice(self.id_chars) for _ in range(64))
        else:
            return ''.join(random.choice(self.rand_chars) for _ in range(i))

    class fakeContent(object):
        def __init__(self, path, size, id_r):
            self.path = path
            self.size = size
            self.cont_id = id_r

        def get_nb_chunks(self):
            return 1

    class fakeChunk(object):
        def __init__(self, size, id_r):
            self.size = size
            self.chunk_id = id_r

        def get_position(self):
            return 0

        def get_md5(self):
            return "f0419b9e3cd4c0da4dba99feb6233f54"

    def setUp(self):
        super(TestConscienceFunctional, self).setUp()
        self.content_data = self.gen_rand('data', 24)
        self.content = self.fakeContent('c1', len(self.content_data),
                                        self.gen_rand('id', 64))
        self.chunk = self.fakeChunk(self.content.size, self.gen_rand('id', 64))

        self.headers_put = {'content_path': self.content.path,
                            'content_size': self.content.size,
                            'content_chunksnb': self.content.get_nb_chunks(),
                            'content_containerid': self.content.cont_id,
                            'chunk_id': self.chunk.chunk_id,
                            'chunk_size': self.chunk.size,
                            'chunk_position': self.chunk.get_position()}
        self.chunk_path = self.test_dir + 'data/NS-rawx-1/' + self.chunk.chunk_id[
                                                              0:2] + "/" + self.chunk.chunk_id

    def tearDown(self):
        print ""
        super(TestConscienceFunctional, self).tearDown()
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
            self.content_data = self.gen_rand('data', length)
        self.content = self.fakeContent('c1', len(self.content_data),
                                        self.gen_rand('id', 64))
        self.chunk = self.fakeChunk(self.content.size, self.gen_rand('id', 64))

        self.headers_put = {'content_path': self.content.path,
                            'content_size': self.content.size,
                            'content_chunksnb': self.content.get_nb_chunks(),
                            'content_containerid': self.content.cont_id,
                            'chunk_id': self.chunk.chunk_id,
                            'chunk_size': self.chunk.size,
                            'chunk_position': self.chunk.get_position()}
        self.chunk_path = self.test_dir + 'data/NS-rawx-1/' + self.chunk.chunk_id[
                                                              0:2] + "/" + self.chunk.chunk_id

    def setup_compressed(self, tmpfile, length):

        if length == 0:
            self.content_data = ""
        else:
            self.content_data = self.gen_rand('data', length)

        gzip.GzipFile(fileobj=tmpfile, mode="wb").write(self.content_data)
        tmpfile.seek(0, 0)

        self.content = self.fakeContent('c1', tmpfile.tell(),
                                        self.gen_rand('id', 64))
        self.chunk = self.fakeChunk(self.content.size, self.gen_rand('id', 64))

        self.headers_put = {'content_path': self.content.path,
                            'content_size': self.content.size,
                            'content_chunksnb': self.content.get_nb_chunks(),
                            'content_containerid': self.content.cont_id,
                            'chunk_id': self.chunk.chunk_id,
                            'chunk_size': self.chunk.size,
                            'chunk_position': self.chunk.get_position(),
                            'Transfer_encoding': 'gzip'}

        self.chunk_path = self.test_dir + 'data/NS-rawx-1/' + self.chunk.chunk_id[
                                                              0:2] + "/" + self.chunk.chunk_id

    def prepare_compressed(self, length):

        with tempfile.NamedTemporaryFile(delete=True) as gzfile:
            self.setup_compressed(gzfile, 24)

            resp = self.session.put(self.rawx + self.chunk.chunk_id,
                                    data=gzfile, headers=self.headers_put)
            self.assertEqual(resp.status_code, 201)

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

        p = self.session.put(self.rawx + self.chunk.chunk_id,
                             data=self.content_data,
                             headers=self.headers_put)

        with open(self.chunk_path) as f:
            self.chunk_data = f.read()
        self.assertEqual(self.chunk_data, "")

    def test_put_no_chunk_position(self):

        del self.headers_put['chunk_position']

        resp = self.init_chunk()
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(os.path.isfile(self.chunk_path), True)

        resp = self.session.get(self.rawx + self.chunk.chunk_id).headers
        self.assertFalse('chunk_position' in resp.keys())

    def test_put_no_chunk_size(self):

        del self.headers_put['chunk_size']

        resp = self.init_chunk()
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(os.path.isfile(self.chunk_path), True)

        resp = self.session.get(self.rawx + self.chunk.chunk_id).headers
        self.assertFalse('chunk_size' in resp.keys())

    def test_put_no_chunk_id(self):

        del self.headers_put['chunk_id']

        resp = self.init_chunk()
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(os.path.isfile(self.chunk_path), True)

        resp = self.session.get(self.rawx + self.chunk.chunk_id).headers
        self.assertFalse('chunk_id' in resp.keys())

    def test_put_no_number_chunks(self):

        del self.headers_put['content_chunksnb']

        resp = self.init_chunk()
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(os.path.isfile(self.chunk_path), True)

        resp = self.session.get(self.rawx + self.chunk.chunk_id).headers
        self.assertFalse('content_chunksnb' in resp.keys())

    def test_put_no_container_id(self):

        del self.headers_put['content_containerid']

        resp = self.init_chunk()
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(os.path.isfile(self.chunk_path), True)

        resp = self.session.get(self.rawx + self.chunk.chunk_id).headers
        self.assertFalse('content_containerid' in resp.keys())

    def test_put_no_content_size(self):

        del self.headers_put['content_size']

        resp = self.init_chunk()
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(os.path.isfile(self.chunk_path), True)

        resp = self.session.get(self.rawx + self.chunk.chunk_id).headers
        self.assertFalse('content_size' in resp.keys())

    def test_put_no_content_path(self):

        del self.headers_put['content_path']

        resp = self.init_chunk()
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(os.path.isfile(self.chunk_path), True)

        resp = self.session.get(self.rawx + self.chunk.chunk_id).headers
        self.assertFalse('content_path' in resp.keys())

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

    def test_put_compress(self):

        with tempfile.NamedTemporaryFile(delete=True) as gzfile:
            self.setup_compressed(gzfile, 24)

            resp = self.session.put(self.rawx + self.chunk.chunk_id,
                                    data=gzfile, headers=self.headers_put)
            self.assertEqual(resp.status_code, 201)

        with open(self.chunk_path) as f:
            data_to_decode = StringIO.StringIO(f.read())
        self.assertEqual(gzip.GzipFile(fileobj=data_to_decode).read(),
                         self.content_data)

    def test_get_compress(self):

        self.prepare_compressed(24)

        resp = self.session.get(self.rawx + self.chunk.chunk_id,
                                headers={'Accept-encoding': 'gzip'})
        self.assertEqual(resp.status_code, 200)
        data_to_decode = StringIO.StringIO(resp.content)
        self.assertEqual(gzip.GzipFile(fileobj=data_to_decode).read(),
                         self.content_data)

    def test_get_compress_empty(self):

        self.prepare_compressed(0)

        resp = self.session.get(self.rawx + self.chunk.chunk_id,
                                headers={'Accept-encoding': 'gzip'})
        self.assertEqual(resp.status_code, 200)
        data_to_decode = StringIO.StringIO(resp.content)
        self.assertEqual(gzip.GzipFile(fileobj=data_to_decode).read(),
                         self.content_data)

    def test_get_compress_1M(self):

        self.prepare_compressed(1310720)

        resp = self.session.get(self.rawx + self.chunk.chunk_id,
                                headers={'Accept-encoding': 'gzip'})
        self.assertEqual(resp.status_code, 200)
        data_to_decode = StringIO.StringIO(resp.content)
        self.assertEqual(gzip.GzipFile(fileobj=data_to_decode).read(),
                         self.content_data)

    def test_get_attr(self):

        self.init_chunk()

        resp = self.session.get(self.rawx + self.chunk.chunk_id).headers
        self.assertEqual(resp["content_path"], self.content.path)
        self.assertEqual(resp["content_size"], str(self.content.size))
        self.assertEqual(resp["content_chunksnb"],
                         str(self.content.get_nb_chunks()))
        self.assertEqual(resp["content_containerid"], self.content.cont_id)
        self.assertEqual(resp["chunk_id"], self.chunk.chunk_id)
        self.assertEqual(resp["chunk_size"], str(self.chunk.size))
        self.assertEqual(resp["chunk_position"], str(self.chunk.get_position()))

    def test_check_attr(self):

        self.init_chunk()

        self.assertEqual(
            xattr.getxattr(self.chunk_path, 'user.grid.content.path'),
            self.content.path)
        self.assertEqual(
            xattr.getxattr(self.chunk_path, 'user.grid.content.nbchunk'),
            str(self.content.get_nb_chunks()))
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
            str(self.chunk.get_position()))
        self.assertEqual(
            xattr.getxattr(self.chunk_path, 'user.grid.content.container'),
            self.content.cont_id)

    def test_get_hash(self):

        self.init_chunk()
        m = md5.new()
        m.update(self.content_data)
        handmade_hash = m.hexdigest().upper()

        resp = self.session.get(self.rawx + self.chunk.chunk_id).headers[
            "chunk_hash"]
        self.assertEqual(resp, handmade_hash)

    def test_put_correct_hash(self):

        m = md5.new()
        m.update(self.content_data)
        handmade_hash = m.hexdigest().upper()
        self.headers_put['chunk_hash'] = handmade_hash

        self.init_chunk()

        resp = self.session.get(self.rawx + self.chunk.chunk_id).headers[
            "chunk_hash"]
        self.assertEqual(resp, handmade_hash)

        self.assertEqual(
            xattr.getxattr(self.chunk_path, 'user.grid.chunk.hash'),
            handmade_hash)

    def test_put_wrong_hash(self):

        self.headers_put['chunk_hash'] = '00000000000000000000000000000000'

        self.init_chunk()

        m = md5.new()
        m.update(self.content_data)
        handmade_hash = m.hexdigest().upper()

        resp = self.session.get(self.rawx + self.chunk.chunk_id).headers[
            "chunk_hash"]
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
