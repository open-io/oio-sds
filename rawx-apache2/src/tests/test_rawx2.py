import unittest
import requests
import json
import os
import string
import random
from src.tests import load_functest_config

class TestConscienceFunctional(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestConscienceFunctional, self).__init__(*args, **kwargs)
        self._load_config()

    def _load_config(self):
        config = load_functest_config()

	self.namespace = config.get('func_test', 'namespace')
	self.test_dir = os.path.expanduser('~/.oio/sds/')
	with open(self.test_dir+'conf/test_py.conf') as f:
		self.IP_list = json.load(f)
	self.rawx = 'http://' + self.IP_list["rawx"][0]+ '/'
        self.session = requests.session()
	self.id_chars = string.digits + 'ABCDEF'
	self.rand_chars = string.digits + string.ascii_lowercase + string.ascii_uppercase

    def gen_rand(self, r_type):
	if r_type=='id':
	    return ''.join(random.choice(self.id_chars) for _ in range(64))
	else:
	    return ''.join(random.choice(self.rand_chars) for _ in range(26))

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
	self.content_data = self.gen_rand('data')
        self.content = self.fakeContent('c1', len(self.content_data), self.gen_rand('id'))
        self.chunk = self.fakeChunk(self.content.size, self.gen_rand('id'))

	self.headers_put = {'content_path': self.content.path, 'content_size': self.content.size, 'content_chunksnb':self.content.get_nb_chunks(), 'content_containerid': self.content.cont_id, 'chunk_id': self.chunk.chunk_id, 'chunk_size': self.chunk.size, 'chunk_position': self.chunk.get_position(), 'chunk_hash': self.chunk.get_md5()}	
	self.chunk_path = self.test_dir+'data/NS-rawx-1/'+self.chunk.chunk_id[0:2] + "/" + self.chunk.chunk_id
	
    def tearDown(self):
        super(TestConscienceFunctional, self).tearDown()
	try:
		os.remove(self.chunk_path)
	except Exception:
	    pass

	try:
		os.removedirs(self.test_dir+'data/NS-rawx-1/'+self.chunk.chunk_id[0:2])
	except Exception:
	    pass

    def init_chunk(self):
	resp=self.session.put(self.rawx+self.chunk.chunk_id, data=self.content_data, headers=self.headers_put)

    def test_put(self):
	resp=self.session.put(self.rawx+self.chunk.chunk_id, data=self.content_data, headers=self.headers_put)
	self.assertEqual(resp.status_code,201)

	with open (self.chunk_path) as f:
		self.chunk_data = f.read()
	self.assertEqual(self.chunk_data,self.content_data)

    def test_get(self):

	self.init_chunk()
	
	resp=self.session.get(self.rawx+self.chunk.chunk_id)
	self.assertEqual(resp.status_code, 200)
	self.assertEqual(resp.content, self.content_data)

    def test_delete(self):
	
	self.init_chunk()

	resp=self.session.delete(self.rawx+self.chunk.chunk_id)
	self.assertEqual(resp.status_code, 204)
	
	resp=os.listdir(self.test_dir+'data/NS-rawx-1/'+self.chunk.chunk_id[0:2])
	self.assertEqual(resp, [])

