#!/usr/bin/python2.6

import os
import tempfile
import shutil
import subprocess
import time
import httplib
import hashlib
from string import Template
import pygrid.http
import pygrid.services
import io
import binascii
import re

httpd_binary = '/usr/sbin/httpd'
namespace = 'DEVREMI'
rawx_module = '/home/fr19895/src/autotools/rawx-apache2/src/.libs/mod_dav_rawx.so'
rawx_url = ("127.0.0.1", "65535")
chunk_id = '353AB2556F45CD080A0F298230ED926EF378171C598ED765ED82DCB2EFD02640'

class fakeContent(object):
        def __init__(self, path, size):
                self.path = path
                self.size = size
        def get_container_id(self):
                return '080EF86FEA45C8EB69565B3C2C012AD0A2BBAEAC9F8001DE92A2467091584A3B'
        def get_path(self):
                return self.path
        def get_size(self):
                return self.size
        def get_nb_chunks(self):
                return 1

class fakeChunk(object):
        def __init__(self, size):
                self.size = size
        def get_chunk_id(self):
                return binascii.unhexlify(chunk_id)
        def get_size(self):
                return self.size
        def get_position(self):
                return 0
        def get_md5(self):
                return "f0419b9e3cd4c0da4dba99feb6233f54"

class TestData(object):
	def __init__(self):
		self.httpd = None
		self.testDir = tempfile.mkdtemp(dir='/tmp')

def get_chunk_path(data):
	return data.testDir + "/data/" + chunk_id[0:2] + "/" + chunk_id[2:4] + "/" + chunk_id

def setup(data):
	# prepare env
	os.mkdir(data.testDir + '/conf')
	os.mkdir(data.testDir + '/logs')
	os.mkdir(data.testDir + '/run')
	os.mkdir(data.testDir + '/core')
	os.mkdir(data.testDir + '/data')
	os.mkdir(data.testDir + '/root')
	os.symlink('/usr/lib64/httpd/modules', data.testDir + '/modules')
	print 'Created tmp dir in', data.testDir

	# Create config file
	src = open('httpd.conf')
	dst = open(data.testDir + '/conf/httpd.conf', 'w')
	template = Template(src.read())
	dst.write(template.substitute(
		HTTPD_IP=rawx_url[0],
		HTTPD_PORT=rawx_url[1],
		ROOTDIR=data.testDir,
		NAMESPACE=namespace,
		RAWX_MODULE=rawx_module))
	dst.close()
	src.close()

	# Start httpd process and wait 5s
	data.httpd = subprocess.Popen(args=[httpd_binary + " -D FOREGROUND -d " +data.testDir],
			stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
	time.sleep(5)
	data.httpd.poll()
	assert data.httpd.returncode is None, "Failed to start apache process (see logs in " + data.testDir + "/logs/httpd-error.log)" + "\nSTDERR :\n" + data.httpd.stdout.read()

def teardown(data):
	print "teardown"
	# kill httpd server
	data.httpd.terminate()
	# delete test dir
	shutil.rmtree(data.testDir)

def test_put(data):
	print "test_put :",

	content_data = "azertyuiopqsdfghjklmwxcvbn"
	content = fakeContent('c1', len(content_data))
	chunk = fakeChunk(content.get_size())
	http = pygrid.http.make_http_client_from_url(':'.join(rawx_url))
	rawx = pygrid.services.Rawx(namespace, http)

	# Do the put
	rawx.upload(content, chunk, io.BytesIO(content_data))

	# Check the chunk file
	f = open(get_chunk_path(data))
	chunk_data = f.read()
	assert chunk_data == content_data, "Failed => Data in chunk file does not match data sent to apache"
	print "OK"

	# Clean chunk file
	os.remove(get_chunk_path(data))

def test_put_empty(data):
	print "test_put_empty :",

	content_data = ""
	content = fakeContent('c1', 0)
	chunk = fakeChunk(0)
	http = pygrid.http.make_http_client_from_url(':'.join(rawx_url))
	rawx = pygrid.services.Rawx(namespace, http)

	# Do the put
	rawx.upload(content, chunk, io.BytesIO(content_data))

	# Check the chunk file
	info = os.stat(get_chunk_path(data))
	assert info.st_size == 0, "Failed => Chunk file is not empty"
	print "OK"

	# Clean chunk file
	os.remove(get_chunk_path(data))

def test_get(data):
	print "test_get :",

	content_data = "azertyuiopqsdfghjklmwxcvbn"
	content = fakeContent('c1', len(content_data))
	chunk = fakeChunk(content.get_size())
	http = pygrid.http.make_http_client_from_url(':'.join(rawx_url))
	rawx = pygrid.services.Rawx(namespace, http)

	# Do the put
	rawx.upload(content, chunk, io.BytesIO(content_data))

	# Do the get
	(headers, chunk_data) = rawx.download(chunk)

	# Check the data
	assert chunk_data == content_data, "FAILED => Data from apache does not match data sent to apache (" + chunk_data + "/" + content_data + ")"
	print "OK"

	# Clean chunk file
	os.remove(get_chunk_path(data))

def test_get_empty(data):
	print "test_get_empty :",

	content_data = ""
	content = fakeContent('c1', 0)
	chunk = fakeChunk(0)
	http = pygrid.http.make_http_client_from_url(':'.join(rawx_url))
	rawx = pygrid.services.Rawx(namespace, http)

	# Do the put
	rawx.upload(content, chunk, io.BytesIO(content_data))

	# Do the get
	(headers, chunk_data) = rawx.download(chunk)

	# Check the data
	assert chunk_data == "", "FAILED => Data from apache does not match data sent to apache (" + chunk_data + "/)"
	print "OK"

	# Clean chunk file
	os.remove(get_chunk_path(data))

def test_get_range(data):
	print "test_get_range :",

	content_data = "azertyuiopqsdfghjklmwxcvbn"
	content = fakeContent('c1', len(content_data))
	chunk = fakeChunk(content.get_size())
	http = pygrid.http.make_http_client_from_url(':'.join(rawx_url))
	rawx = pygrid.services.Rawx(namespace, http)

	# Do the put
	rawx.upload(content, chunk, io.BytesIO(content_data))

	# Do the range get
	(headers, chunk_data) = rawx.download(chunk, (5, 5))

	# check data
	assert chunk_data == content_data[5:10], "FAILED => Ranged data from apache does not match data sent to apache (" + chunk_data + "/" + content_data[5:10] + ")"
	print "OK"

	# Clean chunk file
	os.remove(get_chunk_path(data))

def test_get_range_empty(data):
	print "test_get_range_empty :",

	content_data = ""
	content = fakeContent('c1', 0)
	chunk = fakeChunk(0)
	http = pygrid.http.make_http_client_from_url(':'.join(rawx_url))
	rawx = pygrid.services.Rawx(namespace, http)

	# Do the put
	rawx.upload(content, chunk, io.BytesIO(content_data))

	# Do the range get
	(headers, chunk_data) = rawx.download(chunk, (5, 5))

	# check data
	assert chunk_data == "", "FAILED => Ranged data from apache does not match data sent to apache (" + chunk_data + "/)"
	print "OK"

	# Clean chunk file
	os.remove(get_chunk_path(data))

def test_get_range_10M(data):
	print "test_get_range_10M :",

	content_data = os.urandom(10485760)
	content = fakeContent('c1', 10485760)
	chunk = fakeChunk(10485760)
	http = pygrid.http.make_http_client_from_url(':'.join(rawx_url))
	rawx = pygrid.services.Rawx(namespace, http)

	# Do the put
	rawx.upload(content, chunk, io.BytesIO(content_data))

	# Do the range get
	(headers, chunk_data) = rawx.download(chunk, (5, 10000))

	# check data
	assert chunk_data == content_data[5:10005], "FAILED => Ranged data from apache does not match data sent to apache (" + chunk_data + "/" + content_data[5:10005] + ")"
	print "OK"

	# Clean chunk file
	os.remove(get_chunk_path(data))

def test_get_compress(data):
	print "test_get_compress :",

	content_data = "azertyuiopqsdfghjklmwxcvbn"
	content = fakeContent('c1', len(content_data))
	chunk = fakeChunk(content.get_size())
	http = pygrid.http.make_http_client_from_url(':'.join(rawx_url))
	rawx = pygrid.services.Rawx(namespace, http)

	# Do the put
	rawx.upload(content, chunk, io.BytesIO(content_data), ('ZLIB', 512000))

	# Do the range get
	(headers, chunk_data) = rawx.download(chunk)

	# check data
	assert chunk_data == content_data, "FAILED => Data from apache does not match data sent to apache (" + chunk_data + "/" + content_data + ")"
	print "OK"

	# Clean chunk file
	os.remove(get_chunk_path(data))

def test_get_compress_empty(data):
	print "test_get_compress_empty :",

	content_data = ""
	content = fakeContent('c1', 0)
	chunk = fakeChunk(content.get_size())
	http = pygrid.http.make_http_client_from_url(':'.join(rawx_url))
	rawx = pygrid.services.Rawx(namespace, http)

	# Do the put
	rawx.upload(content, chunk, io.BytesIO(content_data), ('ZLIB', 512000))

	# Do the range get
	(headers, chunk_data) = rawx.download(chunk)

	# check data
	assert chunk_data == content_data, "FAILED => Data from apache does not match data sent to apache (" + chunk_data + "/" + content_data + ")"
	print "OK"

	# Clean chunk file
	os.remove(get_chunk_path(data))

def test_get_compress_10M(data):
	print "test_get_compress_10M :",

	content_data = os.urandom(10485760)
	content = fakeContent('c1', 10485760)
	chunk = fakeChunk(10485760)
	http = pygrid.http.make_http_client_from_url(':'.join(rawx_url))
	rawx = pygrid.services.Rawx(namespace, http)

	# Do the put
	rawx.upload(content, chunk, io.BytesIO(content_data), ('ZLIB', 512000))

	# Do the range get
	(headers, chunk_data) = rawx.download(chunk)

	# check data
	assert chunk_data == content_data, "FAILED => Ranged data from apache does not match data sent to apache (" + chunk_data + "/" + content_data + ")"
	print "OK"

	# Clean chunk file
	os.remove(get_chunk_path(data))

def test_get_compress_range(data):
	print "test_get_compress_range :",

	content_data = "azertyuiopqsdfghjklmwxcvbn"
	content = fakeContent('c1', len(content_data))
	chunk = fakeChunk(content.get_size())
	http = pygrid.http.make_http_client_from_url(':'.join(rawx_url))
	rawx = pygrid.services.Rawx(namespace, http)

	# Do the put
	rawx.upload(content, chunk, io.BytesIO(content_data), ('ZLIB', 512000))

	# Do the range get
	(headers, chunk_data) = rawx.download(chunk, (5, 5))

	# check data
	assert chunk_data == content_data[5:10], "FAILED => Ranged data from apache does not match data sent to apache (" + chunk_data + "/" + content_data[5:10] + ")"
	print "OK"

	# Clean chunk file
	os.remove(get_chunk_path(data))

def test_get_compress_range_empty(data):
	print "test_get_compress_range_empty :",

	content_data = ""
	content = fakeContent('c1', 0)
	chunk = fakeChunk(0)
	http = pygrid.http.make_http_client_from_url(':'.join(rawx_url))
	rawx = pygrid.services.Rawx(namespace, http)

	# Do the put
	rawx.upload(content, chunk, io.BytesIO(content_data), ('ZLIB', 512000))

	# Do the range get
	(headers, chunk_data) = rawx.download(chunk, (5, 10000))

	# check data
	assert chunk_data == "", "FAILED => Ranged data from apache does not match data sent to apache (" + chunk_data + "/)"
	print "OK"

	# Clean chunk file
	os.remove(get_chunk_path(data))

def test_get_compress_range5_10M(data):
	print "test_get_compress_range5_10M :",

	content_data = os.urandom(10485760)
	content = fakeContent('c1', 10485760)
	chunk = fakeChunk(10485760)
	http = pygrid.http.make_http_client_from_url(':'.join(rawx_url))
	rawx = pygrid.services.Rawx(namespace, http)

	# Do the put
	rawx.upload(content, chunk, io.BytesIO(content_data), ('ZLIB', 512000))

	# Do the range get
	(headers, chunk_data) = rawx.download(chunk, (5, 5))

	# check data
	assert chunk_data == content_data[5:10], "FAILED => Ranged data from apache does not match data sent to apache (" + chunk_data + "/" + content_data[5:10] + ")"
	print "OK"

	# Clean chunk file
	os.remove(get_chunk_path(data))

def test_get_compress_range10000_10M(data):
	print "test_get_compress_range10000_10M :",

	content_data = os.urandom(10485760)
	content = fakeContent('c1', 10485760)
	chunk = fakeChunk(10485760)
	http = pygrid.http.make_http_client_from_url(':'.join(rawx_url))
	rawx = pygrid.services.Rawx(namespace, http)

	# Do the put
	rawx.upload(content, chunk, io.BytesIO(content_data), ('ZLIB', 512000))

	# Do the range get
	(headers, chunk_data) = rawx.download(chunk, (5, 10000))

	# check data
	assert chunk_data == content_data[5:10005], "FAILED => Ranged data from apache does not match data sent to apache (" + chunk_data + "/" + content_data[5:10005] + ")"
	print "OK"

	# Clean chunk file
	os.remove(get_chunk_path(data))

def test_delete(data):
	print "test_delete :",

	content_data = "azertyuiopqsdfghjklmwxcvbn"
	content = fakeContent('c1', len(content_data))
	chunk = fakeChunk(content.get_size())
	http = pygrid.http.make_http_client_from_url(':'.join(rawx_url))
	rawx = pygrid.services.Rawx(namespace, http)

	# Do the put
	rawx.upload(content, chunk, io.BytesIO(content_data))

	# Do the delete
	rawx.delete(chunk)

	# Check the chunk file
	try:
		f = open(get_chunk_path(data))
		assert "Failed => Chunk was not deleted"
	except IOError:
		print "OK"

def test_access_status_code(data):
	print "test_access_status_code :",

	file = open(data.testDir + "/logs/httpd-access.log", "r")
	expr = re.compile(" 2.. ")
	for line in file:
		assert expr.search(line) != None, "FAILED => A test did not return a 2XX reponse (" + line + ")"
	print "OK"


# Do the tests
data = TestData()
setup(data)
try:
	test_put(data)
	test_put_empty(data)
	test_get(data)
	test_get_empty(data)
	test_get_range(data)
	test_get_range_empty(data)
	test_get_range_10M(data)
	test_get_compress(data)
	test_get_compress_empty(data)
	test_get_compress_10M(data)
	test_get_compress_range(data)
	test_get_compress_range_empty(data)
	test_get_compress_range5_10M(data)
	test_get_compress_range10000_10M(data)
	test_delete(data)
	test_access_status_code(data)
except Exception as e:
	print e
finally:
	teardown(data)
