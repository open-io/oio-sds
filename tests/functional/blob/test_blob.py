import string
import random
import os
import os.path
from hashlib import md5
from urlparse import urlparse
from urllib import quote_plus
from oio.common.http import http_connect
from oio.common.constants import OIO_VERSION

from tests.utils import BaseTestCase


def random_buffer(dictionary, n):
    slot = 512
    pattern = ''.join(random.choice(dictionary) for _ in range(slot))
    t = []
    while len(t) * slot < n:
        t.append(pattern)
    return ''.join(t)[:n]


# TODO we should the content of events sent by the rawx
class TestBlobFunctional(BaseTestCase):

    def chunkid(self):
        return random_buffer('0123456789ABCDEF', 64)

    def _chunk_attr(self, name, data):
        return {
            'x-oio-chunk-meta-content-id': '0123456789ABCDEF',
            'x-oio-chunk-meta-content-version': '1456938361143740',
            'x-oio-chunk-meta-content-path': 'test-plop',
            'x-oio-chunk-meta-content-chunk-method':
                'ec/algo=liberasurecode_rs_vand,k=6,m=3',
            'x-oio-chunk-meta-content-storage-policy': 'TESTPOLICY',
            'x-oio-chunk-meta-container-id': '1'*64,
            'x-oio-chunk-meta-chunk-id': name,
            'x-oio-chunk-meta-chunk-size': len(data),
            'x-oio-chunk-meta-chunk-hash': md5(data).hexdigest().upper(),
            'x-oio-chunk-meta-chunk-pos': 0,
            'x-oio-chunk-meta-full-path': quote_plus(('test/test/test' +
                                                      ',test1/test1/test1'),
                                                     ","),
            'x-oio-chunk-meta-oio-version': OIO_VERSION
        }

    def _rawx_url(self, chunkid):
        return '/'.join((self.rawx, chunkid))

    def _chunk_path(self, chunkid):
        chunkid = chunkid.upper()
        return self.rawx_path + '/' + chunkid[:3] + '/' + chunkid

    def setUp(self):
        super(TestBlobFunctional, self).setUp()
        self.namespace = self.conf['namespace']
        self.test_dir = self.conf['sds_path']
        rawx_num, rawx_path, rawx_addr = self.get_service_url('rawx')
        self.rawx = 'http://' + rawx_addr
        self.rawx_path = rawx_path + '/'

    def tearDown(self):
        super(TestBlobFunctional, self).tearDown()

    def _http_request(self, chunkurl, method, body, headers, trailers=None):
        parsed = urlparse(chunkurl)
        if method == 'PUT':
            headers['transfer-encoding'] = 'chunked'
        if trailers:
            headers['Trailer'] = list()
            for k, v in trailers.iteritems():
                headers['Trailer'].append(k)

        conn = http_connect(parsed.netloc, method, parsed.path,
                            headers)
        if method == 'PUT':
            if body:
                conn.send('%x\r\n%s\r\n' % (len(body), body))
            conn.send('0\r\n')
            if trailers:
                for k, v in trailers.iteritems():
                    conn.send('%s: %s\r\n' % (k, v))
            conn.send('\r\n')
        if method == 'PUT':
            del headers['transfer-encoding']
        if trailers:
            del headers['Trailer']

        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        return resp, body

    def _cycle_put(self, length, expected, remove_headers=None):
        chunkid = self.chunkid()
        chunkdata = random_buffer(string.printable, length)
        chunkurl = self._rawx_url(chunkid)
        chunkpath = self._chunk_path(chunkid)
        headers = self._chunk_attr(chunkid, chunkdata)
        if remove_headers:
            for h in remove_headers:
                del headers[h]

        # we do not really care about the actual value
        metachunk_size = 9 * length
        # TODO take random legit value
        metachunk_hash = md5().hexdigest()
        # TODO should also include meta-chunk-hash
        trailers = {'x-oio-chunk-meta-metachunk-size': metachunk_size,
                    'x-oio-chunk-meta-metachunk-hash': metachunk_hash}

        self._check_not_present(chunkurl)

        # Initial put that must succeed
        resp, body = self._http_request(chunkurl, 'PUT', chunkdata, headers,
                                        trailers)
        self.assertEqual(resp.status, expected)
        if expected / 100 != 2:
            self.assertFalse(os.path.isfile(chunkpath))
            return
        # the first PUT succeeded, the second MUST fail
        resp, body = self._http_request(chunkurl, 'PUT', chunkdata, headers,
                                        trailers)
        self.assertEqual(resp.status, 409)
        # check the file if is correct
        with open(chunkpath) as f:
            data = f.read()
            self.assertEqual(data, chunkdata)

        # check the whole download is correct
        # TODO FIXME getting an empty content should return 204
        resp, body = self._http_request(chunkurl, 'GET', '', {})
        self.assertEqual(resp.status, 200)
        self.assertEqual(body, chunkdata)
        headers['x-oio-chunk-meta-metachunk-size'] = metachunk_size
        headers['x-oio-chunk-meta-metachunk-hash'] = metachunk_hash.upper()
        for k, v in headers.items():
            self.assertEqual(resp.getheader(k), str(v))

        # check ranges can be downloaded
        def ranges():
            if length <= 0:
                return
            yield (0, 0)
            if length > 1:
                yield (0, 1)
                yield (0, length-1)
                yield (length-2, length-1)
            if length > 4:
                yield (2, length-3)
        for start, end in ranges():
            r = "bytes={0}-{1}".format(start, end)
            resp, body = self._http_request(chunkurl, 'GET', '', {'Range': r})
            self.assertEqual(resp.status/100, 2)
            self.assertEqual(len(body), end-start+1)
            self.assertEqual(body, chunkdata[start:end+1])
        if length > 0:
            # TODO FIXME getting an unsatisfiable range on an empty content
            # returns "200 OK" with an empty body, but should return 416
            r = "bytes={0}-{1}".format(length, length+1)
            resp, body = self._http_request(chunkurl, 'GET', '', {'Range': r})
            self.assertEqual(resp.status, 416)

        # delete the chunk, check it is missing as expected
        resp, body = self._http_request(chunkurl, 'DELETE', '', {})
        self.assertEqual(resp.status, 204)
        self.assertFalse(os.path.isfile(chunkpath))

        self._check_not_present(chunkurl)

    def test_empty_chunk(self):
        self._cycle_put(0, 201)

    def test_small_chunks(self):
        for i in [1, 2, 3, 4, 32, 64, 128, 256, 512]:
            self._cycle_put(i, 201)

    def test_1K(self):
        self._cycle_put(1024, 201)

    def test_8K(self):
        self._cycle_put(8*1024, 201)

    def test_64K(self):
        self._cycle_put(64*1024, 201)

    def test_1M(self):
        self._cycle_put(1024*1024, 201)

    def test_fat_chunk(self):
        self._cycle_put(1024*1024*128, 201)

    def test_missing_headers(self):
        self._cycle_put(32, 400,
                        remove_headers=['x-oio-chunk-meta-chunk-pos'])
        self._cycle_put(32, 201,
                        remove_headers=['x-oio-chunk-meta-chunk-size'])
        self._cycle_put(32, 201,
                        remove_headers=['x-oio-chunk-meta-chunk-id'])
        self._cycle_put(32, 400,
                        remove_headers=['x-oio-chunk-meta-content-id'])
        self._cycle_put(32, 400,
                        remove_headers=['x-oio-chunk-meta-content-version'])
        self._cycle_put(32, 400,
                        remove_headers=['x-oio-chunk-meta-content-path'])
        self._cycle_put(32, 400,
                        remove_headers=['x-oio-chunk-meta-container-id'])

    def _check_not_present(self, chunkurl):
        resp, body = self._http_request(chunkurl, 'GET', '', {})
        self.assertEqual(resp.status, 404)
        resp, body = self._http_request(chunkurl, 'DELETE', '', {})
        self.assertEqual(resp.status, 404)

    def _check_bad_headers(self, length, bad_headers=None, bad_trailers=None):
        chunkid = self.chunkid()
        chunkdata = random_buffer(string.printable, length)
        chunkurl = self._rawx_url(chunkid)
        headers = self._chunk_attr(chunkid, chunkdata)
        # force the bad headers
        if bad_headers:
            for k, v in bad_headers.items():
                headers[k] = v
        trailers = None
        if bad_trailers:
            trailers = {}
            for k, v in bad_trailers.items():
                trailers[k] = v

        self._check_not_present(chunkurl)

        resp, body = self._http_request(chunkurl, 'PUT', chunkdata, headers,
                                        trailers)
        self.assertEqual(resp.status, 400)

        self._check_not_present(chunkurl)

    def test_bad_chunkhash(self):
        # not hexa
        self._check_bad_headers(
            32, bad_headers={'x-oio-chunk-meta-chunk-hash': '0'})
        self._check_bad_headers(
            32, bad_headers={'x-oio-chunk-meta-chunk-hash': 'xx'})
        # TODO FIXME the rawx should accept only MD5/SHA hashes ...

        # TODO
        # self._check_bad_headers(
        #     32, bad_trailers={'x-oio-chunk-meta-chunk-hash': 'xx'})
        # self._check_bad_headers(
        #     32, bad_trailers={'x-oio-chunk-meta-chunk-hash': 'xx'})

    def test_bad_chunkid(self):
        self._check_bad_headers(
            32, bad_headers={'x-oio-chunk-meta-chunk-id': '00'*32})
