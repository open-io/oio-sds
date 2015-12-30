import string
import random
import logging
import hashlib
import os
import os.path
import requests

from tests.utils import BaseTestCase


def random_buffer(dictionary, n):
    slot = 512
    pattern = ''.join(random.choice(dictionary) for _ in range(slot))
    t = []
    while len(t) * slot < n:
        t.append(pattern)
    return ''.join(t)[:n]


class TestBlobFunctional(BaseTestCase):

    def chunkid(self):
        return random_buffer('0123456789ABCDEF', 64)

    def _chunk_attr(self, name, data):
        return {
            'X-oio-chunk-meta-content-id': '0123456789ABCDEF',
            'X-oio-chunk-meta-content-path': 'test-plop',
            'X-oio-chunk-meta-content-mime-type': 'application/octet-stream',
            'X-oio-chunk-meta-content-chunk-method': 'bytes',
            'X-oio-chunk-meta-content-storage-policy': 'TESTPOLICY',
            'X-oio-chunk-meta-content-size': len(data),
            'X-oio-chunk-meta-content-chunksnb': 1,
            'X-oio-chunk-meta-container-id': '1'*64,
            'X-oio-chunk-meta-chunk-id': name,
            'X-oio-chunk-meta-chunk-size': len(data),
            'X-oio-chunk-meta-chunk-pos': 0,
            'X-oio-chunk-meta-chunk-hash': '',
        }

    def _rawx_url(self, chunkid):
        return '/'.join((self.rawx, chunkid))

    def _chunk_path(self, chunkid):
        chunkid = chunkid.upper()
        return self.rawx_path + '/' + chunkid[:2] + '/' + chunkid

    def setUp(self):
        super(TestBlobFunctional, self).setUp()
        self.namespace = self.conf['namespace']
        self.test_dir = self.conf['sds_path']
        self.rawx = 'http://' + self.conf["rawx"][0]['addr']
        self.rawx_path = self.conf["rawx"][0]['path'] + '/'
        self.session = requests.session()

    def tearDown(self):
        super(TestBlobFunctional, self).tearDown()

    def _cycle_put(self, length, expected, remove_headers=[]):
        chunkid = self.chunkid()
        chunkdata = random_buffer(string.printable, length)
        chunkurl = self._rawx_url(chunkid)
        chunkpath = self._chunk_path(chunkid)
        h = hashlib.new('md5')
        h.update(chunkdata)
        chunkhash = h.hexdigest().upper()
        chunkheaders = self._chunk_attr(chunkid, chunkdata)
        for h in remove_headers:
            del chunkheaders[h]

        self._check_not_present(chunkurl)

        # Initial put that must succeed
        resp = self.session.put(chunkurl, data=chunkdata, headers=chunkheaders)
        self.assertEqual(resp.status_code, expected)
        if expected / 100 != 2:
            self.assertFalse(os.path.isfile(chunkpath))
            return
        # the first PUT succeeded, the second MUST fail
        resp = self.session.put(chunkurl, data=chunkdata, headers=chunkheaders)
        self.assertEqual(resp.status_code, 409)
        # check the file if is correct
        with open(chunkpath) as f:
            data = f.read()
            self.assertEqual(data, chunkdata)

        # check the whole download is correct
        # TODO FIXME getting an empty content should return 204
        resp = self.session.get(chunkurl)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.text, chunkdata)
        logging.debug("GOT  %s", repr(resp.headers))
        chunkheaders['X-oio-chunk-meta-chunk-hash'] = chunkhash
        for k, v in chunkheaders.items():
            logging.debug("SENT %s", k)
            self.assertEqual(resp.headers[k], str(v))

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
            resp = self.session.get(chunkurl, headers={"Range": r})
            self.assertEqual(resp.status_code/100, 2)
            self.assertEqual(len(resp.text), end-start+1)
            self.assertEqual(resp.text, chunkdata[start:end+1])
        if length > 0:
            # TODO FIXME getting an unsatisfiable range on an empty content
            # returns "200 OK" with an empty body, but should return 416
            r = "bytes={0}-{1}".format(length, length+1)
            resp = self.session.get(chunkurl, headers={"Range": r, })
            logging.debug("Range(%d-%d) Length(%d)", length, length+1, length)
            self.assertEqual(resp.status_code, 416)

        # delete the chunk, check it is missing as expected
        resp = self.session.delete(chunkurl)
        self.assertEqual(resp.status_code, 204)
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

    def test_missing_headers(self):
        self._cycle_put(32, 201,
                        remove_headers=['X-oio-chunk-meta-chunk-hash'])
        self._cycle_put(32, 400,
                        remove_headers=['X-oio-chunk-meta-chunk-pos'])
        self._cycle_put(32, 201,
                        remove_headers=['X-oio-chunk-meta-chunk-size'])
        self._cycle_put(32, 201,
                        remove_headers=['X-oio-chunk-meta-chunk-id'])
        self._cycle_put(32, 400,
                        remove_headers=['X-oio-chunk-meta-content-id'])
        self._cycle_put(32, 201,
                        remove_headers=['X-oio-chunk-meta-content-chunksnb'])
        self._cycle_put(32, 201,
                        remove_headers=['X-oio-chunk-meta-content-size'])
        self._cycle_put(32, 400,
                        remove_headers=['X-oio-chunk-meta-content-path'])
        self._cycle_put(32, 400,
                        remove_headers=['X-oio-chunk-meta-container-id'])

    def _check_not_present(self, chunkurl):
        resp = self.session.get(chunkurl)
        self.assertEqual(resp.status_code, 404)
        resp = self.session.delete(chunkurl)
        self.assertEqual(resp.status_code, 404)

    def _check_bad_header(self, length, bad_headers):
        chunkid = self.chunkid()
        chunkdata = random_buffer(string.printable, length)
        chunkurl = self._rawx_url(chunkid)
        chunkheaders = self._chunk_attr(chunkid, chunkdata)
        # force the bad headers
        for k, v in bad_headers.items():
            chunkheaders[k] = v

        self._check_not_present(chunkurl)

        resp = self.session.put(chunkurl, data=chunkdata, headers=chunkheaders)
        self.assertEqual(resp.status_code, 400)

        self._check_not_present(chunkurl)

    def test_bad_chunkhash(self):
        # not hexa
        self._check_bad_header(32, {'X-oio-chunk-meta-chunk-hash': '0'})
        self._check_bad_header(32, {'X-oio-chunk-meta-chunk-hash': 'xx'})
        # TODO FIXME the rawx should accept only MD5/SHA hashes ...

    def test_bad_chunkid(self):
        self._check_bad_header(32, {'X-oio-chunk-meta-chunk-id': '00'*32})
