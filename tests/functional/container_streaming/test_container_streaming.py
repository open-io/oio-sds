# coding: utf-8
import random
import tarfile
from io import BytesIO
import itertools

import requests
from oio import ObjectStorageApi
from tests.utils import BaseTestCase


def random_container(pfx=""):
    return '{0}content-{1}'.format(pfx, random.randint(0, 65536))

def gen_data(size):
    with open("/dev/urandom", "rb") as rand:
        return rand.read(size)

def gen_names():
    index = 0
    for c0 in "01234567":
        for c1 in "01234567":
            i, index = index, index + 1
            yield i, '{0}/{1}/plop'.format(c0, c1)


# class TestContainerDownload(TestCase):
class TestContainerDownload(BaseTestCase):

    def setUp(self):
        super(TestContainerDownload, self).setUp()
        # FIXME: should we use direct API from BaseTestCase or still container.client ?
        self.conn = ObjectStorageApi(self.ns)
        self._streaming = 'http://' + self.get_service_url('admin')[2] + '/'
        self._cnt = random_container()
        self._uri = self._streaming + self._cnt
        self._data = {}
        self.conn.container_create(self.account, self._cnt)
        self.raw = ""

    def tearDown(self):
        for name in self._data:
            self.conn.object_delete(self.account, self._cnt, name)
        self.conn.container_delete(self.account, self._cnt)
        super(TestContainerDownload, self).tearDown()

    def _create_data(self):
        for idx, name in itertools.islice(gen_names(), 5):
            data = gen_data(513 * idx)
            self._data[name] = data
            self.conn.object_create(self.account, self._cnt, obj_name=name, data=data)

    def test_missing_container(self):
        ret = requests.get(self._streaming + random_container("ms-"))
        self.assertEqual(ret.status_code, 404)

    def test_invalid_url(self):
        ret = requests.get(self._streaming)
        self.assertEqual(ret.status_code, 404)

        ret = requests.head(self._streaming + random_container('inv')
                            + '/' +  random_container('inv'))
        self.assertEqual(ret.status_code, 404)

    def test_download_empty_container(self):
        ret = requests.get(self._uri)
        self.assertEqual(ret.status_code, 204)

    def test_simple_download(self):
        self._create_data()

        ret = requests.get(self._uri)
        self.assertGreater(len(ret.content), 0)
        self.assertEqual(ret.status_code, 200)
        self.raw = ret.content

        raw = BytesIO(ret.content)
        tar = tarfile.open(fileobj=raw)
        info = self._data.keys()
        for entry in tar.getnames():
            self.assertIn(entry, info)

            tmp = tar.extractfile(entry)
            self.assertEqual(self._data[entry], tmp.read())

            info.remove(entry)

        self.assertEqual(len(info), 0)

    def test_download_per_range(self):
        self._create_data()

        org = requests.get(self._uri)

        data = []
        for idx in xrange(0, int(org.headers['content-length']), 512):
            ret = requests.get(self._uri, headers={'Range': 'bytes=%d-%d' % (idx, idx+511)})
            data.append(ret.content)

        data = "".join(data)
        self.assertGreater(len(data), 0)
        self.assertEqual(org.content, data)

    def test_invalid_range(self):
        self._create_data()

        ranges = ((-512, 511), (512, 0), (1, 3), (98888, 99999))
        for start, end in ranges:
            ret = requests.get(self._uri, headers={'Range': 'bytes=%d-%d' % (start, end)})
            self.assertEqual(ret.status_code, 416, "for range %d-%d" % (start, end))

        ret = requests.get(self._uri, headers={'Range': 'bytes=0-511, 512-1023'})
        self.assertEqual(ret.status_code, 416)
