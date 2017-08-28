# coding: utf-8

# Copyright (C) 2017-2017 OpenIO SAS, as part of OpenIO SDS
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

from hashlib import md5
import random
import tarfile
from io import BytesIO
import itertools
import json
import string
from tempfile import TemporaryFile
import unittest

import requests
from oio.api.object_storage import ObjectStorageApi
from oio.container.backup import CONTAINER_PROPERTIES, CONTAINER_MANIFEST
from tests.utils import BaseTestCase
from nose.plugins.attrib import attr


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


# random selection from http://www.columbia.edu/~fdc/utf8/
CHARSET = [
    "طوقونمز",
    "ᛖᚴ ᚷᛖᛏ ᛖᛏᛁ",
    "शक्नोम्यत्तुम्",
    "يؤلمني",
    "က္ယ္ဝန္‌တော္‌",
    "私はガ",
    "yishą́ągo",
    ]

MIMETYPE = [
    "application/x-bzip",
    "image/png",
    "audio/vorbis",
    "video/3gpp2",
    "multipart/signed"
    ]


def rand_byte(n):
    return ''.join([chr(random.randint(32, 255)) for _ in xrange(n)])


def rand_str(n):
    return ''.join([random.choice(string.ascii_letters) for i in xrange(n)])


def rand_charset(_):
    return random.choice(CHARSET)


def gen_charset_names():
    index = 0
    for c0 in "01234567":
        for c1 in "01234567":
            i, index = index, index + 1
            yield i, '{0}/{1}/plop'.format(c0, random.choice(CHARSET))


def gen_byte_names():
    index = 0
    for c0 in "01234567":
        for c1 in "01234567":
            i, index = index, index + 1
            yield i, '{0}/{1}/plop'.format(c0, rand_byte(10))


def gen_metadata():
    name = rand_str(20)
    value = rand_str(100)
    return (name, value)


def gen_byte_metadata():
    name = rand_str(20)
    value = rand_byte(100)
    return (name, value)


def gen_charset_metadata():
    name = random.choice(CHARSET)
    value = random.choice(CHARSET)
    return (name, value)


# class TestContainerDownload(TestCase):
class TestContainerDownload(BaseTestCase):

    def setUp(self):
        super(TestContainerDownload, self).setUp()
        # FIXME: should we use direct API from BaseTestCase
        #        or still container.client ?
        self.conn = ObjectStorageApi(self.ns)
        self._streaming = 'http://' + self.get_service_url('container')[2]
        self._cnt = random_container()
        self._uri = self.make_uri('dump')
        self._data = {}
        self.conn.container_create(self.account, self._cnt)
        self.raw = ""
        self._slo = []

    def make_uri(self, action, account=None, container=None):
        account = account or self.account
        container = container or self._cnt
        return '%s/v1.0/container/%s?acct=%s&ref=%s' % (self._streaming,
                                                        action, account,
                                                        container)

    def tearDown(self):
        for name in self._data:
            self.conn.object_delete(self.account, self._cnt, name)
        self.conn.container_delete(self.account, self._cnt)
        super(TestContainerDownload, self).tearDown()

    def _create_data(self, name=gen_names, metadata=None, size=513):
        for idx, _name in itertools.islice(name(), 5):
            data = gen_data(size * idx)
            mime = random.choice(MIMETYPE)
            entry = {'data': data, 'meta': None, 'mime': mime}
            self.conn.object_create(self.account, self._cnt, obj_name=_name,
                                    data=data, mime_type=mime)
            if metadata:
                entry['meta'] = {}
                for _ in xrange(10):
                    key, val = metadata()
                    entry['meta'][key] = val
                    self.conn.object_update(self.account, self._cnt, _name,
                                            entry['meta'])
            self._data[_name] = entry

    def _create_s3_slo(self, name=gen_names, metadata=None):
        # create a fake S3 bucket with a SLO object
        chunksize = 10000
        parts = 5
        res = []
        full_data = ""
        self.conn.container_create(self.account, self._cnt + '+segments')
        _name = "toto"
        etag = rand_str(50)
        part_number = 1
        for size in [chunksize] * parts + [444]:
            data = gen_data(size)
            res.append({
                'bytes': size,
                'content_type': 'application/octect-stream',
                'hash': md5(data).hexdigest().upper(),
                'last_modified': '2017-06-21T12:42:47.000000',
                'name': '/%s+segments/%s/%s/%d' % (self._cnt, _name, etag,
                                                   part_number)
            })
            self.conn.object_create(self.account, "%s+segments" % self._cnt,
                                    obj_name='%s/%s/%d' % (_name, etag,
                                                           part_number),
                                    data=data)
            full_data += data
            part_number += 1

        self._data[_name] = {'data': full_data, 'meta': {
            'x-static-large-object': 'true',
            'x-object-sysmeta-slo-etag': etag,
            'x-object-sysmeta-slo-size': str(len(full_data))
        }}
        self._slo.append(_name)
        data = json.dumps(res)
        self.conn.object_create(self.account, self._cnt, obj_name=_name,
                                data=data)
        self.conn.object_update(self.account, self._cnt, _name,
                                self._data[_name]['meta'])

    def _simple_download(self, name=gen_names, metadata=None):
        self._create_data(name, metadata)

        ret = requests.get(self._uri)
        self.assertGreater(len(ret.content), 0)
        self.assertEqual(ret.status_code, 200)
        self.raw = ret.content

        with TemporaryFile() as tmpfile:
            tmpfile.write(self.raw)

        raw = BytesIO(ret.content)
        tar = tarfile.open(fileobj=raw, ignore_zeros=True)
        info = self._data.keys()
        for entry in tar.getnames():
            if entry == CONTAINER_MANIFEST:
                # skip special entry
                continue

            self.assertIn(entry, info)

            tmp = tar.extractfile(entry)
            self.assertEqual(self._data[entry]['data'], tmp.read())
            info.remove(entry)

        self.assertEqual(info, [])
        return tar

    def _check_metadata(self, tar):
        for entry in tar.getnames():
            if entry == CONTAINER_MANIFEST:
                # skip special entry
                continue
            headers = tar.getmember(entry).pax_headers
            keys = headers.keys()[:]
            for key, val in self._data[entry]['meta'].items():
                key = u"SCHILY.xattr.user." + key.decode('utf-8')
                self.assertIn(key, headers)
                self.assertEqual(val.decode('utf-8'), headers[key])
                keys.remove(key)
            #
            self.assertEqual(self._data[entry]['mime'], headers['mime_type'])
            keys.remove('mime_type')
            #
            self.assertEqual(keys, [])

    def test_missing_container(self):
        ret = requests.get(self._streaming + '/' + random_container("ms-"))
        self.assertEqual(ret.status_code, 404)

    def test_invalid_url(self):
        ret = requests.get(self._streaming)
        self.assertEqual(ret.status_code, 404)

        ret = requests.head(self._streaming + '/' + random_container('inv')
                            + '/' + random_container('inv'))
        self.assertEqual(ret.status_code, 404)

    def test_download_empty_container(self):
        ret = requests.get(self._uri)
        self.assertEqual(ret.status_code, 204)

    def test_simple_download(self):
        self._simple_download()

    def test_check_head(self):
        self._create_data()

        get = requests.get(self._uri)
        head = requests.head(self._uri)

        self.assertEqual(get.headers['content-length'],
                         head.headers['content-length'])

    def test_download_per_range(self):
        self._create_data()

        org = requests.get(self._uri)

        data = []
        for idx in xrange(0, int(org.headers['content-length']), 512):
            ret = requests.get(self._uri, headers={'Range': 'bytes=%d-%d' %
                                                            (idx, idx+511)})
            self.assertIn(ret.status_code, [200, 206])
            data.append(ret.content)

        data = "".join(data)
        self.assertGreater(len(data), 0)
        self.assertEqual(md5(data).hexdigest(), md5(org.content).hexdigest())

    def test_invalid_range(self):
        self._create_data()

        ranges = ((-512, 511), (512, 0), (1, 3), (98888, 99999))
        for start, end in ranges:
            ret = requests.get(self._uri, headers={'Range': 'bytes=%d-%d' %
                                                            (start, end)})
            self.assertEqual(ret.status_code, 416,
                             "Invalid error code for range %d-%d" %
                             (start, end))

        ret = requests.get(self._uri,
                           headers={'Range': 'bytes=0-511, 512-1023'})
        self.assertEqual(ret.status_code, 416)

    def test_file_metadata(self):
        tar = self._simple_download(metadata=gen_metadata)
        self._check_metadata(tar)

    def test_container_metadata(self):
        key, val = gen_metadata()
        ret = self.conn.container_update(self.account, self._cnt, {key: val})
        ret = self.conn.container_show(self.account, self._cnt)
        ret = requests.get(self._uri)
        self.assertEqual(ret.status_code, 200)

        raw = BytesIO(ret.content)
        tar = tarfile.open(fileobj=raw, ignore_zeros=True)
        self.assertIn(CONTAINER_PROPERTIES, tar.getnames())

        data = json.load(tar.extractfile(CONTAINER_PROPERTIES))
        self.assertIn(key, data)
        self.assertEqual(val, data[key])

    def test_charset_file(self):
        self._simple_download(name=gen_charset_names)

    @unittest.skip("wip")
    def test_byte_metadata(self):
        tar = self._simple_download(metadata=gen_byte_metadata)
        self._check_metadata(tar)

    def test_charset_metadata(self):
        tar = self._simple_download(metadata=gen_charset_metadata)
        self._check_metadata(tar)

    @attr('s3')
    def test_s3_simple_download(self):
        self._create_s3_slo()
        ret = requests.get(self._uri)
        self.assertGreater(len(ret.content), 0)
        self.assertEqual(ret.status_code, 200)
        self.raw = ret.content

        raw = BytesIO(ret.content)
        tar = tarfile.open(fileobj=raw, ignore_zeros=True)
        info = self._data.keys()
        for entry in tar.getnames():
            if entry == CONTAINER_MANIFEST:
                # skip special entry
                continue
            self.assertIn(entry, info)

            tmp = tar.extractfile(entry)
            self.assertEqual(self._data[entry]['data'], tmp.read())
            info.remove(entry)

        self.assertEqual(len(info), 0)
        return tar

    @attr('s3')
    def test_s3_range_download(self):
        self._create_s3_slo()
        org = requests.get(self._uri)

        data = []
        for idx in xrange(0, int(org.headers['content-length']), 512):
            ret = requests.get(self._uri, headers={'Range': 'bytes=%d-%d' %
                                                            (idx, idx+511)})
            self.assertIn(ret.status_code, [200, 206])
            data.append(ret.content)

        data = "".join(data)
        self.assertGreater(len(data), 0)
        self.assertEqual(md5(data).hexdigest(), md5(org.content).hexdigest())

    @attr('s3')
    def test_s3_check_slo_metadata_download(self):
        self._create_s3_slo()

        org = requests.get(self.make_uri('dump'))
        self.assertEqual(org.status_code, 200)

        cnt = rand_str(20)
        res = requests.put(self.make_uri('restore', container=cnt),
                           data=org.content)
        self.assertEqual(org.status_code, 200)

        res = self.conn.object_get_properties(self.account, cnt, self._slo[0])
        props = res['properties']
        self.assertNotIn('x-static-large-object', props)
        self.assertNotIn('x-object-sysmeta-slo-size', props)
        self.assertNotIn('x-object-sysmeta-slo-etag', props)

    @attr('simple')
    def test_simple_restore(self):
        self._create_data(metadata=gen_metadata)
        org = requests.get(self.make_uri('dump'))
        cnt = rand_str(20)
        res = requests.put(self.make_uri('restore', container=cnt),
                           data=org.content)
        self.assertEqual(res.status_code, 201)
        ret = self.conn.object_list(account=self.account, container=cnt)
        names = self._data.keys()
        for obj in ret['objects']:
            name = obj['name']
            self.assertIn(name, self._data)
            self.assertEqual(obj['size'], len(self._data[name]['data']))
            meta = self.conn.object_get_properties(self.account, cnt, name)
            self.assertEqual(meta['properties'], self._data[name]['meta'])
            names.remove(name)
        self.assertEqual(len(names), 0)

    @attr('restore')
    def test_multipart_restore(self):
        self._create_data(metadata=gen_metadata, size=1025*1024)
        org = requests.get(self.make_uri('dump'))
        cnt = rand_str(20)
        size = 1014 * 1024
        parts = [org.content[x:x+size] for x in xrange(0, len(org.content),
                                                       size)]
        uri = self.make_uri('restore', container=cnt)
        start = 0
        for part in parts:
            hdrs = {'Range': 'bytes=%d-%d' % (start, start + len(part) - 1)}
            res = requests.put(uri, data=part, headers=hdrs)
            start += len(part)
            self.assertIn(res.status_code, [201, 206])

    @attr('restore')
    def test_multipart_invalid_restore(self):
        self._create_data(metadata=gen_metadata, size=1025*1024)
        org = requests.get(self.make_uri('dump'))
        cnt = rand_str(20)
        uri = self.make_uri('restore', container=cnt)
        size = 1014 * 1024
        parts = [org.content[x:x+size] for x in xrange(0, len(org.content),
                                                       size)]
        start = 0

        for part in parts:
            hdrs = {'Range': 'bytes=%d-%d' % (start, start + len(part) - 1)}
            res = requests.put(uri, data=part, headers=hdrs)
            self.assertIn(res.status_code, [201, 206])
            start += len(part)

            # only unfinished restoration expose X-Consumed-Size
            if res.status_code == 206:
                res = requests.head(uri)
                self.assertEqual(int(res.headers['X-Consumed-Size']), start)

            inv = requests.put(uri, data=part, headers=hdrs)
            self.assertEqual(inv.status_code, 422)

            if res.status_code == 206:
                res = requests.head(uri)
                self.assertEqual(int(res.headers['X-Consumed-Size']), start)

        cnt = rand_str(20)
        uri = self.make_uri('restore', container=cnt)

        hdrs = {'Range': 'bytes=%d-%d' % (size, size + len(parts[1]) - 1)}
        res = requests.put(uri, data=part, headers=hdrs)
        self.assertEqual(res.status_code, 422)
