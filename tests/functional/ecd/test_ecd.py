# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import random
from six.moves.urllib_parse import urlparse

from tests.utils import BaseTestCase, random_data, random_str
from oio.api.object_storage import _sort_chunks
from oio.common.constants import CHUNK_METADATA_PREFIX
from oio.common.storage_method import STORAGE_METHODS


class TestECD(BaseTestCase):

    def setUp(self):
        super(TestECD, self).setUp()
        self.ecd_conf = random.choice(self.conf['services']['ecd'])
        self.ecd_addr = self.ecd_conf['addr']
        self.ecd_url = 'http://' + self.ecd_addr
        if len(self.conf['services']['rawx']) < 9:
            self.skipTest("need at least 9 rawx to run")

    def _download_metachunk(self, meta, chunks):
        headers = dict()
        headers[CHUNK_METADATA_PREFIX + "content-chunk-method"] = \
            meta['chunk_method']
        headers[CHUNK_METADATA_PREFIX + "chunk-size"] = \
            meta['chunk_size']
        for chunk in chunks:
            headers[CHUNK_METADATA_PREFIX + "chunk-" + str(chunk['num'])] = \
                chunk['real_url']
        resp = self.request('GET', self.ecd_url, headers=headers)
        return resp

    def _test_download(self, length):
        container = random_str(8)
        obj = random_str(8)
        expected_data = random_data(length)
        chunks, _, _, meta = self.storage.object_create_ext(
            self.account, container, obj_name=obj, data=expected_data,
            policy='EC')
        storage_method = STORAGE_METHODS.load(meta['chunk_method'])
        sorted_chunks = _sort_chunks(chunks, storage_method.ec)

        data = b''
        for pos in range(len(sorted_chunks)):
            resp = self._download_metachunk(meta, sorted_chunks[pos])
            self.assertEqual(200, resp.status)
            data += resp.data
        self.assertEqual(expected_data, data)

    def test_download_0(self):
        self._test_download(0)

    def test_download_1K(self):
        self._test_download(1024)

    def test_download_10K(self):
        self._test_download(1024*10)

    def test_download_100K(self):
        self._test_download(1024*100)

    def test_download_1M(self):
        self._test_download(1024*1024)

    def test_download_10M(self):
        self._test_download(1024*1024*10)

    def test_download_with_missing_chunks(self):
        container = random_str(8)
        obj = random_str(8)
        expected_data = random_data(10)
        chunks, _, _, meta = self.storage.object_create_ext(
            self.account, container, obj_name=obj, data=expected_data,
            policy='EC')
        storage_method = STORAGE_METHODS.load(meta['chunk_method'])
        sorted_chunks = _sort_chunks(chunks, storage_method.ec)

        for i in range(storage_method.ec_nb_parity):
            data = b''
            for pos in range(len(sorted_chunks)):
                chunk = random.choice(sorted_chunks[pos])
                sorted_chunks[pos].remove(chunk)
                resp = self._download_metachunk(meta, sorted_chunks[pos])
                self.assertEqual(200, resp.status)
                data += resp.data
            self.assertEqual(expected_data, data)

        for pos in range(len(sorted_chunks)):
            chunk = random.choice(sorted_chunks[pos])
            sorted_chunks[pos].remove(chunk)
            resp = self._download_metachunk(meta, sorted_chunks[pos])
            self.assertEqual(500, resp.status)

    def test_download_with_lost_chunks(self):
        container = random_str(8)
        obj = random_str(8)
        expected_data = random_data(10)
        chunks, _, _, meta = self.storage.object_create_ext(
            self.account, container, obj_name=obj, data=expected_data,
            policy='EC')
        storage_method = STORAGE_METHODS.load(meta['chunk_method'])
        sorted_chunks = _sort_chunks(chunks, storage_method.ec)

        sorted_present_chunks = sorted_chunks.copy()
        for i in range(storage_method.ec_nb_parity):
            data = b''
            for pos in range(len(sorted_chunks)):
                chunk = random.choice(sorted_present_chunks[pos])
                sorted_present_chunks[pos].remove(chunk)
                self.request('DELETE', chunk['real_url'])
                resp = self._download_metachunk(meta, sorted_chunks[pos])
                self.assertEqual(200, resp.status)
                data += resp.data
            self.assertEqual(expected_data, data)

        for pos in range(len(sorted_chunks)):
            chunk = random.choice(sorted_present_chunks[pos])
            sorted_present_chunks[pos].remove(chunk)
            self.request('DELETE', chunk['real_url'])
            resp = self._download_metachunk(meta, sorted_chunks[pos])
            self.assertEqual(500, resp.status)

    def test_download_with_stopped_rawx(self):
        container = random_str(8)
        obj = random_str(8)
        expected_data = random_data(10)
        chunks, _, _, meta = self.storage.object_create_ext(
            self.account, container, obj_name=obj, data=expected_data,
            policy='EC')
        storage_method = STORAGE_METHODS.load(meta['chunk_method'])
        sorted_chunks = _sort_chunks(chunks, storage_method.ec)

        sorted_present_chunks = sorted_chunks.copy()
        try:
            for i in range(storage_method.ec_nb_parity):
                data = b''
                for pos in range(len(sorted_chunks)):
                    if pos == 0:
                        chunk = random.choice(sorted_present_chunks[pos])
                        sorted_present_chunks[pos].remove(chunk)
                        gridinit_key = self.service_to_gridinit_key(
                            urlparse(chunk['url']).netloc, 'rawx')
                        self._service(gridinit_key, 'stop')
                    resp = self._download_metachunk(meta, sorted_chunks[pos])
                    self.assertEqual(200, resp.status)
                    data += resp.data
                self.assertEqual(expected_data, data)

            chunk = random.choice(sorted_present_chunks[0])
            sorted_present_chunks[0].remove(chunk)
            gridinit_key = self.service_to_gridinit_key(
                urlparse(chunk['url']).netloc, 'rawx')
            self._service(gridinit_key, 'stop')
            resp = self._download_metachunk(meta, sorted_chunks[pos])
            self.assertEqual(500, resp.status)
        finally:
            self._service('@rawx', 'start')
