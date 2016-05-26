# Copyright (C) 2015 OpenIO, original work as part of
# OpenIO Software Defined Storage
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

from tests.utils import BaseTestCase


class TestRainContent(BaseTestCase):
    def setUp(self):
        super(TestRainContent, self).setUp()

    def tearDown(self):
        super(TestRainContent, self).tearDown()

    def test_upload_0_byte(self):
        self.skipTest("to be re-implemented with the lastest EC methods")

    def test_upload_1_byte(self):
        self.skipTest("to be re-implemented with the lastest EC methods")

    def test_upload_chunksize_bytes(self):
        self.skipTest("to be re-implemented with the lastest EC methods")

    def test_upload_chunksize_plus_1_bytes(self):
        self.skipTest("to be re-implemented with the lastest EC methods")

    def test_chunks_cleanup_when_upload_failed(self):
        self.skipTest("to be re-implemented with the lastest EC methods")

    def test_content_0_byte_rebuild_pos_0_0(self):
        self.skipTest("to be re-implemented with the lastest EC methods")

    def test_content_0_byte_rebuild_pos_0_0_and_0_p0(self):
        self.skipTest("to be re-implemented with the lastest EC methods")

    def test_content_1_byte_rebuild_pos_0_0(self):
        self.skipTest("to be re-implemented with the lastest EC methods")

    def test_content_1_byte_rebuild_pos_0_p0(self):
        self.skipTest("to be re-implemented with the lastest EC methods")

    def test_content_1_byte_rebuild_pos_0_0_and_0_p0(self):
        self.skipTest("to be re-implemented with the lastest EC methods")

    def test_content_chunksize_bytes_rebuild_pos_0_0(self):
        self.skipTest("to be re-implemented with the lastest EC methods")

    def test_content_chunksize_bytes_rebuild_pos_0_0_and_0_1(self):
        self.skipTest("to be re-implemented with the lastest EC methods")

    def test_content_chunksize_bytes_rebuild_pos_0_0_and_0_p0(self):
        self.skipTest("to be re-implemented with the lastest EC methods")

    def test_content_chunksize_bytes_rebuild_pos_0_p0_and_0_p1(self):
        self.skipTest("to be re-implemented with the lastest EC methods")

    def test_content_chunksize_bytes_rebuild_more_than_k_chunk(self):
        self.skipTest("to be re-implemented with the lastest EC methods")

    def _new_content(self, data, broken_pos_list=[]):
        self.skipTest("to be re-implemented with the lastest EC methods")

    def test_orphan_chunk(self):
        self.skipTest("to be re-implemented with the lastest EC methods")

    def test_rebuild_on_the_fly(self):
        self.skipTest("to be re-implemented with the lastest EC methods")

    def _test_download(self, data_size, broken_pos_list):
        self.skipTest("to be re-implemented with the lastest EC methods")

    def test_download_content_0_byte_without_broken_chunks(self):
        self.skipTest("to be re-implemented with the lastest EC methods")

    def test_download_content_1_byte_without_broken_chunks(self):
        self.skipTest("to be re-implemented with the lastest EC methods")

    def test_download_content_chunksize_bytes_without_broken_chunks(self):
        self.skipTest("to be re-implemented with the lastest EC methods")

    def test_download_content_chunksize_plus_1_without_broken_chunks(self):
        self.skipTest("to be re-implemented with the lastest EC methods")

    def test_download_content_0_byte_with_broken_0_0_and_0_p0(self):
        self.skipTest("to be re-implemented with the lastest EC methods")

    def test_download_content_1_byte_with_broken_0_0_and_0_p0(self):
        self.skipTest("to be re-implemented with the lastest EC methods")

    def test_download_content_2xchunksize_with_broken_0_2_and_1_0(self):
        self.skipTest("to be re-implemented with the lastest EC methods")

    def test_download_content_chunksize_bytes_with_3_broken_chunks(self):
        self.skipTest("to be re-implemented with the lastest EC methods")

    def test_download_interrupt_close(self):
        self.skipTest("to be re-implemented with the lastest EC methods")
