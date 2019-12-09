# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
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

import tempfile
import fileinput
import os

from oio.common import exceptions
from oio.common.utils import cid_from_name
from oio.crawler.integrity import Checker, Target, \
    DEFAULT_DEPTH, IRREPARABLE_PREFIX
from oio.event.evob import EventTypes
from tests.utils import BaseTestCase, random_str


class TestIntegrityCrawler(BaseTestCase):
    def setUp(self):
        super(TestIntegrityCrawler, self).setUp()
        self.container = 'ct-' + random_str(8)
        self.obj = 'obj-' + random_str(8)
        self.account = 'test-integrity-' + random_str(8)
        self.storage.object_create(
            self.account, self.container, obj_name=self.obj, data="chunk")
        _, self.rebuild_file = tempfile.mkstemp()
        self.checker = Checker(self.ns, rebuild_file=self.rebuild_file)
        self.meta, chunks = self.storage.object_locate(
            self.account, self.container, self.obj)
        self.chunk = chunks[0]
        self.irreparable = len(chunks) == 1
        self.storage.blob_client.chunk_delete(self.chunk['real_url'])
        self.beanstalkd0.drain_tube('oio-preserved')

    def tearDown(self):
        super(TestIntegrityCrawler, self).tearDown()
        os.remove(self.rebuild_file)
        self.storage.container_flush(self.account, self.container)
        self.storage.container_delete(self.account, self.container)
        self.wait_for_event('oio-preserved',
                            types=[EventTypes.CONTAINER_DELETED],
                            fields={'user': self.container})
        try:
            self.storage.account_delete(self.account)
        except exceptions.Conflict:
            pass  # Yes I know, that's not supposed to fail, but...

    def _verify_rebuilder_input(self):
        try:
            line = next(fileinput.input(self.rebuild_file)).strip()
            cid = cid_from_name(self.account, self.container)
            expected = '|'.join([cid, self.meta['id'], self.chunk['url']])
            if self.irreparable:
                expected = IRREPARABLE_PREFIX + '|' + expected
            self.assertEqual(expected, line)
        finally:
            fileinput.close()

    def test_account_rebuilder_output(self):
        self.checker.check(Target(self.account), recurse=DEFAULT_DEPTH)
        for _ in self.checker.run():
            pass
        self.checker.fd.flush()
        self._verify_rebuilder_input()

    def test_container_rebuilder_output(self):
        self.checker.check(Target(self.account, container=self.container),
                           recurse=DEFAULT_DEPTH)
        for _ in self.checker.run():
            pass
        self.checker.fd.flush()
        self._verify_rebuilder_input()

    def test_object_rebuilder_output(self):
        self.checker.check(Target(self.account, container=self.container,
                                  obj=self.obj),
                           recurse=DEFAULT_DEPTH)
        for _ in self.checker.run():
            pass
        self.checker.fd.flush()
        self._verify_rebuilder_input()

    def test_object_rebuilder_output_with_confirmations(self):
        """
        Check that chunk targets showing errors are reported only after
        the right number of confirmations.
        """
        self.checker.required_confirmations = 2
        tgt = Target(self.account, container=self.container, obj=self.obj,
                     content_id=self.meta['id'], version=self.meta['version'])
        self.checker.check(tgt, recurse=DEFAULT_DEPTH)
        for _ in self.checker.run():
            pass
        self.checker.fd.flush()
        # File is empty
        self.assertRaises(StopIteration, self._verify_rebuilder_input)
        self.assertIn(repr(tgt), self.checker.delayed_targets)

        # 1st confirmation
        for dtgt in self.checker.delayed_targets.values():
            self.checker.check(dtgt, recurse=DEFAULT_DEPTH)
        for _ in self.checker.run():
            pass
        self.checker.fd.flush()
        # File is empty
        self.assertRaises(StopIteration, self._verify_rebuilder_input)
        self.assertIn(repr(tgt), self.checker.delayed_targets)

        # 2nd confirmation
        for dtgt in self.checker.delayed_targets.values():
            self.checker.check(dtgt, recurse=DEFAULT_DEPTH)
        for _ in self.checker.run():
            pass
        self.checker.fd.flush()
        # File is NOT empty
        self._verify_rebuilder_input()
        self.assertNotIn(repr(tgt), self.checker.delayed_targets)
