# -*- coding: utf-8 -*-
# Copyright (C) 2016-2019 OpenIO SAS, as part of OpenIO SDS
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

import uuid
import re
import tempfile

from oio.event.evob import EventTypes
from tests.functional.cli import CliTestCase, CommandFailed
from tests.utils import random_str


class ContainerTest(CliTestCase):
    """Functional tests for containers."""
    NAME = uuid.uuid4().hex

    @classmethod
    def setUpClass(cls):
        opts = cls.get_format_opts(fields=('Name', ))
        output = cls.openio('container create ' + cls.NAME + opts)
        cls.CID = cls._get_cid_from_name(cls.NAME)
        cls.assertOutput(cls.NAME + '\n', output)

    @classmethod
    def tearDownClass(cls):
        output = cls.openio('container delete ' + cls.NAME)
        cls.assertOutput('', output)

    @classmethod
    def _get_cid_from_name(self, name):
        opts = self.get_format_opts('json')
        output = self.openio('container show ' + name + opts)
        data = self.json_loads(output)
        return data['base_name']

    def _test_container_show(self, with_cid=False):
        opts = self.get_format_opts(fields=('container', ))
        cid_opt = ''
        name = self.NAME
        if with_cid:
            cid_opt = '--cid '
            name = self.CID
        output = self.openio('container show ' + cid_opt + name + opts)
        self.assertEqual(self.NAME + '\n', output)

    def test_container_show(self):
        self._test_container_show()

    def test_container_show_with_cid(self):
        self._test_container_show(with_cid=True)

    def _test_container_show_table(self, with_cid=False):
        opts = self.get_format_opts('table')
        cid_opt = ''
        name = self.NAME
        if with_cid:
            cid_opt = '--cid '
            name = self.CID
        output = self.openio('container show ' + cid_opt + name + opts)
        regex = r"|\s*%s\s*|\s*%s\s*|"
        self.assertIsNotNone(re.match(regex % ("bytes_usage", "0B"), output))
        self.assertIsNotNone(re.match(regex % ("objects", "0"), output))

    def test_container_show_table(self):
        self._test_container_show_table()

    def test_container_show_table_with_cid(self):
        self._test_container_show_table(with_cid=True)

    def test_container_list(self):
        opts = self.get_format_opts(fields=('Name', ))
        output = self.openio('container list ' + opts)
        self.assertIn(self.NAME, output)

    def test_unicode_container_list(self):
        opts = self.get_format_opts(fields=('Name', )) + ' -a ' + self.account
        cname = u"Intérêts-" + uuid.uuid4().hex
        self.storage.container_create(self.account, cname)
        self.wait_for_event('oio-preserved',
                            fields={'user': cname},
                            types=(EventTypes.CONTAINER_NEW, ))
        output = self.openio('container list ' + opts)
        self.assertIn(cname, output)

    def _test_container_refresh(self, with_cid=False):
        cid_opt = ''
        name = self.NAME
        if with_cid:
            cid_opt = '--cid '
            name = self.CID
        self.openio('container refresh ' + cid_opt + name)
        opts = self.get_format_opts('json')
        output = self.openio('container list ' + opts)
        containers = self.json_loads(output)
        for container in containers:
            if container["Name"] == self.NAME:
                self.assertEqual(container["Count"], 0)
                self.assertEqual(container["Bytes"], 0)
                return
        self.fail("No container %s" % self.NAME)

    def test_container_refresh(self):
        self._test_container_refresh()

    def test_container_refresh_with_cid(self):
        self._test_container_refresh(with_cid=True)

    def _test_container_snapshot(self, with_cid=False):
        self.wait_for_score(('meta2', ))
        # Snapshot should reply the name of the snapshot on success
        opts = self.get_format_opts('json')
        cid_opt = ''
        name = self.NAME
        if with_cid:
            cid_opt = '--cid '
            name = self.CID
        output = self.openio('container snapshot ' + cid_opt + name + opts)
        output = self.json_loads(output)[0]
        self.assertEqual(output['Status'], "OK")
        # Snapshot should reply Missing container on non existant container
        self.assertRaises(CommandFailed,
                          self.openio,
                          ('container snapshot Should_not_exist' + opts))
        # Use specified name
        dst_account = random_str(16)
        dst_container = random_str(16)
        opts += " --dst-account " + dst_account
        opts += " --dst-container " + dst_container
        output = self.openio('container snapshot ' + cid_opt + name + opts)
        output = self.json_loads(output)[0]
        self.assertEqual(output['Account'], dst_account)
        self.assertEqual(output['Container'], dst_container)
        self.assertEqual(output['Status'], "OK")
        # Snapshot should reply Container already exists when using already
        #   specified name
        self.assertRaises(CommandFailed,
                          self.openio,
                          ('container snapshot ' + cid_opt + name + opts))

    def test_container_snapshot(self):
        self._test_container_snapshot()

    def test_container_snapshot_with_cid(self):
        self._test_container_snapshot(with_cid=True)

    def _test_container_purge(self, with_cid=False):
        cid_opt = ''
        name = self.NAME
        if with_cid:
            cid_opt = '--cid '
            name = self.CID
        output = self.openio('container purge ' + cid_opt + name)
        self.assertEqual('', output)

    def test_container_purge(self):
        self._test_container_purge()

    def test_container_purge_with_cid(self):
        self._test_container_purge(with_cid=True)

    def _test_container_flush(self, with_cid=False):
        cid_opt = ''
        name = self.NAME
        if with_cid:
            cid_opt = '--cid '
            name = self.CID
        with tempfile.NamedTemporaryFile(delete=False) as ntf:
            ntf.write('test_exists')
            ntf.flush()
            obj = ntf.name
            for _ in range(10):
                obj_name = random_str(16)
                self.openio('object create ' + self.NAME
                            + ' ' + obj + ' --name ' + obj_name)
        output = self.openio('container flush ' + cid_opt + name)
        self.assertEqual('', output)
        output = self.openio('object list ' + self.NAME)
        self.assertEqual('\n', output)

    def test_container_flush(self):
        self._test_container_flush()

    def test_container_flush_with_cid(self):
        self._test_container_flush(with_cid=True)

    def _test_container_flush_quickly(self, with_cid=False):
        cid_opt = ''
        name = self.NAME
        if with_cid:
            cid_opt = '--cid '
            name = self.CID
        with tempfile.NamedTemporaryFile(delete=False) as ntf:
            ntf.write('test_exists')
            ntf.flush()
            obj = ntf.name
            for _ in range(10):
                obj_name = random_str(16)
                self.openio('object create ' + cid_opt + name
                            + ' ' + obj + ' --name ' + obj_name)
        output = self.openio('container flush --quickly ' + cid_opt + name)
        self.assertEqual('', output)
        output = self.openio('object list ' + cid_opt + name)
        self.assertEqual('\n', output)

    def test_container_flush_quickly(self):
        self._test_container_flush_quickly()

    def test_container_flush_quickly_with_cid(self):
        self._test_container_flush_quickly(with_cid=True)

    def _test_container_set_status(self, with_cid=False):
        cid_opt = ''
        name = self.NAME
        if with_cid:
            cid_opt = '--cid '
            name = self.CID
        opts = ' -f json'
        output = self.openio('container show ' + cid_opt + name + opts)
        output = self.json_loads(output)
        self.assertEqual(output['status'], "Enabled")
        output = self.openio('container set --status frozen ' + cid_opt + name)
        self.assertEqual('', output)
        output = self.openio('container show ' + cid_opt + name + opts)
        output = self.json_loads(output)
        self.assertEqual(output['status'], "Frozen")
        output = self.openio('container set --status enabled ' +
                             cid_opt + name)
        self.assertEqual('', output)
        output = self.openio('container show ' + cid_opt + name + opts)
        output = self.json_loads(output)
        self.assertEqual(output['status'], "Enabled")

    def test_container_set_status(self):
        self._test_container_set_status()

    def test_container_set_status_with_cid(self):
        self._test_container_set_status(with_cid=True)

    def _test_container_set_properties(self, with_cid=False):
        cid_opt = ''
        name = self.NAME
        if with_cid:
            cid_opt = '--cid '
            name = self.CID
        opts = ' -f json'

        output = self.openio('container set ' + cid_opt + name +
                             ' --property test1=1 --property test2=2')
        self.assertEqual(output, '')
        output = self.openio('container show ' + cid_opt + name + opts)
        output = self.json_loads(output)
        self.assertEqual(self.NAME, output['container'])
        self.assertEqual('1', output['meta.test1'])
        self.assertEqual('2', output['meta.test2'])

        output = self.openio('container set ' + cid_opt + name +
                             ' --property test3=3')
        self.assertEqual(output, '')
        output = self.openio('container show ' + cid_opt + name + opts)
        output = self.json_loads(output)
        self.assertEqual(self.NAME, output['container'])
        self.assertEqual('1', output['meta.test1'])
        self.assertEqual('2', output['meta.test2'])
        self.assertEqual('3', output['meta.test3'])

        output = self.openio('container set ' + cid_opt + name +
                             ' --clear --property test4=4')
        self.assertEqual(output, '')
        output = self.openio('container show ' + cid_opt + name + opts)
        output = self.json_loads(output)
        self.assertEqual(self.NAME, output['container'])
        self.assertNotIn('meta.test1', output)
        self.assertNotIn('meta.test2', output)
        self.assertNotIn('meta.test3', output)
        self.assertEqual('4', output['meta.test4'])

    def test_container_set_properties(self):
        self._test_container_set_properties()

    def test_container_set_properties_with_cid(self):
        self._test_container_set_properties(with_cid=True)
