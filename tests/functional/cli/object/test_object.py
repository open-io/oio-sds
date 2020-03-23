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

import os
import tempfile
import uuid
from hashlib import md5
from tests.functional.cli import CliTestCase, CommandFailed
from testtools.matchers import Equals
from tests.utils import random_str


HEADERS = ['Name', 'Created']
OBJ_HEADERS = ['Name', 'Size', 'Hash']
CONTAINER_LIST_HEADERS = ['Name', 'Bytes', 'Count']
CONTAINER_FIELDS = ['account', 'base_name', 'bytes_usage', 'quota',
                    'container', 'ctime', 'storage_policy', 'objects',
                    'max_versions', 'status', 'damaged_objects',
                    'missing_chunks']
OBJ_FIELDS = ['account', 'container', 'ctime', 'hash', 'id', 'mime-type',
              'mtime', 'object', 'policy', 'size', 'version']


class ObjectTest(CliTestCase):
    """Functional tests for objects."""

    CONTAINER_NAME = uuid.uuid4().hex

    @classmethod
    def _get_cid_from_name(self, name):
        opts = self.get_opts([], 'json')
        output = self.openio('container show ' + name + opts)
        data = self.json_loads(output)
        return data['base_name']

    def __test_obj(self, name, with_cid=False):
        with tempfile.NamedTemporaryFile() as f:
            test_content = b'test content'
            f.write(test_content)
            f.flush()
            self._test_obj(f.name, test_content, name, with_cid=with_cid)
        self._test_many_obj(with_cid=with_cid)

    def test_obj(self):
        self.__test_obj(uuid.uuid4().hex)

    def test_obj_with_cid(self):
        self.__test_obj(uuid.uuid4().hex, with_cid=True)

    def test_obj_without_autocreate(self):
        with tempfile.NamedTemporaryFile() as f:
            test_content = b'test content'
            f.write(test_content)
            f.flush()

            self.assertRaises(
                CommandFailed,
                self.openio,
                'object create --no-autocreate ' +
                uuid.uuid4().hex + ' ' + f.name)

    def _test_many_obj(self, with_cid=False):
        cname = self.CONTAINER_NAME
        cid_opt = ''
        if with_cid:
            cname = self._get_cid_from_name(self.CONTAINER_NAME)
            cid_opt = '--cid '
        opts = self.get_opts([], 'json')
        obj_name_exists = ''
        obj_name_also_exists = ''

        # delete 2 existent
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'test_exists')
            f.flush()
            obj_file_exists = f.name
            obj_name_exists = os.path.basename(f.name)
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'test_also_exists')
            f.flush()
            obj_file_also_exists = f.name
            obj_name_also_exists = os.path.basename(f.name)
        self.openio('object create ' + cid_opt + ' ' + cname +
                    ' ' + obj_file_exists + ' ' + obj_file_also_exists
                    + ' ' + opts)
        output = self.openio('object delete ' + cid_opt + cname + ' ' +
                             obj_name_exists + ' ' + obj_name_also_exists +
                             opts)
        data_json = self.json_loads(output)
        self.assertEqual(data_json[0]['Deleted'], True)
        self.assertEqual(data_json[1]['Deleted'], True)
        # delete 2 nonexistent
        output = self.openio('object delete ' + cid_opt + cname + ' ' +
                             'should_not_exists' + ' ' +
                             'should_also_not_exists' + opts)
        data_json = self.json_loads(output)
        self.assertEqual(data_json[0]['Deleted'], False)
        self.assertEqual(data_json[1]['Deleted'], False)
        # delete 1 existent 1 nonexistent
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'test_exists')
            f.flush()
            obj_file_exists = f.name
            obj_name_exists = os.path.basename(f.name)
        self.openio('object create ' + cid_opt + ' ' + cname +
                    ' ' + obj_file_exists + opts)
        output = self.openio('object delete ' + cid_opt + cname + ' ' +
                             obj_name_exists + ' should_not_exists' + opts)
        data_json = self.json_loads(output)
        self.assertEqual(data_json[0]['Deleted'], True)
        self.assertEqual(data_json[1]['Deleted'], False)

    def test_auto_container(self):
        with open('/etc/fstab', 'rb') as source:
            test_content = source.read()
            self._test_auto_container(test_content)

    def _test_auto_container(self, test_content):
        self._test_obj('/etc/fstab', test_content, '06EE0', auto='--auto')

    def _test_obj(self, obj_file, test_content,
                  cname, auto='', with_cid=False, with_tls=False):
        cid_opt = ''
        checksum = md5(test_content).hexdigest().upper()
        opts = self.get_opts([], 'json')
        output = self.openio('container create ' + cname + opts)
        data = self.json_loads(output)
        self.assertThat(len(data), Equals(1))
        self.assert_list_fields(data, HEADERS)
        self.assertThat(data[0]['Name'], Equals(cname))
        cname_or_cid = cname
        if with_cid:
            cname_or_cid = self._get_cid_from_name(cname)
            cid_opt = '--cid '
        # TODO ensure a clean environment before the test, and proper cleanup
        # after, so that we can check the container is properly created
        if not auto:
            self.assertThat(data[0]['Created'], Equals(True))

        opts = self.get_opts([], 'json')
        output = self.openio('container list' + opts)
        listing = self.json_loads(output)
        self.assert_list_fields(listing, CONTAINER_LIST_HEADERS)
        self.assertGreaterEqual(len(listing), 1)
        # TODO verify CONTAINER_NAME in list

        opts = self.get_opts([], 'json')
        output = self.openio('container show ' + cname + opts)
        data = self.json_loads(output)
        self.assert_show_fields(data, CONTAINER_FIELDS)

        fake_cname = cname
        if auto:
            fake_cname = '_'
        obj_name = os.path.basename(obj_file)
        opts = self.get_opts([], 'json')
        if with_tls:
            opts += " --tls"
        output = self.openio('object create ' + auto + ' ' + fake_cname +
                             ' ' + obj_file + ' ' + obj_file + ' ' + opts)
        data = self.json_loads(output)
        self.assert_list_fields(data, OBJ_HEADERS)
        self.assertThat(len(data), Equals(2))
        item = data[0]
        self.assertThat(item['Name'], Equals(obj_name))
        self.assertThat(item['Size'], Equals(len(test_content)))
        self.assertThat(item['Hash'], Equals(checksum))

        opts = self.get_opts([], 'json')
        output = self.openio('object list ' + cid_opt + cname_or_cid + opts)
        listing = self.json_loads(output)
        self.assert_list_fields(listing, OBJ_HEADERS)
        self.assertThat(len(data), Equals(2))
        item = data[0]
        self.assertThat(item['Name'], Equals(obj_name))
        self.assertThat(item['Size'], Equals(len(test_content)))
        self.assertThat(item['Hash'], Equals(checksum))

        output = self.openio('object save ' + cid_opt +
                             cname_or_cid + ' ' + obj_name)
        self.addCleanup(os.remove, obj_name)
        self.assertOutput('', output)

        tmp_file = 'tmp_obj'
        opts = " --tls" if with_tls else ""
        output = self.openio('object save ' + cid_opt + cname_or_cid +
                             ' ' + obj_name + ' --file ' + tmp_file + opts)
        self.addCleanup(os.remove, tmp_file)
        self.assertOutput('', output)

        opts = self.get_opts([], 'json')
        output = self.openio('object show ' + cid_opt + cname_or_cid +
                             ' ' + obj_name + opts)
        data = self.json_loads(output)
        self.assert_show_fields(data, OBJ_FIELDS)
        self.assertThat(data['object'], Equals(obj_name))
        self.assertThat(data['size'], Equals(str(len(test_content))))
        self.assertThat(data['hash'], Equals(checksum))

        output = self.openio('object delete ' + cid_opt + cname_or_cid +
                             ' ' + obj_name + opts)
        self.assertEqual(True, self.json_loads(output)[0]['Deleted'])

    def _test_drain(self, with_cid=False):
        cname = random_str(16)
        cid_opt = ''
        if with_cid:
            self.openio(' '.join(['container create', cname]))
            cname = self._get_cid_from_name(cname)
            cid_opt = '--cid'

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'test_exists')
            f.flush()
            obj = f.name
            obj_name = random_str(16)
            self.openio(' '.join(['object create ', cid_opt, cname, obj,
                                  '--name ', obj_name]))
            self.openio(' '.join(['object drain ', cid_opt, cname,
                                  ' ', obj_name]))

        self.assertRaises(CommandFailed,
                          self.openio,
                          ' '.join(['object drain', cid_opt, cname,
                                    'should not exist']))

    def test_drain(self):
        self._test_drain()

    def test_drain_with_cid(self):
        self._test_drain(with_cid=True)

    def _test_autocontainer_object_listing(self, args='', env=None):
        obj_count = 7
        prefix = random_str(8)
        expected = list()
        with tempfile.NamedTemporaryFile() as myfile:
            myfile.write(b'something')
            myfile.flush()
            # TODO(FVE): find a quicker way to upload several objects
            commands = list()
            for i in range(obj_count):
                obj_name = '%s_%d' % (prefix, i)
                commands.append(' '.join(['object create --auto ',
                                          myfile.name, '--name ',
                                          obj_name, args]))
                expected.append(obj_name)
            self.openio_batch(commands, env=env)

        # Default listing
        opts = self.get_format_opts('json') + ' --attempts 3'
        output = self.openio('object list --auto --prefix ' +
                             prefix + ' ' + opts + ' ' + args,
                             env=env)
        listing = self.json_loads(output)
        self.assertEqual(obj_count, len(listing))
        for obj in listing:
            # 4 columns
            self.assertEqual(4, len(obj))

        # Listing with properties
        output = self.openio('object list --auto --properties --prefix ' +
                             prefix + ' ' + opts + ' ' + args, env=env)
        listing = self.json_loads(output)
        self.assertEqual(obj_count, len(listing))
        for obj in listing:
            # 9 columns
            self.assertEqual(9, len(obj))

        # Unpaged listing
        output = self.openio('object list --auto --no-paging --prefix ' +
                             prefix + ' ' + opts + ' ' + args, env=env)
        listing = self.json_loads(output)
        actual = sorted(x['Name'] for x in listing)
        self.assertEqual(expected, actual)
        for obj in listing:
            # 4 columns
            self.assertEqual(4, len(obj))

    def test_autocontainer_object_listing(self):
        env = {"OIO_ACCOUNT": "ACT-%s" % uuid.uuid4().hex}
        self._test_autocontainer_object_listing(env=env)

    def test_autocontainer_object_listing_other_flatns(self):
        env = {"OIO_ACCOUNT": "ACT-%s" % uuid.uuid4().hex}
        self._test_autocontainer_object_listing(
            '--flat-bits 8', env=env)
        opts = self.get_opts([], 'json')
        output = self.openio('container list ' + opts, env=env)
        for entry in self.json_loads(output):
            self.assertEqual(len(entry['Name']), 2)

    def _test_object_link(self, with_cid=False):
        cont_name = random_str(8)
        obj_name = random_str(8)
        lk_name = obj_name + '-link'
        cid_opt = ''

        output = self.openio('container create ' + cont_name)
        if with_cid:
            cont_name = self._get_cid_from_name(cont_name)
            cid_opt = '--cid '

        with tempfile.NamedTemporaryFile() as myfile:
            myfile.write(b'something')
            myfile.flush()
            output = self.openio('object create ' + cid_opt + cont_name + ' ' +
                                 myfile.name + ' --name ' + obj_name +
                                 ' -f json')
        output = self.openio('object show -f json ' + cid_opt +
                             cont_name + ' ' + obj_name)
        output = self.json_loads(output)
        self.assertEqual(output['object'], obj_name)

        output = self.openio('object link ' + cid_opt + cont_name +
                             ' ' + obj_name + ' ' + lk_name)
        self.assertEqual(output, '')
        output = self.openio('object show -f json ' + cid_opt +
                             cont_name + ' ' + lk_name)
        output = self.json_loads(output)
        self.assertEqual(output['object'], lk_name)

    def test_object_link(self):
        self._test_object_link()

    def test_object_link_with_cid(self):
        self._test_object_link(with_cid=True)

    def _test_object_set_properties(self, with_cid=False):
        cont_name = random_str(8)
        obj_name = random_str(8)
        cid_opt = ''

        output = self.openio('container create ' + cont_name)
        if with_cid:
            cont_name = self._get_cid_from_name(cont_name)
            cid_opt = '--cid '

        with tempfile.NamedTemporaryFile() as myfile:
            myfile.write(b'something')
            myfile.flush()
            output = self.openio('object create ' + cid_opt + cont_name +
                                 ' ' + myfile.name + ' --name ' + obj_name +
                                 ' -f json')
        output = self.openio('object show -f json ' + cid_opt + cont_name +
                             ' ' + obj_name)
        output = self.json_loads(output)
        self.assertEqual(obj_name, output['object'])

        output = self.openio('object set ' + cid_opt + cont_name +
                             ' ' + obj_name +
                             ' --property test1=1 --property test2=2')
        self.assertEqual(output, '')
        output = self.openio('object show -f json ' + cid_opt + cont_name +
                             ' ' + obj_name)
        output = self.json_loads(output)
        self.assertEqual(obj_name, output['object'])
        self.assertEqual('1', output['meta.test1'])
        self.assertEqual('2', output['meta.test2'])

        output = self.openio('object set ' + cid_opt + cont_name +
                             ' ' + obj_name +
                             ' --property test3=3')
        self.assertEqual(output, '')
        output = self.openio('object show -f json ' + cid_opt + cont_name +
                             ' ' + obj_name)
        output = self.json_loads(output)
        self.assertEqual(obj_name, output['object'])
        self.assertEqual('1', output['meta.test1'])
        self.assertEqual('2', output['meta.test2'])
        self.assertEqual('3', output['meta.test3'])

        output = self.openio('object set ' + cid_opt + cont_name +
                             ' ' + obj_name + ' --clear' +
                             ' --property test4=4')
        self.assertEqual(output, '')
        output = self.openio('object show -f json ' + cid_opt + cont_name +
                             ' ' + obj_name)
        output = self.json_loads(output)
        self.assertEqual(obj_name, output['object'])
        self.assertNotIn('meta.test1', output)
        self.assertNotIn('meta.test2', output)
        self.assertNotIn('meta.test3', output)
        self.assertEqual('4', output['meta.test4'])

    def test_object_set_properties(self):
        self._test_object_set_properties()

    def test_object_set_properties_with_cid(self):
        self._test_object_set_properties(with_cid=True)

    def test_object_with_tls(self):
        if not self.conf.get('use_tls'):
            self.skipTest('TLS support must enabled for RAWX')
        with tempfile.NamedTemporaryFile() as f:
            test_content = b'test content'
            f.write(test_content)
            f.flush()
            self._test_obj(f.name, test_content,
                           random_str(10), with_tls=True)
