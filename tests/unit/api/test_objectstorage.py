import json
from mock import MagicMock as Mock
import random
import unittest


from oio.common import exceptions
from oio.common.constants import container_headers, object_headers
from oio.api.object_storage import handle_object_not_found
from oio.api.object_storage import handle_container_not_found
from oio.api.object_storage import _sort_chunks
from tests.utils import random_str
from tests.unit.api import FakeStorageAPI, FakeAPIResponse


class ObjectStorageTest(unittest.TestCase):
    def setUp(self):
        self.api = FakeStorageAPI("NS", "http://1.2.3.4:8000")
        self.account = "test"
        self.container = "fake"
        self.headers = {"x-req-id": random_str(32)}
        self.policy = "THREECOPIES"
        self.uri_base = "NS"

    def test_handle_container_not_found(self):
        @handle_container_not_found
        def test(self, account, container):
            raise exceptions.NotFound("No container")

        container = random_str(32)
        self.assertRaises(
            exceptions.NoSuchContainer, test, self, self.account, container)

    def test_handle_object_not_found(self):
        @handle_object_not_found
        def test(self, account, container, obj):
            raise exceptions.NotFound("No object")

        obj = random_str(32)
        self.assertRaises(
            exceptions.NoSuchObject, test, self, self.account, self.container,
            obj)

    def test_container_list(self):
        resp = FakeAPIResponse()
        name = random_str(32)
        marker = random_str(32)
        delimiter = random_str(32)
        end_marker = random_str(32)
        prefix = random_str(32)
        limit = random.randint(1, 1000)
        body = {"listing": [[name, 0, 0, 0]]}
        self.api._request = Mock(return_value=(resp, body))
        self.api._get_service_url = Mock(return_value='fake_endpoint')
        containers, meta = self.api.container_list(
            self.account, limit=limit, marker=marker, prefix=prefix,
            delimiter=delimiter, end_marker=end_marker, headers=self.headers)
        params = {"id": self.account, "prefix": prefix, "delimiter": delimiter,
                  "marker": marker, "end_marker": end_marker, "limit": limit}
        uri = "v1.0/account/containers"
        self.api._request.assert_called_once_with(
            'GET', uri, endpoint='fake_endpoint', params=params,
            headers=self.headers)
        self.assertEqual(len(containers), 1)

    def test_object_list(self):
        api = self.api
        marker = random_str(32)
        delimiter = random_str(32)
        end_marker = random_str(32)
        prefix = random_str(32)
        limit = random.randint(1, 1000)
        name0 = random_str(32)
        name1 = random_str(32)
        resp_body = {"objects": [{"name": name0}, {"name": name1}]}
        api._request = Mock(return_value=(None, resp_body))
        l = api.object_list(
            self.account, self.container, limit=limit, marker=marker,
            prefix=prefix, delimiter=delimiter, end_marker=end_marker,
            headers=self.headers)
        uri = "%s/container/list" % self.uri_base
        params = {'acct': self.account, 'ref': self.container,
                  'marker': marker, 'max': limit,
                  'delimiter': delimiter, 'prefix': prefix,
                  'end_marker': end_marker}
        api._request.assert_called_once_with(
            'GET', uri, params=params, headers=self.headers)
        self.assertEqual(len(l['objects']), 2)

    def test_container_show(self):
        api = self.api
        resp = FakeAPIResponse()
        name = random_str(32)
        cont_size = random.randint(1, 1000)
        resp.headers = {
            container_headers["size"]: cont_size
        }
        api._request = Mock(return_value=(resp, {}))
        info = api.container_show(self.account, name, headers=self.headers)
        uri = "%s/container/get_properties" % self.uri_base
        params = {'acct': self.account, 'ref': name}
        api._request.assert_called_once_with(
            'POST', uri, params=params, headers=self.headers)
        self.assertEqual(info, {})

    def test_container_show_not_found(self):
        api = self.api
        api._request = Mock(side_effect=exceptions.NotFound("No container"))
        name = random_str(32)
        self.assertRaises(exceptions.NoSuchContainer, api.container_show,
                          self.account, name)

    def test_container_create(self):
        api = self.api
        resp = FakeAPIResponse()
        resp.status_code = 204
        api._request = Mock(return_value=(resp, None))

        name = random_str(32)
        result = api.container_create(self.account, name, headers=self.headers)
        self.assertEqual(result, True)

        uri = "%s/container/create" % self.uri_base
        params = {'acct': self.account, 'ref': name}
        self.headers['x-oio-action-mode'] = 'autocreate'
        data = json.dumps({'properties': {}})
        api._request.assert_called_once_with(
            'POST', uri, params=params, data=data, headers=self.headers)

    def test_container_create_exist(self):
        api = self.api
        resp = FakeAPIResponse()
        resp.status_code = 201
        api._request = Mock(return_value=(resp, None))

        name = random_str(32)
        result = api.container_create(self.account, name)
        self.assertEqual(result, False)

    def test_container_delete(self):
        api = self.api

        resp = FakeAPIResponse()
        resp.status_code = 204
        api._request = Mock(return_value=(resp, None))
        api.directory.unlink = Mock(return_value=None)
        name = random_str(32)
        api.container_delete(self.account, name, headers=self.headers)

        uri = "%s/container/destroy" % self.uri_base
        params = {'acct': self.account, 'ref': name}
        api._request.assert_called_once_with(
            'POST', uri, params=params, headers=self.headers)

    def test_container_delete_not_empty(self):
        api = self.api

        api._request = Mock(side_effect=exceptions.Conflict(""))
        api.directory.unlink = Mock(return_value=None)
        name = random_str(32)

        self.assertRaises(
            exceptions.ContainerNotEmpty, api.container_delete, self.account,
            name)

    def test_container_update(self):
        api = self.api

        name = random_str(32)
        key = random_str(32)
        value = random_str(32)
        meta = {key: value}
        resp = FakeAPIResponse()
        api._request = Mock(return_value=(resp, None))
        api.container_set_properties(
            self.account, name, meta, headers=self.headers)

        data = json.dumps({'properties': meta})
        uri = "%s/container/set_properties" % self.uri_base
        params = {'acct': self.account, 'ref': name}
        api._request.assert_called_once_with(
            'POST', uri, data=data, params=params, headers=self.headers)

    def test_object_show(self):
        api = self.api
        name = random_str(32)
        size = random.randint(1, 1000)
        content_hash = random_str(32)
        content_type = random_str(32)
        resp = FakeAPIResponse()
        resp.headers = {object_headers["name"]: name,
                        object_headers["size"]: size,
                        object_headers["hash"]: content_hash,
                        object_headers["mime_type"]: content_type}
        api._request = Mock(return_value=(resp, {'properties': {}}))
        obj = api.object_show(
            self.account, self.container, name, headers=self.headers)

        uri = "%s/content/get_properties" % self.uri_base
        params = {'acct': self.account, 'ref': self.container,
                  'path': name}
        api._request.assert_called_once_with(
            'POST', uri, params=params, headers=self.headers)
        self.assertIsNotNone(obj)

    def test_object_create_no_data(self):
        api = self.api
        name = random_str(32)
        self.assertRaises(exceptions.MissingData, api.object_create,
                          self.account, self.container, obj_name=name)

    def test_object_create_no_name(self):
        api = self.api
        self.assertRaises(exceptions.MissingName, api.object_create,
                          self.account, self.container, data="x")

    def test_object_create_no_content_length(self):
        api = self.api
        name = random_str(32)
        f = Mock()
        self.assertRaises(
            exceptions.MissingContentLength, api.object_create, self.account,
            self.container, f, obj_name=name)

    def test_object_create_missing_file(self):
        api = self.api
        name = random_str(32)
        self.assertRaises(
            exceptions.FileNotFound, api.object_create, self.account,
            self.container, name)

    def test_object_update(self):
        api = self.api

        name = random_str(32)
        key = random_str(32)
        value = random_str(32)
        meta = {key: value}
        resp = FakeAPIResponse()
        api._request = Mock(return_value=(resp, None))
        api.object_update(
            self.account, self.container, name, meta, headers=self.headers)

        data = json.dumps(meta)
        uri = "%s/content/set_properties" % self.uri_base
        params = {'acct': self.account, 'ref': self.container,
                  'path': name}
        api._request.assert_called_once_with(
            'POST', uri, data=data, params=params, headers=self.headers)

    def test_object_delete(self):
        api = self.api
        name = random_str(32)
        resp_body = [
            {"url": "http://1.2.3.4:6000/AAAA", "pos": "0", "size": 32},
            {"url": "http://1.2.3.4:6000/BBBB", "pos": "1", "size": 32},
            {"url": "http://1.2.3.4:6000/CCCC", "pos": "2", "size": 32}
        ]
        api._request = Mock(return_value=(None, resp_body))

        api.object_delete(
            self.account, self.container, name, headers=self.headers)

        uri = "%s/content/delete" % self.uri_base
        params = {'acct': self.account, 'ref': self.container,
                  'path': name}
        api._request.assert_called_once_with(
            'POST', uri, params=params, headers=self.headers)

    def test_object_delete_not_found(self):
        api = self.api
        name = random_str(32)
        api._request = Mock(side_effect=exceptions.NotFound("No object"))
        self.assertRaises(
            exceptions.NoSuchObject, api.object_delete, self.account,
            self.container, name)

    def test_sort_chunks(self):
        raw_chunks = [
            {"url": "http://1.2.3.4:6000/AAAA", "pos": "0", "size": 32},
            {"url": "http://1.2.3.4:6000/BBBB", "pos": "0", "size": 32},
            {"url": "http://1.2.3.4:6000/CCCC", "pos": "1", "size": 32},
            {"url": "http://1.2.3.4:6000/DDDD", "pos": "1", "size": 32},
            {"url": "http://1.2.3.4:6000/EEEE", "pos": "2", "size": 32},
            {"url": "http://1.2.3.4:6000/FFFF", "pos": "2", "size": 32},
        ]
        chunks = _sort_chunks(raw_chunks, False)
        sorted_chunks = {
            0: [
                {"url": "http://1.2.3.4:6000/AAAA", "pos": "0", "size": 32},
                {"url": "http://1.2.3.4:6000/BBBB", "pos": "0", "size": 32}],
            1: [
                {"url": "http://1.2.3.4:6000/CCCC", "pos": "1", "size": 32},
                {"url": "http://1.2.3.4:6000/DDDD", "pos": "1", "size": 32}],
            2: [
                {"url": "http://1.2.3.4:6000/EEEE", "pos": "2", "size": 32},
                {"url": "http://1.2.3.4:6000/FFFF", "pos": "2", "size": 32}
            ]}
        self.assertEqual(chunks, sorted_chunks)
        raw_chunks = [
            {"url": "http://1.2.3.4:6000/AAAA", "pos": "0.0", "size": 32},
            {"url": "http://1.2.3.4:6000/BBBB", "pos": "0.1", "size": 32},
            {"url": "http://1.2.3.4:6000/CCCC", "pos": "0.2", "size": 32},
            {"url": "http://1.2.3.4:6000/DDDD", "pos": "1.0", "size": 32},
            {"url": "http://1.2.3.4:6000/EEEE", "pos": "1.1", "size": 32},
            {"url": "http://1.2.3.4:6000/FFFF", "pos": "1.2", "size": 32},
        ]
        chunks = _sort_chunks(raw_chunks, True)
        sorted_chunks = {
            0: [{"url": "http://1.2.3.4:6000/AAAA",
                 "pos": "0.0", "size": 32, "num": 0},
                {"url": "http://1.2.3.4:6000/BBBB",
                 "pos": "0.1", "size": 32, "num": 1},
                {"url": "http://1.2.3.4:6000/CCCC",
                 "pos": "0.2", "size": 32, "num": 2}],
            1: [{"url": "http://1.2.3.4:6000/DDDD",
                 "pos": "1.0", "size": 32, "num": 0},
                {"url": "http://1.2.3.4:6000/EEEE",
                 "pos": "1.1", "size": 32, "num": 1},
                {"url": "http://1.2.3.4:6000/FFFF",
                 "pos": "1.2", "size": 32, "num": 2}]
        }
        self.assertEqual(chunks, sorted_chunks)
