import unittest
import json

from mock import MagicMock as Mock

from oio.common import exceptions
from tests.unit.api import FakeDirectoryAPI, FakeAPIResponse
from tests.utils import random_id, random_str


class DirectoryTest(unittest.TestCase):
    def setUp(self):
        self.endpoint = "http://1.2.3.4:8000"
        self.api = FakeDirectoryAPI("NS", self.endpoint)
        self.account = "AUTH_test"
        self.headers = {"x-req-id": random_id(64)}
        self.uri_base = "NS"
        self.name = random_str(64)

    def test_get(self):
        api = self.api
        resp = FakeAPIResponse()
        api._request = Mock(return_value=(resp, None))
        uri = "%s/reference/show" % self.uri_base
        params = {'acct': self.account, 'ref': self.name}
        api.get(self.account, self.name)
        api._request.assert_called_once_with(
            'GET', uri, params=params, headers=None)

    def test_has(self):
        api = self.api
        resp = FakeAPIResponse()
        api._request = Mock(return_value=(resp, None))
        uri = "%s/reference/has" % self.uri_base
        params = {'acct': self.account, 'ref': self.name}
        self.assertTrue(api.has(self.account, self.name))
        api._request.assert_called_once_with(
            'GET', uri, params=params, headers=None)

    def test_has_not_found(self):
        api = self.api
        api._request = Mock(side_effect=exceptions.NotFound("No reference"))
        self.assertFalse(api.has(self.account, self.name))

    def test_create(self):
        api = self.api
        resp = FakeAPIResponse()
        resp.status_code = 201
        api._request = Mock(return_value=(resp, None))
        api.create(self.account, self.name)
        uri = "%s/reference/create" % self.uri_base
        params = {'acct': self.account, 'ref': self.name}

        api._request.assert_called_with(
            'POST', uri, params=params, headers=None)

    def test_create_already_exists(self):
        api = self.api
        resp = FakeAPIResponse()
        resp.status_code = 202
        api._request = Mock(return_value=(resp, None))
        api.create(self.account, self.name)
        uri = "%s/reference/create" % self.uri_base
        params = {'acct': self.account, 'ref': self.name}

        api._request.assert_called_once_with(
            'POST', uri, params=params, headers=None)

    def test_create_error(self):
        api = self.api
        resp = FakeAPIResponse()
        resp.status_code = 300
        api._request = Mock(return_value=(resp, None))

        self.assertRaises(exceptions.ClientException, api.create, self.account,
                          self.name)

    def test_delete(self):
        api = self.api
        resp = FakeAPIResponse()
        api._request = Mock(return_value=(resp, None))
        api.delete(self.account, self.name)
        uri = "%s/reference/destroy" % self.uri_base
        params = {'acct': self.account, 'ref': self.name}
        api._request.assert_called_once_with(
            'POST', uri, params=params, headers=None)

    def test_list(self):
        api = self.api
        service_type = random_str(32)
        resp = FakeAPIResponse()
        resp_body = [{"seq": 1,
                      "type": service_type,
                      "host": "127.0.0.1:6000",
                      "args": ""}]

        api._request = Mock(return_value=(resp, resp_body))
        l = api.list_services(self.account, self.name, service_type)
        uri = "%s/reference/show" % self.uri_base
        params = {'acct': self.account, 'ref': self.name,
                  'type': service_type}
        api._request.assert_called_once_with(
            'GET', uri, params=params, headers=None)
        self.assertEqual(l, resp_body)

    def test_unlink(self):
        api = self.api
        service_type = random_str(32)
        resp = FakeAPIResponse()
        api._request = Mock(return_value=(resp, None))
        api.unlink(self.account, self.name, service_type)
        uri = "%s/reference/unlink" % self.uri_base
        params = {'acct': self.account, 'ref': self.name,
                  'type': service_type}
        api._request.assert_called_once_with(
            'POST', uri, params=params, headers=None)

    def test_link(self):
        api = self.api
        service_type = random_str(32)
        resp = FakeAPIResponse()
        api._request = Mock(return_value=(resp, None))
        api.link(self.account, self.name, service_type)
        uri = "%s/reference/link" % self.uri_base
        params = {'acct': self.account, 'ref': self.name,
                  'type': service_type}
        api._request.assert_called_once_with(
            'POST', uri, params=params, headers=None)

    def test_renew(self):
        api = self.api
        service_type = random_str(32)
        resp = FakeAPIResponse()
        api._request = Mock(return_value=(resp, None))
        api.renew(self.account, self.name, service_type)
        uri = "%s/reference/renew" % self.uri_base
        params = {'acct': self.account, 'ref': self.name,
                  'type': service_type}
        api._request.assert_called_once_with(
            'POST', uri, params=params, headers=None)

    def test_force(self):
        api = self.api
        service_type = random_str(32)
        services = {'seq': 1, 'type': service_type, 'host': '127.0.0.1:8000'}
        resp = FakeAPIResponse()
        api._request = Mock(return_value=(resp, None))
        api.force(self.account, self.name, service_type, services)
        uri = "%s/reference/force" % self.uri_base
        params = {'acct': self.account, 'ref': self.name,
                  'type': service_type}
        data = json.dumps(services)
        api._request.assert_called_once_with(
            'POST', uri, data=data, params=params, headers=None)

    def test_get_properties(self):
        api = self.api
        properties = [random_str(64)]
        resp = FakeAPIResponse()
        api._request = Mock(return_value=(resp, None))
        api.get_properties(self.account, self.name, properties)
        uri = "%s/reference/get_properties" % self.uri_base
        params = {'acct': self.account, 'ref': self.name}
        data = json.dumps(properties)
        api._request.assert_called_once_with(
            'POST', uri, data=data, params=params, headers=None)

    def test_set_properties(self):
        api = self.api
        properties = {random_str(64): random_str(64)}
        resp = FakeAPIResponse()
        api._request = Mock(return_value=(resp, None))
        api.set_properties(self.account, self.name, properties)
        uri = "%s/reference/set_properties" % self.uri_base
        params = {'acct': self.account, 'ref': self.name}
        data = json.dumps(properties)
        api._request.assert_called_once_with(
            'POST', uri, data=data, params=params, headers=None)

    def test_delete_properties(self):
        api = self.api
        properties = [random_str(64)]
        resp = FakeAPIResponse()
        api._request = Mock(return_value=(resp, None))
        api.del_properties(self.account, self.name, properties)
        uri = "%s/reference/del_properties" % self.uri_base
        params = {'acct': self.account, 'ref': self.name}
        data = json.dumps(properties)
        api._request.assert_called_once_with(
            'POST', uri, data=data, params=params, headers=None)
