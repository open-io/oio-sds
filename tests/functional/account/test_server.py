# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2022 OVH SAS
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

import simplejson as json

from werkzeug.test import Client
from werkzeug.wrappers import Response

from oio.account.server import create_app
from oio.common.timestamp import Timestamp
from tests.utils import BaseTestCase


class TestAccountServerBase(BaseTestCase):
    def setUp(self):
        super(TestAccountServerBase, self).setUp()
        _, _, self.redis_host, self.redis_port = self.get_service('redis')
        # Make IAM use the second database so we can flush it between tests
        iam_cnxstr = 'redis://%s:%s/?db=1&allow_empty_policy_name=False' % (
            self.redis_host, self.redis_port)
        conf = {'redis_host': self.redis_host, 'redis_port': self.redis_port,
                'namespace': self.ns, 'iam.connection': iam_cnxstr}
        self.account_id = 'test'

        self.acct_app = create_app(conf)
        self.app = Client(self.acct_app, Response)


class TestAccountServer(TestAccountServerBase):
    """
    Test account-related features of the account service.
    """

    def setUp(self):
        super(TestAccountServer, self).setUp()
        self._create_account()

    def _create_account(self):
        resp = self.app.put('/v1.0/account/create',
                            query_string={"id": self.account_id})
        self.assertIn(resp.status_code, (201, 202))

    def test_status(self):
        resp = self.app.get('/status')
        self.assertEqual(resp.status_code, 200)
        status = self.json_loads(resp.data.decode('utf-8'))
        self.assertGreater(status['account_count'], 0)

    def test_account_list(self):
        resp = self.app.get('/v1.0/account/list')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(self.account_id, resp.data.decode('utf-8'))
        self.assertNotIn('Should_no_exist', resp.data)

    def test_account_info(self):
        resp = self.app.get('/v1.0/account/show',
                            query_string={"id": self.account_id})
        self.assertEqual(resp.status_code, 200)
        data = self.json_loads(resp.data.decode('utf-8'))

        for field in ("ctime", "objects", "bytes", "containers", "metadata"):
            self.assertIn(field, data)

        self.assertGreaterEqual(data['objects'], 0)
        self.assertGreaterEqual(data['containers'], 0)
        self.assertGreaterEqual(data['bytes'], 0)

    def test_account_update(self):
        data = {'metadata': {'foo': 'bar'}, 'to_delete': []}
        data = json.dumps(data)
        resp = self.app.put('/v1.0/account/update',
                            data=data, query_string={'id': self.account_id})
        self.assertEqual(resp.status_code, 204)

    def test_account_container_update(self):
        data = {'name': 'foo', 'mtime': Timestamp().normal,
                'objects': 0, 'bytes': 0}
        data = json.dumps(data)
        resp = self.app.put('/v1.0/account/container/update',
                            data=data, query_string={'id': self.account_id})
        self.assertEqual(resp.status_code, 200)

    def test_account_containers(self):
        args = {'id': self.account_id}
        resp = self.app.get('/v1.0/account/containers',
                            query_string=args)
        self.assertEqual(resp.status_code, 200)
        data = self.json_loads(resp.data.decode('utf-8'))
        for field in ("ctime", "objects", "bytes", "listing", "containers",
                      "metadata"):
            self.assertIn(field, data)
        self.assertGreaterEqual(data['objects'], 0)
        self.assertGreaterEqual(data['containers'], 0)
        self.assertGreaterEqual(data['bytes'], 0)

    def test_account_container_reset(self):
        data = {'name': 'foo', 'mtime': Timestamp().normal,
                'objects': 12, 'bytes': 42}
        dataj = json.dumps(data)
        resp = self.app.put('/v1.0/account/container/update',
                            data=dataj, query_string={'id': self.account_id})

        data = {'name': 'foo', 'mtime': Timestamp().normal}
        dataj = json.dumps(data)
        resp = self.app.put('/v1.0/account/container/reset',
                            data=dataj, query_string={'id': self.account_id})
        self.assertEqual(resp.status_code, 204)

        resp = self.app.get('/v1.0/account/containers',
                            query_string={'id': self.account_id,
                                          'prefix': 'foo'})
        resp = self.json_loads(resp.data)
        for container in resp["listing"]:
            name, nb_objects, nb_bytes, _, mtime = container
            if not name.startswith('foo'):
                self.fail("No prefix foo: %s" % name)
            if name == 'foo':
                self.assertEqual(0, nb_objects)
                self.assertEqual(0, nb_bytes)
                self.assertEqual(float(data['mtime']), mtime)
                return
        self.fail("No container foo")

    def test_account_refresh(self):
        data = {'name': 'foo', 'mtime': Timestamp().normal,
                'objects': 12, 'bytes': 42}
        data = json.dumps(data)
        resp = self.app.put('/v1.0/account/container/update',
                            data=data, query_string={'id': self.account_id})

        resp = self.app.post('/v1.0/account/refresh',
                             query_string={'id': self.account_id})
        self.assertEqual(resp.status_code, 204)

        resp = self.app.get('/v1.0/account/show',
                            query_string={'id': self.account_id})
        resp = self.json_loads(resp.data)
        self.assertEqual(resp["bytes"], 42)
        self.assertEqual(resp["objects"], 12)

    def test_account_flush(self):
        data = {'name': 'foo', 'mtime': Timestamp().normal,
                'objects': 12, 'bytes': 42}
        data = json.dumps(data)
        resp = self.app.put('/v1.0/account/container/update',
                            data=data, query_string={'id': self.account_id})

        resp = self.app.post('/v1.0/account/flush',
                             query_string={'id': self.account_id})
        self.assertEqual(resp.status_code, 204)

        resp = self.app.get('/v1.0/account/show',
                            query_string={'id': self.account_id})
        resp = self.json_loads(resp.data)
        self.assertEqual(resp["bytes"], 0)
        self.assertEqual(resp["objects"], 0)

        resp = self.app.get('/v1.0/account/containers',
                            query_string={'id': self.account_id})
        resp = self.json_loads(resp.data)
        self.assertEqual(len(resp["listing"]), 0)


IAM_POLICY_FULLACCESS = """{
    "Statement": [
        {
            "Sid": "FullAccess",
            "Action": [
                "s3:*"
            ],
            "Effect": "Allow",
            "Resource": [
                "*"
            ]
        }
    ]
}
"""


class TestIamServer(TestAccountServerBase):
    """
    Test IAM-related features of the account service.
    """

    def setUp(self):
        super(TestIamServer, self).setUp()
        self.user1 = self.account_id + ':user1'
        self.user2 = self.account_id + ':user2'

    def tearDown(self):
        # We do not use the main database but another one,
        # we can flush it without messing up with other account data.
        self.acct_app.iam.redis.conn.flushdb()
        super(TestIamServer, self).tearDown()

    def test_put_user_policy(self):
        resp = self.app.put('/v1.0/iam/put-user-policy',
                            query_string={'account': self.account_id,
                                          'user': self.user1,
                                          'policy-name': 'mypolicy'},
                            data=IAM_POLICY_FULLACCESS.encode('utf-8'))
        self.assertEqual(resp.status_code, 201)

    def test_put_user_policy_no_body(self):
        resp = self.app.put('/v1.0/iam/put-user-policy',
                            query_string={'account': self.account_id,
                                          'user': self.user1,
                                          'policy-name': 'mypolicy'})
        self.assertIn(b'Missing policy document', resp.data)
        self.assertEqual(resp.status_code, 400)

    def test_put_user_policy_no_name(self):
        resp = self.app.put('/v1.0/iam/put-user-policy',
                            query_string={'account': self.account_id,
                                          'user': self.user1},
                            data=IAM_POLICY_FULLACCESS.encode('utf-8'))
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b'policy name cannot be empty', resp.data)

    def test_put_user_policy_invalid_name(self):
        resp = self.app.put('/v1.0/iam/put-user-policy',
                            query_string={'account': self.account_id,
                                          'user': self.user1,
                                          'policy-name': 'invalid:policy'},
                            data=IAM_POLICY_FULLACCESS.encode('utf-8'))
        self.assertIn(b'policy name does not match', resp.data)
        self.assertEqual(resp.status_code, 400)

    def test_put_user_policy_not_json(self):
        resp = self.app.put('/v1.0/iam/put-user-policy',
                            query_string={'account': self.account_id,
                                          'user': self.user1,
                                          'policy-name': 'mypolicy'},
                            data='FullAccess')
        self.assertIn(b'policy is not JSON-formatted', resp.data)
        self.assertEqual(resp.status_code, 400)

    def test_put_user_policy_wrong_method(self):
        resp = self.app.get('/v1.0/iam/put-user-policy',
                            query_string={'account': self.account_id,
                                          'user': self.user1,
                                          'policy-name': 'mypolicy'},
                            data=IAM_POLICY_FULLACCESS.encode('utf-8'))
        self.assertEqual(resp.status_code, 405)

    def _compare_policies(self, expected, actual):
        exp_st = expected.get('Statement', {})
        act_st = actual.get('Statement', {})
        self.assertEqual(exp_st[0], act_st[0])

    def test_get_user_policy(self):
        resp = self.app.put('/v1.0/iam/put-user-policy',
                            query_string={'account': self.account_id,
                                          'user': self.user1,
                                          'policy-name': 'mypolicy'},
                            data=IAM_POLICY_FULLACCESS.encode('utf-8'))
        resp = self.app.get('/v1.0/iam/get-user-policy',
                            query_string={'account': self.account_id,
                                          'user': self.user1,
                                          'policy-name': 'mypolicy'})
        self.assertEqual(resp.status_code, 200)
        expected = json.loads(IAM_POLICY_FULLACCESS)
        actual = json.loads(resp.data.decode('utf-8'))
        self._compare_policies(expected, actual)

    def test_get_user_policy_no_name(self):
        resp = self.app.get('/v1.0/iam/get-user-policy',
                            query_string={'account': self.account_id,
                                          'user': self.user1})
        # XXX: for backward compatibility reasons, we accept to load
        # a policy with no name.
        self.assertIn(b'not found', resp.data)
        self.assertEqual(resp.status_code, 404)

    def test_get_user_policy_not_existing(self):
        resp = self.app.get('/v1.0/iam/get-user-policy',
                            query_string={'account': self.account_id,
                                          'user': self.user1,
                                          'policy-name': 'missing'})
        self.assertIn(b'not found', resp.data)
        self.assertEqual(resp.status_code, 404)

    def test_list_user_policies(self):
        # First policy
        resp = self.app.put('/v1.0/iam/put-user-policy',
                            query_string={'account': self.account_id,
                                          'user': self.user1,
                                          'policy-name': 'mypolicy'},
                            data=IAM_POLICY_FULLACCESS.encode('utf-8'))
        self.assertEqual(resp.status_code, 201)
        resp = self.app.get('/v1.0/iam/list-user-policies',
                            query_string={'account': self.account_id,
                                          'user': self.user1})
        self.assertEqual(resp.status_code, 200)
        actual = json.loads(resp.data.decode('utf-8'))
        self.assertIn('PolicyNames', actual)
        self.assertEqual(actual['PolicyNames'], ['mypolicy'])

        # Second policy
        resp = self.app.put('/v1.0/iam/put-user-policy',
                            query_string={'account': self.account_id,
                                          'user': self.user1,
                                          'policy-name': 'mysecondpolicy'},
                            data=IAM_POLICY_FULLACCESS.encode('utf-8'))

        self.assertEqual(resp.status_code, 201)
        resp = self.app.get('/v1.0/iam/list-user-policies',
                            query_string={'account': self.account_id,
                                          'user': self.user1})
        self.assertEqual(resp.status_code, 200)
        actual = json.loads(resp.data.decode('utf-8'))
        self.assertIn('PolicyNames', actual)
        self.assertEqual(actual['PolicyNames'], ['mypolicy', 'mysecondpolicy'])

    def test_list_user_policies_no_policies(self):
        resp = self.app.get('/v1.0/iam/list-user-policies',
                            query_string={'account': self.account_id,
                                          'user': self.user1})
        self.assertEqual(resp.status_code, 200)
        actual = json.loads(resp.data.decode('utf-8'))
        self.assertIn('PolicyNames', actual)
        self.assertFalse(actual['PolicyNames'])

    def test_list_users(self):
        # First user
        resp = self.app.put('/v1.0/iam/put-user-policy',
                            query_string={'account': self.account_id,
                                          'user': self.user1,
                                          'policy-name': 'mypolicy'},
                            data=IAM_POLICY_FULLACCESS.encode('utf-8'))
        self.assertEqual(resp.status_code, 201)
        resp = self.app.get('/v1.0/iam/list-users',
                            query_string={'account': self.account_id})
        self.assertEqual(resp.status_code, 200)
        actual = json.loads(resp.data.decode('utf-8'))
        self.assertIn('Users', actual)
        self.assertEqual(actual['Users'], [self.user1])

        # Second user
        resp = self.app.put('/v1.0/iam/put-user-policy',
                            query_string={'account': self.account_id,
                                          'user': self.user2,
                                          'policy-name': 'mypolicy'},
                            data=IAM_POLICY_FULLACCESS.encode('utf-8'))
        self.assertEqual(resp.status_code, 201)
        resp = self.app.get('/v1.0/iam/list-users',
                            query_string={'account': self.account_id})
        self.assertEqual(resp.status_code, 200)
        actual = json.loads(resp.data.decode('utf-8'))
        self.assertIn('Users', actual)
        self.assertEqual(actual['Users'], [self.user1, self.user2])

    def test_list_users_no_user(self):
        resp = self.app.get('/v1.0/iam/list-users',
                            query_string={'account': self.account_id})
        self.assertEqual(resp.status_code, 200)
        actual = json.loads(resp.data.decode('utf-8'))
        self.assertIn('Users', actual)
        self.assertFalse(actual['Users'])

    def test_delete_user_policy(self):
        # Put a bunch of policies
        resp = self.app.put('/v1.0/iam/put-user-policy',
                            query_string={'account': self.account_id,
                                          'user': self.user1,
                                          'policy-name': 'mypolicy'},
                            data=IAM_POLICY_FULLACCESS.encode('utf-8'))
        self.assertEqual(resp.status_code, 201)
        resp = self.app.put('/v1.0/iam/put-user-policy',
                            query_string={'account': self.account_id,
                                          'user': self.user1,
                                          'policy-name': 'mysecondpolicy'},
                            data=IAM_POLICY_FULLACCESS.encode('utf-8'))
        self.assertEqual(resp.status_code, 201)
        resp = self.app.get('/v1.0/iam/list-user-policies',
                            query_string={'account': self.account_id,
                                          'user': self.user1})
        self.assertEqual(resp.status_code, 200)
        actual = json.loads(resp.data.decode('utf-8'))
        self.assertIn('PolicyNames', actual)
        self.assertEqual(actual['PolicyNames'], ['mypolicy', 'mysecondpolicy'])

        # Delete the policies
        resp = self.app.delete('/v1.0/iam/delete-user-policy',
                               query_string={'account': self.account_id,
                                             'user': self.user1,
                                             'policy-name': 'mypolicy'})
        self.assertEqual(resp.status_code, 204)
        resp = self.app.get('/v1.0/iam/list-user-policies',
                            query_string={'account': self.account_id,
                                          'user': self.user1})
        self.assertEqual(resp.status_code, 200)
        actual = json.loads(resp.data.decode('utf-8'))
        self.assertIn('PolicyNames', actual)
        self.assertEqual(actual['PolicyNames'], ['mysecondpolicy'])
        resp = self.app.delete('/v1.0/iam/delete-user-policy',
                               query_string={'account': self.account_id,
                                             'user': self.user1,
                                             'policy-name': 'mysecondpolicy'})
        self.assertEqual(resp.status_code, 204)
        resp = self.app.get('/v1.0/iam/list-user-policies',
                            query_string={'account': self.account_id,
                                          'user': self.user1})
        self.assertEqual(resp.status_code, 200)
        actual = json.loads(resp.data.decode('utf-8'))
        self.assertIn('PolicyNames', actual)
        self.assertFalse(actual['PolicyNames'])

    def test_delete_user_policy_not_existing(self):
        resp = self.app.delete('/v1.0/iam/delete-user-policy',
                               query_string={'account': self.account_id,
                                             'user': self.user1,
                                             'policy-name': 'mypolicy'})
        self.assertEqual(resp.status_code, 204)
