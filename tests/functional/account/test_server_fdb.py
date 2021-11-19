# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021 OVH SAS
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
import simplejson as json
from pathlib import Path

from werkzeug.test import Client
from werkzeug.wrappers import BaseResponse

from oio.account.server import create_app
from oio.common.timestamp import Timestamp
from tests.utils import BaseTestCase
from oio.account.backend_fdb import AccountBackendFdb
import fdb
fdb.api_version(630)


class TestAccountServerBase(BaseTestCase):
    def setUp(self):
        super(TestAccountServerBase, self).setUp()
        iam_cnxstr = 'fdb://%s:%s/?db=1&allow_empty_policy_name=False' % (
            0, 0)
        if os.path.exists(AccountBackendFdb.DEFAULT_FDB):
            self.fdb_file = AccountBackendFdb.DEFAULT_FDB
        else:
            self.fdb_file = \
                str(Path.home())+'/.oio/sds/conf/OPENIO-fdb.cluster'
        conf = {'namespace': self.ns, 'iam.connection': iam_cnxstr}
        conf['default_location'] = 'test_region'
        conf['backend_type'] = 'fdb'
        conf['fdb_file'] = self.fdb_file

        self.account_id = 'test'
        self.acct_app = create_app(conf)
        self.acct_app.backend.init_db()
        self.acct_app.iam.init_db()
        self.app = Client(self.acct_app, BaseResponse)

    @classmethod
    def _monkey_patch(cls):
        import eventlet
        eventlet.patcher.monkey_patch(os=False, thread=False)

    def _create_account(self, account_id):
        resp = self.app.put('/v1.0/account/create',
                            query_string={"id": account_id})
        self.assertIn(resp.status_code, (201, 202))

    def _flush_account(self, account_id):
        self.app.post('/v1.0/account/flush',
                      query_string={"id": account_id})

    def _delete_account(self, account_id):
        self.app.post('/v1.0/account/delete',
                      query_string={"id": account_id})


class TestAccountServer(TestAccountServerBase):
    """
    Test account-related features of the account service.
    """

    def setUp(self):
        super(TestAccountServer, self).setUp()
        self._create_account(self.account_id)

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
        fdb.directory.remove(self.acct_app.iam.db,
                             (self.acct_app.iam.key_prefix, ))
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


class TestAccountMetrics(TestAccountServerBase):
    """
    Test account-related features of the account service.
    """

    def setUp(self):
        super(TestAccountMetrics, self).setUp()
        # not the best way to clear
        del(self.acct_app.backend.db[:])

    def test_metrics_nb_accounts(self):
        # Create and delete some accounts
        for i in range(1, 3):
            account_id = 'acct1-' + str(i)
            self._create_account(account_id)
        resp = self.app.get('/v1.0/account/metrics?format=json')
        self.assertEqual(resp.status_code, 200)
        resp = self.json_loads(resp.data)
        self.assertEqual(resp['obsto_accounts'], 2)

        for key in resp.keys():
            self.assertIn(key, ('obsto_accounts', 'obsto_buckets',
                          'obsto_containers', 'obsto_objects', 'obsto_bytes'))

        for i in range(1, 2):
            account_id = 'acct1-' + str(i)
            self._flush_account(account_id)
            self._delete_account(account_id)

        resp = self.app.get('/v1.0/account/metrics?format=json')
        self.assertEqual(resp.status_code, 200)
        resp = self.json_loads(resp.data)
        self.assertEqual(resp['obsto_accounts'], 1)

        for i in range(2, 4):
            account_id = 'acct1-' + str(i)
            self._flush_account(account_id)
            self._delete_account(account_id)

        resp = self.app.get('/v1.0/account/metrics?format=json')
        self.assertEqual(resp.status_code, 200)
        resp = self.json_loads(resp.data)
        self.assertEqual(resp['obsto_accounts'], 0)

    def test_metrics_nb_containers(self):
        self._create_account(self.account_id)
        # create  and delete some containers
        # check to send headers for region, storage class
        data = {'name': 'ct1', 'mtime': Timestamp().normal,
                'objects': 1, 'bytes': 20}
        data = json.dumps(data)
        resp = self.app.put('/v1.0/account/container/update',
                            data=data,
                            query_string={'id': self.account_id})

        resp = self.app.get('/v1.0/account/metrics?format=json')
        resp = self.json_loads(resp.data)

        self.assertEqual(resp['obsto_containers']['test_region'], 1)

        data = {'name': 'ct1', 'dtime': Timestamp().normal}
        data = json.dumps(data)
        self.app.put('/v1.0/account/container/update',
                     data=data,
                     query_string={'id': self.account_id})

        resp = self.app.get('/v1.0/account/metrics?format=json')
        resp = self.json_loads(resp.data)
        self.assertNotIn('test_region', resp['obsto_containers'].keys())

    def test_metrics_nb_objects_bytes(self):
        self._create_account(self.account_id)
        # add some data
        data = {'name': 'ct2', 'mtime': Timestamp().normal,
                'objects': 3, 'bytes': 40,
                'objects-details': {"class1": 1, "class2": 2},
                'bytes-details': {"class1": 30, "class2": 10}
                }
        data = json.dumps(data)
        self.app.put('/v1.0/account/container/update',
                     data=data,
                     query_string={'id': self.account_id})

        resp = self.app.get('/v1.0/account/metrics?format=json')
        resp = self.json_loads(resp.data)
        # TODO enable when PR OBTO-855 is merged
        # self.assertEqual(resp['obsto_objects']['test_region']['class1'], 1)
        # self.assertEqual(resp['obsto_objects']['test_region']['class2'], 2)
        # self.assertEqual(resp['obsto_bytes']['test_region']['class1'], 30)
        # self.assertEqual(resp['obsto_bytes']['test_region']['class2'], 10)
