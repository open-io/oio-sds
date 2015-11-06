from __future__ import print_function
import sys
import os
import json
import testtools
import requests
import random


def trim_srv(srv):
    return {'score': srv['score'], 'addr': srv['addr'], 'tags': srv['tags']}


def get_config(defaults=None):
    conf = {}
    if defaults is not None:
        conf.update(defaults)

    default_conf_path = os.path.expanduser('~/.oio/sds/conf/test.conf')
    conf_file = os.environ.get('SDS_TEST_CONFIG_FILE', default_conf_path)

    try:
        with open(conf_file, 'r') as f:
            conf = json.load(f)
    except SystemExit:
        if not os.path.exists(conf_file):
            reason = 'file not found'
        elif not os.access(conf_file, os.R_OK):
            reason = 'permission denied'
        else:
            reason = 'n/a'
            print('Unable to read test config %s (%s)' % (conf_file, reason),
                  file=sys.stderr)
    return conf


class BaseTestCase(testtools.TestCase):

    def _mod(self, name):
        return '/'.join((self.uri, "v3.0", self.ns, name))

    def _url_cs(self, action):
        return self._mod("conscience") + '/' + action

    def _url_ref(self, action):
        return self._mod("reference") + '/' + action

    def setUp(self):
        super(BaseTestCase, self).setUp()
        self.conf = get_config()
        self.uri = self.conf['proxyd_uri']
        self.ns = self.conf['namespace']
        if 'account' in self.conf:
            self.account = self.conf['account']
        self.session = requests.session()
        self._flush_cs('echo')

    def tearDown(self):
        super(BaseTestCase, self).tearDown()
        self._flush_cs('echo')

    def _flush_cs(self, srvtype):
        params = {'type': srvtype}
        resp = self.session.post(self._url_cs("deregister"), params=params)
        self.assertEqual(resp.status_code / 100, 2)

    def _register_srv(self, srv):
        resp = self.session.post(self._url_cs("register"), json.dumps(srv))
        self.assertEqual(resp.status_code, 200)

    def _lock_srv(self, srv):
        resp = self.session.post(self._url_cs("lock"), json.dumps(srv))
        self.assertEqual(resp.status_code, 200)

    def _unlock_srv(self, srv):
        resp = self.session.post(self._url_cs("unlock"), json.dumps(srv))
        self.assertEqual(resp.status_code, 200)

    def _reload(self):
        url = self.uri + '/v2.0/cache/flush/local'
        resp = self.session.post(url, '')
        self.assertEqual(resp.status_code / 100, 2)
        for srvtype in ('meta1', 'meta2'):
            for t in self.conf[srvtype]:
                url = self.uri + '/v2.0/forward/' + str(t)
                resp = self.session.post(url, params={'action': 'flush'})
                self.assertEqual(resp.status_code, 204)
        for srvtype in ('meta1', 'meta2'):
            for t in self.conf[srvtype]:
                url = self.uri + '/v2.0/forward/' + str(t)
                resp = self.session.post(url, params={'action': 'reload'})
                self.assertEqual(resp.status_code, 204)

    def _addr(self):
        return '127.0.0.2:' + str(random.randint(7000, 65535))

    def _srv(self, srvtype):
        return {'ns': self.ns,
                'type': str(srvtype),
                'addr': self._addr(),
                'score': random.randint(0, 100),
                'tags': {'stat.cpu': 1, 'tag.vol': 'test', 'tag.up': True}}

    def assertIsError(self, body, expected_code_oio):
        self.assertIsInstance(body, dict)
        self.assertIn('status', body)
        self.assertIn('message', body)
        self.assertEqual(body['status'], expected_code_oio)

    def assertError(self, resp, code_http, expected_code_oio):
        self.assertEqual(resp.status_code, code_http)
        self.assertIsError(resp.json(), expected_code_oio)
