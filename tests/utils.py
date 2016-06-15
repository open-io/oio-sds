from __future__ import print_function
import sys
import os
import json
import yaml
import testtools
import requests
import random
import time
import string
from functools import wraps

random_chars = string.ascii_lowercase + string.ascii_uppercase +\
    string.digits

random_chars_id = 'ABCDEF' + string.digits

CODE_NAMESPACE_NOTMANAGED = 418
CODE_SRVTYPE_NOTMANAGED = 453
CODE_POLICY_NOT_SATISFIABLE = 481


def ec(fnc):
    @wraps(fnc)
    def _wrapped(self):
        if len(self.conf['services']['rawx']) < 12:
            self.skipTest("Not enough rawx. "
                          "EC tests needs at least 12 rawx to run")
        fnc(self)
    return _wrapped


def random_str(n, chars=random_chars):
    return ''.join(random.choice(chars) for _ in range(n))


def random_id(n):
    return random_str(n, chars=random_chars_id)


def trim_srv(srv):
    return {'score': srv['score'], 'addr': srv['addr'], 'tags': srv['tags']}


def get_config(defaults=None):
    conf = {}
    if defaults is not None:
        conf.update(defaults)

    default_conf_path = os.path.expanduser('~/.oio/sds/conf/test.yml')
    conf_file = os.environ.get('SDS_TEST_CONFIG_FILE', default_conf_path)

    try:
        with open(conf_file, 'r') as f:
            conf = yaml.load(f)
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

    _last_cache_flush = 0

    def get_service_url(self, srvtype, i=0):
        allsrv = self.conf['services'][srvtype]
        srv = allsrv[i]
        return srv['num'], srv['path'], srv['addr']

    def get_service(self, srvtype, i=0):
        num, path, addr = self.get_service_url(srvtype, i=i)
        ip, port = addr.split(':')
        return num, path, ip, port

    def _url(self, name):
        return '/'.join((self.uri, "v3.0", self.ns, name))

    def _url_cs(self, action):
        return self._url("conscience") + '/' + action

    def _url_lb(self, action):
        return self._url("lb") + '/' + action

    def _url_ref(self, action):
        return self._url("reference") + '/' + action

    def url_container(self, action):
        return self._url("container") + '/' + action

    def url_content(self, action):
        return self._url("content") + '/' + action

    def param_srv(self, ref, srvtype):
        return {'ref': ref, 'acct': self.account, 'type': srvtype}

    def param_ref(self, ref):
        return {'ref': ref, 'acct': self.account}

    def param_content(self, ref, path):
        return {'ref': ref, 'acct': self.account, 'path': path}

    def setUp(self):
        super(BaseTestCase, self).setUp()
        self.conf = get_config()
        self.uri = 'http://' + self.conf['proxy']
        self.ns = self.conf['namespace']
        self.account = self.conf['account']
        self.session = requests.session()
        self._flush_cs('echo')

    def tearDown(self):
        super(BaseTestCase, self).tearDown()
        self._flush_cs('echo')

    @classmethod
    def tearDownClass(cls):
        now = time.time()
        if (now - cls._last_cache_flush) < 12:
            # Flushing the proxy's service cache may make further tests
            # fail. By sleeping a bit, we allow the proxy to reload
            # its service cache.
            time.sleep(12)

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
        url = self.uri + '/v3.0/cache/flush/local'
        resp = self.session.post(url, '')
        self.assertEqual(resp.status_code / 100, 2)
        for srvtype in ('meta1', 'meta2'):
            for t in self.conf['services'][srvtype]:
                url = self.uri + '/v3.0/forward/flush'
                resp = self.session.post(url, params={'id': t['addr']})
                self.assertEqual(resp.status_code, 204)
        for srvtype in ('meta1', 'meta2'):
            for t in self.conf['services'][srvtype]:
                url = self.uri + '/v3.0/forward/reload'
                resp = self.session.post(url, params={'id': t['addr']})
                self.assertEqual(resp.status_code, 204)
        BaseTestCase._last_cache_flush = time.time()

    def _addr(self, low=7000, high=65535):
        return '127.0.0.2:' + str(random.randint(low, high))

    def _srv(self, srvtype, extra_tags={}, lowport=7000, highport=65535):
        outd = {'ns': self.ns,
                'type': str(srvtype),
                'addr': self._addr(low=lowport, high=highport),
                'score': random.randint(0, 100),
                'tags': {'stat.cpu': 1, 'tag.vol': 'test', 'tag.up': True}}
        if extra_tags:
            outd["tags"].update(extra_tags)
        return outd

    def assertIsError(self, body, expected_code_oio):
        self.assertIsInstance(body, dict)
        self.assertIn('status', body)
        self.assertIn('message', body)
        self.assertEqual(body['status'], expected_code_oio)

    def assertError(self, resp, code_http, expected_code_oio):
        self.assertEqual(resp.status_code, code_http)
        self.assertIsError(resp.json(), expected_code_oio)
