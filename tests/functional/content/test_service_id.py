# Copyright (C) 2015-2018 OpenIO SAS, as part of OpenIO SDS
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
import random
from subprocess import check_call
import time
import urllib3
from ConfigParser import SafeConfigParser
import yaml

from oio.api.object_storage import ObjectStorageApi
from tests.utils import BaseTestCase, random_str


def exp(path):
    return os.path.expanduser(path)


GRID_CONF = exp("~/.oio/sds/conf/gridinit.conf")
WATCH_CONF = exp("~/.oio/sds/conf/watch/%s-%s.yml")
HTTPD_CONF = exp("~/.oio/sds/conf/%s-%s.httpd.conf")


class TestServiceId(BaseTestCase):
    def setUp(self):
        super(TestServiceId, self).setUp()

        if not self.conf['with_service_id']:
            self.skipTest("Service ID not enabled")

        # support mix deployement
        self.rawx = {}
        while 'service_id' not in self.rawx:
            self.rawx = random.choice(self.conf['services']['rawx'])

        self.conn = ObjectStorageApi(self.ns)
        self.name = "rawx-%d" % int(self.rawx['num'])

        self._cnt = random_str(10)
        self._port = int(self.rawx['addr'].split(':')[1])
        self._newport = self._port + 10000 + random.randint(0, 200)

        self.org_rawx = self.rawx.copy()
        self.http = urllib3.PoolManager()

    def tearDown(self):
        super(TestServiceId, self).tearDown()
        # TODO: restore rawx addr

    def _service(self, name, action):
        name = "%s-%s" % (self.conf['namespace'], name)
        check_call(['gridinit_cmd', '-S',
                    exp('~/.oio/sds/run/gridinit.sock'), action, name])

    def _update_gridinit(self, port):

        grid = SafeConfigParser()
        grid.read(exp(GRID_CONF))

        section = "Service.%s-%s" % (self.ns, self.name)
        val = grid.get(section, "Group").split(",")

        val[3] = val[3].split(':')[0] + ':' + str(port)
        grid.set(section, "Group", ",".join(val))

        with open(exp(GRID_CONF), "w") as fp:
            grid.write(fp)

    def _update_event_watch(self, port):
        conf = None
        path = WATCH_CONF % (self.ns, self.name)
        with open(path, "r") as fp:
            conf = yaml.load(fp)

        conf['port'] = port

        with open(path, "w") as fp:
            yaml.dump(conf, stream=fp)

    def _update_apache(self, port):
        path = HTTPD_CONF % (self.ns, self.name)
        with open(path, "r") as fp:
            data = fp.read().split('\n')
        for idx in xrange(len(data)):
            if data[idx].startswith('Listen'):
                data[idx] = data[idx].split(':')[0] + ':' + str(port)
            elif data[idx].startswith('<VirtualHost'):
                data[idx] = data[idx].split(':')[0] + ':' + str(port) + '>'
        with open(path, "w") as fp:
            fp.write('\n'.join(data))

    def _cache_flush(self):
        for item in ['local', 'low', 'high']:
            r = self.http.request('POST', 'http://%s/v3.0/cache/flush/%s'
                                  % (self.conf['proxy'], item))
            self.assertEqual(r.status, 204)

    def _create_data(self):
        ret = self.conn.object_create(self.account, self._cnt,
                                      obj_name="plop", data="*" * 1024)
        ret = self.conn.object_locate(self.account, self._cnt, "plop")
        return ret

    def _change_rawx_addr(self, port):
        self._service(self.name, "stop")

        self._update_gridinit(port)
        self._update_event_watch(port)
        self._update_apache(port)

        self._service(self.name, "reload")
        self._service(self.name, "restart")
        self._service("conscience-agent", "restart")
        check_call(["openio", "cluster", "flush", "rawx"])
        check_call(["openio", "cluster", "unlockall"])
        self._cache_flush()

    def _generate_data(self):
        # generate content with a chunk located on rawx
        while True:
            ret = self._create_data()[1]
            for item in ret:
                if self.rawx['service_id'] in item['url']:
                    return

    def _wait_data(self):
        ret = self.conn.object_locate(self.account, self._cnt, "plop")[1]
        for item in ret:
            if self.rawx['service_id'] in item['url']:
                try:
                    self.http.request('GET', item.get('real_url'))
                    return True
                except Exception as exc:
                    print("%s: %s", item.get('real_url'), str(exc))
        return False

    def test_service_id_new_addr(self):
        self._generate_data()
        self._change_rawx_addr(self._newport)

        # wait that chunk become available
        timeout = 10
        while not self._wait_data():
            time.sleep(1)
            timeout -= 1
            self.assertTrue(timeout)

        # reset addr of rawx
        self._change_rawx_addr(self._port)

        timeout = 10
        while not self._wait_data():
            time.sleep(1)
            timeout -= 1
            self.assertTrue(timeout)
