# Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2024 OVH SAS
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

import configparser
import os
import random
import time
from subprocess import check_call

from oio.common.exceptions import ServiceBusy
from tests.utils import BaseTestCase, random_str


def exp(path):
    return os.path.expandvars(path)


SYSTEMDDIR = exp("${HOME}/.config/systemd/user")
if "OIO_SYSTEMD_SYSTEM" in os.environ:
    SYSTEMDDIR = "/etc/systemd/system"
SYSTEMD_CONF = SYSTEMDDIR + "/%s"
HTTPD_CONF = exp("${HOME}/.oio/sds/conf/%s-%s.httpd.conf")


class SystemDict(dict):
    def __setitem__(self, key, value):
        if isinstance(value, list) and key in self:
            self[key].extend(value)
        else:
            super().__setitem__(key, value)


class SystemdParser(configparser.RawConfigParser):
    def __init__(self):
        super().__init__(dict_type=SystemDict, strict=False, allow_no_value=True)
        self.optionxform = str

    def _join_multiline_values(self):
        return

    def _write_section(self, fp, section_name, section_items, delimiter):
        fp.write("[{}]\n".format(section_name))
        for key, values in section_items:
            for value in values:
                value = self._interpolation.before_write(self, section_name, key, value)
                if (value is not None and len(value) > 0) or not self._allow_no_value:
                    value = delimiter + str(value).replace("\n", "\n\t")
                    fp.write("{}{}\n".format(key, value))
        fp.write("\n")


class BaseServiceIdTest(BaseTestCase):
    def setUp(self):
        super(BaseServiceIdTest, self).setUp()

        if not self.conf["with_service_id"]:
            self.skipTest("Service ID not enabled")

        self._cnt = random_str(10)
        self.api = self.storage
        self.name = None
        self.wait_for_score(("meta2",))

    def tearDown(self):
        super(BaseServiceIdTest, self).tearDown()
        self.wait_for_score(("meta2",))
        self._reload_meta()

    def _update_apache(self, port):
        path = HTTPD_CONF % (self.ns, self.name)
        with open(path, "r") as fp:
            data = fp.read().split("\n")
        for idx in range(len(data)):
            if data[idx].startswith("listen"):
                data[idx] = data[idx].split(":")[0] + ":" + str(port)
            elif data[idx].startswith("<VirtualHost"):
                data[idx] = data[idx].split(":")[0] + ":" + str(port) + ">"
        with open(path, "w") as fp:
            fp.write("\n".join(data))

    def _cache_flush(self):
        for item in ("local", "low", "high"):
            r = self.http_pool.request(
                "POST", "http://%s/v3.0/cache/flush/%s" % (self.conf["proxy"], item)
            )
            self.assertEqual(r.status, 204)

    def _create_data(self):
        ret = self.api.object_create(
            self.account, self._cnt, obj_name="plop", data="*" * 1024
        )
        ret = self.api.object_locate(self.account, self._cnt, "plop")
        return ret

    def _service_in_charge_is_up(self):
        """
        Tells if the service in charge of the mock object is up and running.
        """
        try:
            # cache may be empty for meta2 as well, catch exceptions here
            self.api.object_locate(self.account, self._cnt, "plop")[1]
            return True
        except ServiceBusy:
            return False

    def _wait_for_data_availability(self, timeout=10):
        """Wait for the mock object to become available."""
        while timeout > 0 and not self._service_in_charge_is_up():
            time.sleep(1)
            timeout -= 1
        self.assertGreater(timeout, 0)

    def _update_event_watch(self, name, port):
        conf = self.load_watch_conf(name)
        conf["port"] = port
        self.save_watch_conf(name, conf)

    def _change_rawx_addr(self, name, port):
        service = "oio-%s.service" % name
        self._service(service, "stop")

        self._update_systemd_service_rawx(service, port)
        self._update_event_watch(name, port)
        self._update_apache(port)

        self._service(service, "daemon-reload")
        self._service(service, "restart")
        self._service("oio-conscience-agent-1.service", "restart")
        check_call(["openio", "cluster", "flush", "rawx"])
        check_call(["openio", "cluster", "unlockall"])
        self._cache_flush()


class TestRawxServiceId(BaseServiceIdTest):
    def setUp(self):
        super(TestRawxServiceId, self).setUp()

        if not self.conf["with_service_id"]:
            self.skipTest("Service ID not enabled")

        # support mixed deployment
        self.rawx = {}
        while "service_id" not in self.rawx:
            self.rawx = random.choice(self.conf["services"]["rawx"])

        self.name = "rawx-%d" % int(self.rawx["num"])

        self._port = int(self.rawx["addr"].split(":")[1])
        self._newport = self._port + 10000 + random.randint(0, 200)

        self.org_rawx = self.rawx.copy()

    def tearDown(self):
        super(TestRawxServiceId, self).tearDown()

    def _check_data(self):
        try:
            # cache may be empty for meta2 as well, catch exceptions here
            ret = self.api.object_locate(self.account, self._cnt, "plop")[1]
        except ServiceBusy:
            return False

        for item in ret:
            if self.rawx["service_id"] in item["url"]:
                try:
                    self.http_pool.request("GET", item.get("real_url"))
                    return True
                except Exception as exc:
                    print("%s: %s", item.get("real_url"), str(exc))
        return False

    def _update_systemd_service_rawx(self, service, port):
        conf = SystemdParser()
        conf.read(SYSTEMD_CONF % service)

        unit = conf["Unit"]
        if "OioGroup" in unit:
            val = unit["OioGroup"][0].split(",")
            old_addr, old_port = val[2].split(":")
            val[2] = old_addr + ":" + str(port)
            unit["OioGroup"][0] = ",".join(val)

            section = conf["Service"]
            if "ExecStartPost" in section:
                val = section["ExecStartPost"][0]
                section["ExecStartPost"][0] = val.replace(old_port, str(port))

        with open(SYSTEMD_CONF % service, "w") as fp:
            conf.write(fp)

    def _generate_data(self):
        """
        Create an object with a chunk located on the rawx service under test.
        """
        while True:
            ret = self._create_data()[1]
            for item in ret:
                if self.rawx["service_id"] in item["url"]:
                    return

    def test_rawx_service_id_new_addr(self):
        self._generate_data()
        self._change_rawx_addr(self.name, self._newport)

        self._wait_for_data_availability()
        # reset addr of rawx
        self._change_rawx_addr(self.name, self._port)

        self._wait_for_data_availability()


class TestMeta2ServiceId(BaseServiceIdTest):
    def setUp(self):
        super(TestMeta2ServiceId, self).setUp()

        if not self.conf["with_service_id"]:
            self.skipTest("Service ID not enabled")

        # support mixed deployment
        self.meta2 = list(self.conf["services"]["meta2"])
        for entry in self.meta2:
            port = int(entry["addr"].split(":")[1])
            entry["old_port"] = port
            if "service_id" in entry:
                entry["new_port"] = port + 1000
            else:
                entry["new_port"] = port

    def tearDown(self):
        super(TestMeta2ServiceId, self).tearDown()

    def _update_systemd_service_meta(self, service, port):
        conf = SystemdParser()
        conf.read(SYSTEMD_CONF % service)

        unit = conf["Unit"]
        if "OioGroup" in unit:
            val = unit["OioGroup"][0].split(",")
            old_addr, old_port = val[2].split(":")
            val[2] = old_addr + ":" + str(port)
            unit["OioGroup"][0] = ",".join(val)

            section = conf["Service"]
            if "ExecStart" in section:
                val = section["ExecStart"][0]
                section["ExecStart"][0] = val.replace(old_port, str(port))
            if "ExecStartPost" in section:
                val = section["ExecStartPost"][0]
                section["ExecStartPost"][0] = val.replace(old_port, str(port))

        with open(SYSTEMD_CONF % service, "w") as fp:
            conf.write(fp)

    def _change_meta2_addr(self, field):
        for entry in self.meta2:
            name = "meta2-%s" % entry["num"]
            port = entry[field]

            service = "oio-%s.service" % name
            self._service(service, "stop")
            self._update_systemd_service_meta(service, port)
            self._update_event_watch(name, port)

            self._service(service, "daemon-reload")
            self._service(service, "start")

        self._service("oio-conscience-agent-1.service", "restart")
        check_call(["openio", "cluster", "flush", "meta2"])
        check_call(["openio", "cluster", "unlockall"])
        self._cache_flush()

    def test_meta2_service_id_new_addr(self):
        self._create_data()
        self._change_meta2_addr("new_port")

        self._wait_for_data_availability(timeout=10)

        # reset configuration
        self._change_meta2_addr("old_port")
        self._wait_for_data_availability(timeout=10)
