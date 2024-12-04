# Copyright (C) 2016-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2020-2024 OVH SAS
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

import logging
import random
import re
import time

from oio.common.json import json
from tests.utils import BaseTestCase
from tests.utils import CODE_SRVTYPE_NOTMANAGED


class TestConscienceFunctional(BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # oio-proxy cache buffers service registrations before sending them
        # to conscience. Since we do a lot of registrations here and we don't
        # want to abuse of time.sleep(), we disable the cache.
        prev_setting = cls._cls_get_proxy_config()
        cls.cache_enabled = prev_setting["proxy.cache.enabled"]

    def setUp(self):
        super().setUp()
        # There is at least one test restarting the proxy,
        # as a security we set this before each test.
        self._cls_set_proxy_config({"proxy.cache.enabled": "off"})

    def tearDown(self):
        self._flush_cs("echo")
        super().tearDown()

    @classmethod
    def tearDownClass(cls):
        cls._cls_set_proxy_config({"proxy.cache.enabled": cls.cache_enabled})
        super().tearDownClass()

    def test_namespace_get(self):
        resp = self.request("GET", self._url_cs("info"))
        self.assertEqual(resp.status, 200)
        self.assertIsInstance(self.json_loads(resp.data), dict)
        resp = self.request("GET", self._url_cs("info/anything"))
        self.assertError(resp, 404, 404)

    def _assert_list_echo(self, expect_empty=False):
        """
        Get the list of "echo" services, ensure the response is a list.

        :param expect_empty: if True, expect an empty list. When False, and
                             an empty list is received, retry (2 times).
        """
        for _ in range(4):
            resp = self.request("GET", self._url_cs("list"), params={"type": "echo"})
            self.assertEqual(resp.status, 200)
            parsed = self.json_loads(resp.data)
            self.assertIsInstance(parsed, list)
            # We expect an empty list, or the list is not empty
            if expect_empty or bool(parsed):
                break
            time.sleep(1.0)
        return parsed

    def test_service_pool_get(self):
        echo_list = self._assert_list_echo(expect_empty=True)
        self.assertEqual(len(echo_list), 0)
        resp = self.request("GET", self._url_cs("list"), params={"type": "error"})
        self.assertError(resp, 404, CODE_SRVTYPE_NOTMANAGED)
        resp = self.request("GET", self._url_cs("list"))
        self.assertError(resp, 400, 400)

    def test_service_pool_put_replace(self):
        srvin = self._srv("echo")
        self._register_srv(srvin)
        srvin = self._srv("echo")
        self._register_srv(srvin)
        body = self._assert_list_echo()
        self.assertIn(srvin["addr"], [x["addr"] for x in body])

    def test_service_pool_put_invalid_addr(self):
        srvin = self._srv("echo")
        srvin["addr"] = "kqjljqdk"
        resp = self.request("POST", self._url_cs("register"), json.dumps(srvin))
        self.assertError(resp, 400, 400)

    def test_service_pool_put_missing_info(self):
        for d in (
            "addr",
            "type",
        ):
            s = self._srv("echo")
            del s[d]
            logging.debug("Trying without [%s]", d)
            resp = self.request("POST", self._url_cs("register"), json.dumps(s))
            self.assertError(resp, 400, 400)
        for d in (
            "ns",
            "tags",
        ):
            s = self._srv("echo")
            del s[d]
            logging.debug("Trying without [%s]", d)
            resp = self.request("POST", self._url_cs("register"), json.dumps(s))
            self.assertIn(resp.status, (200, 204))

    def test_service_pool_delete(self):
        self._flush_cs("echo")
        services = self._assert_list_echo(expect_empty=True)
        self.assertListEqual(services, [])

    def test_service_pool_delete_wrong(self):
        params = {"type": "error"}
        resp = self.request("POST", self._url_cs("deregister"), params=params)
        self.assertEqual(resp.status, 404)

    def test_service_pool_actions_lock(self):
        srv = self._srv("echo")
        resp = self.request("POST", self._url_cs("lock"), json.dumps(srv))
        self.assertIn(resp.status, (200, 204))

    def test_service_pool_actions_lock_and_reput(self):
        srv = self._srv("echo")
        resp = self.request("POST", self._url_cs("lock"), json.dumps(srv))
        self.assertIn(resp.status, (200, 204))
        body = self._assert_list_echo()
        self.assertIn(srv["addr"], [x["addr"] for x in body])

        self._register_srv(srv)
        body = self._assert_list_echo()
        self.assertIn(srv["addr"], [x["addr"] for x in body])

        srv2 = dict(srv)
        srv2["score"] = -1
        self._register_srv(srv2)
        body = self._assert_list_echo()
        self.assertIn(srv["addr"], [x["addr"] for x in body])

    def test_service_pool_actions_lock_and_relock(self):
        srv = self._srv("echo")
        resp = self.request("POST", self._url_cs("lock"), json.dumps(srv))
        self.assertIn(resp.status, (200, 204))
        body = self._assert_list_echo()
        self.assertIn(srv["addr"], [x["addr"] for x in body])

        srv["score"] = 0
        resp = self.request("POST", self._url_cs("lock"), json.dumps(srv))
        self.assertIn(resp.status, (200, 204))
        body = self._assert_list_echo()
        self.assertIn(str(srv["addr"]), [x["addr"] for x in body])

    def test_services_pool_actions_unlock(self):
        srv = self._srv("echo")
        resp = self.request("POST", self._url_cs("lock"), json.dumps(srv))
        self.assertIn(resp.status, (200, 204))
        resp = self.request("POST", self._url_cs("unlock"), json.dumps(srv))
        self.assertIn(resp.status, (200, 204))
        self._assert_list_echo()

    def test_service_unlock_no_register(self):
        self._flush_cs("echo")
        self._reload()
        srv = self._srv("echo")
        srv["score"] = -1
        resp = self.request("POST", self._url_cs("unlock"), json.dumps(srv))
        self.assertIn(resp.status, (200, 204))
        body = self._assert_list_echo(expect_empty=True)
        self.assertListEqual(body, [])
        self._flush_cs("echo")

    def test_not_polled_when_score_is_zero(self):
        self._flush_cs("echo")
        srv = self._srv("echo")

        def check_service_known(body, expected_score=None):
            self.assertIsInstance(body, list)
            self.assertListEqual([srv["addr"]], [s["addr"] for s in body])
            if expected_score is not None:
                self.assertEqual(expected_score, body[0]["score"])

        # register the service with a positive score
        srv["score"] = 1
        resp = self.request("POST", self._url_cs("lock"), json.dumps(srv))
        self.assertIn(resp.status, (200, 204))
        # Ensure the proxy reloads its LB pool
        self._flush_proxy()
        self._reload_proxy()
        # check it appears
        body = self._assert_list_echo()
        check_service_known(body, 1)
        # check it is polled
        resp = self.request("POST", self._url_lb("poll"), params={"pool": "echo"})
        raw_body = resp.data
        self.assertEqual(resp.status, 200, f"Failed to poll 'echo' service: {raw_body}")
        body = self.json_loads(raw_body)
        check_service_known(body)

        # register the service locked to 0
        srv["score"] = 0
        resp = self.request("POST", self._url_cs("lock"), json.dumps(srv))
        self.assertIn(resp.status, (200, 204))
        # Ensure the proxy reloads its LB pool
        self._flush_proxy()
        self._reload_proxy()
        # check it appears
        body = self._assert_list_echo()
        check_service_known(body, 0)
        # the service must not be polled
        resp = self.request("POST", self._url_lb("poll"), params={"pool": "echo"})
        self.assertError(resp, 503, 481)

    def test_service_lock_tag(self):
        """Ensure lock tags are set on service whose both scores are locked."""
        self.wait_for_score(("rawx",))
        all_rawx = self.conscience.all_services("rawx")
        one_rawx = all_rawx[0]
        one_rawx["scores"]["score.put"] = 1
        one_rawx["scores"]["score.get"] = 1
        one_rawx["type"] = "rawx"
        self.conscience.lock_score(one_rawx)
        time.sleep(0.1)  # Inter-conscience communication

        all_rawx = self.conscience.all_services("rawx")
        my_rawx = [x for x in all_rawx if x["addr"] == one_rawx["addr"]][0]
        self.assertIn("tag.lock", my_rawx["tags"])
        self.assertIn("tag.putlock", my_rawx["tags"])
        self.assertIn("tag.getlock", my_rawx["tags"])
        self.assertTrue(my_rawx["tags"]["tag.lock"])
        self.assertTrue(my_rawx["tags"]["tag.putlock"])
        self.assertTrue(my_rawx["tags"]["tag.getlock"])
        self.assertEqual(1, my_rawx["score"])
        self.assertEqual(1, my_rawx["scores"]["score.put"])
        self.assertEqual(1, my_rawx["scores"]["score.get"])

        self.conscience.unlock_score(one_rawx)
        self.wait_for_score(("rawx",), score_threshold=5)
        all_rawx = self.conscience.all_services("rawx")
        my_rawx = [x for x in all_rawx if x["addr"] == one_rawx["addr"]][0]
        self.assertIn("tag.lock", my_rawx["tags"])
        self.assertIn("tag.putlock", my_rawx["tags"])
        self.assertIn("tag.getlock", my_rawx["tags"])
        self.assertFalse(my_rawx["tags"]["tag.lock"])
        self.assertFalse(my_rawx["tags"]["tag.putlock"])
        self.assertFalse(my_rawx["tags"]["tag.getlock"])
        self.assertGreaterEqual(my_rawx["score"], 1)
        self.assertGreaterEqual(my_rawx["scores"]["score.put"], 1)
        self.assertGreaterEqual(my_rawx["scores"]["score.get"], 1)

    def test_service_putlock_tag(self):
        """Ensure a 'tag.putlock' tag is set on service whose put score is locked."""
        self.wait_for_score(("rawx",))
        all_rawx = self.conscience.all_services("rawx")
        one_rawx = all_rawx[0]
        one_rawx["scores"]["score.put"] = 1
        one_rawx["scores"].pop("score.get")
        one_rawx["type"] = "rawx"
        self.conscience.lock_score(one_rawx)
        time.sleep(0.1)  # Inter-conscience communication

        all_rawx = self.conscience.all_services("rawx")
        my_rawx = [x for x in all_rawx if x["addr"] == one_rawx["addr"]][0]
        self.assertIn("tag.lock", my_rawx["tags"])
        self.assertIn("tag.putlock", my_rawx["tags"])
        self.assertIn("tag.getlock", my_rawx["tags"])
        self.assertFalse(my_rawx["tags"]["tag.lock"])
        self.assertTrue(my_rawx["tags"]["tag.putlock"])
        self.assertFalse(my_rawx["tags"]["tag.getlock"])
        self.assertEqual(1, my_rawx["score"])
        self.assertEqual(1, my_rawx["scores"]["score.put"])
        self.assertNotEqual(1, my_rawx["scores"]["score.get"])

        self.conscience.unlock_score(one_rawx)
        self.wait_for_score(("rawx",), score_threshold=5)
        all_rawx = self.conscience.all_services("rawx")
        my_rawx = [x for x in all_rawx if x["addr"] == one_rawx["addr"]][0]
        self.assertIn("tag.putlock", my_rawx["tags"])
        self.assertFalse(my_rawx["tags"]["tag.putlock"])
        self.assertGreaterEqual(my_rawx["scores"]["score.put"], 1)

    def test_service_getlock_tag(self):
        """Ensure a 'tag.getlock' tag is set on service whose getscore is locked."""
        self.wait_for_score(("rawx",))
        all_rawx = self.conscience.all_services("rawx")
        one_rawx = all_rawx[0]
        one_rawx["scores"].pop("score.put")
        one_rawx["scores"]["score.get"] = 1
        one_rawx["type"] = "rawx"
        self.conscience.lock_score(one_rawx)
        time.sleep(0.1)  # Inter-conscience communication

        all_rawx = self.conscience.all_services("rawx")
        my_rawx = [x for x in all_rawx if x["addr"] == one_rawx["addr"]][0]
        self.assertIn("tag.lock", my_rawx["tags"])
        self.assertFalse(my_rawx["tags"]["tag.lock"])
        self.assertIn("tag.putlock", my_rawx["tags"])
        self.assertFalse(my_rawx["tags"]["tag.putlock"])
        self.assertIn("tag.getlock", my_rawx["tags"])
        self.assertTrue(my_rawx["tags"]["tag.getlock"])
        self.assertNotEqual(1, my_rawx["score"])
        self.assertNotEqual(1, my_rawx["scores"]["score.put"])
        self.assertEqual(1, my_rawx["scores"]["score.get"])

        self.conscience.unlock_score(one_rawx)
        self.wait_for_score(("rawx",), score_threshold=5)
        all_rawx = self.conscience.all_services("rawx")
        my_rawx = [x for x in all_rawx if x["addr"] == one_rawx["addr"]][0]
        self.assertIn("tag.getlock", my_rawx["tags"])
        self.assertFalse(my_rawx["tags"]["tag.getlock"])
        self.assertGreaterEqual(my_rawx["scores"]["score.get"], 1)

    def test_lock_survives_conscience_restart(self):
        """
        Check that a locked service is still locked after a conscience restart.
        """
        self.wait_for_score(("rawx",))
        all_rawx = self.conscience.all_services("rawx")
        one_rawx = all_rawx[0]
        one_rawx["scores"]["score.put"] = 1
        one_rawx["scores"]["score.get"] = 2
        one_rawx["type"] = "rawx"
        self.conscience.lock_score(one_rawx)

        # Stop conscience.
        self._service("oio-conscience-1.service", "stop")
        # Ensure conscience is stopped.
        self.assertRaises(
            Exception, self._service, "oio-conscience-1.service", "status"
        )
        # Start it again.
        self._service("oio-conscience-1.service", "start")
        # Load all rawx services.
        # Make several attempts in case conscience is slow to start.
        all_rawx = self.conscience.all_services("rawx", request_attempts=4)
        my_rawx = [x for x in all_rawx if x["addr"] == one_rawx["addr"]][0]
        self.assertIn("tag.putlock", my_rawx["tags"])
        self.assertTrue(my_rawx["tags"]["tag.putlock"])
        self.assertTrue(my_rawx["tags"]["tag.getlock"])
        self.assertEqual(1, my_rawx["score"])
        self.assertEqual(1, my_rawx["scores"]["score.put"])
        self.assertEqual(2, my_rawx["scores"]["score.get"])
        self.conscience.unlock_score(one_rawx)

    def test_lock_created_during_conscience_restart(self):
        """
        Check that a service locked while one conscience is down
        persists when the conscience is back up.
        """
        if len(self.conf["services"]["conscience"]) < 2:
            self.skipTest("Requires at least 2 consciences")

        cs_addr = self.conf["services"]["conscience"][0]["addr"]
        cs_unit = self.conf["services"]["conscience"][0]["unit"]

        # Stop conscience.
        self._service(cs_unit, "stop")
        # Ensure conscience is stopped.
        self.assertRaises(Exception, self._service, cs_unit, "status")

        self.wait_for_score(("rawx",))
        all_rawx = self.conscience.all_services("rawx")
        one_rawx = all_rawx[0]
        one_rawx["scores"]["score.put"] = 1
        one_rawx["scores"]["score.get"] = 2
        one_rawx["type"] = "rawx"
        self.conscience.lock_score(one_rawx)
        self.locked_svc.append(one_rawx)  # unlock at tearDown

        # Start conscience again.
        self._service(cs_unit, "start")

        # Do the checks several times to make sure the inter-conscience
        # synchronization does not introduce new locks.
        for attempt in range(5):
            time.sleep(1.0)
            self.logger.debug("Checking service locks, attempt %d", attempt)
            # Load all rawx services.
            # Allow several attempts in case conscience is slow to start.
            all_rawx = self.conscience.all_services(
                "rawx", request_attempts=4, cs=cs_addr
            )
            my_rawx = [x for x in all_rawx if x["addr"] == one_rawx["addr"]][0]
            other_rawx = [x for x in all_rawx if x["addr"] != one_rawx["addr"]]

            # Ensure the one rawx is still locked
            self.assertIn("tag.putlock", my_rawx["tags"])
            self.assertTrue(my_rawx["tags"]["tag.putlock"], "Put lock disappeared")
            self.assertTrue(my_rawx["tags"]["tag.getlock"], "Get lock disappeared")
            self.assertEqual(1, my_rawx["score"], "Locked score has changed")
            self.assertEqual(
                1, my_rawx["scores"]["score.put"], "Locked Put score has changed"
            )
            self.assertEqual(
                2, my_rawx["scores"]["score.get"], "Locked Get score has changed"
            )

            # Ensure all other rawx is still unlocked
            for rawx in other_rawx:
                self.assertFalse(
                    rawx["tags"].get("tag.putlock"),
                    "There is a Put lock where there should not be",
                )
                self.assertFalse(
                    rawx["tags"].get("tag.getlock"),
                    "There is a Get lock where there should not be",
                )
                self.assertGreater(rawx["score"], 0, "Score is too low")
                self.assertGreater(
                    rawx["scores"]["score.put"], 0, "Put score is too low"
                )
                # Disabled, was too flaky
                # self.assertGreater(
                #     rawx["scores"]["score.get"], 0, "Get score is too low"
                # )

    def test_deregister_services(self):
        self._flush_cs("echo")
        self._reload()
        expected_services = []
        expected_services.append(self._srv("echo", ip="127.0.0.1"))
        expected_services.append(self._srv("echo", ip="127.0.0.2"))
        expected_services.append(self._srv("echo", ip="127.0.0.3"))
        self._register_srv(expected_services)
        self.wait_for_service("echo", expected_services[0]["tags"]["tag.service_id"])
        services = self._list_srvs("echo")
        self.assertListEqual(
            sorted([srv["addr"] for srv in expected_services]),
            sorted([srv["addr"] for srv in services]),
        )

        service = random.choice(expected_services)
        expected_services.remove(service)
        self._deregister_srv(service)
        services = self._list_srvs("echo")
        self.assertListEqual(
            sorted([srv["addr"] for srv in expected_services]),
            sorted([srv["addr"] for srv in services]),
        )

        self._deregister_srv(expected_services)
        services = self._list_srvs("echo")
        self.assertListEqual([], services)

    def test_single_score(self):
        srv0 = self._srv("echo", ip="127.0.0.3")

        def check(isFound):
            srv_list = self.conscience.all_services("echo")
            print(srv_list)
            if isFound:
                self.assertNotEqual(srv_list, [])
            else:
                self.assertEqual(srv_list, [])

        # Service not found
        self._reload()
        check(False)
        # Registration -> found
        self._register_srv([srv0])
        self._reload_proxy()
        check(True)
        # lock to 0 -> found
        resp = self.request("POST", self._url_cs("lock"), json.dumps(srv0))
        self.assertIn(resp.status, (200, 204))
        self._reload_proxy()
        check(True)
        # removal -> not found
        resp = self.request("POST", self._url_cs("unlock"), json.dumps(srv0))
        self._deregister_srv(srv0)
        self._flush_proxy()
        self._reload_proxy()
        check(False)

    def test_get_score(self):
        """
        Test getscore is 100 even if stat.space is low
        """
        self._flush_cs("rawx")
        srv0 = self._srv(
            "rawx",
            lowport=7000,
            highport=7000,
            extra_tags={"stat.cpu": 100, "stat.space": 10, "stat.io": 100},
        )
        # Services are locked when registered for the 1st time, we need to unlock them,
        # and register them twice. Besides, the score variation is bound to 50,
        # therefore we must start high if we don't want to wait too long.
        srv0["score"] = 99
        self._register_srv(srv0)
        self._unlock_srv(srv0)
        srv0["score"] = -2  # Special value: SCORE_UNLOCK
        for _ in range(22):
            self._register_srv(srv0)
            srv_list = [
                s
                for s in self.conscience.all_services("rawx", full=True)
                if s["addr"] == srv0["addr"]
            ]
            if srv_list and srv_list[0]["scores"]["score.get"] == 100:
                break
            time.sleep(0.5)
        logging.debug("Fake service: %s", srv0)
        logging.debug("Filtered services: %s", srv_list)
        self.assertEqual(srv_list[0]["scores"]["score.get"], 100)

    def test_restart_conscience_with_locked_services(self):
        services = self._list_srvs("rawx")
        for service in services:
            service["ns"] = self.ns
            service["type"] = "rawx"
        try:
            for service in services:
                self._lock_srv(service)

            # Wait until all conscience are up to date
            for _ in range(4):
                for _ in range(8):
                    self._flush_proxy()
                    self._reload_proxy()
                    expected_services = self._list_srvs("rawx")
                    for service in expected_services:
                        if not service["tags"].get("tag.putlock"):
                            break
                    else:
                        continue
                    break
                else:
                    break
                time.sleep(1)
            else:
                self.fail("At least one service unlocked")
            self.assertEqual(len(services), len(expected_services))
            expected_services.sort(key=lambda x: x["addr"])

            self._service("oio-conscience-1.service", "stop")
            self._service("oio-conscience-1.service", "start")
            time.sleep(1)

            for _ in range(8):
                self._flush_proxy()
                self._reload_proxy()
                self.assertListEqual(
                    expected_services,
                    sorted(self._list_srvs("rawx"), key=lambda x: x["addr"]),
                )
        finally:
            try:
                for service in services:
                    self._unlock_srv(service)
            except Exception:
                pass

    def _test_list_services(
        self,
        stat_line_regex,
        service_type="rawx",
        output_format=None,
        cs=None,
        expected_status=200,
        expected_nb_services=None,
    ):
        params = {"type": service_type}
        if output_format:
            params["format"] = output_format
        if cs:
            params["cs"] = cs
        resp = self.request("GET", self._url_cs("list"), params=params)
        self.assertEqual(expected_status, resp.status)
        if expected_status != 200:
            return
        services = resp.data.decode("utf-8")
        nb_services = 0
        if not stat_line_regex and (not output_format or output_format == "json"):
            nb_services = len(json.loads(services))
        else:
            for line in services.split("\n"):
                if not line.strip():
                    continue
                match = stat_line_regex.match(line)
                self.assertTrue(
                    match, "'%s' did not match %r" % (line, stat_line_regex.pattern)
                )
                if output_format == "prometheus":
                    if line.startswith("conscience_score{"):
                        nb_services += 1
                else:
                    nb_services += 1
        if expected_nb_services is not None:
            self.assertEqual(expected_nb_services, nb_services)
        return nb_services

    def test_list_services_no_format(self):
        self._test_list_services(None)

    def test_list_services_json(self):
        self._test_list_services(None, output_format="json")

    def test_list_services_prometheus(self):
        stat_re = re.compile(r"^(\w+){(.+)} ([\w\.-]+)$")
        self._test_list_services(stat_re, output_format="prometheus")

    def test_list_services_with_specific_cs(self):
        cs = random.choice(self.conf["services"]["conscience"])["addr"]
        self._test_list_services(None, cs=cs)
        self._test_list_services(None, output_format="json", cs=cs)
        stat_re = re.compile(r"^(\w+){(.+)} ([\w\.-]+)$")
        self._test_list_services(stat_re, output_format="prometheus", cs=cs)

    def test_list_services_with_unknown_cs(self):
        stat_re = re.compile(r"^(\w+){(.+)} ([\w\.-]+)$")
        self._test_list_services(stat_re, cs="127.0.0.1:8888", expected_status=503)
        self._test_list_services(
            stat_re, output_format="json", cs="127.0.0.1:8888", expected_status=503
        )
        self._test_list_services(
            stat_re,
            output_format="prometheus",
            cs="127.0.0.1:8888",
            expected_status=503,
        )

    def _service_types(self):
        params = {"what": "types"}
        resp = self.request("GET", self._url_cs("info"), params=params)
        self.assertEqual(200, resp.status)
        return json.loads(resp.data)

    def test_list_all_services(self):
        nb_services = 0
        srv_types = self._service_types()
        for srv_type in srv_types:
            nb_services += self._test_list_services(None, service_type=srv_type)

        self._test_list_services(
            None, service_type="all", expected_nb_services=nb_services
        )
        self._test_list_services(
            None,
            service_type="all",
            output_format="json",
            expected_nb_services=nb_services,
        )
        stat_re = re.compile(r"^(\w+){(.+)} ([\w\.-]+)$")
        self._test_list_services(
            stat_re,
            service_type="all",
            output_format="prometheus",
            expected_nb_services=nb_services,
        )

    def test_seamlessly_reload_proxy(self):
        start = time.time()
        self._service("oio-proxy-1.service", "reload")
        exc_count = 0
        # Send requests for 2 seconds and count the number of errors we get
        while time.time() < start + 2.0:
            try:
                self.conscience.info()
            except Exception:
                exc_count += 1
        self.logger.debug("%d exceptions during oio-proxy reload", exc_count)
        self.assertLess(exc_count, 3)

    def test_up_status(self):
        def check(isUp):
            echo_services = self._assert_list_echo()
            echo = echo_services[0]
            self.assertEqual(isUp, echo["tags"]["tag.up"])

        srv0 = self._srv("echo", ip="127.0.0.3")
        self._register_srv(srv0)
        self._reload_proxy()
        check(True)
        # Wait for timeout
        time.sleep(12)
        check(False)

    def test_up_status_locked_service(self):
        def check(isUp):
            echo_services = self._assert_list_echo()
            echo = echo_services[0]
            self.assertEqual(isUp, echo["tags"]["tag.up"])

        srv0 = self._srv("echo", ip="127.0.0.3")
        self._register_srv(srv0)
        self._reload_proxy()
        check(True)
        # Lock service echo
        self.conscience.lock_score(srv0)
        check(True)
        # Wait for timeout
        time.sleep(12)
        check(False)

    def test_scores_calculation(self):
        # Always use the same conscience to avoid synchronization issues
        cs = self.conf["services"]["conscience"][0]["addr"]
        srv = self._srv("echo")
        self._register_srv(srv, cs=cs)
        self._unlock_srv(srv, cs=cs)

        def clamp(n, low, high):
            return max(low, min(high, n))

        def update_and_check(space, cpu, io):
            # Update the stats
            stats = {"stat.space": space, "stat.cpu": cpu, "stat.io": io}
            srv["tags"].update(stats)
            self._register_srv(srv, cs=cs, deregister=False)

            # Compute scores
            put_score = int(
                (
                    (clamp((space - 20) * 1.25, 0, 100) ** 2)
                    * clamp((cpu - 5) * 6.666667, 1, 100)
                    * clamp((io - 5) * 1.333333, 1, 100)
                )
                ** (1 / 4)
            )
            get_score = int(
                (
                    clamp((cpu - 5) * 6.666667, 0, 100)
                    * clamp((io - 5) * 1.333333, 0, 100)
                )
                ** (1 / 2)
            )

            # Wait for the service update
            for _ in range(4):
                self._register_srv(srv, cs=cs, deregister=False)
                echo_services = self.conscience.all_services("echo", full=True, cs=cs)
                for echo_srv in echo_services:
                    if echo_srv["addr"] == srv["addr"]:
                        echo = echo_srv
                        break
                else:
                    # The service is not yet known to the requested conscience
                    continue
                if not all((echo["tags"].get(k) == v for k, v in stats.items())):
                    # The requested conscience is not yet up to date
                    continue
                if (
                    echo["scores"]["score.put"] != put_score
                    or echo["scores"]["score.get"] != get_score
                ):
                    # The scores is not yet stabilized (or there is a bug)
                    continue
                break
            else:
                self.fail(
                    f"No echo service with address '{srv['addr']}', stats '{stats}' "
                    f"and scores 'get={get_score} put={put_score}': "
                    f"{echo_services}",
                )

        for space in (0, 20, 25, 62.5, 100):
            for cpu in (0, 5, 10, 54.3, 100):
                for io in (0, 5, 10, 56.7, 100):
                    update_and_check(space, cpu, io)

    def test_conscience_agent_rdir_stats_and_tags(self):
        rdir_services = self.conscience.all_services("rdir", full=True)
        my_rdir = rdir_services[0]
        # service_id is not a "stat", if it exists, it must be a "tag"
        self.assertNotIn("stat.service_id", my_rdir["tags"])
        if self.conf["services"]["rdir"][0].get("service_id"):
            self.assertIn("tag.service_id", my_rdir["tags"])
        # A bug made these booleans, check they are now integers (or floats)
        self.assertIn("stat.meta2_volumes", my_rdir["tags"])
        self.assertIn("stat.rawx_volumes", my_rdir["tags"])
        self.assertIsInstance(my_rdir["tags"]["stat.meta2_volumes"], (int, float))
        self.assertIsInstance(my_rdir["tags"]["stat.rawx_volumes"], (int, float))

    def test_conscience_agent_static_tags(self):
        svc = self.conf["services"]["proxy"][0]["service_id"]
        watch_conf = self.load_watch_conf(svc)
        static_conf = {"type": "static", "tags": {"aymeric_wants_tests": True}}
        watch_conf["stats"].append(static_conf)
        self.save_watch_conf(svc, watch_conf)
        must_remove = True
        try:
            # Test the insertion of a new tag
            self._service("oio-conscience-agent-1.service", "restart")
            time.sleep(1.5)
            proxy_service = self.wait_for_service("oioproxy", svc, full=True)
            self.assertIn(
                "tag.aymeric_wants_tests",
                proxy_service["tags"],
                "New tag not found in service description",
            )
            self.assertTrue(
                proxy_service["tags"]["tag.aymeric_wants_tests"],
                "New tag does not have the expected value",
            )

            # Test the removal of the tag
            watch_conf["stats"].remove(static_conf)
            self.save_watch_conf(svc, watch_conf)
            must_remove = False
            self._service("oio-conscience-agent-1.service", "restart")
            # /!\ do not call self._deregister_srv() here: we want to check
            # that outdated tags are automatically removed (maybe not immediately).
            for _ in range(5):
                time.sleep(1.0)
                proxy_service = self.wait_for_service("oioproxy", svc, full=True)
                if "tag.aymeric_wants_tests" not in proxy_service["tags"]:
                    break
            self.assertNotIn(
                "tag.aymeric_wants_tests",
                proxy_service["tags"],
                "Static tag is still there whereas it should have been cleaned",
            )
        except Exception:
            if must_remove:
                watch_conf["stats"].remove(static_conf)
                self.save_watch_conf(svc, watch_conf)
            raise
