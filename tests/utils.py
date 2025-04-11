# -*- coding: utf-8 -*-
# Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2025 OVH SAS
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
import os
import random
import string
import sys
import unittest
from collections import defaultdict
from functools import wraps
from subprocess import check_call
from urllib.parse import urlencode

import yaml
from confluent_kafka import OFFSET_END, TopicPartition

from oio.common.configuration import load_namespace_conf, set_namespace_options
from oio.common.constants import M2_PROP_CONTAINER_NAME, REQID_HEADER
from oio.common.green import eventlet, get_watchdog, time
from oio.common.http_urllib3 import get_pool_manager
from oio.common.json import json as jsonlib
from oio.common.kafka import DEFAULT_PRESERVED_TOPIC, KafkaConsumer
from oio.common.logger import get_logger
from oio.common.storage_method import STORAGE_METHODS
from oio.event.beanstalk import Beanstalk, ResponseError
from oio.event.evob import Event

RANDOM_CHARS = string.ascii_letters + string.digits
RANDOM_CHARS_ID = "ABCDEF" + string.digits

CODE_NAMESPACE_NOTMANAGED = 418
CODE_SRVTYPE_NOTMANAGED = 453
CODE_POLICY_NOT_SATISFIABLE = 481
CODE_POLICY_NOT_SUPPORTED = 480

DEFAULT_GROUP_ID_TEST = "event-agent-test"


def ec(fnc):
    @wraps(fnc)
    def _wrapped(self):
        if len(self.conf["services"]["rawx"]) < 12:
            self.skipTest("Not enough rawx. EC tests needs at least 12 rawx to run")
        fnc(self)

    return _wrapped


def random_str(size, chars=RANDOM_CHARS):
    return "".join(random.choice(chars) for _ in range(size))


strange_paths = [
    "Annual report.txt",
    "foo+bar=foobar.txt",
    "100%_bug_free.c",
    "forward/slash/allowed",
    "I\\put\\backslashes\\and$dollar$signs$in$file$names",
    "Je suis tombé sur la tête, mais ça va bien.",
    "%s%f%u%d%%",
    "{1},{0},{3}",
    "carriage\rreturn",
    "line\nfeed",
    "ta\tbu\tla\ttion",
    "controlchars",
    "//azeaze\\//azeaz\\//azea",
]


def random_id(size):
    return random_str(size, chars=RANDOM_CHARS_ID)


def random_data(size):
    """Return `size` bytes of random data as a str object"""
    try:
        return os.urandom(size)
    except NotImplementedError:
        return random_str(size)


def trim_srv(srv):
    return {"score": srv["score"], "addr": srv["addr"], "tags": srv["tags"]}


def get_config(defaults=None):
    conf = {}
    if defaults is not None:
        conf.update(defaults)

    default_conf_path = os.path.expandvars("${HOME}/.oio/sds/conf/test.yml")
    conf_file = os.environ.get("SDS_TEST_CONFIG_FILE", default_conf_path)

    try:
        with open(conf_file, "r") as infile:
            conf = yaml.load(infile, Loader=yaml.Loader)
    except SystemExit:
        if not os.path.exists(conf_file):
            reason = "file not found"
        elif not os.access(conf_file, os.R_OK):
            reason = "permission denied"
        else:
            reason = "n/a"
            print(
                "Unable to read test config %s (%s)" % (conf_file, reason),
                file=sys.stderr,
            )
    return conf


class CommonTestCase(unittest.TestCase):
    CLIENT_LOCATION = "dc.rack.127-0-0-1.0"
    TEST_HEADERS = {REQID_HEADER: "7E571D0000000000"}

    _cls_kafka_consumer = None
    _cls_logger = logging.getLogger("test")

    def _compression(self):
        rx = self.conf.get("rawx", {})
        v = self.conf.get("compression", rx.get("compression", ""))
        return v and v != "off"

    def is_running_on_public_ci(self):
        from os import getenv

        clues = (getenv("TRAVIS"), getenv("CIRCLECI"))
        return any(clue is not None for clue in clues)

    def _random_user(self):
        return "user-" + random_str(16, "0123456789ABCDEF")

    def get_service_url(self, srvtype, i=0):
        allsrv = self.conf["services"][srvtype]
        srv = allsrv[i]
        return srv["num"], srv["path"], srv["addr"], srv.get("uuid")

    def get_service(self, srvtype, i=0):
        num, path, addr, _ = self.get_service_url(srvtype, i=i)
        ip, port = addr.split(":")
        return num, path, ip, port

    def _url(self, name):
        return "/".join((self.uri, "v3.0", self.ns, name))

    def _url_cs(self, action):
        return self._url("conscience") + "/" + action

    def _url_lb(self, action):
        return self._url("lb") + "/" + action

    def _url_ref(self, action):
        return self._url("reference") + "/" + action

    def url_container(self, action):
        return self._url("container") + "/" + action

    def url_content(self, action):
        return self._url("content") + "/" + action

    def param_srv(self, ref, srvtype):
        return {"ref": ref, "acct": self.account, "type": srvtype}

    def param_ref(self, ref):
        return {"ref": ref, "acct": self.account}

    def param_content(self, ref, path, version=None):
        params = {"ref": ref, "acct": self.account, "path": path}
        if version is not None:
            params["version"] = version
        return params

    @staticmethod
    def static_request(
        method, url, data=None, params=None, headers=None, json=None, http_pool=None
    ):
        if not http_pool:
            http_pool = get_pool_manager()
        # Add query string
        if params:
            out_param = []
            for k, v in params.items():
                if v is not None:
                    if isinstance(v, str):
                        v = v.encode("utf-8")
                    out_param.append((k, v))
            encoded_args = urlencode(out_param)
            url += "?" + encoded_args

        # Convert json and add Content-Type
        headers = headers if headers else {}
        if json:
            headers["Content-Type"] = "application/json"
            data = jsonlib.dumps(json)

        out_kwargs = {}
        out_kwargs["headers"] = headers
        out_kwargs["body"] = data

        return http_pool.request(method, url, **out_kwargs)

    def request(self, method, url, data=None, params=None, headers=None, json=None):
        return self.static_request(
            method,
            url,
            data=data,
            params=params,
            headers=headers,
            json=json,
            http_pool=self.http_pool,
        )

    @classmethod
    def _monkey_patch(cls):
        eventlet.patcher.monkey_patch(os=False)

    @classmethod
    def setUpClass(cls):
        super(CommonTestCase, cls).setUpClass()
        cls._monkey_patch()
        cls._cls_conf = get_config()
        cls._cls_account = cls._cls_conf["account"]
        cls._cls_ns = cls._cls_conf["namespace"]
        cls._cls_uri = "http://" + cls._cls_conf["proxy"]

        cls._cls_logger = get_logger(cls._cls_conf, name="test")

        cls._consumers = []
        cls._cls_kafka_consumer = cls._register_consumer()

    @classmethod
    def _register_consumer(cls, topic=DEFAULT_PRESERVED_TOPIC, group_id=None):
        if group_id is None:
            group_id = f"{DEFAULT_GROUP_ID_TEST}-{random_str(8)}"

        consumer = KafkaConsumer(
            cls._cls_conf["kafka_endpoints"],
            [topic],
            group_id,
            logger=cls._cls_logger,
            app_conf=cls._cls_conf,
            kafka_conf={
                "enable.auto.commit": True,
                "auto.offset.reset": "latest",
            },
        )
        cls._consumers.append(consumer)
        return consumer

    def setUp(self):
        super(CommonTestCase, self).setUp()
        # Some test classes do not call setUpClass
        if hasattr(self.__class__, "_cls_conf"):
            self.conf = self.__class__._cls_conf.copy()
        else:
            self.conf = get_config()
        self.uri = "http://" + self.conf["proxy"]
        self.ns = self.conf["namespace"]
        self.account = self.conf["account"]
        queue_addr = random.choice(self.conf["services"]["beanstalkd"])["addr"]
        self.conf["queue_addr"] = queue_addr
        self.conf["queue_url"] = "beanstalk://" + queue_addr
        main_queue_addr = self.conf["services"]["beanstalkd"][0]["addr"]
        self.conf["main_queue_url"] = "beanstalk://" + main_queue_addr
        self._admin = None
        self._beanstalk = None
        self._beanstalkd0 = None
        self._conscience = None
        self._http_pool = None
        self._logger = None
        self._rdir_client = None
        self._storage_api = None
        self._container_sharding = None
        self._watchdog = None
        self._bucket = None
        self._preserved_offset = None

        # Namespace configuration, from "sds.conf"
        self._ns_conf = None
        # Namespace configuration as it was when the test started
        self._ns_conf_backup = None

        # Set of containers to flush and remove at teardown
        self._containers_to_clean = []
        # Set of buckets to remove at teardown
        self._buckets_to_clean = []
        self._deregister_at_teardown = []

        self._cached_events = {}
        self._used_events = {}

        for consumer in self._consumers:
            partitions = self._wait_kafka_partition_assignment(kafka_consumer=consumer)
            self._set_kafka_offset(partitions, kafka_consumer=consumer)

    def _wait_kafka_partition_assignment(self, kafka_consumer=None):
        if not kafka_consumer:
            kafka_consumer = self._cls_kafka_consumer

        if not kafka_consumer:
            return

        assigned_partitions = []
        while not assigned_partitions:
            kafka_consumer._client.poll(1.0)
            assigned_partitions = kafka_consumer._client.assignment()

        self.logger.warning(
            "Assigned partitions: [%s]",
            ",".join(
                [
                    f"(topic: {p.topic},part:{p.partition},offset:{p.offset})"
                    for p in assigned_partitions
                ],
            ),
        )
        return assigned_partitions

    def _set_kafka_offset(self, partitions, kafka_consumer=None, offset=OFFSET_END):
        if not kafka_consumer:
            kafka_consumer = self._cls_kafka_consumer
        if not kafka_consumer:
            return

        self.logger.warning("Seek partition offset: %s", offset)
        for part in partitions:
            watermark = kafka_consumer._client.get_watermark_offsets(part, timeout=5)
            self.logger.warning("Get watermark for %s = %s", str(part), str(watermark))
            self.assertIsNotNone(watermark)
            _, high_offset = watermark
            kafka_consumer._client.seek(
                TopicPartition(part.topic, part.partition, high_offset)
            )

    def tearDown(self):
        for acct, ct in self._containers_to_clean:
            try:
                # Disable versioning to be able to fully flush the container.
                self.storage.container_set_properties(
                    acct, ct, system={"sys.m2.policy.version": "0"}
                )
                self.storage.container_flush(acct, ct, all_versions=True)
                self.storage.container_delete(acct, ct)
            except Exception:
                # Maybe its a root container, flush is not possible, delete it
                # with force=True.
                try:
                    self.storage.container_delete(acct, ct, force=True)
                except Exception as exc:
                    self.logger.info("Failed to clean container %s", exc)

        for acct, bucket in self._buckets_to_clean:
            try:
                self.storage.bucket.bucket_delete(bucket, acct)
            except Exception as exc:
                self.logger.info("Failed to remove bucket, %s", exc)

        # Reset namespace configuration as it was before we mess with it
        if self._ns_conf != self._ns_conf_backup:
            remove = {x for x in self._ns_conf if x not in self._ns_conf_backup}
            self.set_ns_opts(self._ns_conf_backup, remove=remove)
        for srv in self._deregister_at_teardown:
            try:
                self._deregister_srv(srv)
            except Exception:
                pass

        super().tearDown()

    @classmethod
    def tearDownClass(cls):
        for consumer in cls._consumers:
            if consumer is not None:
                # Close consumer
                consumer.close()
        cls._cls_kafka_consumer = None
        super(CommonTestCase, cls).tearDownClass()

    @property
    def conscience(self):
        return self.storage.conscience

    @property
    def http_pool(self):
        if not self._http_pool:
            self._http_pool = get_pool_manager()
        return self._http_pool

    @property
    def admin(self):
        """Get a client for admin operations (especially sqliterepo)."""
        if not self._admin:
            from oio.directory.admin import AdminClient

            self._admin = AdminClient(
                self.conf, pool_manager=self.http_pool, logger=self.logger
            )
        return self._admin

    @property
    def beanstalkd(self):
        if not self._beanstalk:
            self._beanstalk = Beanstalk.from_url(self.conf["queue_url"])
        return self._beanstalk

    @property
    def beanstalkd0(self):
        if not self._beanstalkd0:
            self._beanstalkd0 = Beanstalk.from_url(self.conf["main_queue_url"])
        return self._beanstalkd0

    def get_kafka_consumer(self, topics=None, group_id=DEFAULT_GROUP_ID_TEST):
        kafka_consumer = KafkaConsumer(
            self.conf["kafka_endpoints"],
            topics,
            group_id,
            logger=self.logger,
            app_conf=self.conf,
            kafka_conf={
                "enable.auto.commit": False,
                "auto.offset.reset": "latest",
            },
        )
        return kafka_consumer

    @property
    def bucket_client(self):
        return self.storage.bucket

    @property
    def kms(self):
        return self.storage.kms

    @property
    def rdir(self):
        if self._rdir_client is None:
            from oio.rdir.client import RdirClient

            self._rdir_client = RdirClient(
                self.conf, directory_client=self.storage.directory, logger=self.logger
            )
        return self._rdir_client

    @property
    def storage(self):
        if self._storage_api is None:
            from oio.api.object_storage import ObjectStorageApi

            self._storage_api = ObjectStorageApi(
                self.ns,
                pool_manager=self.http_pool,
                watchdog=self.watchdog,
                location=self.CLIENT_LOCATION,
                logger=self.logger,
            )
        return self._storage_api

    @property
    def container_sharding(self):
        if self._container_sharding is None:
            from oio.container.sharding import ContainerSharding

            self._container_sharding = ContainerSharding(
                self.conf,
                logger=self.logger,
                pool_manager=self.http_pool,
            )
        return self._container_sharding

    @property
    def logger(self):
        return self._cls_logger

    @property
    def watchdog(self):
        if self._watchdog is None:
            self._watchdog = get_watchdog(called_from_main_application=True)
        return self._watchdog

    @property
    def ns_conf(self):
        """
        Get the configuration of the local namespace ("sds.conf").
        """
        if self._ns_conf is None:
            self._ns_conf = load_namespace_conf(self.ns)
            self._ns_conf_backup = dict(self._ns_conf)
        return self._ns_conf

    def clean_later(self, container, account=None, prepend=False):
        """
        Register a container to be cleaned at tearDown.
        If prepend is true, container will be added at the start of the list otherwise
        at the end.
        """
        if prepend:
            self._containers_to_clean.insert(0, (account or self.account, container))
        else:
            self._containers_to_clean.append((account or self.account, container))

    def bucket_clean_later(self, bucket, account=None):
        self._buckets_to_clean.append((account or self.account, bucket))

    def set_ns_opts(self, opts, remove=None):
        """
        Insert new options in the namespace configuration file,
        and reload ns_conf.
        """
        self._ns_conf = set_namespace_options(self.ns, opts, remove=remove)

    def _list_srvs(self, srvtype):
        resp = self.request("GET", self._url_cs("list"), params={"type": srvtype})
        self.assertEqual(resp.status, 200)
        return self.json_loads(resp.data)

    def _flush_cs(self, srvtype):
        params = {"type": srvtype}
        resp = self.request(
            "POST", self._url_cs("flush"), params=params, headers=self.TEST_HEADERS
        )
        self.assertIn(resp.status, (200, 204))

    def _deregister_srv(self, srv):
        resp = self.request(
            "POST",
            self._url_cs("deregister"),
            jsonlib.dumps(srv),
            headers=self.TEST_HEADERS,
        )
        self.assertIn(resp.status, (200, 204))

    def _register_srv(self, srv, cs=None, deregister=True):
        params = None
        if cs:
            params = {"cs": cs}
        resp = self.request(
            "POST",
            self._url_cs("register"),
            jsonlib.dumps(srv),
            headers=self.TEST_HEADERS,
            params=params,
        )
        self.assertIn(resp.status, (200, 204))
        if deregister:
            self._deregister_at_teardown.append(srv)

    def _lock_srv(self, srv):
        resp = self.request(
            "POST", self._url_cs("lock"), jsonlib.dumps(srv), headers=self.TEST_HEADERS
        )
        self.assertIn(resp.status, (200, 204))

    def _unlock_srv(self, srv, cs=None):
        params = None
        if cs:
            params = {"cs": cs}
        resp = self.request(
            "POST",
            self._url_cs("unlock"),
            jsonlib.dumps(srv),
            headers=self.TEST_HEADERS,
            params=params,
        )
        self.assertIn(resp.status, (200, 204))

    def _flush_proxy(self):
        """Flush high and low caches, and the internal load-balancer."""
        url = self.uri + "/v3.0/cache/flush/local"
        resp = self.request("POST", url, "", headers=self.TEST_HEADERS)
        self.assertEqual(resp.status // 100, 2)

    @classmethod
    def _cls_reload_proxy(cls):
        url = "{0}/v3.0/{1}/lb/reload".format(cls._cls_uri, cls._cls_ns)
        cls.static_request("POST", url, "")

    @classmethod
    def _cls_get_proxy_config(cls):
        """
        Get the current configuration of the local oio-proxy.

        :rtype: dict
        """
        url = f"{cls._cls_uri}/v3.0/config"
        resp = cls.static_request("GET", url)
        return jsonlib.loads(resp.data)

    @classmethod
    def _cls_set_proxy_config(cls, config):
        url = f"{cls._cls_uri}/v3.0/config"
        cls.static_request("POST", url, json=config)

    def _reload_proxy(self):
        """Ask oio-proxy to reload the whole list of services from conscience."""
        url = "{0}/v3.0/{1}/lb/reload".format(self.uri, self.ns)
        resp = self.request("POST", url, "", headers=self.TEST_HEADERS)
        self.assertEqual(resp.status // 100, 2)

    def _flush_meta(self):
        for srvtype in ("meta1", "meta2"):
            for t in self.conf["services"][srvtype]:
                url = self.uri + "/v3.0/forward/flush"
                resp = self.request(
                    "POST", url, params={"id": t["addr"]}, headers=self.TEST_HEADERS
                )
                if resp.status != 204:
                    self.logger.warning(
                        "Failed to flush caches of %s: (%d) %s",
                        t["addr"],
                        resp.status,
                        resp.data,
                    )

    @classmethod
    def _cls_reload_meta(cls):
        for srvtype in ("meta1", "meta2"):
            for t in cls._cls_conf["services"][srvtype]:
                url = cls._cls_uri + "/v3.0/forward/reload"
                cls.static_request("POST", url, params={"id": t["addr"]})

    def _reload_meta(self):
        for srvtype in ("meta1", "meta2"):
            for t in self.conf["services"][srvtype]:
                url = self.uri + "/v3.0/forward/reload"
                resp = self.request(
                    "POST", url, params={"id": t["addr"]}, headers=self.TEST_HEADERS
                )
                if resp.status != 204:
                    self.logger.warning(
                        "Failed to reload LB of %s: (%d) %s",
                        t["addr"],
                        resp.status,
                        resp.data,
                    )

    def _reload(self, wait=1.0):
        self._flush_proxy()
        self._flush_meta()
        # In a perfect world™️ we do not need the time.sleep().
        # For mysterious reason, all services are not reloaded immediately.
        self._reload_meta()
        time.sleep(wait)
        self._reload_proxy()
        time.sleep(wait)

    def _addr(self, low=7000, high=65535, ip="127.0.0.2"):
        return ip + ":" + str(random.randint(low, high))

    def _srv(
        self, srvtype, extra_tags={}, lowport=7000, highport=65535, ip="127.0.0.2"
    ):
        netloc = self._addr(low=lowport, high=highport, ip=ip)
        outd = {
            "ns": self.ns,
            "type": str(srvtype),
            "addr": netloc,
            "score": random.randint(1, 100),
            "tags": {
                "stat.cpu": 1,
                "tag.vol": "test",
                "tag.up": True,
                "tag.service_id": netloc,
            },
        }
        if extra_tags:
            outd["tags"].update(extra_tags)
        return outd

    def assertIsError(self, body, expected_code_oio):
        self.assertIsInstance(body, dict)
        self.assertIn("status", body)
        self.assertIn("message", body)
        self.assertEqual(body["status"], expected_code_oio)

    def assertError(self, resp, code_http, expected_code_oio):
        self.assertEqual(resp.status, code_http)
        self.assertIsError(self.json_loads(resp.data), expected_code_oio)

    @classmethod
    def json_loads(cls, data):
        try:
            return jsonlib.loads(data)
        except ValueError:
            logging.info("Unparsable data: %s", str(data))
            raise


class BaseTestCase(CommonTestCase):
    def setUp(self):
        super().setUp()
        self.locked_svc = []

    def tearDown(self):
        if self.locked_svc:
            self.conscience.unlock_score(self.locked_svc)
        super().tearDown()
        if self.locked_svc:
            self.conscience.unlock_score(self.locked_svc)

    def _lock_services(self, type_, services, wait=1.0, score=0, reload_meta=False):
        """
        Lock specified services, wait for the score to be propagated.
        """
        new_locked_svc = [
            {"type": type_, "addr": svc["addr"], "score": score} for svc in services
        ]
        self.conscience.lock_score(new_locked_svc)
        self.locked_svc.extend(new_locked_svc)
        # In a perfect world™️ we do not need the time.sleep().
        # For mysterious reason, all services are not reloaded immediately.
        self._reload_proxy()
        time.sleep(wait)
        if reload_meta:
            self._reload_meta()
            time.sleep(wait)

    @classmethod
    def _service(cls, name, action, wait=0):
        """
        Execute a systemctl action on a service, and optionally sleep for
        some seconds before returning.

        :param name: The service or group upon which the command
            should be executed.
        :param action: The command to send. (E.g. 'start' or 'stop')
        :param wait: The amount of time in seconds to wait after the command.
        """
        cmd = ["systemctl"]
        if "OIO_SYSTEMD_SYSTEM" not in os.environ:
            cmd.append("--user")

        if action == "daemon-reload":
            cmd.append(action)
        else:
            cmd.extend([action, name])
        check_call(cmd)
        if wait > 0:
            time.sleep(wait)

    def grouped_services(self, type_, key, reqid=None):
        """
        Build a dictionary of lists of services indexed by `key`.

        :param type_: the type if services to index
        :param key: a function
        """
        all_svcs = self.conscience.all_services(type_, reqid=reqid)
        out = defaultdict(list)
        for svc in all_svcs:
            out[key(svc)].append(svc)
        return out

    def load_watch_conf(self, svc):
        watch_file = os.path.expandvars(
            f"${{HOME}}/.oio/sds/conf/watch/{self.ns}-{svc}.yml"
        )
        with open(watch_file, "r", encoding="utf-8") as infile:
            conf = yaml.load(infile, Loader=yaml.Loader)
        return conf

    def save_watch_conf(self, svc, conf):
        watch_file = os.path.expandvars(
            f"${{HOME}}/.oio/sds/conf/watch/{self.ns}-{svc}.yml"
        )
        with open(watch_file, "w", encoding="utf-8") as outfile:
            yaml.dump(conf, outfile)

    def service_to_systemd_key(self, svc, type_):
        """
        Convert a service addr or ID to the systemd key for the same service.
        """
        for descr in self.conf["services"][type_]:
            svcid = descr.get("service_id")
            if svc == svcid:
                return descr["unit"]
            elif svc == descr["addr"]:
                return descr["unit"]
        raise ValueError("%s not found in the list of %s services" % (svc, type_))

    def storage_method_from_policy(self, storage_policy):
        """Get a StorageMethod instance from a storage policy name."""
        cluster_info = self.conscience.info()
        _pool, datasec = cluster_info["storage_policy"][storage_policy].split(":")
        return STORAGE_METHODS.load(cluster_info["data_security"].get(datasec, "plain"))

    def wait_for_score(self, types, timeout=12.0, score_threshold=35, score_type="put"):
        """Wait for services to have a score greater than the threshold.

        :param score_type: The type of score to wait, can be "put", get or
            "both".
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            wait = False
            for type_ in types:
                try:
                    all_svcs = self.conscience.all_services(type_)
                    for service in all_svcs:
                        if (
                            score_type == "put"
                            and int(service["score"]) < score_threshold
                        ):
                            wait = True
                            break
                        elif (
                            score_type == "get"
                            and int(service["scores"]["score.get"]) < score_threshold
                        ):
                            wait = True
                            break
                        elif (
                            score_type == "both"
                            and int(service["scores"]["score.put"]) < score_threshold
                            and int(service["scores"]["score.get"]) < score_threshold
                        ):
                            wait = True
                            break
                    else:
                        # No service registered yet, must wait.
                        if not all_svcs:
                            wait = True
                except Exception as err:
                    logging.warning("Could not check service score: %s", err)
                    wait = True
                if wait:
                    # No need to check other types, we have to wait anyway
                    break
            if not wait:
                return
            time.sleep(1)
        logging.info(
            "Service(s) fails to reach %d score (timeout %d)", score_threshold, timeout
        )

    def wait_for_service(self, service_type, service_id, timeout=5.0, **kwargs):
        """
        Wait for a specific service to appear in conscience.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            all_svcs = self.conscience.all_services(service_type, **kwargs)
            for svc in all_svcs:
                id_ = svc["tags"].get("tag.service_id", svc["addr"])
                if id_ == service_id:
                    return svc
            time.sleep(1.0)
        return None

    def clear_events(self, kafka_consumer=None):
        """
        Clear all cached events.
        """
        if not kafka_consumer:
            kafka_consumer = self._cls_kafka_consumer

        cached_events = self._cached_events.setdefault(kafka_consumer, {})
        used_events = self._used_events.setdefault(kafka_consumer, set())

        cached_events.clear()
        used_events.clear()

    def wait_for_kafka_event(self, *args, **kwargs):
        return self.wait_for_event(*args, **kwargs)

    def wait_for_event(
        self,
        reqid=None,
        svcid=None,
        types=None,
        fields=None,
        origin=None,
        data_fields=None,
        timeout=30.0,
        kafka_consumer=None,
    ):
        """
        Wait for an event to pass through event agents.
        If reqid, types and/or fields are specified, drain events until the
        specified event is found.

        :param fields: dict of fields to look for in the event's URL
        :param types: list of types of events the method should look for
        """
        if not kafka_consumer:
            kafka_consumer = self._cls_kafka_consumer

        cached_events = self._cached_events.setdefault(kafka_consumer, {})
        used_events = self._used_events.setdefault(kafka_consumer, set())

        def match_event(key, event):
            if types and event.event_type not in types:
                self.logger.debug("ignore event %s (event mismatch)", event)
                return False
            if reqid and event.reqid != reqid:
                self.logger.info("ignore event %s (request_id mismatch)", event)
                return False
            if svcid and event.svcid != svcid:
                self.logger.info("ignore event %s (service_id mismatch)", event)
                return False
            if fields and any(fields[k] != event.url.get(k) for k in fields):
                self.logger.info("ignore event %s (filter mismatch)", event)
                return False
            if origin and event.origin != origin:
                self.logger.info("ignore event %s (origin mismatch)", event)
                return False
            if data_fields and any(
                data_fields[k] != event.data.get(k) for k in data_fields
            ):
                self.logger.info("ignore event %s (data_fields mismatch)", event)
                return False

            self.logger.info("event %s", event)
            used_events.add(key)
            return True

        # Check if event is already present
        for key, event in cached_events.items():
            if key in used_events:
                continue
            if match_event(key, event):
                return event

        now = time.time()
        deadline = now + timeout
        try:
            for event in kafka_consumer.fetch_events():
                now = time.time()
                if now > deadline:
                    # Stop fetching events
                    break
                if not event or event.error():
                    continue
                event_key = f"{event.topic()},{event.partition()},{event.offset()}"
                data = event.value()
                event_obj = Event(jsonlib.loads(data))
                event_obj.job_id = event.offset()
                event_obj.event_key = event.key()

                # Add to cache
                cached_events[event_key] = event_obj

                if match_event(event_key, event_obj):
                    return event_obj

            self._cls_logger.warning(
                "wait_for_kafka_event(reqid=%s, types=%s, svcid=%s, fields=%s,"
                " timeout=%s) reached its timeout",
                reqid,
                types,
                svcid,
                fields,
                timeout,
            )
        except ResponseError as err:
            self._cls_logger.warning("%s", err)
        return None

    def wait_until_empty(
        self,
        topic,
        group_id,
        timeout=30.0,
        poll_interval=2.0,
        initial_delay=0.0,
    ):
        """
        Wait until all events in the specified topic are consumed or the timeout
        expires.
        """
        deadline = time.time() + timeout
        if initial_delay > 0.0:
            time.sleep(initial_delay)
        kafka_consumer = self.get_kafka_consumer(topics=[], group_id=group_id)
        try:
            while True:
                time.sleep(poll_interval)
                lags = kafka_consumer.get_topic_lag(topic)
                sum_lag = sum(lags.values())
                if sum_lag == 0:
                    break
                if time.time() > deadline:
                    raise TimeoutError(
                        f"Topic {topic} not empty after {timeout} (lag={sum_lag})"
                    )
        finally:
            kafka_consumer.close()

    def wait_for_chunk_indexation(self, chunk_url, timeout=10.0):
        _, rawx_service, chunk_id = chunk_url.rsplit("/", 2)
        deadline = time.monotonic() + timeout
        rdir_entries = self.rdir.chunk_search(rawx_service, chunk_id)
        while not rdir_entries and time.monotonic() < deadline:
            self.logger.info("Waiting for chunk %s to be indexed in rdir", chunk_url)
            time.sleep(1.0)
            rdir_entries = self.rdir.chunk_search(rawx_service, chunk_id)

        if not rdir_entries:
            self.logger.warning(
                "Chunk %s not found in rdir after %.3fs", chunk_url, timeout
            )
        else:
            self.logger.debug("Chunk %s found in rdir: %s", chunk_url, rdir_entries)

    def shard_container(self, container, account=None):
        """
        Shard a container and add all shards to the list of containers to clean later
        (done by teardown method).
        """
        if not account:
            account = self.account

        objs = self.storage.object_list(
            account=account, container=container, deleted=True
        )["objects"]
        objs.sort(key=lambda x: x["name"])
        if len(objs) < 2:
            return []
        mid_obj_name = objs[len(objs) // 2 - 1]["name"]
        shards = [
            {"index": 0, "lower": "", "upper": mid_obj_name},
            {"index": 1, "lower": mid_obj_name, "upper": ""},
        ]

        format_shards = self.container_sharding.format_shards(shards, are_new=True)
        modified = self.container_sharding.replace_shard(
            account, container, format_shards, enable=True
        )
        self.assertTrue(modified)

        # Update list to clean containers during teardown
        new_shards = self.container_sharding.show_shards(account, container)
        new_containers = []
        shard_account = f".shards_{self.account}"
        for shard in new_shards:
            props = self.storage.container_get_properties(
                account=None, container=None, cid=shard["cid"]
            )
            cname = props["system"][M2_PROP_CONTAINER_NAME]
            self.clean_later(
                container=cname,
                account=shard_account,
                prepend=True,
            )
            new_containers.append((shard_account, cname))
        return new_containers
