# Copyright (C) 2017-2019 OpenIO SAS, as part of OpenIO SDS
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

import json
import random
import time
from datetime import datetime, timedelta, timezone

from oio.common.client import ProxyClient
from oio.common.kafka import DEFAULT_ENDPOINT, DEFAULT_LIFECYCLE_TOPIC, KafkaConsumer
from oio.common.utils import cid_from_name, request_id
from oio.container.lifecycle import (
    LIFECYCLE_PROPERTY_KEY,
    TAGGING_KEY,
    ContainerLifecycle,
)
from oio.directory.admin import AdminClient
from oio.event.evob import EventTypes
from tests.functional.cli import CliTestCase
from tests.utils import BaseTestCase, random_str

DEFAULT_GROUP_ID_TEST = "event-agent-test"


class Helper(object):
    def __init__(self, api, account, container):
        self.api = api
        self.account = account
        self.container = container

    def enable_versioning(self):
        self.api.container_set_properties(
            self.account, self.container, system={"sys.m2.policy.version": "-1"}
        )
        self.api.container_set_properties(
            self.account, self.container, system={"sys.policy.version": "-1"}
        )


class BaseClassLifeCycle(BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super(BaseTestCase, cls).setUpClass()
        group_id = f"{DEFAULT_GROUP_ID_TEST}-{random_str(8)}"
        cls._cls_kafka_consumer = KafkaConsumer(
            DEFAULT_ENDPOINT,
            [DEFAULT_LIFECYCLE_TOPIC],
            group_id,
            logger=cls._cls_logger,
            app_conf=cls._cls_conf,
            kafka_conf={
                "enable.auto.commit": True,
                "auto.offset.reset": "latest",
            },
        )

    def setUp(self):
        super(BaseClassLifeCycle, self).setUp()
        self.api = self.storage
        self.account = "test_lifecycle"
        self.container = "lifecycle-" + random_str(4)
        self.api.container_create(self.account, self.container)
        self.clean_later(self.container)
        self.lifecycle = ContainerLifecycle(self.api, self.account, self.container)
        self.helper = Helper(self.api, self.account, self.container)

    def tearDown(self):
        super(BaseClassLifeCycle, self).tearDown()

    def _upload_something(
        self, prefix="", random_length=4, data=None, name=None, size=None, **kwargs
    ):
        name = name or (prefix + random_str(random_length))
        data = data or (random_str(8))
        self.api.object_create(
            self.account, self.container, obj_name=name, data=data, **kwargs
        )
        obj_meta = self.api.object_show(self.account, self.container, name)
        obj_meta["container"] = self.container
        if size is not None:
            obj_meta["size"] = size
        return obj_meta


class TestContainerLifecycle(BaseClassLifeCycle):
    @staticmethod
    def _time_to_date(timestamp=None):
        if timestamp is None:
            timestamp = time.time()
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(timestamp))

    def _enable_versioning(self):
        if not self.api.container_create(
            self.account, self.container, system={"sys.m2.policy.version": "-1"}
        ):
            self.api.container_set_properties(
                self.account, self.container, system={"sys.policy.version": "-1"}
            )

    def test_load_from_container_property(self):
        source = """{"Rules":
            {"id1":{
                "Status":"Enabled","Expiration":{"Days":11},
                "Filter":{"Prefix":"test","ObjectSizeGreaterThan":101}
                }
            }
        }"""
        props = {LIFECYCLE_PROPERTY_KEY: source}
        self.api.container_set_properties(
            self.account, self.container, properties=props
        )
        self.lifecycle.load()

    def test_save_to_container_property(self):
        source = """{"Rules":
            {"id1":{
                "Status":"Enabled","Expiration":{"Days":11},
                "Filter":{"Prefix":"test","ObjectSizeGreaterThan":101}
                }
            }
        }"""

        self.lifecycle.load_json(source)
        self.lifecycle.save()
        json_conf = self.lifecycle.get_configuration()
        self.assertEqual(
            source.replace(" ", "").replace("\n", ""),
            json_conf.replace(" ", "").replace("\n", ""),
        )


class TestLifecycleConform(CliTestCase, BaseClassLifeCycle):
    def setUp(self):
        super(TestLifecycleConform, self).setUp()
        self.batch_size = 2
        self.to_match = []
        self.not_to_match = []
        self.to_match_markers = []
        self.lifecycle = ContainerLifecycle(self.api, self.account, self.container)
        self.proxy_client = ProxyClient(
            self.conf, pool_manager=self.api.container.pool_manager, logger=self.logger
        )
        admin_args = {}
        admin_args["force_master"] = False
        self.admin_client = AdminClient(self.conf, logger=self.logger, **admin_args)
        self.helper = Helper(self.api, self.account, self.container)
        self.prefix = "doc"
        self.data_short = "test"
        self.data_middle = "test some data"
        self.data_long = "some long data oustide max conditions"

        self.action = "Expiration"
        self.action_config = {"Expiration": {"Days": 11}}

        self.versioning_enabled = False
        self.number_of_versions = 1
        self.expected_to_cycle = 1

        self.conditions = {
            "prefix": self.prefix,
            "greater": 10,
            "lesser": 20,
            "tag1": {"key1": "value1"},
            "tag2": {"key2": "value2"},
            "tag3": {"key3": "value1"},
        }
        self.number_match = random.randint(2, 3)
        self.number_not_match = random.randint(2, 3)

        self.not_match_tag_set = """
            <Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
            <TagSet><Tag><Key>excluded-key</Key><Value>value1</Value></Tag>
            </Tagset></Tagging>"""

    def tearDown(self):
        super(TestLifecycleConform, self).tearDown()

    def _copy_db(self):
        self.cid = cid_from_name(self.account, self.container)

        status = self.admin_client.election_status(
            "meta2", account=self.account, reference=self.container
        )
        slaves = status.get("slaves", [])
        if slaves:
            self.peer_to_use = slaves[0]
        else:
            self.peer_to_use = status.get("master", [])

        params = {"type": "meta2", "cid": self.cid, "suffix": "lifecycle"}
        json_peers = {"from": self.peer_to_use, "to": self.peer_to_use, "local": 1}

        resp, body = self.proxy_client._request(
            "POST", "/admin/copy", params=params, json=json_peers
        )
        self.assertEqual(resp.status, 204)

    def _check_and_apply(self, source, nothing_to_match=False):
        if not nothing_to_match:
            self.assertIsNot(len(self.to_match), 0)
        self._copy_db()
        time.sleep(1)
        self._exec_rules_via_sql_query(source)

    def _check_event(self, elements_to_match, event):
        elem_to_remove = None
        found = False
        for elem in elements_to_match:
            version = int(elem["version"])
            if (
                elem["name"] == event.data["object"]
                and version == event.data["version"]
                and int(elem["mtime"]) == event.data["mtime"]
            ):
                found = True
                elem_to_remove = elem
                break

        return [found, elem_to_remove]

    def _get_action_parameters(self, act_type, act):
        days = None
        date = None
        delete_marker = None
        if act_type == "Expiration":
            days = act.get("Days")
            date = act.get("Date")
            delete_marker = act.get("ExpiredObjectDeleteMarker")
        elif act_type == "Transitions":
            days = act.get("Days")
            date = act.get("Date")
        return [days, date, delete_marker]

    def _check_query_events(
        self,
        queries,
        action,
        view_queries,
        newer_non_current_versions,
        policy,
        last_rule_action,
    ):
        for key_query, val_query in queries.items():
            offset = 0
            while True:
                sql_query = val_query
                if action in (
                    "NoncurrentVersionExpiration",
                    "NoncurrentVersionTransition",
                ):
                    sql_query = f"{sql_query} limit 100" f" offset {offset} "
                else:
                    sql_query = (
                        f"{sql_query} limit {self.batch_size} " f" offset {offset} "
                    )

                kwargs = {}
                params = {"cid": self.cid, "service_id": self.peer_to_use}
                data = {}
                data["action"] = action
                data["suffix"] = "lifecycle"
                if offset == 0 and key_query == "base":
                    for key, val in view_queries.items():
                        data[key] = val
                data["query"] = sql_query
                # force checks non_current_days
                data["newerNoncurrentDays"] = 0
                data["newerNoncurrentVersions"] = newer_non_current_versions
                data["policy"] = policy
                data["batch_size"] = self.batch_size
                if last_rule_action:
                    data["last_action"] = 1

                reqid = request_id()
                resp, body = self.proxy_client._request(
                    "POST",
                    "/container/lifecycle/apply",
                    params=params,
                    reqid=reqid,
                    json=data,
                    **kwargs,
                )
                count = int(resp.getheader("x-oio-count", 0))
                offset += count
                count_events = 0

                if action in ("Expiration", "Transition"):
                    exptected_events = count * self.expected_to_cycle
                else:
                    exptected_events = self.expected_to_cycle

                while count_events < exptected_events:
                    event = self.wait_for_kafka_event(
                        types=(EventTypes.LIFECYCLE_ACTION,)
                    )
                    self.assertIsNotNone(event)
                    self.assertEqual(event.event_type, "storage.lifecycle.action")
                    self.assertEqual(event.data["account"], self.account)
                    self.assertEqual(event.data["container"], self.container)

                    elements_to_match = (
                        self.to_match if key_query == "base" else self.to_match_markers
                    )

                    [found, elem_to_remove] = self._check_event(
                        elements_to_match, event
                    )
                    if not found:
                        # For debug
                        print("elements_to_match:", elements_to_match)
                        print("event.data:", event.data)
                    self.assertEqual(found, True)
                    list_of_bool = [
                        True
                        for elem in self.not_to_match
                        if event.data["object"]
                        and event.data["version"] in elem.values()
                    ]
                    self.assertEqual(any(list_of_bool), False)
                    elements_to_match.remove(elem_to_remove)

                    self.assertEqual(event.data["action"], action)
                    count_events += 1

                if count == 0:
                    break

    def _is_last_action_last_rule(self, rules, actions, count_rules, count_actions):
        if (count_rules == len(rules) - 1) and (count_actions == len(actions) - 1):
            return True
        else:
            return False

    def _get_actions(self, rule):
        actions = {}
        expiration = rule.get("Expiration", None)
        transitions = rule.get("Transitions", [])
        if expiration is not None:
            actions["Expiration"] = [expiration]
        if len(transitions) > 0:
            actions["Transitions"] = transitions
        return actions

    def _exec_rules_via_sql_query(self, source):
        lc = ContainerLifecycle(self.api, self.account, self.container)
        lc.load_json(source)
        lc.save()
        json_dict = json.loads(source)

        count_rules = 0
        count_actions = 0
        for rule_id, rule in json_dict["Rules"].items():
            rule["ID"] = rule_id
            actions = self._get_actions(rule)
            for act_type, act_list in actions.items():
                for act in act_list:
                    days_in_sec = None
                    base_sql_query = None
                    non_current = False
                    newer_non_current_versions = 0
                    non_current_days = 0
                    policy = ""
                    queries = {}
                    view_queries = {}
                    action = ""
                    days = None
                    date = None
                    delete_marker = None

                    if act_type == "NoncurrentVersionExpiration":
                        newer_non_current_versions = act["NewerNoncurrentVersions"]
                        non_current_days = act["Days"]
                        non_current = True
                        action = "NoncurrentVersionExpiration"
                    elif act_type == "NoncurrentVersionTransitions":
                        newer_non_current_versions = act["NewerNoncurrentVersions"]
                        non_current_days = act["Days"]
                        policy = act["StorageClass"]
                        non_current = True
                        action = "NoncurrentVersionTransition"
                    elif act_type == "Expiration":
                        action = "Expiration"
                    elif act_type == "Transitions":
                        policy = act["StorageClass"]
                        action = "Transition"
                    else:
                        print("Unsupported action type", act_type)
                        return

                    days, date, delete_marker = self._get_action_parameters(
                        act_type, act
                    )
                    # TODO(check if versioning is enabled on client side)
                    # Versioning and NoncurrentVersions
                    # For tests(non_current_days_in_sec set to 0)
                    # non_current_days_in_sec = 86400 * non_current_days
                    non_current_days_in_sec = 0 * non_current_days

                    if self.versioning_enabled:
                        if non_current:
                            non_current_days_in_sec = non_current_days_in_sec
                            noncurrent_view = lc.create_noncurrent_view(
                                non_current_days_in_sec
                            )
                            current_view = lc.create_common_views(
                                "current_view", non_current_days_in_sec
                            )

                            view_queries["noncurrent_view"] = noncurrent_view
                            view_queries["current_view"] = current_view
                            queries["base"] = lc.noncurrent_query()
                        # versioning for Expiration/Transition
                        else:
                            delete_marker_view = lc.create_common_views(
                                "marker_view", non_current_days_in_sec, deleted=True
                            )
                            vesioned_view = lc.create_common_views(
                                "versioned_view", non_current_days_in_sec, deleted=False
                            )

                            noncurrent_view = lc.create_noncurrent_view(
                                non_current_days_in_sec
                            )

                            view_queries["marker_view"] = delete_marker_view
                            view_queries["versioned_view"] = vesioned_view
                            view_queries["noncurrent_view"] = noncurrent_view

                            queries["base"] = lc.build_sql_query(
                                rule, non_current_days_in_sec, None, False, True
                            )
                            queries["marker"] = lc.markers_query()

                    else:  # non versioned
                        if days is not None:
                            days_in_sec = 0 * days
                        base_sql_query = lc.build_sql_query(rule, days_in_sec, date)
                        queries["base"] = base_sql_query

                    last_rule_action = 0
                    self._check_query_events(
                        queries,
                        action,
                        view_queries,
                        newer_non_current_versions,
                        policy,
                        last_rule_action,
                    )
                count_actions += 1
                self.assertEqual(len(self.to_match), 0)
                self.assertEqual(len(self.to_match_markers), 0)
            count_rules += 1


class TestLifecycleConformExpiration(TestLifecycleConform):
    def setUp(self):
        super(TestLifecycleConformExpiration, self).setUp()
        self.action = "Expiration"

    def tearDown(self):
        super(TestLifecycleConformExpiration, self).tearDown()

    def test_apply_prefix(self):
        source = (
            """
            {"Rules":
                {"rule1":
                    {
                    "Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":{"Prefix":"a"}
                    }
                }
            }"""
        )

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()
        for _ in range(self.number_match):
            obj_meta = self._upload_something(prefix="a/")
            self.to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(prefix="b/")
            self.not_to_match.append(obj_meta)

        self._check_and_apply(source)

    def test_apply_tag(self):
        # ["tag1"]
        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]

        source = (
            """
            {"Rules":
                { "rule1":
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        { "Tags":["""
            f"{json.dumps(self.conditions['tag1'])}"
            """]}
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for _ in range(self.number_match):
            obj_meta = self._upload_something(
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match.append(obj_meta)

        self._check_and_apply(source)

    def test_apply_prefix_and_greater(self):
        data_short = "some data"
        data_long = "some data and more"
        middle = (len(data_short) + len(data_long)) // 2

        source = (
            """
            {"Rules":
                {"rule1":
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"Prefix":"a", "ObjectSizeGreaterThan":"""
            f"{middle}"
            """}
                    }
                }
            }"""
        )
        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )

        if self.versioning_enabled:
            self.helper.enable_versioning()

        for _ in range(self.number_match):
            obj_meta = self._upload_something(prefix="a/", data=data_long)
            self.to_match.append(obj_meta)

        for _ in range(self.number_match):
            obj_meta = self._upload_something(prefix="a/", data=data_short)
            self.not_to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(prefix="b/", data=data_short)
            self.not_to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(prefix="b/", data=data_long)
            self.not_to_match.append(obj_meta)
        self._check_and_apply(source)

    def test_apply_prefix_and_lesser(self):
        data_short = "some data"
        data_long = "some data and more"
        middle = (len(data_short) + len(data_long)) // 2

        source = (
            """
            {"Rules":
                {"rule1":
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":{
                        "Prefix":"a/", "ObjectSizeLessThan":"""
            f"{middle}"
            """          }
                    }
                }
            }"""
        )

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for _ in range(self.number_match):
            obj_meta = self._upload_something(prefix="a/", data=data_long)
            self.not_to_match.append(obj_meta)

        for _ in range(self.number_match):
            obj_meta = self._upload_something(prefix="a/", data=data_short)
            self.to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(prefix="b/", data=data_short)
            self.not_to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(prefix="b/", data=data_long)
            self.not_to_match.append(obj_meta)

        self._check_and_apply(source)

    def _upload_expected_combine1(self):
        for _ in range(self.number_not_match):
            name = self.prefix + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_short, random_length=5
                )
                self.not_to_match.append(obj_meta)

        for _ in range(self.number_match):
            name = self.prefix + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_long, random_length=6
                )
                if i == self.number_of_versions - 1:
                    self.to_match.append(obj_meta)

    def test_combine1(self):
        # ["prefix', 'greater"]

        val = self.conditions["prefix"]
        greater = self.conditions["greater"]
        source = (
            """
            {"Rules":
                {"rule1":
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":{
                        "Prefix":"""
            f'"{val}"'
            """, "ObjectSizeGreaterThan":"""
            f"{greater}"
            """         }
                    }
                }
            }"""
        )

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        self._upload_expected_combine1()

        self._check_and_apply(source)

    def test_combine2(self):
        # ["prefix", "lesser"]

        val = self.conditions["prefix"]
        lesser = self.conditions["lesser"]
        source = (
            """
            {"Rules":
                {"rule1":
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"Prefix":"""
            f'"{val}"'
            """, "ObjectSizeLessThan":"""
            f"{lesser}"
            """}
                    }
                }
            }"""
        )

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for j in range(self.number_match):
            name = self.prefix + str(j) + "0" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_middle, random_length=4
                )
                if i == self.number_of_versions - 1:
                    self.to_match.append(obj_meta)

        for j in range(self.number_match):
            name = self.prefix + str(j) + "1" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_short, random_length=5
                )
                if i == self.number_of_versions - 1:
                    self.to_match.append(obj_meta)

        for j in range(self.number_not_match):
            name = self.prefix + str(j) + "2" + random_str(5)
            obj_meta = self._upload_something(
                name=name, data=self.data_long, random_length=6
            )
            self.not_to_match.append(obj_meta)

        self._check_and_apply(source)

    def test_combine3(self):
        # ["prefix", "tag1"]
        prefix = self.conditions["prefix"]
        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]

        source = (
            """
            {"Rules":
                {"rule1":
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"Prefix":"""
            f'"{prefix}"'
            """, "Tags":["""
            f"{json.dumps(self.conditions['tag1'])}"
            """]}
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for j in range(self.number_match):
            name = self.prefix + str(j) + "0" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=5,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match.append(obj_meta)

        for j in range(self.number_not_match):
            name = self.prefix + str(j) + "1" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_long,
                    random_length=6,
                    properties={TAGGING_KEY: self.not_match_tag_set},
                )
                self.not_to_match.append(obj_meta)

        self._check_and_apply(source)

    def test_combine4(self):
        # [prefix, tag1, tag2]
        val = self.conditions["prefix"]
        source = (
            """
            {"Rules":
                {"rule1":
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"Prefix":"""
            f'"{val}"'
            """, "Tags":
                            ["""
            f"{json.dumps(self.conditions['tag1'])}"
            ""","""
            f"{json.dumps(self.conditions['tag2'])}"
            """]
                        }
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for j in range(self.number_match):
            name = self.prefix + str(j) + "0" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=5,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match.append(obj_meta)

        for j in range(self.number_not_match):
            name = self.prefix + str(j) + "1" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_long,
                    random_length=6,
                    properties={TAGGING_KEY: self.not_match_tag_set},
                )
                self.not_to_match.append(obj_meta)

        self._check_and_apply(source)

    def test_combine5(self):
        # ["prefix", "tag1", "tag2", "tag3"]

        prefix = self.conditions["prefix"]
        source = (
            """
            {"Rules":
                {"rule1":
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"Prefix":"""
            f'"{prefix}"'
            """, "Tags":
                            ["""
            f"{json.dumps(self.conditions['tag1'])}"
            ""","""
            f"{json.dumps(self.conditions['tag2'])}"
            ""","""
            f"{json.dumps(self.conditions['tag3'])}"
            """]
                        }
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag3"].keys())[0]
        val = self.conditions["tag3"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for j in range(self.number_match):
            name = self.prefix + str(j) + "0" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=5,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match.append(obj_meta)

        for j in range(self.number_not_match):
            name = self.prefix + str(j) + "j" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    prefix=self.prefix,
                    data=self.data_long,
                    random_length=6,
                    properties={TAGGING_KEY: self.not_match_tag_set},
                )
                self.not_to_match.append(obj_meta)

        self._check_and_apply(source)

    def test_combine6(self):
        # ["prefix", "tag2", "tag3"]

        prefix = self.conditions["prefix"]
        source = (
            """
            {"Rules":
                {"rule1":
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"Prefix":"""
            f'"{prefix}"'
            """, "Tags":["""
            f"{json.dumps(self.conditions['tag2'])}"
            ""","""
            f"{json.dumps(self.conditions['tag3'])}"
            """]
                        }
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag3"].keys())[0]
        val = self.conditions["tag3"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for j in range(self.number_match):
            name = self.prefix + str(j) + "0" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=5,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match.append(obj_meta)

        for j in range(self.number_not_match):
            name = self.prefix + str(j) + "1" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_long,
                    random_length=6,
                    properties={TAGGING_KEY: self.not_match_tag_set},
                )
                self.not_to_match.append(obj_meta)
        self._check_and_apply(source)

    def test_combine7(self):
        # ["prefix", "greater", "lesser", "tag1"])
        prefix = self.conditions["prefix"]
        greater = self.conditions["greater"]
        lesser = self.conditions["lesser"]

        source = (
            """
            {"Rules":
                {"rule1":
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"Prefix":"""
            f'"{prefix}",'
            """"ObjectSizeLessThan":"""
            f"{lesser},"
            """"ObjectSizeGreaterThan":"""
            f"{greater},"
            """"Tags":["""
            f"{json.dumps(self.conditions['tag1'])}"
            """]
                        }
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""
        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for j in range(self.number_not_match):
            name = "not-prefix-" + str(j) + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_middle, random_length=4
                )
                self.not_to_match.append(obj_meta)

        for j in range(self.number_not_match):
            name = "not-prefix-" + str(j) + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_short, random_length=5
                )
                self.not_to_match.append(obj_meta)

        for j in range(self.number_not_match):
            name = "not-prefix-" + str(j) + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_long, random_length=6
                )
                self.not_to_match.append(obj_meta)

        for j in range(self.number_match):
            name = "not-prefix-" + str(j) + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_middle,
                    random_length=4,
                    properties={TAGGING_KEY: tag_set},
                )
                self.not_to_match.append(obj_meta)

        for j in range(self.number_not_match):
            name = "not-prefix-" + str(j) + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=5,
                    properties={TAGGING_KEY: tag_set},
                )
                self.not_to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(5),
                data=self.data_middle,
                random_length=4,
            )
            self.not_to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(5),
                data=self.data_short,
                random_length=5,
            )
            self.not_to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(6),
                data=self.data_long,
                random_length=6,
            )
            self.not_to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(5),
                data=self.data_middle,
                random_length=4,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(5),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix + random_str(5),
                data=self.data_middle,
                random_length=4,
            )
            self.not_to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix + random_str(5),
                data=self.data_short,
                random_length=5,
            )
            self.not_to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix + random_str(6), data=self.data_long, random_length=6
            )
            self.not_to_match.append(obj_meta)

        for j in range(self.number_match):
            name = self.prefix + str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_middle,
                    random_length=4,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix + random_str(5),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix + random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta)
        self._check_and_apply(source)

    def test_combine8(self):
        # ["greater', 'lesser"]
        greater = self.conditions["greater"]
        lesser = self.conditions["lesser"]

        source = (
            """
            {"Rules":
                {"rule1":
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"""
            """"ObjectSizeLessThan":"""
            f"{lesser},"
            """"ObjectSizeGreaterThan":"""
            f"{greater}"
            """}
                    }
                }
            }"""
        )

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for j in range(self.number_match):
            name = str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_middle, random_length=4
                )
                if i == self.number_of_versions - 1:
                    self.to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5), data=self.data_short, random_length=5
            )
            self.not_to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(6), data=self.data_long, random_length=6
            )
            self.not_to_match.append(obj_meta)
        self._check_and_apply(source)

    def test_combine9(self):
        # ["greater", "lesser", "tag1"])
        greater = self.conditions["greater"]
        lesser = self.conditions["lesser"]

        source = (
            """
            {"Rules":
                {"rule1":
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"""
            """"ObjectSizeLessThan":"""
            f"{lesser},"
            """"ObjectSizeGreaterThan":"""
            f"{greater},"
            """"Tags":["""
            f"{json.dumps(self.conditions['tag1'])}"
            """]}
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for _ in range(self.number_match):
            obj_meta = self._upload_something(
                prefix=random_str(5), data=self.data_middle, random_length=4
            )
            self.not_to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5), data=self.data_short, random_length=5
            )
            self.not_to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(6), data=self.data_long, random_length=6
            )
            self.not_to_match.append(obj_meta)

        for j in range(self.number_match):
            name = str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_middle,
                    random_length=4,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta)

        self._check_and_apply(source)

    def test_combine10(self):
        # ["greater", "tag2"]
        greater = self.conditions["greater"]

        source = (
            """
            {"Rules":
                {"rule1":
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"""
            """"ObjectSizeGreaterThan":"""
            f"{greater},"
            """"Tags":["""
            f"{json.dumps(self.conditions['tag2'])}"
            """]
                        }
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        greater = self.conditions["greater"]
        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta)

        for j in range(self.number_match):
            name = str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_long,
                    random_length=6,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match.append(obj_meta)

        self._check_and_apply(source)

    def test_combine11(self):
        # ["greater", "tag1", "tag2"]
        greater = self.conditions["greater"]

        source = (
            """
            {"Rules":
                {"rule1":
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"ObjectSizeGreaterThan":"""
            f"{greater},"
            """"Tags":["""
            f"{json.dumps(self.conditions['tag1'])}"
            f",{json.dumps(self.conditions['tag2'])}"
            """]
                        }
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match.append(obj_meta)

        for j in range(self.number_match):
            name = str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_long,
                    random_length=6,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match.append(obj_meta)

        self._check_and_apply(source)

    def test_combine12(self):
        # ["greater", "tag1", "tag2", "tag3"]
        greater = self.conditions["greater"]

        source = (
            """
            {"Rules":
                {"rule1":
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"ObjectSizeGreaterThan":"""
            f"{greater},"
            """"Tags":["""
            f"{json.dumps(self.conditions['tag1'])}"
            f",{json.dumps(self.conditions['tag2'])}"
            f",{json.dumps(self.conditions['tag3'])}"
            """]}
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag3"].keys())[0]
        val = self.conditions["tag3"][key]

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match.append(obj_meta)

        for j in range(self.number_match):
            name = str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_long,
                    random_length=6,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match.append(obj_meta)

        self._check_and_apply(source)

    def test_combine13(self):
        # ["greater", "tag2"', "tag3"]
        greater = self.conditions["greater"]

        source = (
            """
            {"Rules":
                {"rule1":
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"ObjectSizeGreaterThan":"""
            f"{greater},"
            """"Tags":["""
            f"{json.dumps(self.conditions['tag2'])}"
            f",{json.dumps(self.conditions['tag3'])}"
            """]
                        }
                    }
                }
            }"""
        )
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag3"].keys())[0]
        val = self.conditions["tag3"][key]

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match.append(obj_meta)

        for j in range(self.number_match):
            name = str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_long,
                    random_length=6,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match.append(obj_meta)

        self._check_and_apply(source)

    def test_combine14(self):
        # ["lesser", "tag1"]
        lesser = self.conditions["lesser"]

        source = (
            """
            {"Rules":
                {"rule1":
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"ObjectSizeLessThan":"""
            f"{lesser},"
            """"Tags":["""
            f"{json.dumps(self.conditions['tag1'])}"
            """]}
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for j in range(self.number_match):
            name = str(j) + "0" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_middle,
                    random_length=4,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match.append(obj_meta)

        for j in range(self.number_not_match):
            name = str(j) + "1" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=5,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta)

        for j in range(self.number_not_match):
            name = str(j) + "2" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_middle,
                    random_length=6,
                    properties={TAGGING_KEY: self.not_match_tag_set},
                )
                self.not_to_match.append(obj_meta)

        self._check_and_apply(source)

    def test_combine15(self):
        # ["lesser", "tag1", "tag2"]
        lesser = self.conditions["lesser"]

        source = (
            """
            {"Rules":
                {"rule1":
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"ObjectSizeLessThan":"""
            f"{lesser},"
            """"Tags":["""
            f"{json.dumps(self.conditions['tag1'])}"
            f",{json.dumps(self.conditions['tag2'])}"
            """]}
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for j in range(self.number_match):
            name = str(j) + "0" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_middle,
                    random_length=4,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match.append(obj_meta)

        for j in range(self.number_not_match):
            name = str(j) + "1" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=5,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match.append(obj_meta)

        for j in range(self.number_not_match):
            name = str(j) + "2" + random_str(5)
            obj_meta = self._upload_something(
                name=name,
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta)

        for j in range(self.number_not_match):
            name = str(j) + "3" + random_str(5)
            obj_meta = self._upload_something(
                name=name,
                data=self.data_middle,
                random_length=6,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match.append(obj_meta)

        self._check_and_apply(source)

    def test_combine16(self):
        # ["lesser", "tag1", "tag2", "tag3"]
        lesser = self.conditions["lesser"]

        source = (
            """
            {"Rules":
                {"rule1":
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"ObjectSizeLessThan":"""
            f"{lesser},"
            """"Tags":["""
            f"{json.dumps(self.conditions['tag1'])}"
            f",{json.dumps(self.conditions['tag2'])}"
            f",{json.dumps(self.conditions['tag3'])}"
            """]}
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag3"].keys())[0]
        val = self.conditions["tag3"][key]

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for j in range(self.number_match):
            name = str(j) + "0" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_middle,
                    random_length=4,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match.append(obj_meta)

        for j in range(self.number_not_match):
            name = str(j) + "1" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=5,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(7),
                data=self.data_middle,
                random_length=6,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match.append(obj_meta)

        self._check_and_apply(source)

    def test_combine17(self):
        # ["lesser", "tag2", "tag3"]
        lesser = self.conditions["lesser"]

        source = (
            """
            {"Rules":
                {"rule1":
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"ObjectSizeLessThan":"""
            f"{lesser},"
            """"Tags":["""
            f"{json.dumps(self.conditions['tag2'])}"
            f",{json.dumps(self.conditions['tag3'])}"
            """]}
                    }
                }
            }"""
        )
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag3"].keys())[0]
        val = self.conditions["tag3"][key]

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for j in range(self.number_match):
            name = str(j) + "0" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_middle,
                    random_length=4,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match.append(obj_meta)

        for j in range(self.number_not_match):
            name = str(j) + "1" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=5,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(7),
                data=self.data_middle,
                random_length=6,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match.append(obj_meta)

        self._check_and_apply(source)

    def test_combine18(self):
        # ["tag1", "tag2"]
        source = (
            """
            {"Rules":
                {"rule1":
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"Tags":["""
            f"{json.dumps(self.conditions['tag1'])}"
            f",{json.dumps(self.conditions['tag2'])}"
            """]}
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for j in range(self.number_match):
            name = str(j) + "0" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=5,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5),
                data=self.data_short,
                random_length=6,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match.append(obj_meta)
            self.assertIsNot(len(self.to_match), 0)

        self._check_and_apply(source)

    def test_combine19(self):
        # ["tag1", "tag2", "tag3"])
        source = (
            """
            {"Rules":
                {"rule1":
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"Tags":["""
            f"{json.dumps(self.conditions['tag1'])}"
            f",{json.dumps(self.conditions['tag2'])}"
            f",{json.dumps(self.conditions['tag3'])}"
            """]}
                    }
                }
            }"""
        )
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag3"].keys())[0]
        val = self.conditions["tag3"][key]

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for j in range(self.number_match):
            name = str(j) + "0" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=5,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match.append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5),
                data=self.data_short,
                random_length=6,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match.append(obj_meta)

        self._check_and_apply(source)


class TestLifecycleConformTransition(TestLifecycleConformExpiration):
    def setUp(self):
        super(TestLifecycleConformTransition, self).setUp()
        self.action = "Transitions"
        self.action_config = {
            "Transitions": [{"Days": 11, "StorageClass": "STANDARD_IA"}]
        }

    def tearDown(self):
        super(TestLifecycleConformTransition, self).tearDown()


class TestLifecycleConformExpirationDate(TestLifecycleConformExpiration):
    def setUp(self):
        super(TestLifecycleConformExpirationDate, self).setUp()
        self.action = "Expiration"
        now = datetime.now(timezone.utc)
        now_str = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
        self.action_config = {"Expiration": {"Date": f"{now_str}"}}

    def tearDown(self):
        super(TestLifecycleConformExpirationDate, self).tearDown()

    def test_non_expired_object(self):
        # ["prefix", "tag1"], but date is not reached
        now = datetime.now()
        next_time = now + timedelta(days=1)
        next_day = next_time.strftime("%Y-%m-%dT%H:%M:%S.%f %z")[:-3]
        self.action_config = {"Expiration": {"Date": f"{next_day}"}}

        prefix = self.conditions["prefix"]
        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]

        source = (
            """
            {"Rules":
                {"rule1":
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"Prefix":"""
            f'"{prefix}"'
            """, "Tags":["""
            f"{json.dumps(self.conditions['tag1'])}"
            """]}
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for j in range(self.number_match):
            name = self.prefix + str(j) + "0" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=5,
                    properties={TAGGING_KEY: tag_set},
                )

                self.not_to_match.append(obj_meta)

        for j in range(self.number_not_match):
            name = self.prefix + str(j) + "1" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_long,
                    random_length=6,
                    properties={TAGGING_KEY: self.not_match_tag_set},
                )
                self.not_to_match.append(obj_meta)

        self._check_and_apply(source, nothing_to_match=True)
