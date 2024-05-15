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

import random
import time
from datetime import datetime, timedelta

from mock import patch

from oio.container.lifecycle import (
    ContainerLifecycle,
    LIFECYCLE_PROPERTY_KEY,
    TAGGING_KEY,
    Expiration,
    Transition,
    NoncurrentVersionExpiration,
    NoncurrentVersionTransition,
    AbortIncompleteMultipartUpload,
    DateActionFilter,
    DaysActionFilter,
    NoncurrentCountActionFilter,
    DeletedMarkerActionFilter,
    DaysAfterInitiationActionFilter,
)
from oio.common.exceptions import NoSuchObject
from oio.common.client import ProxyClient
from oio.common.utils import cid_from_name, request_id
from oio.directory.admin import AdminClient
from oio.event.evob import EventTypes
from tests.functional.cli import CliTestCase
from tests.utils import BaseTestCase, random_str

from oio.common.kafka import DEFAULT_ENDPOINT, DEFAULT_LIFECYCLE_TOPIC, KafkaConsumer

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
    CONTAINERS = set()

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
        self.__class__.CONTAINERS.add(self.container)
        obj_meta = self.api.object_show(self.account, self.container, name)
        obj_meta["container"] = self.container
        if size is not None:
            obj_meta["size"] = size
        return obj_meta


class TestContainerLifecycle(BaseClassLifeCycle):
    def setUp(self):
        super(TestContainerLifecycle, self).setUp()

    def tearDown(self):
        self.api.container_delete(self.account, self.container, force=True)
        super(TestContainerLifecycle, self).tearDown()

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
        source = """
        <LifecycleConfiguration>
            <Rule>
                <ID>rule1</ID>
                <Filter>
                    <And>
                        <Prefix>documents/</Prefix>
                        <Tag>
                            <Key>key1</Key>
                            <Value>value1</Value>
                        </Tag>
                        <Tag>
                            <Key>key2</Key>
                            <Value>value2</Value>
                        </Tag>
                    </And>
                </Filter>
                <Status>Enabled</Status>
                <Transition>
                    <Days>1</Days>
                    <StorageClass>THREECOPIES</StorageClass>
                </Transition>
                <Expiration>
                    <Days>60</Days>
                </Expiration>
                <NoncurrentVersionTransition>
                    <NoncurrentDays>1</NoncurrentDays>
                    <StorageClass>THREECOPIES</StorageClass>
                </NoncurrentVersionTransition>
                <NoncurrentVersionExpiration>
                    <NoncurrentDays>60</NoncurrentDays>
                </NoncurrentVersionExpiration>
            </Rule>
        </LifecycleConfiguration>
        """
        props = {LIFECYCLE_PROPERTY_KEY: source}
        self.api.container_create(self.account, self.container, properties=props)
        self.lifecycle.load()
        self.assertEqual(1, len(self.lifecycle.rules))
        rule = self.lifecycle.rules[0]
        self.assertIsNotNone(rule)
        self.assertEqual("rule1", rule.id)
        self.assertIsNotNone(rule.filter)
        self.assertEqual("documents/", rule.filter.prefix)
        self.assertDictEqual({"key1": "value1", "key2": "value2"}, rule.filter.tags)
        self.assertTrue(rule.enabled)
        self.assertEqual(4, len(rule.actions))
        expiration = rule.actions[0]
        self.assertEqual(Expiration, type(expiration))
        self.assertEqual(60, expiration.filter.days)
        transition = rule.actions[1]
        self.assertEqual(Transition, type(transition))
        self.assertEqual(1, transition.filter.days)
        self.assertEqual("THREECOPIES", transition.policy)
        expiration = rule.actions[2]
        self.assertEqual(NoncurrentVersionExpiration, type(expiration))
        self.assertEqual(60, expiration.non_current_days)
        transition = rule.actions[3]
        self.assertEqual(NoncurrentVersionTransition, type(transition))
        self.assertEqual(1, transition.non_current_days)
        self.assertEqual("THREECOPIES", transition.policy)

    def test_save_to_container_property(self):
        source = """
        <LifecycleConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
            <Rule>
                <ID>rule1</ID>
                <Filter>
                    <And>
                        <Prefix>documents/</Prefix>
                        <Tag>
                            <Key>key</Key>
                            <Value>value</Value>
                        </Tag>
                    </And>
                </Filter>
                <Status>Enabled</Status>
                <Expiration>
                    <Days>60</Days>
                </Expiration>
                <Transition>
                    <StorageClass>SINGLE</StorageClass>
                    <Days>30</Days>
                </Transition>
                <Transition>
                    <StorageClass>THREECOPIES</StorageClass>
                    <Days>1</Days>
                </Transition>
                <NoncurrentVersionExpiration>
                    <NoncurrentDays>60</NoncurrentDays>
                </NoncurrentVersionExpiration>
                <NoncurrentVersionTransition>
                    <StorageClass>THREECOPIES</StorageClass>
                    <NoncurrentDays>1</NoncurrentDays>
                </NoncurrentVersionTransition>
            </Rule>
        </LifecycleConfiguration>
        """

        self.api.container_create(self.account, self.container)
        self.lifecycle.load_xml(source)
        self.lifecycle.save()
        xml = self.lifecycle.get_configuration()
        self.assertEqual(
            source.replace(" ", "").replace("\n", ""),
            xml.replace(" ", "").replace("\n", ""),
        )

    def test_immediate_expiration_by_date(self):
        obj_meta = self._upload_something()
        self.lifecycle.load_xml(
            """
        <LifecycleConfiguration>
            <Rule>
                <Filter>
                </Filter>
                <Expiration>
                    <Date>%s</Date>
                </Expiration>
                <Status>enabled</Status>
            </Rule>
        </LifecycleConfiguration>
        """
            % self._time_to_date(time.time() + 86400)
        )
        results = [x for x in self.lifecycle.apply(obj_meta, now=time.time() + 172800)]
        self.assertEqual(1, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual("Deleted", status)
        self.assertRaises(
            NoSuchObject,
            self.api.object_show,
            self.account,
            obj_meta["container"],
            obj_meta["name"],
        )

    def test_immediate_expiration_by_date_after_new_object(self):
        obj_meta = self._upload_something()
        self.lifecycle.load_xml(
            """
        <LifecycleConfiguration>
            <Rule>
                <Filter>
                </Filter>
                <Expiration>
                    <Date>%s</Date>
                </Expiration>
                <Status>enabled</Status>
            </Rule>
        </LifecycleConfiguration>
        """
            % self._time_to_date(time.time() + 172800)
        )
        results = [x for x in self.lifecycle.apply(obj_meta, now=time.time() + 86400)]
        self.assertEqual(1, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual("Kept", status)
        self.api.object_show(self.account, obj_meta["container"], obj_meta["name"])

    def test_future_expiration_by_date(self):
        obj_meta = self._upload_something()
        self.lifecycle.load_xml(
            """
        <LifecycleConfiguration>
            <Rule>
                <Filter>
                </Filter>
                <Expiration>
                    <Date>%s</Date>
                </Expiration>
                <Status>enabled</Status>
            </Rule>
        </LifecycleConfiguration>
        """
            % self._time_to_date(time.time() + 86400)
        )
        results = [x for x in self.lifecycle.apply(obj_meta)]
        self.assertEqual(1, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual("Kept", status)
        self.api.object_show(self.account, obj_meta["container"], obj_meta["name"])

        self.api.object_delete(self.account, obj_meta["container"], obj_meta["name"])

    def test_expiration_by_delay(self):
        obj_meta = self._upload_something()
        self.lifecycle.load_xml(
            """
        <LifecycleConfiguration>
            <Rule>
                <Filter>
                </Filter>
                <Expiration>
                    <Days>1</Days>
                </Expiration>
                <Status>enabled</Status>
            </Rule>
        </LifecycleConfiguration>
        """
        )

        results = [x for x in self.lifecycle.apply(obj_meta)]
        self.assertEqual(1, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual("Kept", status)
        self.api.object_show(self.account, obj_meta["container"], obj_meta["name"])

        results = [x for x in self.lifecycle.apply(obj_meta, now=time.time() + 86400)]
        self.assertEqual(1, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual("Deleted", status)
        self.assertRaises(
            NoSuchObject,
            self.api.object_show,
            self.account,
            obj_meta["container"],
            obj_meta["name"],
        )

    def test_expiration_filtered_by_prefix(self):
        obj_meta = self._upload_something(prefix="photos/")
        obj_meta2 = self._upload_something(prefix="documents/")
        self.lifecycle.load_xml(
            """
        <LifecycleConfiguration>
            <Rule>
                <Filter>
                    <Prefix>documents/</Prefix>
                </Filter>
                <Expiration>
                    <Days>1</Days>
                </Expiration>
                <Status>enabled</Status>
            </Rule>
        </LifecycleConfiguration>
        """
        )

        results = [x for x in self.lifecycle.apply(obj_meta)]
        self.assertEqual(1, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual("Kept", status)
        results = [x for x in self.lifecycle.apply(obj_meta2)]
        self.assertEqual(1, len(results))
        obj_meta2_copy, _, _, status = results[0]
        self.assertEqual(obj_meta2, obj_meta2_copy)
        self.assertEqual("Kept", status)
        self.api.object_show(self.account, obj_meta["container"], obj_meta["name"])
        self.api.object_show(self.account, obj_meta2["container"], obj_meta2["name"])

        results = [x for x in self.lifecycle.apply(obj_meta, now=time.time() + 86400)]
        self.assertEqual(1, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual("Kept", status)
        results = [x for x in self.lifecycle.apply(obj_meta2, now=time.time() + 86400)]
        self.assertEqual(1, len(results))
        obj_meta2_copy, _, _, status = results[0]
        self.assertEqual(obj_meta2, obj_meta2_copy)
        self.assertEqual("Deleted", status)
        self.api.object_show(self.account, obj_meta["container"], obj_meta["name"])
        self.assertRaises(
            NoSuchObject,
            self.api.object_show,
            self.account,
            obj_meta2["container"],
            obj_meta2["name"],
        )

        self.api.object_delete(self.account, obj_meta["container"], obj_meta["name"])

    def test_expiration_filtered_by_tag(self):
        obj_meta = self._upload_something()
        obj_meta2 = self._upload_something(
            properties={
                TAGGING_KEY: """
            <Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <TagSet>
                    <Tag>
                        <Key>status</Key>
                        <Value>deprecated</Value>
                    </Tag>
                </TagSet>
            </Tagging>
            """
            }
        )
        obj_meta3 = self._upload_something(
            properties={
                TAGGING_KEY: """
            <Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <TagSet>
                    <Tag>
                        <Key>status</Key>
                        <Value>approved</Value>
                    </Tag>
                </TagSet>
            </Tagging>
            """
            }
        )
        self.lifecycle.load_xml(
            """
        <LifecycleConfiguration>
            <Rule>
                <Filter>
                    <Tag>
                        <Key>status</Key>
                        <Value>deprecated</Value>
                    </Tag>
                </Filter>
                <Expiration>
                    <Days>1</Days>
                </Expiration>
                <Status>enabled</Status>
            </Rule>
        </LifecycleConfiguration>
        """
        )

        results = [x for x in self.lifecycle.apply(obj_meta)]
        self.assertEqual(1, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual("Kept", status)
        results = [x for x in self.lifecycle.apply(obj_meta2)]
        self.assertEqual(1, len(results))
        obj_meta2_copy, _, _, status = results[0]
        self.assertEqual(obj_meta2, obj_meta2_copy)
        self.assertEqual("Kept", status)
        results = [x for x in self.lifecycle.apply(obj_meta3)]
        self.assertEqual(1, len(results))
        obj_meta3_copy, _, _, status = results[0]
        self.assertEqual(obj_meta3, obj_meta3_copy)
        self.assertEqual("Kept", status)
        self.api.object_show(self.account, obj_meta["container"], obj_meta["name"])
        self.api.object_show(self.account, obj_meta2["container"], obj_meta2["name"])
        self.api.object_show(self.account, obj_meta3["container"], obj_meta3["name"])

        results = [x for x in self.lifecycle.apply(obj_meta, now=time.time() + 86400)]
        self.assertEqual(1, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual("Kept", status)
        results = [x for x in self.lifecycle.apply(obj_meta2, now=time.time() + 86400)]
        self.assertEqual(1, len(results))
        obj_meta2_copy, _, _, status = results[0]
        self.assertEqual(obj_meta2, obj_meta2_copy)
        self.assertEqual("Deleted", status)
        results = [x for x in self.lifecycle.apply(obj_meta3, now=time.time() + 86400)]
        self.assertEqual(1, len(results))
        obj_meta3_copy, _, _, status = results[0]
        self.assertEqual(obj_meta3, obj_meta3_copy)
        self.assertEqual("Kept", status)
        self.api.object_show(self.account, obj_meta["container"], obj_meta["name"])
        self.assertRaises(
            NoSuchObject,
            self.api.object_show,
            self.account,
            obj_meta2["container"],
            obj_meta2["name"],
        )
        self.api.object_show(self.account, obj_meta3["container"], obj_meta3["name"])

        self.api.object_delete(self.account, obj_meta["container"], obj_meta["name"])
        self.api.object_delete(self.account, obj_meta3["container"], obj_meta3["name"])

    def test_expiration_filtered_by_size(self):
        obj_meta = self._upload_something(prefix="less", size=40)
        obj_meta2 = self._upload_something(prefix="more", size=220)
        obj_meta3 = self._upload_something(prefix="keep", size=150)

        self.lifecycle.load_xml(
            """
        <LifecycleConfiguration>
            <Rule>
                <ID>More</ID>
                <Filter>
                    <ObjectSizeGreaterThan>200</ObjectSizeGreaterThan>
                </Filter>
                <Expiration>
                    <Days>1</Days>
                </Expiration>
                <Status>enabled</Status>
            </Rule>
            <Rule>
                <ID>Less</ID>
                <Filter>
                    <ObjectSizeLessThan>50</ObjectSizeLessThan>
                </Filter>
                <Expiration>
                    <Days>1</Days>
                </Expiration>
                <Status>enabled</Status>
            </Rule>
        </LifecycleConfiguration>
        """
        )

        results = [x for x in self.lifecycle.apply(obj_meta, now=time.time() + 86400)]
        # number of results is 2 because in the first rule the object is kept
        self.assertEqual(2, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual("Kept", status)
        obj_meta_copy, _, _, status = results[1]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual("Deleted", status)
        self.assertRaises(
            NoSuchObject,
            self.api.object_show,
            self.account,
            obj_meta2["container"],
            obj_meta["name"],
        )
        results = [x for x in self.lifecycle.apply(obj_meta2, now=time.time() + 86400)]
        self.assertEqual(1, len(results))
        obj_meta2_copy, _, _, status = results[0]
        self.assertEqual(obj_meta2, obj_meta2_copy)
        self.assertEqual("Deleted", status)
        results = [x for x in self.lifecycle.apply(obj_meta3, now=time.time() + 86400)]
        self.assertEqual(2, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta3, obj_meta_copy)
        self.assertEqual("Kept", status)
        obj = self.api.object_show(
            self.account, obj_meta["container"], obj_meta3["name"]
        )
        self.assertIsNotNone(obj)
        self.api.object_delete(self.account, obj_meta3["container"], obj_meta3["name"])

    def test_transition_filtered_by_tag(self):
        obj_meta = self._upload_something(policy="SINGLE")
        obj_meta2 = self._upload_something(
            policy="SINGLE",
            properties={
                TAGGING_KEY: """
            <Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <TagSet>
                    <Tag>
                        <Key>status</Key>
                        <Value>deprecated</Value>
                    </Tag>
                </TagSet>
            </Tagging>
            """
            },
        )
        obj_meta3 = self._upload_something(
            policy="SINGLE",
            properties={
                TAGGING_KEY: """
            <Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <TagSet>
                    <Tag>
                        <Key>status</Key>
                        <Value>approved</Value>
                    </Tag>
                </TagSet>
            </Tagging>
            """
            },
        )
        self.lifecycle.load_xml(
            """
        <LifecycleConfiguration>
            <Rule>
                <Filter>
                    <Tag>
                        <Key>status</Key>
                        <Value>deprecated</Value>
                    </Tag>
                </Filter>
                <Transition>
                    <Days>1</Days>
                    <StorageClass>THREECOPIES</StorageClass>
                </Transition>
                <Status>enabled</Status>
            </Rule>
        </LifecycleConfiguration>
        """
        )

        results = [x for x in self.lifecycle.apply(obj_meta)]
        self.assertEqual(1, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual("Kept", status)
        results = [x for x in self.lifecycle.apply(obj_meta2)]
        self.assertEqual(1, len(results))
        obj_meta2_copy, _, _, status = results[0]
        self.assertEqual(obj_meta2, obj_meta2_copy)
        self.assertEqual("Kept", status)
        results = [x for x in self.lifecycle.apply(obj_meta3)]
        self.assertEqual(1, len(results))
        obj_meta3_copy, _, _, status = results[0]
        self.assertEqual(obj_meta3, obj_meta3_copy)
        self.assertEqual("Kept", status)
        obj_meta_after, chunks = self.api.object_locate(
            self.account, obj_meta["container"], obj_meta["name"]
        )
        self.assertEqual("SINGLE", obj_meta_after["policy"])
        self.assertEqual(1, len(chunks))
        obj_meta2_after, chunks2 = self.api.object_locate(
            self.account, obj_meta2["container"], obj_meta2["name"]
        )
        self.assertEqual("SINGLE", obj_meta2_after["policy"])
        self.assertEqual(1, len(chunks2))
        obj_meta3_after, chunks3 = self.api.object_locate(
            self.account, obj_meta3["container"], obj_meta3["name"]
        )
        self.assertEqual("SINGLE", obj_meta3_after["policy"])
        self.assertEqual(1, len(chunks3))

        results = [x for x in self.lifecycle.apply(obj_meta, now=time.time() + 86400)]
        self.assertEqual(1, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual("Kept", status)
        results = [x for x in self.lifecycle.apply(obj_meta2, now=time.time() + 86400)]
        self.assertEqual(1, len(results))
        obj_meta2_copy, _, _, status = results[0]
        self.assertEqual(obj_meta2, obj_meta2_copy)
        self.assertEqual("Policy changed to THREECOPIES", status)
        results = [x for x in self.lifecycle.apply(obj_meta3, now=time.time() + 86400)]
        self.assertEqual(1, len(results))
        obj_meta3_copy, _, _, status = results[0]
        self.assertEqual(obj_meta3, obj_meta3_copy)
        self.assertEqual("Kept", status)
        obj_meta_after, chunks = self.api.object_locate(
            self.account, obj_meta["container"], obj_meta["name"]
        )
        self.assertEqual("SINGLE", obj_meta_after["policy"])
        self.assertEqual(1, len(chunks))
        obj_meta2_after, chunks2 = self.api.object_locate(
            self.account, obj_meta2["container"], obj_meta2["name"]
        )
        self.assertEqual("THREECOPIES", obj_meta2_after["policy"])
        self.assertEqual(3, len(chunks2))
        obj_meta3_after, chunks3 = self.api.object_locate(
            self.account, obj_meta3["container"], obj_meta3["name"]
        )
        self.assertEqual("SINGLE", obj_meta3_after["policy"])
        self.assertEqual(1, len(chunks3))

        self.api.object_delete(self.account, obj_meta["container"], obj_meta["name"])
        self.api.object_delete(self.account, obj_meta2["container"], obj_meta2["name"])
        self.api.object_delete(self.account, obj_meta3["container"], obj_meta3["name"])

    def test_transition_filtered_by_tags(self):
        obj_meta = self._upload_something(policy="SINGLE")
        obj_meta2 = self._upload_something(
            policy="SINGLE",
            properties={
                TAGGING_KEY: """
            <Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <TagSet>
                    <Tag>
                        <Key>test1</Key>
                        <Value>test2</Value>
                    </Tag>
                    <Tag>
                        <Key>status</Key>
                        <Value>deprecated</Value>
                    </Tag>
                </TagSet>
            </Tagging>
            """
            },
        )
        obj_meta3 = self._upload_something(
            policy="SINGLE",
            properties={
                TAGGING_KEY: """
            <Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <TagSet>
                    <Tag>
                        <Key>status</Key>
                        <Value>deprecated</Value>
                    </Tag>
                </TagSet>
            </Tagging>
            """
            },
        )
        self.lifecycle.load_xml(
            """
        <LifecycleConfiguration>
            <Rule>
                <Filter>
                    <And>
                        <Tag>
                            <Key>status</Key>
                            <Value>deprecated</Value>
                        </Tag>
                        <Tag>
                            <Key>test1</Key>
                            <Value>test2</Value>
                        </Tag>
                    </And>
                </Filter>
                <Transition>
                    <Days>1</Days>
                    <StorageClass>THREECOPIES</StorageClass>
                </Transition>
                <Status>enabled</Status>
            </Rule>
        </LifecycleConfiguration>
        """
        )

        results = [x for x in self.lifecycle.apply(obj_meta)]
        self.assertEqual(1, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual("Kept", status)
        results = [x for x in self.lifecycle.apply(obj_meta2)]
        self.assertEqual(1, len(results))
        obj_meta2_copy, _, _, status = results[0]
        self.assertEqual(obj_meta2, obj_meta2_copy)
        self.assertEqual("Kept", status)
        results = [x for x in self.lifecycle.apply(obj_meta3)]
        self.assertEqual(1, len(results))
        obj_meta3_copy, _, _, status = results[0]
        self.assertEqual(obj_meta3, obj_meta3_copy)
        self.assertEqual("Kept", status)
        obj_meta_after, chunks = self.api.object_locate(
            self.account, obj_meta["container"], obj_meta["name"]
        )
        self.assertEqual("SINGLE", obj_meta_after["policy"])
        self.assertEqual(1, len(chunks))
        obj_meta2_after, chunks2 = self.api.object_locate(
            self.account, obj_meta2["container"], obj_meta2["name"]
        )
        self.assertEqual("SINGLE", obj_meta2_after["policy"])
        self.assertEqual(1, len(chunks2))
        obj_meta3_after, chunks3 = self.api.object_locate(
            self.account, obj_meta3["container"], obj_meta3["name"]
        )
        self.assertEqual("SINGLE", obj_meta3_after["policy"])
        self.assertEqual(1, len(chunks3))

        results = [x for x in self.lifecycle.apply(obj_meta, now=time.time() + 86400)]
        self.assertEqual(1, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual("Kept", status)
        results = [x for x in self.lifecycle.apply(obj_meta2, now=time.time() + 86400)]
        self.assertEqual(1, len(results))
        obj_meta2_copy, _, _, status = results[0]
        self.assertEqual(obj_meta2, obj_meta2_copy)
        self.assertEqual("Policy changed to THREECOPIES", status)
        results = [x for x in self.lifecycle.apply(obj_meta3, now=time.time() + 86400)]
        self.assertEqual(1, len(results))
        obj_meta3_copy, _, _, status = results[0]
        self.assertEqual(obj_meta3, obj_meta3_copy)
        self.assertEqual("Kept", status)
        obj_meta_after, chunks = self.api.object_locate(
            self.account, obj_meta["container"], obj_meta["name"]
        )
        self.assertEqual("SINGLE", obj_meta_after["policy"])
        self.assertEqual(1, len(chunks))
        obj_meta2_after, chunks2 = self.api.object_locate(
            self.account, obj_meta2["container"], obj_meta2["name"]
        )
        self.assertEqual("THREECOPIES", obj_meta2_after["policy"])
        self.assertEqual(3, len(chunks2))
        obj_meta3_after, chunks3 = self.api.object_locate(
            self.account, obj_meta3["container"], obj_meta3["name"]
        )
        self.assertEqual("SINGLE", obj_meta3_after["policy"])
        self.assertEqual(1, len(chunks3))

        self.api.object_delete(self.account, obj_meta["container"], obj_meta["name"])
        self.api.object_delete(self.account, obj_meta2["container"], obj_meta2["name"])
        self.api.object_delete(self.account, obj_meta3["container"], obj_meta3["name"])

    def test_transition_filtered_by_prefix_and_tags(self):
        obj_meta = self._upload_something(policy="SINGLE", prefix="documents/")
        obj_meta2 = self._upload_something(
            policy="SINGLE",
            prefix="documents/",
            properties={
                TAGGING_KEY: """
            <Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <TagSet>
                    <Tag>
                        <Key>test1</Key>
                        <Value>test2</Value>
                    </Tag>
                    <Tag>
                        <Key>status</Key>
                        <Value>deprecated</Value>
                    </Tag>
                </TagSet>
            </Tagging>
            """
            },
        )
        obj_meta3 = self._upload_something(
            policy="SINGLE",
            properties={
                TAGGING_KEY: """
            <Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <TagSet>
                    <Tag>
                        <Key>test1</Key>
                        <Value>test2</Value>
                    </Tag>
                    <Tag>
                        <Key>status</Key>
                        <Value>deprecated</Value>
                    </Tag>
                </TagSet>
            </Tagging>
            """
            },
        )
        self.lifecycle.load_xml(
            """
        <LifecycleConfiguration>
            <Rule>
                <Filter>
                    <And>
                        <Prefix>documents/</Prefix>
                        <Tag>
                            <Key>status</Key>
                            <Value>deprecated</Value>
                        </Tag>
                        <Tag>
                            <Key>test1</Key>
                            <Value>test2</Value>
                        </Tag>
                    </And>
                </Filter>
                <Transition>
                    <Days>1</Days>
                    <StorageClass>THREECOPIES</StorageClass>
                </Transition>
                <Status>enabled</Status>
            </Rule>
        </LifecycleConfiguration>
        """
        )

        results = [x for x in self.lifecycle.apply(obj_meta)]
        self.assertEqual(1, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual("Kept", status)
        results = [x for x in self.lifecycle.apply(obj_meta2)]
        self.assertEqual(1, len(results))
        obj_meta2_copy, _, _, status = results[0]
        self.assertEqual(obj_meta2, obj_meta2_copy)
        self.assertEqual("Kept", status)
        results = [x for x in self.lifecycle.apply(obj_meta3)]
        self.assertEqual(1, len(results))
        obj_meta3_copy, _, _, status = results[0]
        self.assertEqual(obj_meta3, obj_meta3_copy)
        self.assertEqual("Kept", status)
        obj_meta_after, chunks = self.api.object_locate(
            self.account, obj_meta["container"], obj_meta["name"]
        )
        self.assertEqual("SINGLE", obj_meta_after["policy"])
        self.assertEqual(1, len(chunks))
        obj_meta2_after, chunks2 = self.api.object_locate(
            self.account, obj_meta2["container"], obj_meta2["name"]
        )
        self.assertEqual("SINGLE", obj_meta2_after["policy"])
        self.assertEqual(1, len(chunks2))
        obj_meta3_after, chunks3 = self.api.object_locate(
            self.account, obj_meta3["container"], obj_meta3["name"]
        )
        self.assertEqual("SINGLE", obj_meta3_after["policy"])
        self.assertEqual(1, len(chunks3))

        results = [x for x in self.lifecycle.apply(obj_meta, now=time.time() + 86400)]
        self.assertEqual(1, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual("Kept", status)
        results = [x for x in self.lifecycle.apply(obj_meta2, now=time.time() + 86400)]
        self.assertEqual(1, len(results))
        obj_meta2_copy, _, _, status = results[0]
        self.assertEqual(obj_meta2, obj_meta2_copy)
        self.assertEqual("Policy changed to THREECOPIES", status)
        results = [x for x in self.lifecycle.apply(obj_meta3, now=time.time() + 86400)]
        self.assertEqual(1, len(results))
        obj_meta3_copy, _, _, status = results[0]
        self.assertEqual(obj_meta3, obj_meta3_copy)
        self.assertEqual("Kept", status)
        obj_meta_after, chunks = self.api.object_locate(
            self.account, obj_meta["container"], obj_meta["name"]
        )
        self.assertEqual("SINGLE", obj_meta_after["policy"])
        self.assertEqual(1, len(chunks))
        obj_meta2_after, chunks2 = self.api.object_locate(
            self.account, obj_meta2["container"], obj_meta2["name"]
        )
        self.assertEqual("THREECOPIES", obj_meta2_after["policy"])
        self.assertEqual(3, len(chunks2))
        obj_meta3_after, chunks3 = self.api.object_locate(
            self.account, obj_meta3["container"], obj_meta3["name"]
        )
        self.assertEqual("SINGLE", obj_meta3_after["policy"])
        self.assertEqual(1, len(chunks3))

        self.api.object_delete(self.account, obj_meta["container"], obj_meta["name"])
        self.api.object_delete(self.account, obj_meta2["container"], obj_meta2["name"])
        self.api.object_delete(self.account, obj_meta3["container"], obj_meta3["name"])

    def test_transition_filtered_by_size(self):
        obj_meta = self._upload_something(prefix="less", size=40, policy="SINGLE")
        obj_meta2 = self._upload_something(prefix="more", size=220, policy="SINGLE")

        self.lifecycle.load_xml(
            """
        <LifecycleConfiguration>
            <Rule>
                <ID>More</ID>
                <Filter>
                    <ObjectSizeGreaterThan>200</ObjectSizeGreaterThan>
                </Filter>
                <Transition>
                    <Days>1</Days>
                    <StorageClass>THREECOPIES</StorageClass>
                </Transition>
                <Status>enabled</Status>
            </Rule>
        </LifecycleConfiguration>
        """
        )
        results = [x for x in self.lifecycle.apply(obj_meta)]
        self.assertEqual(1, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual("Kept", status)
        results = [x for x in self.lifecycle.apply(obj_meta2)]
        self.assertEqual(1, len(results))
        obj_meta2_copy, _, _, status = results[0]
        self.assertEqual(obj_meta2, obj_meta2_copy)
        self.assertEqual("Kept", status)
        obj_meta_after, chunks = self.api.object_locate(
            self.account, obj_meta["container"], obj_meta["name"]
        )
        self.assertEqual("SINGLE", obj_meta_after["policy"])
        self.assertEqual(1, len(chunks))
        obj_meta2_after, chunks2 = self.api.object_locate(
            self.account, obj_meta2["container"], obj_meta2["name"]
        )
        self.assertEqual("SINGLE", obj_meta2_after["policy"])
        self.assertEqual(1, len(chunks2))

        results = [x for x in self.lifecycle.apply(obj_meta, now=time.time() + 86400)]
        self.assertEqual(1, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual("Kept", status)
        results = [x for x in self.lifecycle.apply(obj_meta2, now=time.time() + 86400)]
        self.assertEqual(1, len(results))
        obj_meta2_copy, _, _, status = results[0]
        self.assertEqual(obj_meta2, obj_meta2_copy)
        self.assertEqual("Policy changed to THREECOPIES", status)
        obj_meta_after, chunks = self.api.object_locate(
            self.account, obj_meta["container"], obj_meta["name"]
        )
        self.assertEqual("SINGLE", obj_meta_after["policy"])
        self.assertEqual(1, len(chunks))
        obj_meta2_after, chunks2 = self.api.object_locate(
            self.account, obj_meta2["container"], obj_meta2["name"]
        )
        self.assertEqual("THREECOPIES", obj_meta2_after["policy"])
        self.assertEqual(3, len(chunks2))

        self.api.object_delete(self.account, obj_meta["container"], obj_meta["name"])
        self.api.object_delete(self.account, obj_meta2["container"], obj_meta2["name"])

    def test_expiration_with_versioning(self):
        self.api.container_create(self.account, self.container)
        self.helper.enable_versioning()
        obj_meta = self._upload_something()
        obj_meta_v2 = self._upload_something(
            name=obj_meta["name"], data=obj_meta["name"]
        )
        self.lifecycle.load_xml(
            """
        <LifecycleConfiguration>
            <Rule>
                <Filter></Filter>
                <Expiration>
                    <Days>1</Days>
                </Expiration>
                <Status>enabled</Status>
            </Rule>
        </LifecycleConfiguration>
        """
        )

        results = [x for x in self.lifecycle.apply(obj_meta_v2)]
        self.assertEqual(1, len(results))
        obj_meta_v2_copy, _, _, status = results[0]
        self.assertEqual(obj_meta_v2, obj_meta_v2_copy)
        self.assertEqual("Kept", status)
        results = [x for x in self.lifecycle.apply(obj_meta)]
        self.assertEqual(1, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual("Kept", status)
        self.api.object_show(
            self.account,
            self.container,
            obj_meta_v2["name"],
            version=obj_meta_v2["version"],
        )
        self.api.object_show(
            self.account,
            obj_meta["container"],
            obj_meta["name"],
            version=obj_meta["version"],
        )

        results = [
            x for x in self.lifecycle.apply(obj_meta_v2, now=time.time() + 86400)
        ]
        self.assertEqual(1, len(results))
        obj_meta_v2_copy, _, _, status = results[0]
        self.assertEqual(obj_meta_v2, obj_meta_v2_copy)
        self.assertEqual("Deleted", status)
        results = [x for x in self.lifecycle.apply(obj_meta, now=time.time() + 86400)]
        self.assertEqual(1, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual("Kept", status)
        self.assertRaises(
            NoSuchObject,
            self.api.object_locate,
            self.account,
            self.container,
            obj_meta_v2["name"],
        )
        self.api.object_show(
            self.account,
            self.container,
            obj_meta_v2["name"],
            version=obj_meta_v2["version"],
        )
        self.api.object_show(
            self.account,
            obj_meta["container"],
            obj_meta["name"],
            version=obj_meta["version"],
        )

        self.api.object_delete(
            self.account,
            obj_meta["container"],
            obj_meta["name"],
            version=obj_meta["version"],
        )

    def test_noncurrent_expiration(self):
        self.api.container_create(self.account, self.container)
        self.helper.enable_versioning()
        obj_meta = self._upload_something()
        obj_meta_v2 = self._upload_something(
            name=obj_meta["name"], data=obj_meta["name"]
        )
        self.lifecycle.load_xml(
            """
        <LifecycleConfiguration>
            <Rule>
                <Filter></Filter>
                <NoncurrentVersionExpiration>
                    <NoncurrentDays>1</NoncurrentDays>
                </NoncurrentVersionExpiration>
                <Status>enabled</Status>
            </Rule>
        </LifecycleConfiguration>
        """
        )

        results = [x for x in self.lifecycle.apply(obj_meta_v2)]
        self.assertEqual(1, len(results))
        obj_meta_v2_copy, _, _, status = results[0]
        self.assertEqual(obj_meta_v2, obj_meta_v2_copy)
        self.assertEqual("Kept", status)
        results = [x for x in self.lifecycle.apply(obj_meta)]
        self.assertEqual(1, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual("Kept", status)
        self.api.object_show(
            self.account,
            self.container,
            obj_meta_v2["name"],
            version=obj_meta_v2["version"],
        )
        self.api.object_show(
            self.account,
            obj_meta["container"],
            obj_meta["name"],
            version=obj_meta["version"],
        )

        results = [
            x for x in self.lifecycle.apply(obj_meta_v2, now=time.time() + 86400)
        ]
        self.assertEqual(1, len(results))
        obj_meta_v2_copy, _, _, status = results[0]
        self.assertEqual(obj_meta_v2, obj_meta_v2_copy)
        self.assertEqual("Kept", status)
        results = [x for x in self.lifecycle.apply(obj_meta, now=time.time() + 86400)]
        self.assertEqual(1, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual("Deleted", status)
        self.api.object_show(
            self.account,
            self.container,
            obj_meta_v2["name"],
            version=obj_meta_v2["version"],
        )
        self.assertRaises(
            NoSuchObject,
            self.api.object_show,
            self.account,
            obj_meta["container"],
            obj_meta["name"],
            version=obj_meta["version"],
        )

        self.api.object_delete(
            self.account,
            self.container,
            obj_meta_v2["name"],
            version=obj_meta_v2["version"],
        )

    def test_execute_expiration(self):
        self.api.container_create(
            self.account,
            self.container,
            properties={
                LIFECYCLE_PROPERTY_KEY: """
            <LifecycleConfiguration>
                <Rule>
                    <ID>rule1</ID>
                    <Filter>
                    </Filter>
                    <Status>Enabled</Status>
                    <Expiration>
                        <Days>1</Days>
                    </Expiration>
                </Rule>
            </LifecycleConfiguration>
            """
            },
        )
        for _ in range(3):
            self._upload_something()
        self.lifecycle.load()

        results = [x for x in self.lifecycle.execute()]
        self.assertEqual(3, len(results))
        for res in results:
            self.assertEqual("Kept", res[3])
        listing = self.api.object_list(self.account, self.container)
        self.assertEqual(3, len(listing["objects"]))

        results = [x for x in self.lifecycle.execute(now=time.time() + 86400)]
        self.assertEqual(3, len(results))
        for res in results:
            self.assertEqual("Deleted", res[3])
        listing = self.api.object_list(self.account, self.container)
        self.assertEqual(0, len(listing["objects"]))

    def test_execute_expiration_with_disabled_status(self):
        self.api.container_create(
            self.account,
            self.container,
            properties={
                LIFECYCLE_PROPERTY_KEY: """
            <LifecycleConfiguration>
                <Rule>
                    <ID>rule1</ID>
                    <Filter>
                    </Filter>
                    <Status>Disabled</Status>
                    <Expiration>
                        <Days>1</Days>
                    </Expiration>
                </Rule>
            </LifecycleConfiguration>
            """
            },
        )
        for _ in range(3):
            self._upload_something()
        self.lifecycle.load()

        results = [x for x in self.lifecycle.execute()]
        self.assertEqual(3, len(results))
        for res in results:
            self.assertEqual("Kept", res[3])
        listing = self.api.object_list(self.account, self.container)
        self.assertEqual(3, len(listing["objects"]))

        results = [x for x in self.lifecycle.execute(now=time.time() + 86400)]
        self.assertEqual(3, len(results))
        for res in results:
            self.assertEqual("Kept", res[3])
        listing = self.api.object_list(self.account, self.container)
        self.assertEqual(3, len(listing["objects"]))

    def test_execute_expiration_on_missing_objects(self):
        self.api.container_create(
            self.account,
            self.container,
            properties={
                LIFECYCLE_PROPERTY_KEY: """
            <LifecycleConfiguration>
                <Rule>
                    <ID>rule1</ID>
                    <Filter>
                    </Filter>
                    <Status>Enabled</Status>
                    <Expiration>
                        <Days>1</Days>
                    </Expiration>
                </Rule>
            </LifecycleConfiguration>
            """
            },
        )
        fake_listing = {
            "objects": [
                {
                    "name": "a",
                    "version": 1540933092888883,
                    "mtime": "12",
                    "deleted": False,
                },
                {
                    "name": "b",
                    "version": 1540933092888883,
                    "mtime": "12",
                    "deleted": False,
                },
                {
                    "name": "c",
                    "version": 1540933092888883,
                    "mtime": "12",
                    "deleted": False,
                },
                {
                    "name": "d",
                    "version": 1540933092888883,
                    "mtime": "12",
                    "deleted": False,
                },
            ],
            "truncated": False,
        }
        with patch.object(self.api, "object_list", side_effect=[fake_listing]):
            self.lifecycle.load()

            results = [x for x in self.lifecycle.execute()]
            self.assertEqual(4, len(results))
            for res in results:
                self.assertIsInstance(res[3], Exception)

    def test_execute_exceeding_version_expiration_without_versioning(self):
        self.api.container_create(
            self.account,
            self.container,
            properties={
                LIFECYCLE_PROPERTY_KEY: """
            <LifecycleConfiguration>
                <Rule>
                    <ID>rule1</ID>
                    <Filter>
                    </Filter>
                    <Status>Enabled</Status>
                    <NoncurrentVersionExpiration>
                        <NoncurrentDays>1</NoncurrentDays>
                        <NewerNoncurrentVersions>2</NewerNoncurrentVersions>
                    </NoncurrentVersionExpiration>
                </Rule>
            </LifecycleConfiguration>
            """
            },
        )
        for _ in range(5):
            self._upload_something()
        self.lifecycle.load()

        results = [x for x in self.lifecycle.execute()]
        self.assertEqual(5, len(results))
        for res in results:
            self.assertEqual("Kept", res[3])
        listing = self.api.object_list(self.account, self.container, versions=True)
        self.assertEqual(5, len(listing["objects"]))

    def test_execute_exceeding_version_expiration_with_versioning(self):
        self.api.container_create(
            self.account,
            self.container,
            properties={
                LIFECYCLE_PROPERTY_KEY: """
            <LifecycleConfiguration>
                <Rule>
                    <ID>rule1</ID>
                    <Filter>
                    </Filter>
                    <Status>Enabled</Status>
                    <NoncurrentVersionExpiration>
                        <NoncurrentDays>1</NoncurrentDays>
                        <NewerNoncurrentVersions>2</NewerNoncurrentVersions>
                    </NoncurrentVersionExpiration>
                </Rule>
            </LifecycleConfiguration>
            """
            },
            system={"sys.m2.policy.version": "4"},
        )
        for _ in range(5):
            self._upload_something(name="versioned1", data="versioned1")
        for _ in range(5):
            self._upload_something(name="versioned2", data="versioned2")
        listing = self.api.object_list(self.account, self.container, versions=True)
        self.assertEqual(10, len(listing["objects"]))
        self.lifecycle.load()

        results = [x for x in self.lifecycle.execute(now=time.time() + 86400)]
        self.assertEqual(10, len(results))
        listing = self.api.object_list(self.account, self.container, versions=True)
        self.assertEqual(6, len(listing["objects"]))

    def test_execute_multiple_rules(self):
        meta = {"sys.m2.policy.version": "4"}
        self.api.container_create(
            self.account,
            self.container,
            properties={
                LIFECYCLE_PROPERTY_KEY: """
            <LifecycleConfiguration>
                <Rule>
                    <Filter>
                        <Tag>
                            <Key>status</Key>
                            <Value>deprecated</Value>
                        </Tag>
                    </Filter>
                    <Expiration>
                        <Days>1</Days>
                    </Expiration>
                    <Status>enabled</Status>
                </Rule>
                <Rule>
                    <Filter>
                        <Prefix>documents/</Prefix>
                    </Filter>
                    <Expiration>
                        <Days>1</Days>
                    </Expiration>
                    <Status>Enabled</Status>
                </Rule>
            </LifecycleConfiguration>
            """
            },
            system=meta,
        )
        obj_meta = self._upload_something(policy="SINGLE", system=meta)
        obj_meta2 = self._upload_something(
            policy="SINGLE",
            properties={
                TAGGING_KEY: """
            <Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <TagSet>
                    <Tag>
                        <Key>status</Key>
                        <Value>deprecated</Value>
                    </Tag>
                </TagSet>
            </Tagging>
            """
            },
            system=meta,
        )
        obj_meta3 = self._upload_something(
            name="documents/object3",
            data="documents/object3",
            policy="SINGLE",
            system=meta,
        )
        self.lifecycle.load()

        results = [x for x in self.lifecycle.execute()]
        self.assertEqual(6, len(results))
        for res in results:
            self.assertEqual("Kept", res[3])
        self.api.object_show(self.account, obj_meta["container"], obj_meta["name"])
        self.api.object_show(self.account, obj_meta2["container"], obj_meta2["name"])
        self.api.object_show(self.account, obj_meta3["container"], obj_meta3["name"])

        results = [x for x in self.lifecycle.execute(now=time.time() + 86400)]
        self.assertEqual(5, len(results))
        self.api.object_locate(self.account, obj_meta["container"], obj_meta["name"])
        self.api.object_show(
            self.account,
            obj_meta["container"],
            obj_meta["name"],
            version=obj_meta["version"],
        )
        self.assertRaises(
            NoSuchObject,
            self.api.object_locate,
            self.account,
            obj_meta2["container"],
            obj_meta2["name"],
        )
        self.api.object_show(
            self.account,
            obj_meta2["container"],
            obj_meta2["name"],
            version=obj_meta2["version"],
        )
        self.assertRaises(
            NoSuchObject,
            self.api.object_locate,
            self.account,
            obj_meta3["container"],
            obj_meta3["name"],
        )
        self.api.object_show(
            self.account,
            obj_meta3["container"],
            obj_meta3["name"],
            version=obj_meta3["version"],
        )

        self.api.object_delete(
            self.account,
            obj_meta["container"],
            obj_meta["name"],
            version=obj_meta["version"],
        )
        self.api.object_delete(
            self.account,
            obj_meta2["container"],
            obj_meta2["name"],
            version=obj_meta2["version"],
        )
        self.api.object_delete(
            self.account,
            obj_meta3["container"],
            obj_meta3["name"],
            version=obj_meta3["version"],
        )

    def test_order_rules_conf1(self):
        """
        Rules with expiration and transition: expiration rules are first
        and transition rules are ordered by policy.
        """
        self.api.container_create(
            self.account,
            self.container,
            properties={
                LIFECYCLE_PROPERTY_KEY: """
            <LifecycleConfiguration>
                <Rule>
                    <ID>rule-1></ID>
                    <Filter>
                    </Filter>
                    <Expiration>
                        <Days>1</Days>
                    </Expiration>
                    <Status>enabled</Status>
                </Rule>
                <Rule>
                    <ID>rule-2></ID>
                    <Filter>
                        <Prefix>documents/</Prefix>
                    </Filter>
                    <Transition>
                        <Days>1</Days>
                        <StorageClass>ARCHIVE</StorageClass>
                    </Transition>
                    <Expiration>
                        <Days>10</Days>
                    </Expiration>
                    <Status>Enabled</Status>
                </Rule>
                <Rule>
                    <ID>rule-3></ID>
                    <Filter>
                        <Prefix>documents/</Prefix>
                    </Filter>
                    <Transition>
                        <Days>90</Days>
                        <StorageClass>STANDARD_IA</StorageClass>
                    </Transition>
                    <Transition>
                        <Days>180</Days>
                        <StorageClass>ARCHIVE</StorageClass>
                    </Transition>
                    <Status>Enabled</Status>
                </Rule>
            </LifecycleConfiguration>
            """
            },
        )
        self.lifecycle.load()

        [sorted_current_rules, _, _, _] = self.lifecycle.order_rules(False)
        actions_order = list()
        for k, v in sorted_current_rules.items():
            action = v[1]
            actions_order.append(str(action))
        self.assertEqual(
            actions_order,
            [
                "<Expiration><Days>1</Days></Expiration>",
                "<Transition><StorageClass>ARCHIVE</StorageClass>"
                "<Days>1</Days></Transition>",
                "<Expiration><Days>10</Days></Expiration>",
                "<Transition><StorageClass>STANDARD_IA</StorageClass>"
                "<Days>90</Days></Transition>",
                "<Transition><StorageClass>ARCHIVE</StorageClass><Days>180"
                "</Days></Transition>",
            ],
        )

    def test_order_rules_conf2(self):
        """
        Predominance of expiration over transition
        """
        self.api.container_create(
            self.account,
            self.container,
            properties={
                LIFECYCLE_PROPERTY_KEY: """
            <LifecycleConfiguration>
                <Rule>
                    <ID>rule-1></ID>
                    <Filter>
                    </Filter>
                    <Transition>
                        <Days>1</Days>
                        <StorageClass>ARCHIVE</StorageClass>
                    </Transition>
                    <Status>enabled</Status>
                </Rule>
                <Rule>
                    <ID>rule-2></ID>
                    <Filter>
                        <Prefix>documents/</Prefix>
                    </Filter>
                    <Expiration>
                        <Days>10</Days>
                    </Expiration>
                    <Status>Enabled</Status>
                </Rule>
            </LifecycleConfiguration>
            """
            },
        )
        self.lifecycle.load()

        [sorted_current_rules, _, _, _] = self.lifecycle.order_rules(False)
        actions_order = list()
        for k, v in sorted_current_rules.items():
            action = v[1]
            actions_order.append(str(action))
        self.assertEqual(
            actions_order,
            [
                "<Transition><StorageClass>ARCHIVE</StorageClass>"
                "<Days>1</Days></Transition>",
                "<Expiration><Days>10</Days></Expiration>",
            ],
        )


class TestLifecycleConform(CliTestCase, BaseClassLifeCycle):
    CONTAINERS = set()

    def setUp(self):
        super(TestLifecycleConform, self).setUp()
        self.batch_size = 2
        self.to_match = {}
        self.not_to_match = {}
        self.to_match_markers = {}
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

        self.versioning_enabled = False
        self.number_of_versions = 1
        self.expected_to_cycle = {}

        self.end_source = """</And>
                    </Filter>
                    <Status>Enabled</Status>
                    <Expiration>
                        <Days>10</Days>
                    </Expiration>
                </Rule>
            </LifecycleConfiguration>"""

        self.not_match_tag_set = """
            <Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
            <TagSet><Tag><Key>excluded-key</Key><Value>value1</Value></Tag>
            </Tagset></Tagging>"""

        # dict to store rules and actions
        self.rules = {}

    def tearDown(self):
        objects = self.api.object_list(
            self.account, self.container, deleted=True, versions=True
        )

        for obj in objects["objects"]:
            self.api.object_delete(
                self.account, self.container, obj["name"], obj["version"]
            )
        self.api.container_delete(self.account, self.container, force=True)
        super(TestLifecycleConform, self).tearDown()

    def _init_match_rules(self):
        for rule, actions in self.rules.items():
            self.to_match[rule] = {}
            self.not_to_match[rule] = {}
            self.to_match_markers[rule] = {}
            for action in actions:
                self.to_match[rule][action] = []
                self.not_to_match[rule][action] = []
                self.to_match_markers[rule][action] = []

    def _create_container_versioning(self, lifecycle_source):
        self.api.container_create(
            self.account,
            self.container,
            properties={LIFECYCLE_PROPERTY_KEY: lifecycle_source},
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

    def _copy_db(self, container=None):
        ct = container or self.container
        self.cid = cid_from_name(self.account, ct)

        status = self.admin_client.election_status(
            "meta2", account=self.account, reference=ct
        )
        slaves = status.get("slaves", [])
        if slaves:
            self.peer_to_use = slaves[0]
        else:
            self.peer_to_use = status.get("master", [])

        params = {"type": "meta2", "cid": self.cid, "suffix": "lifecycle"}
        json = {"from": self.peer_to_use, "to": self.peer_to_use, "local": 1}

        resp, body = self.proxy_client._request(
            "POST", "/admin/copy", params=params, json=json
        )
        self.assertEqual(resp.status, 204)

    def _check_and_apply(self, source, container=None, nothing_to_match=False):
        if not nothing_to_match:
            self.assertIsNot(len(self.to_match), 0)
        self._copy_db(container)
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

    def _get_action_parameters(self, act):
        days = None
        date = None
        delete_marker = None
        if isinstance(act, Expiration):
            if type(act.filter) is DaysActionFilter:
                days = act.filter.days
            elif type(act.filter) is DateActionFilter:
                date = act.filter.date
            elif type(act.filter) is DeletedMarkerActionFilter:
                delete_marker = act.filter.expired_object_deleted_marker
        elif isinstance(act, Transition):
            if type(act.filter) is DaysActionFilter:
                days = act.filter.days
            elif type(act.filter) is DaysActionFilter:
                date = act.filter.date
            elif type(act.filter) is NoncurrentCountActionFilter:
                days = act.filter.days
            else:
                raise ValueError(
                    "Unsopported filter %s for action %s", type(act.filter), act
                )
        return [days, date, delete_marker]

    def _check_query_events(
        self,
        queries,
        action,
        view_queries,
        newer_non_current_versions,
        storage_class,
        last_rule_action,
        rule_id,
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
                    create_views_data = {}
                    create_views_data["suffix"] = "lifecycle"
                    for key, val in view_queries.items():
                        create_views_data[key] = val
                    resp, body = self.proxy_client._request(
                        "POST",
                        "/container/lifecycle/views/create",
                        params=params,
                        json=create_views_data,
                        **kwargs,
                    )
                    self.assertEqual(resp.status, 204)

                if key_query == "marker":
                    data["is_markers"] = 1
                data["query"] = sql_query
                data["query_set_tag"] = val_query
                data["storage_class"] = storage_class
                data["batch_size"] = self.batch_size
                data["rule_id"] = rule_id
                if last_rule_action:
                    # Don't use last_action , delete of copy will be managed by crawlers
                    # data["last_action"] = 1
                    pass

                reqid = request_id()
                if action in (
                    "NoncurrentVersionExpiration",
                    "NoncurrentVersionTransition",
                ):
                    params["action_type"] = "noncurrent"
                else:
                    params["action_type"] = "current"

                resp, body = self.proxy_client._request(
                    "POST",
                    "/container/lifecycle/apply",
                    params=params,
                    reqid=reqid,
                    json=data,
                    **kwargs,
                )
                self.assertEqual(resp.status, 204)
                count = int(resp.getheader("x-oio-count", 0))
                offset += count
                count_events = 0

                if action in ("Expiration", "Transition"):
                    exptected_events = count * self.expected_to_cycle[rule_id][action]
                else:
                    exptected_events = self.expected_to_cycle[rule_id][action]

                while count_events < exptected_events:
                    event = self.wait_for_kafka_event(
                        types=(EventTypes.LIFECYCLE_ACTION,)
                    )
                    self.assertIsNotNone(event)
                    self.assertEqual(event.event_type, "storage.lifecycle.action")
                    self.assertEqual(event.data["account"], self.account)
                    self.assertEqual(event.data["container"], self.container)

                    elements_to_match = (
                        self.to_match[rule_id][action]
                        if key_query == "base"
                        else self.to_match_markers[rule_id][action]
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
                        for elem in self.not_to_match[rule_id][action]
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

    def _exec_rules_via_sql_query(self, source):
        lc = ContainerLifecycle(self.api, self.account, self.container)
        lc.load_xml(source)
        count_rules = 0
        count_actions = 0
        for el in lc.rules:
            rule_id = el.id
            for act in el.actions:
                # Force expiration for test
                days_in_sec = None
                base_sql_query = None
                non_current = False
                newer_non_current_versions = 0
                non_current_days = 0
                storage_class = ""
                queries = {}
                view_queries = {}
                action = ""
                days = None
                date = None
                delete_marker = None
                # important start by checking inherited class types
                if isinstance(act, NoncurrentVersionExpiration):
                    newer_non_current_versions = act.newer_non_current_versions
                    non_current_days = act.non_current_days
                    action = "NoncurrentVersionExpiration"
                    non_current = True
                elif isinstance(act, NoncurrentVersionTransition):
                    newer_non_current_versions = act.newer_non_current_versions
                    non_current_days = act.non_current_days
                    storage_class = act.policy
                    action = "NoncurrentVersionTransition"
                    non_current = True
                elif isinstance(act, Expiration):
                    action = "Expiration"
                elif isinstance(act, Transition):
                    action = "Transition"
                    storage_class = act.policy
                else:
                    print("Unsupported action type", type(act))
                    return

                days, date, delete_marker = self._get_action_parameters(act)
                # TODO(check if versioning is enabled on client side)
                # Versioning and NoncurrentVersions
                # For tests(non_current_days_in_sec set to 0)
                # non_current_days_in_sec = 86400 * non_current_days
                non_current_days_in_sec = 0 * non_current_days

                if self.versioning_enabled:
                    if non_current:
                        non_current_days_in_sec = non_current_days_in_sec
                        noncurrent_view = el.filter.create_noncurrent_view(
                            non_current_days_in_sec
                        )
                        current_view = el.filter.create_common_views(
                            "current_view", non_current_days_in_sec
                        )

                        view_queries["noncurrent_view"] = noncurrent_view
                        view_queries["current_view"] = current_view
                        queries["base"] = el.filter.noncurrent_query(
                            newer_non_current_versions
                        )
                    # versioning for Expiration/Transition
                    else:
                        delete_marker_view = el.filter.create_common_views(
                            "marker_view", non_current_days_in_sec, deleted=True
                        )
                        vesioned_view = el.filter.create_common_views(
                            "versioned_view", non_current_days_in_sec, deleted=False
                        )

                        noncurrent_view = el.filter.create_noncurrent_view(
                            non_current_days_in_sec
                        )

                        view_queries["marker_view"] = delete_marker_view
                        view_queries["versioned_view"] = vesioned_view
                        view_queries["noncurrent_view"] = noncurrent_view

                        if type(act.filter) is DeletedMarkerActionFilter:
                            if act.filter.expired_object_deleted_marker:
                                queries["base"] = el.filter.to_sql_query(
                                    non_current_days_in_sec, None, False, True, True
                                )
                                queries["marker"] = el.filter.markers_query()
                            else:
                                print(
                                    "Skip Expiration with delete marker set " "to false"
                                )
                                continue
                        else:
                            queries["base"] = el.filter.to_sql_query(
                                non_current_days_in_sec, None, False, True
                            )
                            queries["marker"] = el.filter.markers_query()
                else:  # non versioned
                    if days is not None:
                        days_in_sec = 0 * days
                    base_sql_query = el.filter.to_sql_query(days_in_sec, date)
                    queries["base"] = base_sql_query

                last_rule_action = self._is_last_action_last_rule(
                    lc.rules, el.actions, count_rules, count_actions
                )

                self._check_query_events(
                    queries,
                    action,
                    view_queries,
                    newer_non_current_versions,
                    storage_class,
                    last_rule_action,
                    rule_id,
                )

                count_actions += 1
                self.assertEqual(len(self.to_match[rule_id][action]), 0)
                self.assertEqual(len(self.to_match_markers[rule_id][action]), 0)
        count_rules += 1


class TestLifecycleConformExpiration(TestLifecycleConform):
    def setUp(self):
        super(TestLifecycleConformExpiration, self).setUp()
        self.action = "Expiration"
        self.rule_id = "rule1"
        self.begin_source = (
            """<LifecycleConfiguration>
                <Rule>
                    <ID>"""
            f"{self.rule_id}"
            """</ID>
                    <Filter>
                        <And>"""
        )

        self.end_source = """</And>
                    </Filter>
                    <Status>Enabled</Status>
                    <Expiration>
                        <Days>10</Days>
                    </Expiration>
                </Rule>
            </LifecycleConfiguration>"""

        self.rules[self.rule_id] = {}
        self.rules[self.rule_id][self.action] = []
        self._init_match_rules()

        self.source_prefix = (
            """
            <LifecycleConfiguration>
                <Rule>
                    <ID>"""
            f"{self.rule_id}"
            """</ID>
                    <Filter>
                        <Prefix>a/</Prefix>
                    </Filter>
                    <Status>Enabled</Status>
                    <Expiration>
                        <Days>10</Days>
                    </Expiration>
                </Rule>
            </LifecycleConfiguration>
            """
        )
        self.expected_to_cycle = {}
        self.expected_to_cycle[self.rule_id] = {}
        self.expected_to_cycle[self.rule_id][self.action] = 1

    def tearDown(self):
        super(TestLifecycleConformExpiration, self).tearDown()

    def test_apply_prefix(self):
        self._create_container_versioning(self.source_prefix)

        for _ in range(self.number_match):
            obj_meta = self._upload_something(prefix="a/")
            self.to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(prefix="b/")
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(self.source_prefix)

    def _upload_expected_combine1(self):
        for _ in range(self.number_not_match):
            name = self.prefix + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_short, random_length=5
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_match):
            name = self.prefix + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_long, random_length=6
                )
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

    def test_combine1(self):
        # ["prefix", "greater"]

        val = self.conditions["prefix"]
        source = f"{self.begin_source}<Prefix>{val}"
        source = f"{source}</Prefix>"
        greater = self.conditions["greater"]
        source = f"{source}<ObjectSizeGreaterThan>{greater}"
        source = f"{source}</ObjectSizeGreaterThan>"
        source = f"{source} {self.end_source }"

        self._create_container_versioning(source)

        self._upload_expected_combine1()

        self._check_and_apply(source)

    def test_combine2(self):
        # ["prefix", "lesser"]
        val = self.conditions["prefix"]
        source = f"{self.begin_source}<Prefix>{val}"
        source = f"{source}</Prefix>"

        lesser = self.conditions["lesser"]
        source = f"{source}<ObjectSizeLessThan>{lesser}"
        source = f"{source}</ObjectSizeLessThan>"
        source = f"{source} {self.end_source }"

        self._create_container_versioning(source)

        for j in range(self.number_match):
            name = self.prefix + str(j) + "0" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_middle, random_length=4
                )
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_match):
            name = self.prefix + str(j) + "1" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_short, random_length=5
                )
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = self.prefix + str(j) + "2" + random_str(5)
            obj_meta = self._upload_something(
                name=name, data=self.data_long, random_length=6
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)

    def test_combine3(self):
        # ["prefix", "tag1"]
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        val = self.conditions["prefix"]
        source = f"{self.begin_source}<Prefix>{val}"
        source = f"{source}</Prefix>"

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        source = f"{source} {self.end_source }"

        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self._create_container_versioning(source)

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
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = self.prefix + str(j) + "1" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_long,
                    random_length=6,
                    properties={TAGGING_KEY: self.not_match_tag_set},
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)

    def test_combine4(self):
        # [prefix, tag1, tag2]
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        val = self.conditions["prefix"]
        source = f"{self.begin_source}<Prefix>{val}"
        source = f"{source}</Prefix>"

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        source = f"{source} {self.end_source }"

        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self._create_container_versioning(source)

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
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = self.prefix + str(j) + "1" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_long,
                    random_length=6,
                    properties={TAGGING_KEY: self.not_match_tag_set},
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)

    def test_combine5(self):
        # ["prefix", "tag1", "tag2", "tag3"]
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        val = self.conditions["prefix"]
        source = f"{self.begin_source}<Prefix>{val}"
        source = f"{source}</Prefix>"

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag3"].keys())[0]
        val = self.conditions["tag3"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        source = f"{source} {self.end_source }"

        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self._create_container_versioning(source)

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
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = self.prefix + str(j) + "j" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    prefix=self.prefix,
                    data=self.data_long,
                    random_length=6,
                    properties={TAGGING_KEY: self.not_match_tag_set},
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)

    def test_combine6(self):
        # ["prefix", "tag2", "tag3"]
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        val = self.conditions["prefix"]
        source = f"{self.begin_source}<Prefix>{val}"
        source = f"{source}</Prefix>"

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag3"].keys())[0]
        val = self.conditions["tag3"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        source = f"{source} {self.end_source }"

        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self._create_container_versioning(source)

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
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = self.prefix + str(j) + "1" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_long,
                    random_length=6,
                    properties={TAGGING_KEY: self.not_match_tag_set},
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)
        self._check_and_apply(source)

    def test_combine7(self):
        # ["prefix", "greater", "lesser", "tag1"])
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        val = self.conditions["prefix"]
        source = f"{self.begin_source}<Prefix>{val}"
        source = f"{source}</Prefix>"

        greater = self.conditions["greater"]
        source = f"{source}<ObjectSizeGreaterThan>{greater}"
        source = f"{source}</ObjectSizeGreaterThan>"

        lesser = self.conditions["lesser"]
        source = f"{source}<ObjectSizeLessThan>{lesser}"
        source = f"{source}</ObjectSizeLessThan>"

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        source = f"{source} {self.end_source }"

        self._create_container_versioning(source)

        for j in range(self.number_not_match):
            name = "not-prefix-" + str(j) + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_middle, random_length=4
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = "not-prefix-" + str(j) + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_short, random_length=5
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = "not-prefix-" + str(j) + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_long, random_length=6
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_match):
            name = "not-prefix-" + str(j) + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_middle,
                    random_length=4,
                    properties={TAGGING_KEY: tag_set},
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = "not-prefix-" + str(j) + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=5,
                    properties={TAGGING_KEY: tag_set},
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(5),
                data=self.data_middle,
                random_length=4,
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(5),
                data=self.data_short,
                random_length=5,
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(6),
                data=self.data_long,
                random_length=6,
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(5),
                data=self.data_middle,
                random_length=4,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(5),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix + random_str(5),
                data=self.data_middle,
                random_length=4,
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix + random_str(5),
                data=self.data_short,
                random_length=5,
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix + random_str(6), data=self.data_long, random_length=6
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

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
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix + random_str(5),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix + random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)
        self._check_and_apply(source)

    def test_combine8(self):
        # ["greater', 'lesser"]

        greater = self.conditions["greater"]
        source = f"{self.begin_source}<ObjectSizeGreaterThan>{greater}"
        source = f"{source}</ObjectSizeGreaterThan>"

        lesser = self.conditions["lesser"]
        source = f"{source}<ObjectSizeLessThan>{lesser}"
        source = f"{source}</ObjectSizeLessThan>"
        source = f"{source} {self.end_source }"

        self._create_container_versioning(source)

        for j in range(self.number_match):
            name = str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_middle, random_length=4
                )
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5), data=self.data_short, random_length=5
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(6), data=self.data_long, random_length=6
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)
        self._check_and_apply(source)

    def test_combine9(self):
        # ["greater", "lesser", "tag1"])
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        greater = self.conditions["greater"]
        source = f"{self.begin_source}<ObjectSizeGreaterThan>{greater}"
        source = f"{source}</ObjectSizeGreaterThan>"

        lesser = self.conditions["lesser"]
        source = f"{source}<ObjectSizeLessThan>{lesser}"
        source = f"{source}</ObjectSizeLessThan>"

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        source = f"{source} {self.end_source }"

        self._create_container_versioning(source)

        for _ in range(self.number_match):
            obj_meta = self._upload_something(
                prefix=random_str(5), data=self.data_middle, random_length=4
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5), data=self.data_short, random_length=5
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(6), data=self.data_long, random_length=6
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

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
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)

    def test_combine10(self):
        # ["greater", "tag2"]
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        greater = self.conditions["greater"]
        source = f"{self.begin_source}<ObjectSizeGreaterThan>{greater}"
        source = f"{source}</ObjectSizeGreaterThan>"

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        source = f"{source} {self.end_source }"

        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self._create_container_versioning(source)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

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
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)

    def test_combine11(self):
        # ["greater", "tag1", "tag2"]
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        greater = self.conditions["greater"]
        source = f"{self.begin_source}<ObjectSizeGreaterThan>{greater}"
        source = f"{source}</ObjectSizeGreaterThan>"

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"
        source = f"{source} {self.end_source }"

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self._create_container_versioning(source)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

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
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)

    def test_combine12(self):
        # ["greater", "tag1", "tag2", "tag3"]
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        greater = self.conditions["greater"]
        source = f"{self.begin_source}<ObjectSizeGreaterThan>{greater}"
        source = f"{source}</ObjectSizeGreaterThan>"

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag3"].keys())[0]
        val = self.conditions["tag3"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"
        source = f"{source} {self.end_source }"

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self._create_container_versioning(source)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

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
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)

    def test_combine13(self):
        # ["greater", "tag2", "tag3"]
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        greater = self.conditions["greater"]
        source = f"{self.begin_source}<ObjectSizeGreaterThan>{greater}"
        source = f"{source}</ObjectSizeGreaterThan>"

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag3"].keys())[0]
        val = self.conditions["tag3"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"
        source = f"{source} {self.end_source }"

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self._create_container_versioning(source)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

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
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)

    def test_combine14(self):
        # ["lesser", "tag1"]
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        lesser = self.conditions["lesser"]
        source = f"{self.begin_source}<ObjectSizeLessThan>{lesser}"
        source = f"{source}</ObjectSizeLessThan>"

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"
        source = f"{source} {self.end_source }"

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self._create_container_versioning(source)

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
                    self.to_match[self.rule_id][self.action].append(obj_meta)

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
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = str(j) + "2" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_middle,
                    random_length=6,
                    properties={TAGGING_KEY: self.not_match_tag_set},
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)

    def test_combine15(self):
        # ["lesser", "tag1", "tag2"]
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        lesser = self.conditions["lesser"]
        source = f"{self.begin_source}<ObjectSizeLessThan>{lesser}"
        source = f"{source}</ObjectSizeLessThan>"

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"
        source = f"{source} {self.end_source }"

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self._create_container_versioning(source)

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
                    self.to_match[self.rule_id][self.action].append(obj_meta)

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
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = str(j) + "2" + random_str(5)
            obj_meta = self._upload_something(
                name=name,
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = str(j) + "3" + random_str(5)
            obj_meta = self._upload_something(
                name=name,
                data=self.data_middle,
                random_length=6,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)

    def test_combine16(self):
        # ["lesser", "tag1", "tag2", "tag3"]
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        lesser = self.conditions["lesser"]
        source = f"{self.begin_source}<ObjectSizeLessThan>{lesser}"
        source = f"{source}</ObjectSizeLessThan>"

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag3"].keys())[0]
        val = self.conditions["tag3"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"
        source = f"{source} {self.end_source }"

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self._create_container_versioning(source)

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
                    self.to_match[self.rule_id][self.action].append(obj_meta)

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
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(7),
                data=self.data_middle,
                random_length=6,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)

    def test_combine17(self):
        # ["lesser", "tag2", "tag3"]
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        lesser = self.conditions["lesser"]
        source = f"{self.begin_source}<ObjectSizeLessThan>{lesser}"
        source = f"{source}</ObjectSizeLessThan>"

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag3"].keys())[0]
        val = self.conditions["tag3"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"
        source = f"{source} {self.end_source }"

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self._create_container_versioning(source)

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
                    self.to_match[self.rule_id][self.action].append(obj_meta)

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
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(7),
                data=self.data_middle,
                random_length=6,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)

    def test_combine18(self):
        # ["tag1", "tag2"]
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]
        source = f"{self.begin_source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"
        source = f"{source} {self.end_source }"

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self._create_container_versioning(source)

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
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5),
                data=self.data_short,
                random_length=6,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)
            self.assertIsNot(len(self.to_match), 0)

        self._check_and_apply(source)

    def test_combine19(self):
        # ["tag1", "tag2", "tag3"])
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]
        source = f"{self.begin_source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag3"].keys())[0]
        val = self.conditions["tag3"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"
        source = f"{source} {self.end_source }"

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self._create_container_versioning(source)

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
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5),
                data=self.data_short,
                random_length=6,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)


class TestLifecycleConformTransition(TestLifecycleConformExpiration):
    def setUp(self):
        super(TestLifecycleConformTransition, self).setUp()
        self.action = "Transition"
        self.end_source = """</And>
                        </Filter>
                        <Status>Enabled</Status>
                        <Transition>
                            <Days>10</Days>
                            <StorageClass>STANDARD_IA</StorageClass>
                        </Transition>
                    </Rule>
                </LifecycleConfiguration>"""

        self.source_prefix = (
            """
            <LifecycleConfiguration>
                <Rule>
                    <ID>"""
            f"{self.rule_id}"
            """</ID>
                    <Filter>
                        <Prefix>a/</Prefix>
                    </Filter>
                    <Status>Enabled</Status>
                    <Transition>
                        <Days>10</Days>
                        <StorageClass>STANDARD_IA</StorageClass>
                    </Transition>
                </Rule>
            </LifecycleConfiguration>
            """
        )

        self.rules[self.rule_id] = {}
        self.rules[self.rule_id][self.action] = []

        self._init_match_rules()
        self.expected_to_cycle = {}
        self.expected_to_cycle[self.rule_id] = {}
        self.expected_to_cycle[self.rule_id][self.action] = 1

    def tearDown(self):
        super(TestLifecycleConformTransition, self).tearDown()


class TestLifecycleConformExpirationDate(TestLifecycleConformExpiration):
    def setUp(self):
        super(TestLifecycleConformExpirationDate, self).setUp()
        self.action = "Expiration"
        now = time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
        self.end_source = (
            """</And>
                        </Filter>
                        <Status>Enabled</Status>
                        <Expiration>
                            <Date>"""
            f"{now}"
            """</Date>
                        </Expiration>
                    </Rule>
                </LifecycleConfiguration>"""
        )

    def tearDown(self):
        super(TestLifecycleConformExpirationDate, self).tearDown()

    def test_non_expired_object(self):
        """
        Date of expiration not reached, objects shouldn't expire
        """
        # ['prefix', 'tag2']
        now = datetime.now()
        next_time = now + timedelta(days=1)
        next_day = next_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
        self.end_source = (
            """</And>
                        </Filter>
                        <Status>Enabled</Status>
                        <Expiration>
                            <Date>"""
            f"{next_day}"
            """</Date>
                        </Expiration>
                    </Rule>
                </LifecycleConfiguration>"""
        )

        source = """<LifecycleConfiguration>
                <Rule>
                    <ID>rule1</ID>
                    <Filter>
                        <And>"""
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        val = self.conditions["prefix"]
        source = f"{source}<Prefix>{val}"
        source = f"{source}</Prefix>"

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        source = f"{source} {self.end_source }"

        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self._create_container_versioning(source)

        for j in range(self.number_match):
            name = self.prefix + str(j) + "0" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=5,
                    properties={TAGGING_KEY: tag_set},
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = self.prefix + str(j) + "1" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_long,
                    random_length=6,
                    properties={TAGGING_KEY: self.not_match_tag_set},
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)
        self._check_and_apply(source, nothing_to_match=True)


class TestLifecycleConformExpirationVersioning(TestLifecycleConformExpiration):
    def setUp(self):
        super(TestLifecycleConformExpirationVersioning, self).setUp()
        self.versioning_enabled = True
        self.number_of_versions = 3

    # Current version is delete marker but there are other versions
    # No action to do
    def test_delete_marker_1(self):
        # ['greater', 'tag2']
        source = """<LifecycleConfiguration>
                <Rule>
                    <ID>rule1</ID>
                    <Filter>
                        <And>"""
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        greater = self.conditions["greater"]
        source = f"{source}<ObjectSizeGreaterThan>{greater}"
        source = f"{source}</ObjectSizeGreaterThan>"

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        source = f"{source} {self.end_source }"

        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self._create_container_versioning(source)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_match):
            name = str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_long,
                    random_length=6,
                    properties={TAGGING_KEY: tag_set},
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)
            self.api.object_delete(self.account, self.container, obj_meta["name"])

        self._check_and_apply(source, nothing_to_match=True)

    # Current version is delete marker and is only the version
    # action remove delete marker
    def test_delete_marker_2(self):
        self.number_match = 2
        # ['greater', 'tag2']
        source = """<LifecycleConfiguration>
                <Rule>
                    <ID>rule1</ID>
                    <Filter>
                        <And>"""

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        greater = self.conditions["greater"]
        source = f"{source}<ObjectSizeGreaterThan>{greater}"
        source = f"{source}</ObjectSizeGreaterThan>"

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        source = f"{source} {self.end_source }"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self._create_container_versioning(source)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)
        delete_markers = []
        names = []
        for j in range(self.number_match):
            name = str(j) + random_str(5)
            names.append(name)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_long,
                    random_length=6,
                    properties={TAGGING_KEY: tag_set},
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)
            self.api.object_delete(self.account, self.container, name)

        time.sleep(0.1)
        for el in self.not_to_match[self.rule_id][self.action]:
            self.api.object_delete(
                self.account, self.container, el["name"], el["version"]
            )
        for name in names:
            objects = self.api.object_list(
                self.account, self.container, prefix=name, deleted=True, versions=True
            )
            delete_markers.append(objects["objects"][0])

        self.to_match_markers[self.rule_id][self.action] = delete_markers
        self._check_and_apply(source, nothing_to_match=True)

    # Create some objects where:
    # current version matchs the filter but not the only version => match
    # current version doesn't match but some previous matchs => no match
    # current version is delete marker but not the only version => no match
    # current version doesn' match and there is a delete marker => no match
    # current version is delete maker and the olny version => match
    def test_mix_current_versions_and_markers(self):
        # ['prefix', 'tag1']
        source = """<LifecycleConfiguration>
                <Rule>
                    <ID>rule1</ID>
                    <Filter>
                        <And>"""
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""
        val = self.conditions["prefix"]
        source = f"{source}<Prefix>{val}"
        source = f"{source}</Prefix>"

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        source = f"{source} {self.end_source }"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self._create_container_versioning(source)

        for j in range(self.number_match):
            name = self.prefix + str(j) + "0" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=5,
                    properties={TAGGING_KEY: tag_set},
                )
                # Insert delete marker but not the last version for 1 object
                if j == 0 and i == 0:
                    time.sleep(0.01)
                    self.api.object_delete(self.account, self.container, name)
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = self.prefix + str(j) + "1" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_long,
                    random_length=6,
                    properties={TAGGING_KEY: self.not_match_tag_set},
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        names = []
        # the last version a delete marker, and not the only version
        for j in range(self.number_match):
            name = self.prefix + str(j) + "2" + random_str(5)
            names.append(name)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=5,
                    properties={TAGGING_KEY: tag_set},
                )

                self.not_to_match[self.rule_id][self.action].append(obj_meta)
            self.api.object_delete(self.account, self.container, name)

        self._check_and_apply(source)


class TestLifecycleNonCurrentVersionExpiration(TestLifecycleConform):
    def setUp(self):
        super(TestLifecycleNonCurrentVersionExpiration, self).setUp()
        self.versioning_enabled = True
        self.number_of_versions = 4
        self.newer_non_current_versions = 1
        self.rule_id = "rule1"
        self.action = "NoncurrentVersionExpiration"

        self.begin_source = (
            """<LifecycleConfiguration>
                <Rule>
                    <ID>"""
            f"{self.rule_id}"
            """</ID>
                    <Filter>
                        <And>"""
        )
        self.source = ""
        self.end_source = (
            """</And>
                    </Filter>
                    <Status>Enabled</Status>
                    <NoncurrentVersionExpiration>
                        <NoncurrentDays>1</NoncurrentDays>
                        <NewerNoncurrentVersions>"""
            f"{self.newer_non_current_versions}"
            """</NewerNoncurrentVersions>
                            </NoncurrentVersionExpiration>
                </Rule>
            </LifecycleConfiguration>"""
        )

        self.not_to_match_versions = []
        self.expected_to_cycle = {}
        self.expected_to_cycle[self.rule_id] = {}
        self.expected_to_cycle[self.rule_id][self.action] = (
            self.number_of_versions - self.newer_non_current_versions - 1
        )

        self.rules[self.rule_id] = {}
        self.rules[self.rule_id][self.action] = []

        self._init_match_rules()

    def tearDown(self):
        super(TestLifecycleNonCurrentVersionExpiration, self).tearDown()

    def _upload_expected_combine1(self):
        # match only n non current versions per object
        self.numbr_match = 2
        total_count_expected = 0
        for _ in range(self.number_not_match):
            name = self.prefix + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_short, random_length=5
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)
        for j in range(self.number_match):
            name = self.prefix + str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_long, random_length=6
                )
                if i < self.expected_to_cycle[self.rule_id][self.action]:
                    self.to_match[self.rule_id][self.action].append(obj_meta)
                    total_count_expected += 1
                else:
                    # non current to retain
                    self.not_to_match_versions.append(obj_meta)

                if i == self.number_of_versions - 1:  # current version
                    self.not_to_match_versions.append(obj_meta)
        return total_count_expected

    def test_cycle_versions_combine1(self):
        # ['prefix', 'greater']
        # match only 2 non current versions per object
        val = self.conditions["prefix"]
        self.source = f"{self.begin_source}<Prefix>{val}"
        self.source = f"{self.source}</Prefix>"
        greater = self.conditions["greater"]
        self.source = f"{self.source}<ObjectSizeGreaterThan>{greater}"
        self.source = f"{self.source}</ObjectSizeGreaterThan>"
        self.source = f"{self.source} {self.end_source }"

        self.expected_to_cycle[self.rule_id][
            self.action
        ] = 2  # 2 version per object (1 object per batch)
        self._create_container_versioning(self.source)
        self._upload_expected_combine1()
        self._check_and_apply(self.source)

    def test_cycle_versions_combine2(self):
        # ["prefix", "lesser"]
        # match only 2 non current versions per object
        val = self.conditions["prefix"]
        self.source = f"{self.begin_source}<Prefix>{val}"
        self.source = f"{self.source}</Prefix>"
        lesser = self.conditions["lesser"]
        self.source = f"{self.source}<ObjectSizeLessThan>{lesser}"
        self.source = f"{self.source}</ObjectSizeLessThan>"

        self.source = f"{self.source} {self.end_source }"

        # 2 version per object (1 object per batch)
        self.expected_to_cycle[self.rule_id][self.action] = 2
        self._create_container_versioning(self.source)
        self.numbr_match = 2
        total_count_expected = 0
        for _ in range(self.number_not_match):
            name = self.prefix + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_long, random_length=5
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)
        for j in range(self.number_match):
            name = self.prefix + str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_short, random_length=6
                )
                if i < self.expected_to_cycle[self.rule_id][self.action]:
                    self.to_match[self.rule_id][self.action].append(obj_meta)
                    total_count_expected += 1
                else:
                    # non current to retain
                    self.not_to_match_versions.append(obj_meta)

                if i == self.number_of_versions - 1:  # current version
                    self.not_to_match_versions.append(obj_meta)
        self._check_and_apply(self.source)

    def test_cycle_versions_combine3(self):
        # ["prefix", "tag1"]
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        val = self.conditions["prefix"]
        self.source = f"{self.begin_source}<Prefix>{val}"
        self.source = f"{self.source}</Prefix>"

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]
        self.source = f"{self.source}<Tag><Key>{key}</Key><Value>{val}"
        self.source = f"{self.source}</Value></Tag>"

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        self.source = f"{self.source} {self.end_source }"

        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self._create_container_versioning(self.source)

        self.expected_to_cycle[self.rule_id][self.action] = 2
        self._create_container_versioning(self.source)
        self.numbr_match = 2
        total_count_expected = 0
        for _ in range(self.number_not_match):
            name = self.prefix + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_long,
                    random_length=5,
                    properties={TAGGING_KEY: self.not_match_tag_set},
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)
        for j in range(self.number_match):
            name = self.prefix + str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=6,
                    properties={TAGGING_KEY: tag_set},
                )
                if i < self.expected_to_cycle[self.rule_id][self.action]:
                    self.to_match[self.rule_id][self.action].append(obj_meta)
                    total_count_expected += 1
                else:
                    # non current to retain
                    self.not_to_match_versions.append(obj_meta)

                if i == self.number_of_versions - 1:  # current version
                    self.not_to_match_versions.append(obj_meta)
        self._check_and_apply(self.source)

    def test_cycle_versions_combine4(self):
        # [prefix, tag1, tag2]
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        val = self.conditions["prefix"]
        self.source = f"{self.begin_source}<Prefix>{val}"
        self.source = f"{self.source}</Prefix>"

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]
        self.source = f"{self.source}<Tag><Key>{key}</Key><Value>{val}"
        self.source = f"{self.source}</Value></Tag>"

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        self.source = f"{self.source}<Tag><Key>{key}</Key><Value>{val}"
        self.source = f"{self.source}</Value></Tag>"
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        self.source = f"{self.source} {self.end_source }"

        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self._create_container_versioning(self.source)

        self.expected_to_cycle[self.rule_id][self.action] = 2
        self._create_container_versioning(self.source)
        self.numbr_match = 2
        total_count_expected = 0
        for _ in range(self.number_not_match):
            name = self.prefix + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_long,
                    random_length=5,
                    properties={TAGGING_KEY: self.not_match_tag_set},
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)
        for j in range(self.number_match):
            name = self.prefix + str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=6,
                    properties={TAGGING_KEY: tag_set},
                )
                if i < self.expected_to_cycle[self.rule_id][self.action]:
                    self.to_match[self.rule_id][self.action].append(obj_meta)
                    total_count_expected += 1
                else:
                    # non current to retain
                    self.not_to_match_versions.append(obj_meta)

                if i == self.number_of_versions - 1:  # current version
                    self.not_to_match_versions.append(obj_meta)
        self._check_and_apply(self.source)

    def test_cycle_versions_combine7(self):
        # ["prefix", "greater", "lesser", "tag1"])
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        val = self.conditions["prefix"]
        self.source = f"{self.begin_source}<Prefix>{val}"
        self.source = f"{self.source}</Prefix>"

        greater = self.conditions["greater"]
        self.source = f"{self.source}<ObjectSizeGreaterThan>{greater}"
        self.source = f"{self.source}</ObjectSizeGreaterThan>"

        lesser = self.conditions["lesser"]
        self.source = f"{self.source}<ObjectSizeLessThan>{lesser}"
        self.source = f"{self.source}</ObjectSizeLessThan>"

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]
        self.source = f"{self.source}<Tag><Key>{key}</Key><Value>{val}"
        self.source = f"{self.source}</Value></Tag>"
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        self.source = f"{self.source} {self.end_source }"

        self._create_container_versioning(self.source)

        for j in range(self.number_not_match):
            name = "not-prefix-" + str(j) + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_middle, random_length=4
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = "not-prefix-" + str(j) + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_short, random_length=5
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = "not-prefix-" + str(j) + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_long, random_length=6
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_match):
            name = "not-prefix-" + str(j) + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_middle,
                    random_length=4,
                    properties={TAGGING_KEY: tag_set},
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = "not-prefix-" + str(j) + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=5,
                    properties={TAGGING_KEY: tag_set},
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(5),
                data=self.data_middle,
                random_length=4,
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(5),
                data=self.data_short,
                random_length=5,
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(6),
                data=self.data_long,
                random_length=6,
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(5),
                data=self.data_middle,
                random_length=4,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(5),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix + random_str(5),
                data=self.data_middle,
                random_length=4,
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix + random_str(5),
                data=self.data_short,
                random_length=5,
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix + random_str(6), data=self.data_long, random_length=6
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_match):
            name = self.prefix + str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_middle,
                    random_length=4,
                    properties={TAGGING_KEY: tag_set},
                )
                if i < self.expected_to_cycle[self.rule_id][self.action]:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix + random_str(5),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix + random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)
        self._check_and_apply(self.source)

    def test_cycle_versions_combine8(self):
        # ["greater', 'lesser"]

        greater = self.conditions["greater"]
        self.source = f"{self.begin_source}<ObjectSizeGreaterThan>{greater}"
        self.source = f"{self.source}</ObjectSizeGreaterThan>"

        lesser = self.conditions["lesser"]
        self.source = f"{self.source}<ObjectSizeLessThan>{lesser}"
        self.source = f"{self.source}</ObjectSizeLessThan>"
        self.source = f"{self.source} {self.end_source }"

        self._create_container_versioning(self.source)

        for j in range(self.number_match):
            name = str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_middle, random_length=4
                )
                if i < self.expected_to_cycle[self.rule_id][self.action]:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5), data=self.data_short, random_length=5
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(6), data=self.data_long, random_length=6
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)
        self._check_and_apply(self.source)

    def test_cycle_versions_combine9(self):
        # ["greater", "lesser", "tag1"])
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        greater = self.conditions["greater"]
        self.source = f"{self.begin_source}<ObjectSizeGreaterThan>{greater}"
        self.source = f"{self.source}</ObjectSizeGreaterThan>"

        lesser = self.conditions["lesser"]
        self.source = f"{self.source}<ObjectSizeLessThan>{lesser}"
        self.source = f"{self.source}</ObjectSizeLessThan>"

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]
        self.source = f"{self.source}<Tag><Key>{key}</Key><Value>{val}"
        self.source = f"{self.source}</Value></Tag>"
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        self.source = f"{self.source} {self.end_source }"

        self._create_container_versioning(self.source)

        for _ in range(self.number_match):
            obj_meta = self._upload_something(
                prefix=random_str(5), data=self.data_middle, random_length=4
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5), data=self.data_short, random_length=5
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(6), data=self.data_long, random_length=6
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_match):
            name = str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_middle,
                    random_length=4,
                    properties={TAGGING_KEY: tag_set},
                )
                if i < self.expected_to_cycle[self.rule_id][self.action]:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(self.source)

    def test_cycle_versions_combine10(self):
        # ["greater", "tag2"]
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        greater = self.conditions["greater"]
        self.source = f"{self.begin_source}<ObjectSizeGreaterThan>{greater}"
        self.source = f"{self.source}</ObjectSizeGreaterThan>"

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        self.source = f"{self.source}<Tag><Key>{key}</Key><Value>{val}"
        self.source = f"{self.source}</Value></Tag>"
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        self.source = f"{self.source} {self.end_source }"

        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self._create_container_versioning(self.source)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_match):
            name = str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_long,
                    random_length=6,
                    properties={TAGGING_KEY: tag_set},
                )
                if i < self.expected_to_cycle[self.rule_id][self.action]:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(self.source)

    def test_cycle_zero_newer_non_current(self):
        # ['prefix', 'greater']
        # Total versions per object is 4: one current and 0 newer non currnet
        # So 3 versions to match
        self.newer_non_current_versions = 0
        self.action = "NoncurrentVersionExpiration"
        self.end_source = """</And>
                        </Filter>
                    <Status>Enabled</Status>
                    <NoncurrentVersionExpiration>
                        <NoncurrentDays>1</NoncurrentDays>
                        <NewerNoncurrentVersions>"""
        self.end_source = (
            f"{self.end_source}\
            {self.newer_non_current_versions}"
            """</NewerNoncurrentVersions>
            </NoncurrentVersionExpiration></Rule></LifecycleConfiguration>"""
        )

        self.not_to_match_versions = []

        self.expected_to_cycle[self.rule_id][self.action] = (
            self.number_of_versions - self.newer_non_current_versions - 1
        )

        val = self.conditions["prefix"]
        self.source = f"{self.begin_source}<Prefix>{val}"
        self.source = f"{self.source}</Prefix>"
        greater = self.conditions["greater"]
        self.source = f"{self.source}<ObjectSizeGreaterThan>{greater}"
        self.source = f"{self.source}</ObjectSizeGreaterThan>"
        self.source = f"{self.source} {self.end_source }"

        self._create_container_versioning(self.source)
        self._upload_expected_combine1()
        self._check_and_apply(self.source)

    def test_cycle_several_newer_non_current(self):
        # ['prefix', 'greater']
        # Total versions per object is 4: one current and 3 newer
        # So no version to cycle
        self.newer_non_current_versions = 3
        self.action = "NoncurrentVersionExpiration"
        self.end_source = """</And>
                        </Filter>
                    <Status>Enabled</Status>
                    <NoncurrentVersionExpiration>
                        <NoncurrentDays>1</NoncurrentDays>
                        <NewerNoncurrentVersions>"""
        self.end_source = (
            f"{self.end_source}\
            {self.newer_non_current_versions}"
            """</NewerNoncurrentVersions>
            </NoncurrentVersionExpiration></Rule></LifecycleConfiguration>"""
        )

        self.not_to_match_versions = []

        self.expected_to_cycle[self.rule_id][self.action] = (
            self.number_of_versions - self.newer_non_current_versions - 1
        )

        val = self.conditions["prefix"]
        self.source = f"{self.begin_source}<Prefix>{val}"
        self.source = f"{self.source}</Prefix>"
        greater = self.conditions["greater"]
        self.source = f"{self.source}<ObjectSizeGreaterThan>{greater}"
        self.source = f"{self.source}</ObjectSizeGreaterThan>"
        self.source = f"{self.source} {self.end_source }"

        self._create_container_versioning(self.source)
        self._upload_expected_combine1()
        self._check_and_apply(self.source, nothing_to_match=True)

    def test_cycle_also_several_newer_non_current(self):
        # ['prefix', 'greater']
        # Total versions per object is 4: one current and 4 newer
        # So no version to cycle
        self.newer_non_current_versions = 4
        self.action = "NoncurrentVersionExpiration"
        self.end_source = """</And>
                        </Filter>
                    <Status>Enabled</Status>
                    <NoncurrentVersionExpiration>
                        <NoncurrentDays>1</NoncurrentDays>
                        <NewerNoncurrentVersions>"""
        self.end_source = (
            f"{self.end_source}\
        {self.newer_non_current_versions}"
            """</NewerNoncurrentVersions>
        </NoncurrentVersionExpiration></Rule></LifecycleConfiguration>"""
        )

        self.not_to_match_versions = []

        self.expected_to_cycle[self.rule_id][self.action] = (
            self.number_of_versions - self.newer_non_current_versions - 1
        )
        self.source = """<LifecycleConfiguration>
                <Rule>
                    <ID>rule1</ID>
                    <Filter>
                        <And>"""
        val = self.conditions["prefix"]
        self.source = f"{self.source}<Prefix>{val}"
        self.source = f"{self.source}</Prefix>"
        greater = self.conditions["greater"]
        self.source = f"{self.source}<ObjectSizeGreaterThan>{greater}"
        self.source = f"{self.source}</ObjectSizeGreaterThan>"
        self.source = f"{self.source} {self.end_source }"

        self._create_container_versioning(self.source)
        self._upload_expected_combine1()
        self._check_and_apply(self.source, nothing_to_match=True)


class TestLifecycleConformExpiredDelete(TestLifecycleConform):
    def setUp(self):
        super(TestLifecycleConformExpiredDelete, self).setUp()
        self.versioning_enabled = True
        self.number_of_versions = 3
        self.rule_id = "rule1"
        self.action = "Expiration"
        self.begin_source = (
            """<LifecycleConfiguration>
                <Rule>
                    <ID>"""
            f"{self.rule_id}"
            """</ID>
                    <Filter>
                        <Prefix>documents/</Prefix>"""
        )

        self.end_source = """
                    </Filter>
                    <Status>Enabled</Status>
                    <Expiration>
                        <ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker>
                    </Expiration>
                </Rule>
            </LifecycleConfiguration>"""

        self.rules[self.rule_id] = {}
        self.rules[self.rule_id][self.action] = []
        self._init_match_rules()

        self.expected_to_cycle = {}
        self.expected_to_cycle[self.rule_id] = {}
        self.expected_to_cycle[self.rule_id][self.action] = 1

    def test_expired_delete_marker_true(self):
        """
        Add some versions of object, add delete marker
        remove all previous versions
        The only remaining version is the delete marker
        Check that event is sent to expire delete marker
        """
        # ['prefix']

        source = f"{self.begin_source} {self.end_source }"

        self._create_container_versioning(source)
        self.number_match = 1
        for j in range(self.number_match):
            name = "documents/" + str(j) + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_long, random_length=6
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)
            self.api.object_delete(self.account, self.container, name)
            for el in self.not_to_match[self.rule_id][self.action]:
                self.api.object_delete(
                    self.account, self.container, el["name"], version=el["version"]
                )

            objects = self.api.object_list(
                self.account, self.container, deleted=True, versions=True
            )
            self.to_match_markers[self.rule_id][self.action] = objects["objects"]
        self._check_and_apply(source, nothing_to_match=True)

    def test_expired_delete_marker_false(self):
        """Add some versions of object, add delete marker then
        remove all previous versions
        The only remaining version is the delete marker
        Check that event is sent to expire delete marker
        """
        # ['prefix']
        self.end_source = """
                    </Filter>
                    <Status>Enabled</Status>
                    <Expiration>
                        <ExpiredObjectDeleteMarker>false</ExpiredObjectDeleteMarker>
                    </Expiration>
                </Rule>
            </LifecycleConfiguration>"""

        source = f"{self.begin_source} {self.end_source }"

        self._create_container_versioning(source)
        self.number_match = 1
        for j in range(self.number_match):
            name = "documents/" + str(j) + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_long, random_length=6
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)
            self.api.object_delete(self.account, self.container, name)
            for el in self.not_to_match[self.rule_id][self.action]:
                self.api.object_delete(
                    self.account, self.container, el["name"], version=el["version"]
                )

            objects = self.api.object_list(
                self.account, self.container, deleted=True, versions=True
            )
            self.not_to_match[self.rule_id][self.action] = objects["objects"]
        self._check_and_apply(source, nothing_to_match=True)


class TestLifecycleNonCurrentVersionConflict(TestLifecycleConform):
    """
    Test two conflict rules and verify that events are sent one by
    predominant rule
    """

    def setUp(self):
        super(TestLifecycleNonCurrentVersionConflict, self).setUp()
        self.versioning_enabled = True
        self.number_of_versions = 4
        self.newer_non_current_versions = 1
        self.action1 = "NoncurrentVersionExpiration"
        self.action2 = "NoncurrentVersionTransition"

        self.source = ""
        self.end_rule1 = (
            """</And>
                    </Filter>
                    <Status>Enabled</Status>
                    <NoncurrentVersionExpiration>
                        <NoncurrentDays>1</NoncurrentDays>
                        <NewerNoncurrentVersions>"""
            f"{self.newer_non_current_versions}"
            """</NewerNoncurrentVersions>
                    </NoncurrentVersionExpiration>
                </Rule>
            """
        )
        self.end_rule2 = (
            """</And>
                    </Filter>
                    <Status>Enabled</Status>
                    <NoncurrentVersionTransition>
                        <NoncurrentDays>1</NoncurrentDays>
                        <NewerNoncurrentVersions>"""
            f"{self.newer_non_current_versions}"
            """</NewerNoncurrentVersions>
                        <StorageClass>STANDARD</StorageClass>
                    </NoncurrentVersionTransition>
                </Rule>
            """
        )
        self.rule1 = "rule1"
        self.rule2 = "rule2"
        self.rules = {
            self.rule1: {self.action1},
            self.rule2: {self.action2},
        }

        self._init_match_rules()

        self.not_to_match_versions = []
        self.expected_to_cycle[self.rule1] = {}
        self.expected_to_cycle[self.rule2] = {}

        self.expected_to_cycle[self.rule1][self.action1] = (
            self.number_of_versions - self.newer_non_current_versions - 1
        )
        self.expected_to_cycle[self.rule2][self.action2] = 0

    def tearDown(self):
        super(TestLifecycleConform, self).tearDown()

    def _upload_expected_combine1(self):
        # match only n non current versions per object
        self.numbr_match = 2
        total_count_expected = 0
        for _ in range(self.number_not_match):
            name = self.prefix + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_short, random_length=5
                )
                self.not_to_match[self.rule1][self.action1].append(obj_meta)
        for j in range(self.number_match):
            name = self.prefix + str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_long, random_length=6
                )
                if i < self.expected_to_cycle[self.rule1][self.action1]:
                    self.to_match[self.rule1][self.action1].append(obj_meta)
                    total_count_expected += 1
                else:
                    # non current to retain
                    self.not_to_match_versions.append(obj_meta)

                if i == self.number_of_versions - 1:  # current version
                    self.not_to_match_versions.append(obj_meta)

        # nothing to match for rule2
        self.to_match[self.rule2][self.action2] = []
        return total_count_expected

    def test_conflict_noncurrent(self):
        # ["prefix", "greater"]
        # match only 2 non current versions per object
        # As the rules conflit:check that  Expiration sends events but
        # Transitions doesn't
        self.source = """<LifecycleConfiguration>
                <Rule>
                    <ID>rule1</ID>
                    <Filter>
                        <And>"""
        val = self.conditions["prefix"]
        self.source = f"{self.source}<Prefix>{val}"
        self.source = f"{self.source}</Prefix>"
        greater = self.conditions["greater"]
        self.source = f"{self.source}<ObjectSizeGreaterThan>{greater}"
        self.source = f"{self.source}</ObjectSizeGreaterThan>"
        self.source = f"{self.source} {self.end_rule1 }"

        # Second Rule that conclicts
        self.source = (
            f"{self.source} "
            """
                <Rule>
                    <ID>rule2</ID>
                    <Filter>
                        <And>"""
        )

        self.source = f"{self.source}<Prefix>{val}"
        self.source = f"{self.source}</Prefix>"
        greater = self.conditions["greater"]
        self.source = f"{self.source}<ObjectSizeGreaterThan>{greater}"
        self.source = f"{self.source}</ObjectSizeGreaterThan>"
        self.source = f"{self.source} {self.end_rule2 }"
        self.source = f"{self.source} </LifecycleConfiguration>"

        # 2 version per object (1 object per batch)
        self.expected_to_cycle[self.rule1][self.action1] = 2
        self.expected_to_cycle[self.rule2][self.action2] = 0  #
        self._create_container_versioning(self.source)
        self._upload_expected_combine1()
        self._check_and_apply(self.source)


class TestLifecycleExpirationConflict(TestLifecycleConform):
    """
    Test two conflict rules Expiraton/Trainsition and verify that events are sent one by
    predominant rule
    """

    def setUp(self):
        super(TestLifecycleExpirationConflict, self).setUp()
        self.versioning_enabled = True
        self.action1 = "Expiration"
        self.action2 = "Transition"

        self.source = ""
        self.end_rule1 = """</And>
                    </Filter>
                    <Status>Enabled</Status>
                    <Expiration>
                        <Days>1</Days>
                    </Expiration>
                </Rule>
            """
        self.end_rule2 = """</And>
                    </Filter>
                    <Status>Enabled</Status>
                    <Transition>
                        <Days>1</Days>
                        <StorageClass>STANDARD</StorageClass>
                    </Transition>
                </Rule>
            """
        self.rule1 = "rule1"
        self.rule2 = "rule2"
        self.rules = {
            self.rule1: {self.action1},
            self.rule2: {self.action2},
        }

        self._init_match_rules()

        self.not_to_match_versions = []
        self.expected_to_cycle = {}
        self.expected_to_cycle[self.rule1] = {}
        self.expected_to_cycle[self.rule2] = {}
        self.expected_to_cycle[self.rule1][self.action1] = 1
        self.expected_to_cycle[self.rule2][self.action2] = 0

    def tearDown(self):
        super(TestLifecycleConform, self).tearDown()

    def _upload_expected_combine1(self):
        # match only n non current versions per object
        for _ in range(self.number_not_match):
            name = self.prefix + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_short, random_length=5
                )
                self.not_to_match[self.rule1][self.action1].append(obj_meta)

        for _ in range(self.number_match):
            name = self.prefix + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_long, random_length=6
                )
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule1][self.action1].append(obj_meta)

        # nothing to match for rule2
        self.to_match[self.rule2][self.action2] = []

    def test_conflict_current(self):
        # ["prefix", "greater"]
        # match only 2 non current versions per object
        # As the rules conflit:check that  Expiration sends events but
        # Transitions doesn't
        self.source = """<LifecycleConfiguration>
                <Rule>
                    <ID>rule1</ID>
                    <Filter>
                        <And>"""
        val = self.conditions["prefix"]
        self.source = f"{self.source}<Prefix>{val}"
        self.source = f"{self.source}</Prefix>"
        greater = self.conditions["greater"]
        self.source = f"{self.source}<ObjectSizeGreaterThan>{greater}"
        self.source = f"{self.source}</ObjectSizeGreaterThan>"
        self.source = f"{self.source} {self.end_rule1 }"

        # Second Rule that conclicts
        self.source = (
            f"{self.source} "
            """
                <Rule>
                    <ID>rule2</ID>
                    <Filter>
                        <And>"""
        )

        self.source = f"{self.source}<Prefix>{val}"
        self.source = f"{self.source}</Prefix>"
        greater = self.conditions["greater"]
        self.source = f"{self.source}<ObjectSizeGreaterThan>{greater}"
        self.source = f"{self.source}</ObjectSizeGreaterThan>"
        self.source = f"{self.source} {self.end_rule2 }"
        self.source = f"{self.source} </LifecycleConfiguration>"

        self._create_container_versioning(self.source)
        self._upload_expected_combine1()
        self._check_and_apply(self.source)


class TestLifecycleTransitionConflict(TestLifecycleConform):
    """
    Test two conflict rules Expiraton/Transtion and verify that events are sent one by
    predominant rule
    """

    def setUp(self):
        super(TestLifecycleTransitionConflict, self).setUp()
        self.versioning_enabled = True
        self.action1 = "Transition"
        self.action2 = "Transition"

        self.source = ""
        self.end_rule1 = """</And>
                    </Filter>
                    <Status>Enabled</Status>
                    <Transition>
                        <Days>1</Days>
                        <StorageClass>STANDARD_IA</StorageClass>
                    </Transition>
                </Rule>
            """
        self.end_rule2 = """</And>
                    </Filter>
                    <Status>Enabled</Status>
                    <Transition>
                        <Days>1</Days>
                        <StorageClass>ARCHIVE</StorageClass>
                    </Transition>
                </Rule>
            """
        self.rule1 = "rule1"
        self.rule2 = "rule2"
        self.rules = {
            self.rule1: {self.action1},
            self.rule2: {self.action2},
        }

        self._init_match_rules()

        self.not_to_match_versions = []
        self.expected_to_cycle[self.rule1] = {}
        self.expected_to_cycle[self.rule2] = {}

    def tearDown(self):
        super(TestLifecycleTransitionConflict, self).tearDown()

    def _upload_expected_combine1(self):
        # match only n non current versions per object
        for _ in range(self.number_not_match):
            name = self.prefix + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_short, random_length=5
                )
                self.not_to_match[self.rule1][self.action1].append(obj_meta)

        for _ in range(self.number_match):
            name = self.prefix + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_long, random_length=6
                )
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule1][self.action1].append(obj_meta)

        # nothing to match for rule2
        self.to_match[self.rule2][self.action2] = []

    def test_conflict_current(self):
        # ["prefix", "greater"]
        # match only 2 non current versions per object
        # As the rules conflit:check that  first transition sends events but
        # second transition doesn't
        self.source = """<LifecycleConfiguration>
                <Rule>
                    <ID>rule1</ID>
                    <Filter>
                        <And>"""
        val = self.conditions["prefix"]
        self.source = f"{self.source}<Prefix>{val}"
        self.source = f"{self.source}</Prefix>"
        greater = self.conditions["greater"]
        self.source = f"{self.source}<ObjectSizeGreaterThan>{greater}"
        self.source = f"{self.source}</ObjectSizeGreaterThan>"
        self.source = f"{self.source} {self.end_rule1 }"

        # Second Rule that conclicts
        self.source = (
            f"{self.source} "
            """
                <Rule>
                    <ID>rule2</ID>
                    <Filter>
                        <And>"""
        )

        self.source = f"{self.source}<Prefix>{val}"
        self.source = f"{self.source}</Prefix>"
        greater = self.conditions["greater"]
        self.source = f"{self.source}<ObjectSizeGreaterThan>{greater}"
        self.source = f"{self.source}</ObjectSizeGreaterThan>"
        self.source = f"{self.source} {self.end_rule2 }"
        self.source = f"{self.source} </LifecycleConfiguration>"

        self.expected_to_cycle[self.rule1][self.action1] = 1  # 1 current per object
        self.expected_to_cycle[self.rule2][self.action2] = 0
        self._create_container_versioning(self.source)
        self._upload_expected_combine1()
        self._check_and_apply(self.source)


class TestLifecycleAbortIncompleteMpu(TestLifecycleConform):
    """
    Tests for incomplete mpu parts, simulate an incomplete mpu and check
    for events
    """

    def setUp(self):
        super(TestLifecycleAbortIncompleteMpu, self).setUp()
        self.versioning_enabled = False

        self.source = ""
        self.action1 = "AbortIncompleteMultipartUpload"

        self.rule_id = "rule1"
        self.source = (
            """<LifecycleConfiguration>
                <Rule><ID>"""
            f"{self.rule_id}"
            """</ID>
                    <Filter>
                        <Prefix></Prefix>
                    </Filter>
                    <Status>Enabled</Status>
                    <AbortIncompleteMultipartUpload>
                        <DaysAfterInitiation>7</DaysAfterInitiation>
                    </AbortIncompleteMultipartUpload>
                </Rule>
            </LifecycleConfiguration>"""
        )

        self.rule1 = "rule1"
        self.rules = {
            self.rule1: {self.action1},
        }

        self._init_match_rules()

        self.not_to_match_versions = []

    def _upload_incomplete_mpu(self):
        # match only n non current versions per object
        for _ in range(self.number_not_match):
            name = self.prefix + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_short, random_length=5
                )
                self.not_to_match[self.rule1][self.action1].append(obj_meta)
            not_prefix = "x/"
            name = not_prefix + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_short, random_length=5
                )
                self.not_to_match[self.rule1][self.action1].append(obj_meta)
        for _ in range(self.number_match):
            name = self.prefix + random_str(5)
            incomplete_mpu_property = {"x-object-sysmeta-s3api-has-content-type": "no"}
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_long, random_length=6
                )
                self.api.object_set_properties(
                    self.account,
                    self.container + "+segments",
                    name,
                    incomplete_mpu_property,
                )
                self.to_match[self.rule1][self.action1].append(obj_meta)

    def _create_containers_with_mpu(self, lifecycle_source):
        seg_container = self.container + "+segments"
        self.api.container_create(
            self.account,
            self.container,
            properties={LIFECYCLE_PROPERTY_KEY: lifecycle_source},
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        self.api.container_create(
            self.account,
            seg_container,
        )
        if self.versioning_enabled:
            seg_helper = Helper(self.api, self.account, seg_container)
            seg_helper.enable_versioning()

    def _get_action_parameters(self, act):
        days = None
        date = None
        delete_marker = None
        if type(act) is AbortIncompleteMultipartUpload:
            if type(act.filter) is DaysAfterInitiationActionFilter:
                days = act.filter.days
            else:
                raise ValueError(
                    "Unsopported filter %s for action %s", type(act.filter), act
                )
        else:
            raise ValueError("Unsopported action %s test in this class ", act)
        return [days, date, delete_marker]

    def _upload_something(
        self, prefix="", random_length=4, data=None, name=None, size=None, **kwargs
    ):
        seg_container = self.container + "+segments"
        name = name or (prefix + random_str(random_length))
        data = data or (random_str(8))
        self.api.object_create(
            self.account, seg_container, obj_name=name, data=data, **kwargs
        )
        self.__class__.CONTAINERS.add(seg_container)
        obj_meta = self.api.object_show(self.account, seg_container, name)
        obj_meta["container"] = seg_container
        if size is not None:
            obj_meta["size"] = size
        return obj_meta

    # Redefine private methods
    def _exec_rules_via_sql_query(self, source):
        lc = ContainerLifecycle(self.api, self.account, self.container)
        lc.load_xml(source)
        count_rules = 0
        count_actions = 0
        for el in lc.rules:
            rule_id = el.id
            for act in el.actions:
                # Force expiration for test
                days_in_sec = None
                base_sql_query = None
                queries = {}
                action = ""
                days = None
                if type(act) is AbortIncompleteMultipartUpload:
                    days = act.filter.days
                    action = "AbortIncompleteMultipartUpload"
                else:
                    print("Unsupported action type", type(act))
                    return

                days, _, _ = self._get_action_parameters(act)

                # For tests(days_in_sec set to 0)
                # days_in_sec = 86400 * days_in_sec
                if days is not None:
                    days_in_sec = 0 * days
                    base_sql_query = el.filter.abort_incomplete_query(days_in_sec)
                    queries["base"] = base_sql_query

                self._check_query_events(
                    queries,
                    action,
                    {},
                    None,
                    None,
                    None,
                    rule_id,
                )

                count_actions += 1
                self.assertEqual(len(self.to_match[rule_id][action]), 0)
        count_rules += 1

    def _check_query_events(
        self,
        queries,
        action,
        view_queries,
        newer_non_current_versions,
        policy,
        last_rule_action,
        rule_id,
    ):
        for key_query, val_query in queries.items():
            offset = 0
            while True:
                sql_query = val_query
                sql_query = f"{sql_query} limit {self.batch_size} " f" offset {offset} "
                kwargs = {}
                params = {"cid": self.cid, "service_id": self.peer_to_use}
                data = {}
                data["action"] = action
                data["suffix"] = "lifecycle"
                data["query"] = sql_query
                data["batch_size"] = self.batch_size
                data["rule_id"] = rule_id

                reqid = request_id()
                resp, body = self.proxy_client._request(
                    "POST",
                    "/container/lifecycle/apply",
                    params=params,
                    reqid=reqid,
                    json=data,
                    **kwargs,
                )
                self.assertEqual(resp.status, 204)
                count = int(resp.getheader("x-oio-count", 0))
                offset += count
                count_events = 0

                exptected_events = min(
                    len(self.to_match[rule_id][action]), self.batch_size
                )
                while count > 0 and count_events < exptected_events:
                    event = self.wait_for_kafka_event(
                        types=(EventTypes.LIFECYCLE_ACTION,)
                    )
                    self.assertIsNotNone(event)
                    self.assertEqual(event.event_type, "storage.lifecycle.action")
                    self.assertEqual(event.data["account"], self.account)
                    self.assertEqual(
                        event.data["container"], self.container + "+segments"
                    )

                    elements_to_match = (
                        self.to_match[rule_id][action]
                        if key_query == "base"
                        else self.to_match_markers[rule_id][action]
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
                        for elem in self.not_to_match[rule_id][action]
                        if event.data["object"]
                        and event.data["version"] in elem.values()
                    ]
                    self.assertEqual(any(list_of_bool), False)
                    elements_to_match.remove(elem_to_remove)

                    self.assertEqual(event.data["action"], action)
                    count_events += 1
                if count == 0:
                    break

    # List of tests
    def test_abort_all(self):
        self._create_containers_with_mpu(self.source)
        self._upload_incomplete_mpu()
        self._check_and_apply(self.source, container=self.container + "+segments")

    def test_abort_with_prefix(self):
        self.prefix = "a/"
        self.source = (
            """<LifecycleConfiguration>
                <Rule>
                    <ID>"""
            f"{self.rule_id}"
            """</ID>
            <Filter>
            <Prefix>"""
            f"{self.prefix}"
            """</Prefix>
            </Filter>
                <Status>Enabled</Status>
                    <AbortIncompleteMultipartUpload>
                        <DaysAfterInitiation>7</DaysAfterInitiation>
                    </AbortIncompleteMultipartUpload>
                </Rule>
            </LifecycleConfiguration>"""
        )
        self._create_containers_with_mpu(self.source)
        self._upload_incomplete_mpu()
        self._check_and_apply(self.source, container=self.container + "+segments")

    def tearDown(self):
        super(TestLifecycleConform, self).tearDown()
