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

from mock import patch

from oio.container.lifecycle import (
    ContainerLifecycle,
    LIFECYCLE_PROPERTY_KEY,
    TAGGING_KEY,
    Expiration,
    Transition,
    NoncurrentVersionExpiration,
    NoncurrentVersionTransition,
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


def consume(generator):
    """Consume a generator without doing anything with the results"""
    for _ in generator:
        pass


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

    def tearDown(self):
        self.api.container_delete(self.account, self.container, force=True)
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
        self.assertEqual(60, expiration.filter.days)
        transition = rule.actions[3]
        self.assertEqual(NoncurrentVersionTransition, type(transition))
        self.assertEqual(1, transition.filter.days)
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
        self._enable_versioning()
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
        self._enable_versioning()
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
                        <NoncurrentCount>2</NoncurrentCount>
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
                        <NoncurrentCount>2</NoncurrentCount>
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

        results = [x for x in self.lifecycle.execute()]
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


class TestLifecycleConformExpiration(CliTestCase, BaseClassLifeCycle):
    def setUp(self):
        super(TestLifecycleConformExpiration, self).setUp()
        self.batch_size = 2
        self.to_match = []
        self.not_to_match = []
        self.proxy_client = ProxyClient(
            self.conf, pool_manager=self.api.container.pool_manager, logger=self.logger
        )
        admin_args = {}
        admin_args["force_master"] = False
        self.admin_client = AdminClient(self.conf, logger=self.logger, **admin_args)

        self.prefix = "doc"
        self.data_short = "test"
        self.data_middle = "test some data"
        self.data_long = "some long data oustide max conditions"

        self.action = "Expiration"

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

    def tearDown(self):
        super(TestLifecycleConformExpiration, self).tearDown()

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
        json = {"from": self.peer_to_use, "to": self.peer_to_use, "local": 1}

        resp, body = self.proxy_client._request(
            "POST", "/admin/copy", params=params, json=json
        )
        self.assertEqual(resp.status, 204)

    def _check_and_apply(self, source):
        self.assertIsNot(len(self.to_match), 0)
        self._copy_db()
        time.sleep(1)
        self._exec_rules_via_sql_query(source)

    def _exec_rules_via_sql_query(self, source):
        lc = ContainerLifecycle(self.api, self.account, self.container)
        lc.load_xml(source)
        for el in lc.rules:
            for act in el.actions:
                # Force expiration for test
                days_in_sec = 0
                base_sql_query = el.filter.to_sql_query(days_in_sec)

                offset = 0
                action = self.action
                while True:
                    sql_query = (
                        f"{base_sql_query} limit {self.batch_size} " f" offset {offset}"
                    )
                    kwargs = {}
                    params = {"cid": self.cid, "service_id": self.peer_to_use}

                    data = {}

                    data["action"] = action
                    data["query"] = sql_query
                    data["suffix"] = "lifecycle"
                    reqid = request_id()
                    resp, body = self.proxy_client._request(
                        "POST",
                        "/container/lifecycle/prepare",
                        params=params,
                        reqid=reqid,
                        json=data,
                        **kwargs,
                    )
                    count = int(resp.getheader("x-oio-count"))
                    offset += count

                    for i in range(count):
                        event = self.wait_for_kafka_event(
                            reqid=reqid, types=(EventTypes.LIFECYCLE_ACTION,)
                        )
                        self.assertIsNotNone(event)
                        self.assertEqual(event.event_type, "storage.lifecycle.action")
                        self.assertEqual(event.data["account"], self.account)
                        self.assertEqual(event.data["container"], self.container)
                        self.assertIn(event.data["object"], self.to_match)
                        self.assertNotIn(event.data["object"], self.not_to_match)
                        self.to_match.remove(event.data["object"])
                        self.assertEqual(event.data["action"], action)

                    if count == 0:
                        break
            self.assertEqual(len(self.to_match), 0)

    def test_apply_prefix(self):
        source = """
            <LifecycleConfiguration>
                <Rule>
                    <ID>rule1</ID>
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
        self.api.container_create(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        for _ in range(self.number_match):
            obj_meta = self._upload_something(prefix="a/")
            self.to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(prefix="b/")
            self.not_to_match.append(obj_meta["name"])

        self._check_and_apply(source)

    def test_apply_prefix_and_greater(self):
        data_short = "some data"
        data_long = "some data and more"
        middle = (len(data_short) + len(data_long)) // 2

        source = (
            """<LifecycleConfiguration>
                <Rule>
                    <ID>rule1</ID>
                    <Filter>
                        <And>
                        <Prefix>a/</Prefix>
                        <ObjectSizeGreaterThan>"""
            f"{middle}"
            """</ObjectSizeGreaterThan>
                        </And>
                    </Filter>
                    <Status>Enabled</Status>
                    <Expiration>
                        <Days>10</Days>
                    </Expiration>
                </Rule>
            </LifecycleConfiguration>"""
        )

        self.api.container_create(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        for _ in range(self.number_match):
            obj_meta = self._upload_something(prefix="a/", data=data_long)
            self.to_match.append(obj_meta["name"])

        for _ in range(self.number_match):
            obj_meta = self._upload_something(prefix="a/", data=data_short)
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(prefix="b/", data=data_short)
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(prefix="b/", data=data_long)
            self.not_to_match.append(obj_meta["name"])

        self._check_and_apply(source)

    def test_apply_prefix_and_lesser(self):
        data_short = "some data"
        data_long = "some data and more"
        middle = (len(data_short) + len(data_long)) // 2

        source = (
            """<LifecycleConfiguration>
                <Rule>
                    <ID>rule1</ID>
                    <Filter>
                        <And>
                            <Prefix>a/</Prefix>
                            <ObjectSizeLessThan>"""
            f"{middle}"
            """
                            </ObjectSizeLessThan>
                        </And>
                    </Filter>
                    <Status>Enabled</Status>
                    <Expiration>
                        <Days>10</Days>
                    </Expiration>
                </Rule>
            </LifecycleConfiguration>"""
        )

        self.api.container_create(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        for _ in range(self.number_match):
            obj_meta = self._upload_something(prefix="a/", data=data_long)
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_match):
            obj_meta = self._upload_something(prefix="a/", data=data_short)
            self.to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(prefix="b/", data=data_short)
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(prefix="b/", data=data_long)
            self.not_to_match.append(obj_meta["name"])

        self._check_and_apply(source)

    def test_combine1(self):
        # ["prefix', 'greater"]
        source = """<LifecycleConfiguration>
                <Rule>
                    <ID>rule1</ID>
                    <Filter>
                        <And>"""
        val = self.conditions["prefix"]
        source = f"{source}<Prefix>{val}"
        source = f"{source}</Prefix>"
        greater = self.conditions["greater"]
        source = f"{source}<ObjectSizeGreaterThan>{greater}"
        source = f"{source}</ObjectSizeGreaterThan>"
        source = f"{source} {self.end_source }"

        self.api.container_create(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix, data=self.data_short, random_length=5
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_match):
            obj_meta = self._upload_something(
                prefix=self.prefix, data=self.data_long, random_length=6
            )
            self.to_match.append(obj_meta["name"])

        self._check_and_apply(source)

    def test_combine2(self):
        # ["prefix", "lesser"]
        source = """<LifecycleConfiguration>
                <Rule>
                    <ID>rule1</ID>
                    <Filter>
                        <And>"""
        val = self.conditions["prefix"]
        source = f"{source}<Prefix>{val}"
        source = f"{source}</Prefix>"

        lesser = self.conditions["lesser"]
        source = f"{source}<ObjectSizeLessThan>{lesser}"
        source = f"{source}</ObjectSizeLessThan>"
        source = f"{source} {self.end_source }"

        self.api.container_create(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        for _ in range(self.number_match):
            obj_meta = self._upload_something(
                prefix=self.prefix, data=self.data_middle, random_length=4
            )
            self.to_match.append(obj_meta["name"])

        for _ in range(self.number_match):
            obj_meta = self._upload_something(
                prefix=self.prefix, data=self.data_short, random_length=5
            )
            self.to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix, data=self.data_long, random_length=6
            )
            self.not_to_match.append(obj_meta["name"])

        self._check_and_apply(source)

    def test_combine3(self):
        # ["prefix", "tag1"]
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

        self.api.container_create(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        for _ in range(self.number_match):
            obj_meta = self._upload_something(
                prefix=self.prefix,
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix,
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match.append(obj_meta["name"])

        self._check_and_apply(source)

    def test_combine4(self):
        # [prefix, tag1, tag2]
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

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        source = f"{source} {self.end_source }"

        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_create(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        for _ in range(self.number_match):
            obj_meta = self._upload_something(
                prefix=self.prefix,
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix,
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match.append(obj_meta["name"])

        self._check_and_apply(source)

    def test_combine5(self):
        # ["prefix", "tag1", "tag2", "tag3"]
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

        self.api.container_create(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        for _ in range(self.number_match):
            obj_meta = self._upload_something(
                prefix=self.prefix,
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix,
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match.append(obj_meta["name"])

        self._check_and_apply(source)

    def test_combine6(self):
        # ["prefix", "tag2", "tag3"]
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

        key = list(self.conditions["tag3"].keys())[0]
        val = self.conditions["tag3"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        source = f"{source} {self.end_source }"

        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_create(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        for _ in range(self.number_match):
            obj_meta = self._upload_something(
                prefix=self.prefix,
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix,
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match.append(obj_meta["name"])

        self._check_and_apply(source)

    def test_combine7(self):
        # ["prefix", "greater", "lesser", "tag1"])
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

        self.api.container_create(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(5),
                data=self.data_middle,
                random_length=4,
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(5),
                data=self.data_short,
                random_length=5,
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(6),
                data=self.data_long,
                random_length=6,
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(5),
                data=self.data_middle,
                random_length=4,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(5),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(5),
                data=self.data_middle,
                random_length=4,
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(5),
                data=self.data_short,
                random_length=5,
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(6),
                data=self.data_long,
                random_length=6,
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(5),
                data=self.data_middle,
                random_length=4,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(5),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix + random_str(5),
                data=self.data_middle,
                random_length=4,
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix + random_str(5),
                data=self.data_short,
                random_length=5,
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix + random_str(6), data=self.data_long, random_length=6
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_match):
            obj_meta = self._upload_something(
                prefix=self.prefix + random_str(5),
                data=self.data_middle,
                random_length=4,
                properties={TAGGING_KEY: tag_set},
            )
            self.to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix + random_str(5),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix + random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta["name"])

        self._check_and_apply(source)

    def test_combine8(self):
        # ["greater', 'lesser"]
        source = """<LifecycleConfiguration>
                <Rule>
                    <ID>rule1</ID>
                    <Filter>
                        <And>"""

        greater = self.conditions["greater"]
        source = f"{source}<ObjectSizeGreaterThan>{greater}"
        source = f"{source}</ObjectSizeGreaterThan>"

        lesser = self.conditions["lesser"]
        source = f"{source}<ObjectSizeLessThan>{lesser}"
        source = f"{source}</ObjectSizeLessThan>"
        source = f"{source} {self.end_source }"

        self.api.container_create(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        for _ in range(self.number_match):
            obj_meta = self._upload_something(
                prefix=random_str(5), data=self.data_middle, random_length=4
            )
            self.to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5), data=self.data_short, random_length=5
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(6), data=self.data_long, random_length=6
            )
            self.not_to_match.append(obj_meta["name"])

        self._check_and_apply(source)

    def test_combine9(self):
        # ["greater", "lesser", "tag1"])
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

        self.api.container_create(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        for _ in range(self.number_match):
            obj_meta = self._upload_something(
                prefix=random_str(5), data=self.data_middle, random_length=4
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5), data=self.data_short, random_length=5
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(6), data=self.data_long, random_length=6
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_match):
            obj_meta = self._upload_something(
                prefix=random_str(5),
                data=self.data_middle,
                random_length=4,
                properties={TAGGING_KEY: tag_set},
            )
            self.to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta["name"])

        self._check_and_apply(source)

    def test_combine10(self):
        # ["greater", "tag2"]
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

        self.api.container_create(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_match):
            obj_meta = self._upload_something(
                prefix=random_str(5),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.to_match.append(obj_meta["name"])

        self._check_and_apply(source)

    def test_combine11(self):
        # ["greater", "tag1", "tag2"]
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

        self.api.container_create(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_match):
            obj_meta = self._upload_something(
                prefix=random_str(5),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.to_match.append(obj_meta["name"])

        self._check_and_apply(source)

    def test_combine12(self):
        # ["greater", "tag1", "tag2", "tag3"]
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

        self.api.container_create(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_match):
            obj_meta = self._upload_something(
                prefix=random_str(5),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.to_match.append(obj_meta["name"])

        self._check_and_apply(source)

    def test_combine13(self):
        # ["greater", "tag2"', "tag3"]
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

        key = list(self.conditions["tag3"].keys())[0]
        val = self.conditions["tag3"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"
        source = f"{source} {self.end_source }"

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_create(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_match):
            obj_meta = self._upload_something(
                prefix=random_str(5),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.to_match.append(obj_meta["name"])

        self._check_and_apply(source)

    def test_combine14(self):
        # ["lesser", "tag1"]
        source = """<LifecycleConfiguration>
                <Rule>
                    <ID>rule1</ID>
                    <Filter>
                        <And>"""
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        lesser = self.conditions["lesser"]
        source = f"{source}<ObjectSizeLessThan>{lesser}"
        source = f"{source}</ObjectSizeLessThan>"

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]
        source = f"{source}<Tag><Key>{key}</Key><Value>{val}"
        source = f"{source}</Value></Tag>"
        source = f"{source} {self.end_source }"

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_create(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )

        for _ in range(self.number_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_middle,
                random_length=4,
                properties={TAGGING_KEY: tag_set},
            )
            self.to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(7),
                data=self.data_middle,
                random_length=6,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match.append(obj_meta["name"])

        self._check_and_apply(source)

    def test_combine15(self):
        # ["lesser", "tag1", "tag2"]
        source = """<LifecycleConfiguration>
                <Rule>
                    <ID>rule1</ID>
                    <Filter>
                        <And>"""
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        lesser = self.conditions["lesser"]
        source = f"{source}<ObjectSizeLessThan>{lesser}"
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

        self.api.container_create(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )

        for _ in range(self.number_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_middle,
                random_length=4,
                properties={TAGGING_KEY: tag_set},
            )
            self.to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(7),
                data=self.data_middle,
                random_length=6,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match.append(obj_meta["name"])

        self._check_and_apply(source)

    def test_combine16(self):
        # ["lesser", "tag1", "tag2", "tag3"]
        source = """<LifecycleConfiguration>
                <Rule>
                    <ID>rule1</ID>
                    <Filter>
                        <And>"""
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        lesser = self.conditions["lesser"]
        source = f"{source}<ObjectSizeLessThan>{lesser}"
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

        self.api.container_create(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        for _ in range(self.number_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_middle,
                random_length=4,
                properties={TAGGING_KEY: tag_set},
            )
            self.to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(7),
                data=self.data_middle,
                random_length=6,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match.append(obj_meta["name"])

        self._check_and_apply(source)

    def test_combine17(self):
        # ["lesser", "tag2", "tag3"]
        source = """<LifecycleConfiguration>
                <Rule>
                    <ID>rule1</ID>
                    <Filter>
                        <And>"""
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        lesser = self.conditions["lesser"]
        source = f"{source}<ObjectSizeLessThan>{lesser}"
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

        self.api.container_create(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )

        for _ in range(self.number_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_middle,
                random_length=4,
                properties={TAGGING_KEY: tag_set},
            )
            self.to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(7),
                data=self.data_middle,
                random_length=6,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match.append(obj_meta["name"])

        self._check_and_apply(source)

    def test_combine18(self):
        # ["tag1", "tag2"]
        source = """<LifecycleConfiguration>
                <Rule>
                    <ID>rule1</ID>
                    <Filter>
                        <And>"""
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

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

        self.api.container_create(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        for _ in range(self.number_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5),
                data=self.data_short,
                random_length=6,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match.append(obj_meta["name"])
            self.assertIsNot(len(self.to_match), 0)

        self._check_and_apply(source)

    def test_combine19(self):
        # ["tag1", "tag2", "tag3"])
        source = """<LifecycleConfiguration>
                <Rule>
                    <ID>rule1</ID>
                    <Filter>
                        <And>"""
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

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

        self.api.container_create(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )

        for _ in range(self.number_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.to_match.append(obj_meta["name"])

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5),
                data=self.data_short,
                random_length=6,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match.append(obj_meta["name"])

        self._check_and_apply(source)


class TestLifecycleConformTransition(TestLifecycleConformExpiration):
    def setUp(self):
        super(TestLifecycleConformTransition, self).setUp()
        self.end_source = """</And>
                        </Filter>
                        <Status>Enabled</Status>
                        <Transition>
                            <Days>10</Days>
                            <StorageClass>STANDARD_IA</StorageClass>
                        </Transition>
                    </Rule>
                </LifecycleConfiguration>"""
