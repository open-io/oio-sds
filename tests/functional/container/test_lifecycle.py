# Copyright (C) 2017 OpenIO SAS, as part of OpenIO SDS
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

import time
from oio import ObjectStorageApi
from oio.container.lifecycle import ContainerLifecycle, LIFECYCLE_PROPERTY_KEY
from tests.utils import BaseTestCase, random_str


class TestContainerLifecycle(BaseTestCase):

    CONTAINERS = set()

    def setUp(self):
        super(TestContainerLifecycle, self).setUp()
        self.api = ObjectStorageApi(self.ns)
        self.account = "test_lifecycle"
        self.container = "lifecycle-" + random_str(4)
        self.lifecycle = ContainerLifecycle(
            self.api, self.account, self.container)

    @staticmethod
    def _time_to_date(timestamp=None):
        if timestamp is None:
            timestamp = time.time()
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(timestamp))

    def _upload_something(self, prefix="", path=None, **kwargs):
        path = path or (prefix + random_str(8))
        self.api.object_create(self.account, self.container,
                               obj_name=path, data=path, **kwargs)
        self.__class__.CONTAINERS.add(self.container)
        return self.api.object_show(self.account, self.container, path)

    def _enable_versioning(self):
        if not self.api.container_create(
                self.account, self.container,
                system={'sys.m2.policy.version': '-1'}):
            self.api.container_set_properties(
                self.account, self.container,
                system={'sys.policy.version': '-1'})

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
        self.api.container_create(self.account, self.container,
                                  properties=props)
        self.lifecycle.load()
        self.assertIn('rule1', self.lifecycle._rules)
        rule = self.lifecycle._rules['rule1']
        self.assertEqual('rule1', rule.id)
        self.assertTrue(rule.enabled)
        self.assertIsNotNone(rule.filter)
        self.assertIn('Expiration', rule.actions)
        self.assertIn('Transition', rule.actions)
        self.assertIn('NoncurrentVersionExpiration', rule.actions)
        self.assertIn('NoncurrentVersionTransition', rule.actions)

    def test_save_to_container_property(self):
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
        self.api.container_create(self.account, self.container)
        self.lifecycle.load_xml(source)
        self.lifecycle.save()
        props = self.api.container_get_properties(
            self.account, self.container)['properties']
        self.assertIn(LIFECYCLE_PROPERTY_KEY, props)
        self.assertEqual(source, props[LIFECYCLE_PROPERTY_KEY])

    def test_immediate_expiration_by_date(self):
        obj_meta = self._upload_something()
        self.lifecycle.load_xml("""
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
        """ % self._time_to_date(time.time() - 86400))
        self.lifecycle.apply(obj_meta)
        container_descr = self.api.object_list(self.account, self.container)
        obj_names = [obj['name'] for obj in container_descr['objects']]
        self.assertNotIn(obj_meta['name'], obj_names)

    def test_future_expiration_by_date(self):
        obj_meta = self._upload_something()
        self.lifecycle.load_xml("""
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
        """ % self._time_to_date(time.time() + 86400))
        self.lifecycle.apply(obj_meta)
        container_descr = self.api.object_list(self.account, self.container)
        obj_names = [obj['name'] for obj in container_descr['objects']]
        self.assertIn(obj_meta['name'], obj_names)
        self.api.object_delete(self.account, self.container, obj_meta['name'])

    def test_immediate_expiration_by_delay(self):
        obj_meta = self._upload_something()
        self.lifecycle.load_xml("""
        <LifecycleConfiguration>
            <Rule>
                <Filter>
                </Filter>
                <Expiration>
                    <Days>0</Days>
                </Expiration>
                <Status>enabled</Status>
            </Rule>
        </LifecycleConfiguration>
        """)
        self.lifecycle.apply(obj_meta)
        container_descr = self.api.object_list(self.account, self.container)
        obj_names = [obj['name'] for obj in container_descr['objects']]
        self.assertNotIn(obj_meta['name'], obj_names)

    def test_future_expiration_by_delay(self):
        obj_meta = self._upload_something()
        self.lifecycle.load_xml("""
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
        """)
        self.lifecycle.apply(obj_meta)
        container_descr = self.api.object_list(self.account, self.container)
        obj_names = [obj['name'] for obj in container_descr['objects']]
        self.assertIn(obj_meta['name'], obj_names)
        self.api.object_delete(self.account, self.container, obj_meta['name'])

    def test_immediate_expiration_filtered_by_prefix(self):
        obj_meta = self._upload_something(prefix="photos/")
        obj_meta2 = self._upload_something(prefix="documents/")
        self.lifecycle.load_xml("""
        <LifecycleConfiguration>
            <Rule>
                <Filter>
                    <Prefix>documents/</Prefix>
                </Filter>
                <Expiration>
                    <Days>0</Days>
                </Expiration>
                <Status>enabled</Status>
            </Rule>
        </LifecycleConfiguration>
        """)
        self.lifecycle.apply(obj_meta)
        self.lifecycle.apply(obj_meta2)
        container_descr = self.api.object_list(self.account, self.container)
        obj_names = [obj['name'] for obj in container_descr['objects']]
        self.assertIn(obj_meta['name'], obj_names)
        self.assertNotIn(obj_meta2['name'], obj_names)
        self.api.object_delete(self.account, self.container, obj_meta['name'])

    def test_immediate_expiration_filtered_by_tag(self):
        obj_meta = self._upload_something()
        obj_meta2 = self._upload_something(properties={'status': 'deprecated'})
        self.lifecycle.load_xml("""
        <LifecycleConfiguration>
            <Rule>
                <Filter>
                    <Tag>
                        <Key>status</Key>
                        <Value>deprecated</Value>
                    </Tag>
                </Filter>
                <Expiration>
                    <Days>0</Days>
                </Expiration>
                <Status>enabled</Status>
            </Rule>
        </LifecycleConfiguration>
        """)
        self.lifecycle.apply(obj_meta)
        self.lifecycle.apply(obj_meta2)
        container_descr = self.api.object_list(self.account, self.container)
        obj_names = [obj['name'] for obj in container_descr['objects']]
        self.assertIn(obj_meta['name'], obj_names)
        self.assertNotIn(obj_meta2['name'], obj_names)
        self.api.object_delete(self.account, self.container, obj_meta['name'])

    def test_immediate_transition_filtered_by_tag(self):
        obj_meta = self._upload_something(policy='SINGLE')
        obj_meta2 = self._upload_something(policy='SINGLE',
                                           properties={'status': 'deprecated'})
        self.lifecycle.load_xml("""
        <LifecycleConfiguration>
            <Rule>
                <Filter>
                    <Tag>
                        <Key>status</Key>
                        <Value>deprecated</Value>
                    </Tag>
                </Filter>
                <Transition>
                    <Days>0</Days>
                    <StorageClass>THREECOPIES</StorageClass>
                </Transition>
                <Status>enabled</Status>
            </Rule>
        </LifecycleConfiguration>
        """)
        self.lifecycle.apply(obj_meta)
        self.lifecycle.apply(obj_meta2)
        obj_meta_after = self.api.object_show(
            self.account, self.container, obj_meta['name'])
        obj_meta_after2 = self.api.object_show(
            self.account, self.container, obj_meta2['name'])
        self.assertEqual('SINGLE', obj_meta_after['policy'])
        self.assertEqual('THREECOPIES', obj_meta_after2['policy'])
        self.api.object_delete(self.account, self.container, obj_meta['name'])
        self.api.object_delete(self.account, self.container, obj_meta2['name'])

    def test_immediate_noncurrent_expiration(self):
        self._enable_versioning()
        obj_meta = self._upload_something()
        obj_meta_v2 = self._upload_something(path=obj_meta['name'])
        self.lifecycle.load_xml("""
        <LifecycleConfiguration>
            <Rule>
                <Filter></Filter>
                <NoncurrentVersionExpiration>
                    <NoncurrentDays>0</NoncurrentDays>
                </NoncurrentVersionExpiration>
                <Status>enabled</Status>
            </Rule>
        </LifecycleConfiguration>
        """)
        self.lifecycle.apply(obj_meta)
        self.lifecycle.apply(obj_meta_v2)
        container_descr = self.api.object_list(self.account, self.container,
                                               versions=True)
        obj_names = [obj['name'] for obj in container_descr['objects']]
        self.assertIn(obj_meta['name'], obj_names)
        self.assertEqual(1, len(obj_names))
        self.api.object_delete(self.account, self.container, obj_meta['name'])
