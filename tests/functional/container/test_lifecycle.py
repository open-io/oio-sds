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

from mock import patch

from oio import ObjectStorageApi
from oio.container.lifecycle import ContainerLifecycle, \
    LIFECYCLE_PROPERTY_KEY, TAGGING_KEY
from oio.common.exceptions import NoSuchObject
from tests.utils import BaseTestCase, random_str


def consume(generator):
    """Consume a generator without doing anything with the results"""
    for _ in generator:
        pass


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
        self.assertEqual(1, len(self.lifecycle._rules))
        rule = self.lifecycle._rules.get('rule1')
        self.assertIsNotNone(rule)
        self.assertEqual('rule1', rule.id)
        self.assertIsNotNone(rule.filter)
        self.assertEqual('documents/', rule.filter.prefix)
        self.assertDictEqual({'key1': 'value1', 'key2': 'value2'},
                             rule.filter.tags)
        self.assertTrue(rule.enabled)
        transition = rule.actions.get('Transition')
        self.assertIsNotNone(transition)
        self.assertEqual(1, transition.filter.days)
        self.assertEqual('THREECOPIES', transition.policy)
        expiration = rule.actions.get('Expiration')
        self.assertIsNotNone(expiration)
        self.assertEqual(60, expiration.filter.days)
        transition = rule.actions.get('NoncurrentVersionTransition')
        self.assertIsNotNone(transition)
        self.assertEqual(1, transition.filter.days)
        self.assertEqual('THREECOPIES', transition.policy)
        expiration = rule.actions.get('NoncurrentVersionExpiration')
        self.assertIsNotNone(expiration)
        self.assertEqual(60, expiration.filter.days)

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
        results = [x for x in self.lifecycle.apply(obj_meta)]
        self.assertEqual(1, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual('Deleted', status)
        self.assertRaises(NoSuchObject, self.api.object_show,
                          self.account, self.container, obj_meta['name'])

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
        results = [x for x in self.lifecycle.apply(obj_meta)]
        self.assertEqual(1, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual('Kept', status)
        self.api.object_show(self.account, self.container, obj_meta['name'])
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
        results = [x for x in self.lifecycle.apply(obj_meta)]
        self.assertEqual(1, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual('Deleted', status)
        self.assertRaises(NoSuchObject, self.api.object_show,
                          self.account, self.container, obj_meta['name'])

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
        results = [x for x in self.lifecycle.apply(obj_meta)]
        self.assertEqual(1, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual('Kept', status)
        self.api.object_show(self.account, self.container, obj_meta['name'])
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
        results = [x for x in self.lifecycle.apply(obj_meta)]
        self.assertEqual(1, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual('n/a', status)

        results = [x for x in self.lifecycle.apply(obj_meta2)]
        self.assertEqual(1, len(results))
        obj_meta2_copy, _, _, status = results[0]
        self.assertEqual(obj_meta2, obj_meta2_copy)
        self.assertEqual('Deleted', status)

        self.api.object_show(self.account, self.container, obj_meta['name'])
        self.assertRaises(NoSuchObject, self.api.object_show,
                          self.account, self.container, obj_meta2['name'])
        self.api.object_delete(self.account, self.container, obj_meta['name'])

    def test_immediate_expiration_filtered_by_tag(self):
        obj_meta = self._upload_something()
        obj_meta2 = self._upload_something(
            properties={TAGGING_KEY: """
            <Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <TagSet>
                    <Tag>
                        <Key>status</Key>
                        <Value>deprecated</Value>
                    </Tag>
                </TagSet>
            </Tagging>
            """})
        obj_meta3 = self._upload_something(
            properties={TAGGING_KEY: """
            <Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <TagSet>
                    <Tag>
                        <Key>status</Key>
                        <Value>approved</Value>
                    </Tag>
                </TagSet>
            </Tagging>
            """})
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
        results = [x for x in self.lifecycle.apply(obj_meta)]
        self.assertEqual(1, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual('n/a', status)

        results = [x for x in self.lifecycle.apply(obj_meta2)]
        self.assertEqual(1, len(results))
        obj_meta2_copy, _, _, status = results[0]
        self.assertEqual(obj_meta2, obj_meta2_copy)
        self.assertEqual('Deleted', status)

        results = [x for x in self.lifecycle.apply(obj_meta3)]
        self.assertEqual(1, len(results))
        obj_meta3_copy, _, _, status = results[0]
        self.assertEqual(obj_meta3, obj_meta3_copy)
        self.assertEqual('n/a', status)

        self.api.object_show(self.account, self.container, obj_meta['name'])
        self.assertRaises(NoSuchObject, self.api.object_show,
                          self.account, self.container, obj_meta2['name'])
        self.api.object_show(self.account, self.container, obj_meta3['name'])
        self.api.object_delete(self.account, self.container, obj_meta['name'])
        self.api.object_delete(self.account, self.container, obj_meta3['name'])

    def test_immediate_transition_filtered_by_tag(self):
        obj_meta = self._upload_something(policy='SINGLE')
        obj_meta2 = self._upload_something(
            policy='SINGLE', properties={TAGGING_KEY: """
            <Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <TagSet>
                    <Tag>
                        <Key>status</Key>
                        <Value>deprecated</Value>
                    </Tag>
                </TagSet>
            </Tagging>
            """})
        obj_meta3 = self._upload_something(
            policy='SINGLE', properties={TAGGING_KEY: """
            <Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <TagSet>
                    <Tag>
                        <Key>status</Key>
                        <Value>approved</Value>
                    </Tag>
                </TagSet>
            </Tagging>
            """})
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
        results = [x for x in self.lifecycle.apply(obj_meta)]
        self.assertEqual(1, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual('n/a', status)

        results = [x for x in self.lifecycle.apply(obj_meta2)]
        self.assertEqual(1, len(results))
        obj_meta2_copy, _, _, status = results[0]
        self.assertEqual(obj_meta2, obj_meta2_copy)
        self.assertEqual('Policy changed to THREECOPIES', status)

        results = [x for x in self.lifecycle.apply(obj_meta3)]
        self.assertEqual(1, len(results))
        obj_meta3_copy, _, _, status = results[0]
        self.assertEqual(obj_meta3, obj_meta3_copy)
        self.assertEqual('n/a', status)

        obj_meta_after, chunks = self.api.object_locate(
            self.account, self.container, obj_meta['name'])
        self.assertEqual('SINGLE', obj_meta_after['policy'])
        self.assertEqual(1, len(chunks))
        obj_meta2_after, chunks2 = self.api.object_locate(
            self.account, self.container, obj_meta2['name'])
        self.assertEqual('THREECOPIES', obj_meta2_after['policy'])
        self.assertEqual(3, len(chunks2))
        obj_meta3_after, chunks3 = self.api.object_locate(
            self.account, self.container, obj_meta3['name'])
        self.assertEqual('SINGLE', obj_meta3_after['policy'])
        self.assertEqual(1, len(chunks3))

        self.api.object_delete(self.account, self.container, obj_meta['name'])
        self.api.object_delete(self.account, self.container, obj_meta2['name'])
        self.api.object_delete(self.account, self.container, obj_meta3['name'])

    def test_immediate_transition_filtered_by_tags(self):
        obj_meta = self._upload_something(policy='SINGLE')
        obj_meta2 = self._upload_something(
            policy='SINGLE', properties={TAGGING_KEY: """
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
            """})
        obj_meta3 = self._upload_something(
            policy='SINGLE', properties={TAGGING_KEY: """
            <Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <TagSet>
                    <Tag>
                        <Key>status</Key>
                        <Value>deprecated</Value>
                    </Tag>
                </TagSet>
            </Tagging>
            """})
        self.lifecycle.load_xml("""
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
                    <Days>0</Days>
                    <StorageClass>THREECOPIES</StorageClass>
                </Transition>
                <Status>enabled</Status>
            </Rule>
        </LifecycleConfiguration>
        """)
        results = [x for x in self.lifecycle.apply(obj_meta)]
        self.assertEqual(1, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual('n/a', status)

        results = [x for x in self.lifecycle.apply(obj_meta2)]
        self.assertEqual(1, len(results))
        obj_meta2_copy, _, _, status = results[0]
        self.assertEqual(obj_meta2, obj_meta2_copy)
        self.assertEqual('Policy changed to THREECOPIES', status)

        results = [x for x in self.lifecycle.apply(obj_meta3)]
        self.assertEqual(1, len(results))
        obj_meta3_copy, _, _, status = results[0]
        self.assertEqual(obj_meta3, obj_meta3_copy)
        self.assertEqual('n/a', status)

        obj_meta_after, chunks = self.api.object_locate(
            self.account, self.container, obj_meta['name'])
        self.assertEqual('SINGLE', obj_meta_after['policy'])
        self.assertEqual(1, len(chunks))
        obj_meta2_after, chunks2 = self.api.object_locate(
            self.account, self.container, obj_meta2['name'])
        self.assertEqual('THREECOPIES', obj_meta2_after['policy'])
        self.assertEqual(3, len(chunks2))
        obj_meta3_after, chunks3 = self.api.object_locate(
            self.account, self.container, obj_meta3['name'])
        self.assertEqual('SINGLE', obj_meta3_after['policy'])
        self.assertEqual(1, len(chunks3))

        self.api.object_delete(self.account, self.container, obj_meta['name'])
        self.api.object_delete(self.account, self.container, obj_meta2['name'])
        self.api.object_delete(self.account, self.container, obj_meta3['name'])

    def test_immediate_transition_filtered_by_prefix_and_tags(self):
        obj_meta = self._upload_something(policy='SINGLE', prefix="documents/")
        obj_meta2 = self._upload_something(
            policy='SINGLE', prefix="documents/", properties={TAGGING_KEY: """
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
            """})
        obj_meta3 = self._upload_something(
            policy='SINGLE', properties={TAGGING_KEY: """
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
            """})
        self.lifecycle.load_xml("""
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
                    <Days>0</Days>
                    <StorageClass>THREECOPIES</StorageClass>
                </Transition>
                <Status>enabled</Status>
            </Rule>
        </LifecycleConfiguration>
        """)
        results = [x for x in self.lifecycle.apply(obj_meta)]
        self.assertEqual(1, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual('n/a', status)

        results = [x for x in self.lifecycle.apply(obj_meta2)]
        self.assertEqual(1, len(results))
        obj_meta2_copy, _, _, status = results[0]
        self.assertEqual(obj_meta2, obj_meta2_copy)
        self.assertEqual('Policy changed to THREECOPIES', status)

        results = [x for x in self.lifecycle.apply(obj_meta3)]
        self.assertEqual(1, len(results))
        obj_meta3_copy, _, _, status = results[0]
        self.assertEqual(obj_meta3, obj_meta3_copy)
        self.assertEqual('n/a', status)

        obj_meta_after, chunks = self.api.object_locate(
            self.account, self.container, obj_meta['name'])
        self.assertEqual('SINGLE', obj_meta_after['policy'])
        self.assertEqual(1, len(chunks))
        obj_meta2_after, chunks2 = self.api.object_locate(
            self.account, self.container, obj_meta2['name'])
        self.assertEqual('THREECOPIES', obj_meta2_after['policy'])
        self.assertEqual(3, len(chunks2))
        obj_meta3_after, chunks3 = self.api.object_locate(
            self.account, self.container, obj_meta3['name'])
        self.assertEqual('SINGLE', obj_meta3_after['policy'])
        self.assertEqual(1, len(chunks3))

        self.api.object_delete(self.account, self.container, obj_meta['name'])
        self.api.object_delete(self.account, self.container, obj_meta2['name'])
        self.api.object_delete(self.account, self.container, obj_meta3['name'])

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
        results = [x for x in self.lifecycle.apply(obj_meta)]
        self.assertEqual(1, len(results))
        obj_meta_copy, _, _, status = results[0]
        self.assertEqual(obj_meta, obj_meta_copy)
        self.assertEqual('Deleted', status)

        results = [x for x in self.lifecycle.apply(obj_meta_v2)]
        self.assertEqual(1, len(results))
        obj_meta_v2_copy, _, _, status = results[0]
        self.assertEqual(obj_meta_v2, obj_meta_v2_copy)
        self.assertEqual('Kept', status)

        self.assertRaises(NoSuchObject, self.api.object_show,
                          self.account, self.container, obj_meta['name'],
                          version=obj_meta['version'])
        self.api.object_show(self.account, self.container, obj_meta_v2['name'],
                             version=obj_meta_v2['version'])
        self.api.object_delete(
            self.account, self.container, obj_meta_v2['name'],
            version=obj_meta_v2['version'])

    def test_execute_immediate_expiration(self):
        self.api.container_create(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: """
            <LifecycleConfiguration>
                <Rule>
                    <ID>rule1</ID>
                    <Filter>
                    </Filter>
                    <Status>Enabled</Status>
                    <Expiration>
                        <Days>0</Days>
                    </Expiration>
                </Rule>
            </LifecycleConfiguration>
            """})
        for _ in range(3):
            self._upload_something()
        self.lifecycle.load()
        results = [x for x in self.lifecycle.execute()]
        self.assertEqual(3, len(results))
        for res in results:
            self.assertEqual('Deleted', res[3])
        listing = self.api.object_list(self.account, self.container)
        self.assertEqual(0, len(listing['objects']))

    def test_execute_immediate_expiration_with_disabled_status(self):
        self.api.container_create(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: """
            <LifecycleConfiguration>
                <Rule>
                    <ID>rule1</ID>
                    <Filter>
                    </Filter>
                    <Status>Disabled</Status>
                    <Expiration>
                        <Days>0</Days>
                    </Expiration>
                </Rule>
            </LifecycleConfiguration>
            """})
        for _ in range(3):
            self._upload_something()
        self.lifecycle.load()
        results = [x for x in self.lifecycle.execute()]
        self.assertEqual(3, len(results))
        for res in results:
            self.assertEqual('n/a', res[3])
        listing = self.api.object_list(self.account, self.container)
        self.assertEqual(3, len(listing['objects']))

    def test_execute_expiration_on_missing_objects(self):
        self.api.container_create(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: """
            <LifecycleConfiguration>
                <Rule>
                    <ID>rule1</ID>
                    <Filter>
                    </Filter>
                    <Status>Enabled</Status>
                    <Expiration>
                        <Days>0</Days>
                    </Expiration>
                </Rule>
            </LifecycleConfiguration>
            """})
        fake_listing = {
            'objects': [
                {'name': 'a', 'ctime': '12', 'deleted': False},
                {'name': 'b', 'ctime': '12', 'deleted': False},
                {'name': 'c', 'ctime': '12', 'deleted': False},
                {'name': 'd', 'ctime': '12', 'deleted': False}],
            'truncated': False
        }
        with patch.object(self.api, 'object_list',
                          side_effect=[fake_listing]):
            self.lifecycle.load()
            results = [x for x in self.lifecycle.execute()]
        self.assertEqual(4, len(results))
        for res in results:
            self.assertIsInstance(res[3], Exception)

    def test_execute_exceeding_version_expiration_without_versioning(self):
        self.api.container_create(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: """
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
            """})
        for _ in range(5):
            self._upload_something()
        self.lifecycle.load()
        results = [x for x in self.lifecycle.execute()]
        self.assertEqual(5, len(results))
        for res in results:
            self.assertEqual('Kept', res[3])
        listing = self.api.object_list(self.account, self.container,
                                       versions=True)
        self.assertEqual(5, len(listing['objects']))

    def test_execute_exceeding_version_expiration_with_versioning(self):
        self.api.container_create(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: """
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
            """}, system={"sys.m2.policy.version": "4"})
        for _ in range(5):
            self._upload_something(path="versioned1")
        for _ in range(5):
            self._upload_something(path="versioned2")
        listing = self.api.object_list(self.account, self.container,
                                       versions=True)
        self.assertEqual(10, len(listing['objects']))
        self.lifecycle.load()
        results = [x for x in self.lifecycle.execute()]
        self.assertEqual(10, len(results))
        listing = self.api.object_list(self.account, self.container,
                                       versions=True)
        self.assertEqual(6, len(listing['objects']))

    def test_execute_multiple_rules(self):
        self.api.container_create(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: """
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
                <Rule>
                    <Filter>
                        <Prefix>documents/</Prefix>
                    </Filter>
                    <Expiration>
                        <Days>0</Days>
                    </Expiration>
                    <Status>Enabled</Status>
                </Rule>
            </LifecycleConfiguration>
            """}, system={"sys.m2.policy.version": "4"})
        obj_meta = self._upload_something(policy='SINGLE')
        obj_meta2 = self._upload_something(
            policy='SINGLE', properties={TAGGING_KEY: """
            <Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <TagSet>
                    <Tag>
                        <Key>status</Key>
                        <Value>deprecated</Value>
                    </Tag>
                </TagSet>
            </Tagging>
            """})
        obj_meta3 = self._upload_something(prefix="documents/",
                                           policy='SINGLE')
        self.lifecycle.load()
        results = [x for x in self.lifecycle.execute()]
        self.assertEqual(5, len(results))

        self.api.object_show(self.account, self.container, obj_meta['name'])
        self.assertRaises(NoSuchObject, self.api.object_show,
                          self.account, self.container, obj_meta2['name'])
        self.assertRaises(NoSuchObject, self.api.object_show,
                          self.account, self.container, obj_meta3['name'])

        self.api.object_delete(self.account, self.container, obj_meta['name'])
