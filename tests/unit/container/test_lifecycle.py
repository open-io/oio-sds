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

import unittest

try:
    from lxml import etree
except ImportError:
    from xml.etree import cElementTree as etree

from oio.container.lifecycle import Expiration, \
    LifecycleRule, LifecycleRuleFilter, Transition


class TestContainerLifecycle(unittest.TestCase):

    # TODO: for easier regression checking, split the long tests

    def test_Expiration_from_element(self):
        days_elt = etree.XML("<Expiration><Days>365</Days></Expiration>")
        days_exp = Expiration.from_element(days_elt)
        self.assertIsNotNone(days_exp)
        self.assertEqual(days_exp.days, 365)
        self.assertIsNone(days_exp.date)

        date_elt = etree.XML(
            "<Expiration><Date>2006-08-14T02:34:56</Date></Expiration>")
        date_exp = Expiration.from_element(date_elt)
        self.assertIsNotNone(date_exp)
        self.assertEqual(date_exp.date, 1155515696)
        self.assertIsNone(date_exp.days)

        broken_elt = etree.XML(
            "<Expiration></Expiration>")
        self.assertRaises(ValueError, Expiration.from_element, broken_elt)

    def test_Transition_from_element(self):
        trans_elt = etree.XML(
            """
            <Transition>
                <Days>365</Days>
            </Transition>
            """)
        self.assertRaises(ValueError, Transition.from_element, trans_elt)

        trans_elt = etree.XML(
            """
            <Transition>
                <StorageClass>THREECOPIES</StorageClass>
            </Transition>
            """)
        self.assertRaises(ValueError, Transition.from_element, trans_elt)

        trans_elt = etree.XML(
            """
            <Transition>
                <Days>365</Days>
                <StorageClass>THREECOPIES</StorageClass>
            </Transition>
            """)
        trans = Transition.from_element(trans_elt)
        self.assertIsNotNone(trans)
        self.assertEqual(trans.days, 365)
        self.assertIsNone(trans.date)

        trans_elt = etree.XML(
            """
            <Transition>
                <Date>2006-08-14T02:34:56</Date>
                <StorageClass>THREECOPIES</StorageClass>
            </Transition>
            """)
        trans = Transition.from_element(trans_elt)
        self.assertIsNotNone(trans)
        self.assertEqual(trans.date, 1155515696)
        self.assertIsNone(trans.days)

    def test_LifecycleRuleFilter_from_element(self):
        filter_elt = etree.XML(
            """
            <Filter>
            </Filter>
            """)
        filter_ = LifecycleRuleFilter.from_element(filter_elt)
        self.assertIsNotNone(filter_)

        filter_elt = etree.XML(
            """
            <Filter>
                <Prefix>documents/</Prefix>
            </Filter>
            """)
        filter_ = LifecycleRuleFilter.from_element(filter_elt)
        self.assertIsNotNone(filter_)
        self.assertEqual(filter_.prefix, "documents/")
        self.assertEqual(filter_.generate_id(), "prefix=documents/")

        filter_elt = etree.XML(
            """
            <Filter>
                <Tag>
                    <Key>key</Key>
                    <Value>value</Value>
                </Tag>
            </Filter>
            """)
        filter_ = LifecycleRuleFilter.from_element(filter_elt)
        self.assertIsNotNone(filter_)
        self.assertIsNone(filter_.prefix)
        self.assertIn('key', filter_.tags)
        self.assertEqual(filter_.generate_id(), "key=value")

        filter_elt = etree.XML(
            """
            <Filter>
                <And>
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
            """)
        filter_ = LifecycleRuleFilter.from_element(filter_elt)
        self.assertIsNotNone(filter_)
        self.assertIsNone(filter_.prefix)
        self.assertDictEqual({'key1': 'value1', 'key2': 'value2'},
                             filter_.tags)
        self.assertEqual(filter_.generate_id(), "key1=value1,key2=value2")

        filter_elt = etree.XML(
            """
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
            """)
        filter_ = LifecycleRuleFilter.from_element(filter_elt)
        self.assertIsNotNone(filter_)
        self.assertEqual(filter_.prefix, "documents/")
        self.assertDictEqual({'key1': 'value1', 'key2': 'value2'},
                             filter_.tags)
        self.assertEqual(filter_.generate_id(),
                         "prefix=documents/,key1=value1,key2=value2")

    def test_LifecycleRule_from_element(self):
        rule_elt = etree.XML(
            """
            <Rule>
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
            </Rule>
            """)
        rule = LifecycleRule.from_element(rule_elt)
        self.assertIsNotNone(rule)
        self.assertIsNotNone(rule.filter)
        self.assertTrue(rule.enabled)
        self.assertIsNotNone(rule.expiration)
        self.assertIsNotNone(rule.transition)
        self.assertIsNotNone(rule.id)

    def test_LifecycleRule_from_element_no_action(self):
        rule_elt = etree.XML(
            """
            <Rule>
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
            </Rule>
            """)
        self.assertRaises(ValueError, LifecycleRule.from_element, rule_elt)

    def test_LifecycleRule_from_element_no_filter(self):
        rule_elt = etree.XML(
            """
            <Rule>
                <Status>Enabled</Status>
                <Transition>
                    <Days>1</Days>
                    <StorageClass>THREECOPIES</StorageClass>
                </Transition>
                <Expiration>
                    <Days>60</Days>
                </Expiration>
            </Rule>
            """)
        self.assertRaises(ValueError, LifecycleRule.from_element, rule_elt)

    def test_LifecycleRule_from_element_no_status(self):
        rule_elt = etree.XML(
            """
            <Rule>
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
                <Transition>
                    <Days>1</Days>
                    <StorageClass>THREECOPIES</StorageClass>
                </Transition>
                <Expiration>
                    <Days>60</Days>
                </Expiration>
            </Rule>
            """)
        self.assertRaises(ValueError, LifecycleRule.from_element, rule_elt)
