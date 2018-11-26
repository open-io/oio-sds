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
import unittest

try:
    from lxml import etree
except ImportError:
    from xml.etree import cElementTree as etree

from oio.container.lifecycle import LifecycleRule, LifecycleRuleFilter, \
    DaysActionFilter, DateActionFilter, NoncurrentCountActionFilter, \
    NoncurrentDaysActionFilter, Expiration, Transition, \
    NoncurrentVersionExpiration, NoncurrentVersionTransition, \
    TAGGING_KEY


class TestContainerLifecycle(unittest.TestCase):

    # TODO: for easier regression checking, split the long tests

    obj_meta = {
        'hash': '262C4009B642DE2F7A95EFD4FCD0A465',
        'ctime': '554119200',
        'mtime': '554119200',
        'deleted': 'False',
        'id': 'DA5BEBD37F5705004FFD42A9B275AB84',
        'length': '44065',
        'hash_method': 'md5',
        'chunk_method': 'plain/nb_copy=1',
        'version': '1503581411433436',
        'policy': 'SINGLE',
        'properties': {},
        'mime_type': 'application/octet-stream',
        'name': 'Makefile'
    }

    def test_DaysActionFilter_from_element(self):
        days_elt = etree.XML(
            """
            <Days></Days>
            """)
        self.assertRaises(ValueError, DaysActionFilter.from_element, days_elt)

        days_elt = etree.XML(
            """
            <Days>10.5</Days>
            """)
        self.assertRaises(ValueError, DaysActionFilter.from_element, days_elt)

        days_elt = etree.XML(
            """
            <Days>0</Days>
            """)
        self.assertRaises(ValueError, DaysActionFilter.from_element, days_elt)

        days_elt = etree.XML(
            """
            <Days>-2</Days>
            """)
        self.assertRaises(ValueError, DaysActionFilter.from_element, days_elt)

        days_elt = etree.XML(
            """
            <Days>test</Days>
            """)
        self.assertRaises(ValueError, DaysActionFilter.from_element, days_elt)

        days_elt = etree.XML(
            """
            <Days>2018-10-30T02:34:56</Days>
            """)
        self.assertRaises(ValueError, DaysActionFilter.from_element, days_elt)

        days_elt = etree.XML(
            """
            <Days>12</Days>
            """)
        days = DaysActionFilter.from_element(days_elt)
        self.assertIsNotNone(days)
        self.assertEqual(12, days.days)

    def test_NoncurrentDaysActionFilter_from_element(self):
        days_elt = etree.XML(
            """
            <NoncurrentDays></NoncurrentDays>
            """)
        self.assertRaises(ValueError, DaysActionFilter.from_element, days_elt)

        days_elt = etree.XML(
            """
            <NoncurrentDays>10.5</NoncurrentDays>
            """)
        self.assertRaises(ValueError, DaysActionFilter.from_element, days_elt)

        days_elt = etree.XML(
            """
            <NoncurrentDays>0</NoncurrentDays>
            """)
        self.assertRaises(ValueError, DaysActionFilter.from_element, days_elt)

        days_elt = etree.XML(
            """
            <NoncurrentDays>-2</NoncurrentDays>
            """)
        self.assertRaises(ValueError, DaysActionFilter.from_element, days_elt)

        days_elt = etree.XML(
            """
            <NoncurrentDays>test</NoncurrentDays>
            """)
        self.assertRaises(ValueError, DaysActionFilter.from_element, days_elt)

        days_elt = etree.XML(
            """
            <NoncurrentDays>2018-10-30T02:34:56</NoncurrentDays>
            """)
        self.assertRaises(ValueError, DaysActionFilter.from_element, days_elt)

        days_elt = etree.XML(
            """
            <NoncurrentDays>12</NoncurrentDays>
            """)
        days = DaysActionFilter.from_element(days_elt)
        self.assertIsNotNone(days)
        self.assertEqual(12, days.days)

    def test_DateActionFilter_from_element(self):
        date_elt = etree.XML(
            """
            <Date></Date>
            """)
        self.assertRaises(ValueError, DateActionFilter.from_element, date_elt)

        date_elt = etree.XML(
            """
            <Date>1</Date>
            """)
        self.assertRaises(ValueError, DateActionFilter.from_element, date_elt)

        date_elt = etree.XML(
            """
            <Date>test</Date>
            """)
        self.assertRaises(ValueError, DateActionFilter.from_element, date_elt)

        date_elt = etree.XML(
            """
            <Date>2018-10-30T02:34:56</Date>
            """)
        date = DateActionFilter.from_element(date_elt)
        self.assertIsNotNone(date)
        self.assertEqual(1540857600, date.date)

    def test_NoncurrentCountActionFilter_from_element(self):
        count_elt = etree.XML(
            """
            <Count></Count>
            """)
        self.assertRaises(ValueError, NoncurrentCountActionFilter.from_element,
                          count_elt)

        count_elt = etree.XML(
            """
            <Count>10.5</Count>
            """)
        self.assertRaises(ValueError, NoncurrentCountActionFilter.from_element,
                          count_elt)

        count_elt = etree.XML(
            """
            <Count>-2</Count>
            """)
        self.assertRaises(ValueError, NoncurrentCountActionFilter.from_element,
                          count_elt)

        count_elt = etree.XML(
            """
            <Count>test</Count>
            """)
        self.assertRaises(ValueError, NoncurrentCountActionFilter.from_element,
                          count_elt)

        count_elt = etree.XML(
            """
            <Count>2018-10-30T02:34:56</Count>
            """)
        self.assertRaises(ValueError, NoncurrentCountActionFilter.from_element,
                          count_elt)

        count_elt = etree.XML(
            """
            <Count>12</Count>
            """)
        count = NoncurrentCountActionFilter.from_element(count_elt)
        self.assertIsNotNone(count)
        self.assertEqual(12, count.count)

    def test_Expiration_from_element(self):
        exp_elt = etree.XML(
            """
            <Expiration>
            </Expiration>
            """)
        self.assertRaises(ValueError, Expiration.from_element, exp_elt)

        exp_elt = etree.XML(
            """
            <Expiration>
                <Days>365</Days>
                <Date>2006-08-14T02:34:56</Date>
            </Expiration>
            """)
        self.assertRaises(ValueError,
                          Expiration.from_element, exp_elt)

        exp_elt = etree.XML(
            """
            <Expiration>
                <Days>365</Days>
            </Expiration>
            """)
        exp = Expiration.from_element(exp_elt)
        self.assertIsNotNone(exp)
        self.assertEqual(exp.filter.days, 365)

        exp_elt = etree.XML(
            """
            <Expiration>
                <Date>2006-08-14T02:34:56</Date>
            </Expiration>
            """)
        exp = Expiration.from_element(exp_elt)
        self.assertIsNotNone(exp)
        self.assertEqual(1155513600, exp.filter.date)

        exp_elt = etree.XML(
            """
            <Expiration>
                <Days>365</Days>
                <Days>100</Days>
            </Expiration>
            """)
        exp = Expiration.from_element(exp_elt)
        self.assertIsNotNone(exp)
        self.assertEqual(100, exp.filter.days)

        exp_elt = etree.XML(
            """
            <Expiration>
                <Date>2018-10-30T02:34:56</Date>
                <Date>2006-08-14T02:34:56</Date>
            </Expiration>
            """)
        exp = Expiration.from_element(exp_elt)
        self.assertIsNotNone(exp)
        self.assertEqual(1155513600, exp.filter.date)

    def test_Transition_from_element(self):
        trans_elt = etree.XML(
            """
            <Transition>
            </Transition>
            """)
        self.assertRaises(ValueError, Transition.from_element, trans_elt)

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
                <StorageClass></StorageClass>
            </Transition>
            """)
        self.assertRaises(ValueError, Transition.from_element, trans_elt)

        trans_elt = etree.XML(
            """
            <Transition>
                <Days>365</Days>
                <Date>2006-08-14T02:34:56</Date>
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
        self.assertEqual(365, trans.filter.days)
        self.assertEqual('THREECOPIES', trans.policy)

        trans_elt = etree.XML(
            """
            <Transition>
                <Date>2006-08-14T02:34:56</Date>
                <StorageClass>THREECOPIES</StorageClass>
            </Transition>
            """)
        trans = Transition.from_element(trans_elt)
        self.assertIsNotNone(trans)
        self.assertEqual(trans.filter.date, 1155513600)
        self.assertEqual(trans.policy, "THREECOPIES")

        trans_elt = etree.XML(
            """
            <Transition>
                <Days>365</Days>
                <Days>100</Days>
                <StorageClass>THREECOPIES</StorageClass>
            </Transition>
            """)
        trans = Transition.from_element(trans_elt)
        self.assertIsNotNone(trans)
        self.assertEqual(100, trans.filter.days)
        self.assertEqual('THREECOPIES', trans.policy)

        trans_elt = etree.XML(
            """
            <Transition>
                <Date>2018-10-30T02:34:56</Date>
                <Date>2006-08-14T02:34:56</Date>
                <StorageClass>THREECOPIES</StorageClass>
            </Transition>
            """)
        trans = Transition.from_element(trans_elt)
        self.assertIsNotNone(trans)
        self.assertEqual(1155513600, trans.filter.date)
        self.assertEqual('THREECOPIES', trans.policy)

        trans_elt = etree.XML(
            """
            <Transition>
                <Days>365</Days>
                <StorageClass>THREECOPIES</StorageClass>
                <StorageClass>SINGLE</StorageClass>
            </Transition>
            """)
        trans = Transition.from_element(trans_elt)
        self.assertIsNotNone(trans)
        self.assertEqual(365, trans.filter.days)
        self.assertEqual('SINGLE', trans.policy)

    def test_NoncurrentVersionExpiration_from_element(self):
        exp_elt = etree.XML(
            """
            <NoncurrentVersionExpiration>
            </NoncurrentVersionExpiration>
            """)
        self.assertRaises(ValueError,
                          NoncurrentVersionExpiration.from_element, exp_elt)

        exp_elt = etree.XML(
            """
            <NoncurrentVersionExpiration>
                <NoncurrentDays>365</NoncurrentDays>
                <NoncurrentCount>3</NoncurrentCount>
            </NoncurrentVersionExpiration>
            """)
        self.assertRaises(ValueError,
                          NoncurrentVersionExpiration.from_element, exp_elt)

        exp_elt = etree.XML(
            """
            <NoncurrentVersionExpiration>
                <NoncurrentDays>365</NoncurrentDays>
            </NoncurrentVersionExpiration>
            """)
        exp = NoncurrentVersionExpiration.from_element(exp_elt)
        self.assertIsNotNone(exp)
        self.assertEqual(365, exp.filter.days)

        exp_elt = etree.XML(
            """
            <NoncurrentVersionExpiration>
                <NoncurrentCount>3</NoncurrentCount>
            </NoncurrentVersionExpiration>
            """)
        exp = NoncurrentVersionExpiration.from_element(exp_elt)
        self.assertIsNotNone(exp)
        self.assertEqual(3, exp.filter.count)

        exp_elt = etree.XML(
            """
            <NoncurrentVersionExpiration>
                <NoncurrentDays>365</NoncurrentDays>
                <NoncurrentDays>100</NoncurrentDays>
            </NoncurrentVersionExpiration>
            """)
        exp = NoncurrentVersionExpiration.from_element(exp_elt)
        self.assertIsNotNone(exp)
        self.assertEqual(100, exp.filter.days)

        exp_elt = etree.XML(
            """
            <NoncurrentVersionExpiration>
                <NoncurrentCount>5</NoncurrentCount>
                <NoncurrentCount>3</NoncurrentCount>
            </NoncurrentVersionExpiration>
            """)
        exp = NoncurrentVersionExpiration.from_element(exp_elt)
        self.assertIsNotNone(exp)
        self.assertEqual(3, exp.filter.count)

    def test_NoncurrentVersionTransition_from_element(self):
        trans_elt = etree.XML(
            """
            <NoncurrentVersionTransition>
            </NoncurrentVersionTransition>
            """)
        self.assertRaises(
            ValueError, NoncurrentVersionTransition.from_element, trans_elt)

        trans_elt = etree.XML(
            """
            <NoncurrentVersionTransition>
                <NoncurrentDays>365</NoncurrentDays>
            </NoncurrentVersionTransition>
            """)
        self.assertRaises(
            ValueError, NoncurrentVersionTransition.from_element, trans_elt)

        trans_elt = etree.XML(
            """
            <NoncurrentVersionTransition>
                <StorageClass>THREECOPIES</StorageClass>
            </NoncurrentVersionTransition>
            """)
        self.assertRaises(
            ValueError, NoncurrentVersionTransition.from_element, trans_elt)

        trans_elt = etree.XML(
            """
            <NoncurrentVersionTransition>
                <NoncurrentDays>365</NoncurrentDays>
                <StorageClass></StorageClass>
            </NoncurrentVersionTransition>
            """)
        self.assertRaises(
            ValueError, NoncurrentVersionTransition.from_element, trans_elt)

        trans_elt = etree.XML(
            """
            <NoncurrentVersionTransition>
                <NoncurrentDays>365</NoncurrentDays>
                <StorageClass>THREECOPIES</StorageClass>
            </NoncurrentVersionTransition>
            """)
        trans = NoncurrentVersionTransition.from_element(trans_elt)
        self.assertIsNotNone(trans)
        self.assertEqual(365, trans.filter.days)
        self.assertEqual('THREECOPIES', trans.policy)

        trans_elt = etree.XML(
            """
            <NoncurrentVersionTransition>
                <NoncurrentDays>365</NoncurrentDays>
                <NoncurrentDays>100</NoncurrentDays>
                <StorageClass>THREECOPIES</StorageClass>
            </NoncurrentVersionTransition>
            """)
        trans = NoncurrentVersionTransition.from_element(trans_elt)
        self.assertIsNotNone(trans)
        self.assertEqual(100, trans.filter.days)
        self.assertEqual('THREECOPIES', trans.policy)

        trans_elt = etree.XML(
            """
            <NoncurrentVersionTransition>
                <NoncurrentDays>365</NoncurrentDays>
                <StorageClass>THREECOPIES</StorageClass>
                <StorageClass>SINGLE</StorageClass>
            </NoncurrentVersionTransition>
            """)
        trans = NoncurrentVersionTransition.from_element(trans_elt)
        self.assertIsNotNone(trans)
        self.assertEqual(365, trans.filter.days)
        self.assertEqual('SINGLE', trans.policy)

    def test_LifecycleRuleFilter_from_element(self):
        filter_elt = etree.XML(
            """
            <Filter>
                <Prefix></Prefix>
            </Filter>
            """)
        self.assertRaises(ValueError,
                          LifecycleRuleFilter.from_element, filter_elt)

        filter_elt = etree.XML(
            """
            <Filter>
                <Prefix>documents/</Prefix>
                <Tag>
                    <Key>key</Key>
                    <Value>value</Value>
                </Tag>
            </Filter>
            """)
        self.assertRaises(ValueError,
                          LifecycleRuleFilter.from_element, filter_elt)

        filter_elt = etree.XML(
            """
            <Filter>
                <Tag>
                    <Key>key</Key>
                </Tag>
            </Filter>
            """)
        self.assertRaises(ValueError,
                          LifecycleRuleFilter.from_element, filter_elt)

        filter_elt = etree.XML(
            """
            <Filter>
                <Tag>
                    <Value>value</Value>
                </Tag>
            </Filter>
            """)
        self.assertRaises(ValueError,
                          LifecycleRuleFilter.from_element, filter_elt)

        filter_elt = etree.XML(
            """
            <Filter>
                <Tag>
                    <Key></Key>
                    <Value>value</Value>
                </Tag>
            </Filter>
            """)
        self.assertRaises(ValueError,
                          LifecycleRuleFilter.from_element, filter_elt)

        filter_elt = etree.XML(
            """
            <Filter>
                <Tag>
                    <Key>key</Key>
                    <Value></Value>
                </Tag>
            </Filter>
            """)
        self.assertRaises(ValueError,
                          LifecycleRuleFilter.from_element, filter_elt)

        filter_elt = etree.XML(
            """
            <Filter>
                <And>
                    <Tag>
                        <Key>key</Key>
                        <Value>value1</Value>
                    </Tag>
                    <Tag>
                        <Key>key</Key>
                        <Value>value2</Value>
                    </Tag>
                </And>
            </Filter>
            """)
        self.assertRaises(ValueError,
                          LifecycleRuleFilter.from_element, filter_elt)

        filter_elt = etree.XML(
            """
            <Filter>
            </Filter>
            """)
        filter_ = LifecycleRuleFilter.from_element(filter_elt)
        self.assertIsNotNone(filter_)
        self.assertIsNone(filter_.prefix)
        self.assertDictEqual({}, filter_.tags)

        filter_elt = etree.XML(
            """
            <Filter>
                <Prefix>documents/</Prefix>
            </Filter>
            """)
        filter_ = LifecycleRuleFilter.from_element(filter_elt)
        self.assertIsNotNone(filter_)
        self.assertEqual(filter_.prefix, "documents/")
        self.assertDictEqual({}, filter_.tags)

        filter_elt = etree.XML(
            """
            <Filter>
                <Prefix>documents/</Prefix>
                <Prefix>images/</Prefix>
            </Filter>
            """)
        filter_ = LifecycleRuleFilter.from_element(filter_elt)
        self.assertIsNotNone(filter_)
        self.assertEqual(filter_.prefix, "images/")
        self.assertDictEqual({}, filter_.tags)

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
        self.assertDictEqual({'key': 'value'}, filter_.tags)

        filter_elt = etree.XML(
            """
            <Filter>
                <Tag>
                    <Key>key</Key>
                    <Value>value1</Value>
                </Tag>
                <Tag>
                    <Key>key</Key>
                    <Value>value2</Value>
                </Tag>
            </Filter>
            """)
        filter_ = LifecycleRuleFilter.from_element(filter_elt)
        self.assertIsNotNone(filter_)
        self.assertIsNone(filter_.prefix)
        self.assertDictEqual({'key': 'value2'}, filter_.tags)

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

        filter_elt = etree.XML(
            """
            <Filter>
                <And>
                    <Prefix>documents/</Prefix>
                    <Prefix>images/</Prefix>
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
        self.assertEqual(filter_.prefix, "images/")
        self.assertDictEqual({'key1': 'value1', 'key2': 'value2'},
                             filter_.tags)

    def test_LifecycleRule_from_element(self):
        rule_elt = etree.XML(
            """
            <Rule>
                <ID></ID>
                <Status>Enabled</Status>
                <Filter>
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

        rule_elt = etree.XML(
            """
            <Rule>
                <Filter>
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

        rule_elt = etree.XML(
            """
            <Rule>
                <Status></Status>
                <Filter>
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

        rule_elt = etree.XML(
            """
            <Rule>
                <Status>Test</Status>
                <Filter>
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

        rule_elt = etree.XML(
            """
            <Rule>
                <Filter>
                </Filter>
                <Status>Enabled</Status>
                <Transition>
                    <Days>0</Days>
                    <StorageClass>THREECOPIES</StorageClass>
                </Transition>
            </Rule>
            """)
        self.assertRaises(ValueError, LifecycleRule.from_element, rule_elt)

        rule_elt = etree.XML(
            """
            <Rule>
                <Filter>
                </Filter>
                <Status>Enabled</Status>
                <Expiration>
                    <Days>0</Days>
                </Expiration>
            </Rule>
            """)
        self.assertRaises(ValueError, LifecycleRule.from_element, rule_elt)

        rule_elt = etree.XML(
            """
            <Rule>
                <Filter>
                </Filter>
                <Status>Enabled</Status>
                <NoncurrentVersionTransition>
                    <NoncurrentDays>0</NoncurrentDays>
                    <StorageClass>THREECOPIES</StorageClass>
                </NoncurrentVersionTransition>
            </Rule>
            """)
        self.assertRaises(ValueError, LifecycleRule.from_element, rule_elt)

        rule_elt = etree.XML(
            """
            <Rule>
                <Filter>
                </Filter>
                <Status>Enabled</Status>
                <NoncurrentVersionExpiration>
                    <NoncurrentDays>0</NoncurrentDays>
                </NoncurrentVersionExpiration>
            </Rule>
            """)
        self.assertRaises(ValueError, LifecycleRule.from_element, rule_elt)

        rule_elt = etree.XML(
            """
            <Rule>
                <Filter>
                </Filter>
                <Status>Enabled</Status>
                <Expiration>
                    <Days>1</Days>
                </Expiration>
                <Transition>
                    <Days>1</Days>
                    <StorageClass>THREECOPIES</StorageClass>
                </Transition>
            </Rule>
            """)
        self.assertRaises(ValueError, LifecycleRule.from_element, rule_elt)

        rule_elt = etree.XML(
            """
            <Rule>
                <Filter>
                </Filter>
                <Status>Enabled</Status>
                <Expiration>
                    <Days>1</Days>
                </Expiration>
                <Transition>
                    <Days>2</Days>
                    <StorageClass>THREECOPIES</StorageClass>
                </Transition>
            </Rule>
            """)
        self.assertRaises(ValueError, LifecycleRule.from_element, rule_elt)

        rule_elt = etree.XML(
            """
            <Rule>
                <Filter>
                </Filter>
                <Status>Enabled</Status>
                <Expiration>
                    <Days>15</Days>
                </Expiration>
                <Transition>
                    <Days>30</Days>
                    <StorageClass>SINGLE</StorageClass>
                </Transition>
                <Transition>
                    <Days>10</Days>
                    <StorageClass>THREECOPIES</StorageClass>
                </Transition>
            </Rule>
            """)
        self.assertRaises(ValueError, LifecycleRule.from_element, rule_elt)

        rule_elt = etree.XML(
            """
            <Rule>
                <Filter>
                </Filter>
                <Status>Enabled</Status>
                <NoncurrentVersionExpiration>
                    <NoncurrentDays>1</NoncurrentDays>
                </NoncurrentVersionExpiration>
                <NoncurrentVersionTransition>
                    <NoncurrentDays>1</NoncurrentDays>
                    <StorageClass>THREECOPIES</StorageClass>
                </NoncurrentVersionTransition>
            </Rule>
            """)
        self.assertRaises(ValueError, LifecycleRule.from_element, rule_elt)

        rule_elt = etree.XML(
            """
            <Rule>
                <Filter>
                </Filter>
                <Status>Enabled</Status>
                <NoncurrentVersionExpiration>
                    <NoncurrentDays>1</NoncurrentDays>
                </NoncurrentVersionExpiration>
                <NoncurrentVersionTransition>
                    <NoncurrentDays>2</NoncurrentDays>
                    <StorageClass>THREECOPIES</StorageClass>
                </NoncurrentVersionTransition>
            </Rule>
            """)
        self.assertRaises(ValueError, LifecycleRule.from_element, rule_elt)

        rule_elt = etree.XML(
            """
            <Rule>
                <Filter>
                </Filter>
                <Status>Enabled</Status>
                <NoncurrentVersionExpiration>
                    <NoncurrentDays>15</NoncurrentDays>
                </NoncurrentVersionExpiration>
                <NoncurrentVersionTransition>
                    <NoncurrentDays>30</NoncurrentDays>
                    <StorageClass>SINGLE</StorageClass>
                </NoncurrentVersionTransition>
                <NoncurrentVersionTransition>
                    <NoncurrentDays>10</NoncurrentDays>
                    <StorageClass>THREECOPIES</StorageClass>
                </NoncurrentVersionTransition>
            </Rule>
            """)
        self.assertRaises(ValueError, LifecycleRule.from_element, rule_elt)

        rule_elt = etree.XML(
            """
            <Rule>
                <Filter>
                </Filter>
                <Status>Enabled</Status>
                <Expiration>
                    <Date>2018-10-30T02:34:56</Date>
                </Expiration>
                <Transition>
                    <Date>2018-10-30T02:34:56</Date>
                    <StorageClass>THREECOPIES</StorageClass>
                </Transition>
            </Rule>
            """)
        self.assertRaises(ValueError, LifecycleRule.from_element, rule_elt)

        rule_elt = etree.XML(
            """
            <Rule>
                <Filter>
                </Filter>
                <Status>Enabled</Status>
                <Expiration>
                    <Date>2018-10-29T02:34:56</Date>
                </Expiration>
                <Transition>
                    <Date>2018-10-30T02:34:56</Date>
                    <StorageClass>THREECOPIES</StorageClass>
                </Transition>
            </Rule>
            """)
        self.assertRaises(ValueError, LifecycleRule.from_element, rule_elt)

        rule_elt = etree.XML(
            """
            <Rule>
                <Filter>
                </Filter>
                <Status>Enabled</Status>
                <Expiration>
                    <Date>2018-10-15T02:34:56</Date>
                </Expiration>
                <Transition>
                    <Date>2018-10-30T02:34:56</Date>
                    <StorageClass>SINGLE</StorageClass>
                </Transition>
                <Transition>
                    <Date>2018-10-10T02:34:56</Date>
                    <StorageClass>THREECOPIES</StorageClass>
                </Transition>
            </Rule>
            """)
        self.assertRaises(ValueError, LifecycleRule.from_element, rule_elt)

        rule_elt = etree.XML(
            """
            <Rule>
                <Filter>
                </Filter>
                <Status>Enabled</Status>
                <Expiration>
                    <Date>2018-10-15T02:34:56</Date>
                </Expiration>
                <Transition>
                    <Days>1</Days>
                    <StorageClass>THREECOPIES</StorageClass>
                </Transition>
            </Rule>
            """)
        self.assertRaises(ValueError, LifecycleRule.from_element, rule_elt)

        rule_elt = etree.XML(
            """
            <Rule>
                <Filter>
                </Filter>
                <Status>Enabled</Status>
                <Expiration>
                    <Days>1</Days>
                </Expiration>
                <Transition>
                    <Date>2018-10-10T02:34:56</Date>
                    <StorageClass>THREECOPIES</StorageClass>
                </Transition>
            </Rule>
            """)
        self.assertRaises(ValueError, LifecycleRule.from_element, rule_elt)

        rule_elt = etree.XML(
            """
            <Rule>
                <Filter>
                </Filter>
                <Status>Enabled</Status>
                <Transition>
                    <Days>1</Days>
                    <StorageClass>SINGLE</StorageClass>
                </Transition>
                <Transition>
                    <Date>2018-10-10T02:34:56</Date>
                    <StorageClass>THREECOPIES</StorageClass>
                </Transition>
            </Rule>
            """)
        self.assertRaises(ValueError, LifecycleRule.from_element, rule_elt)

        rule_elt = etree.XML(
            """
            <Rule>
                <Filter>
                </Filter>
                <Status>Enabled</Status>
                <NoncurrentVersionExpiration>
                    <NoncurrentCount>1</NoncurrentCount>
                </NoncurrentVersionExpiration>
                <NoncurrentVersionTransition>
                    <NoncurrentDays>100</NoncurrentDays>
                    <StorageClass>THREECOPIES</StorageClass>
                </NoncurrentVersionTransition>
            </Rule>
            """)
        self.assertRaises(ValueError, LifecycleRule.from_element, rule_elt)

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
                    <Days>10</Days>
                    <StorageClass>THREECOPIES</StorageClass>
                </Transition>
                <Transition>
                    <Days>30</Days>
                    <StorageClass>SINGLE</StorageClass>
                </Transition>
                <Expiration>
                    <Days>60</Days>
                </Expiration>
                <NoncurrentVersionTransition>
                    <NoncurrentDays>100</NoncurrentDays>
                    <StorageClass>THREECOPIES</StorageClass>
                </NoncurrentVersionTransition>
                <NoncurrentVersionExpiration>
                    <NoncurrentDays>600</NoncurrentDays>
                </NoncurrentVersionExpiration>
                <NoncurrentVersionTransition>
                    <NoncurrentDays>300</NoncurrentDays>
                    <StorageClass>SINGLE</StorageClass>
                </NoncurrentVersionTransition>
            </Rule>
            """)
        rule = LifecycleRule.from_element(rule_elt)
        self.assertIsNotNone(rule)
        self.assertIsNotNone(rule.id)
        self.assertIsNotNone(rule.filter)
        self.assertTrue(rule.enabled)
        self.assertEqual(6, len(rule.actions))
        expiration = rule.actions[0]
        self.assertEqual(Expiration, type(expiration))
        self.assertEqual(60, expiration.filter.days)
        transition = rule.actions[1]
        self.assertEqual(Transition, type(transition))
        self.assertEqual(30, transition.filter.days)
        self.assertEqual('SINGLE', transition.policy)
        transition = rule.actions[2]
        self.assertEqual(Transition, type(transition))
        self.assertEqual(10, transition.filter.days)
        self.assertEqual('THREECOPIES', transition.policy)
        expiration = rule.actions[3]
        self.assertEqual(NoncurrentVersionExpiration, type(expiration))
        self.assertEqual(600, expiration.filter.days)
        transition = rule.actions[4]
        self.assertEqual(NoncurrentVersionTransition, type(transition))
        self.assertEqual(300, transition.filter.days)
        self.assertEqual('SINGLE', transition.policy)
        transition = rule.actions[5]
        self.assertEqual(NoncurrentVersionTransition, type(transition))
        self.assertEqual(100, transition.filter.days)
        self.assertEqual('THREECOPIES', transition.policy)

        rule_elt = etree.XML(
            """
            <Rule>
                <ID>Test</ID>
                <Filter>
                </Filter>
                <Status>Disabled</Status>
                <Transition>
                    <Days>10</Days>
                    <StorageClass>THREECOPIES</StorageClass>
                </Transition>
                <Expiration>
                    <Days>60</Days>
                </Expiration>
                <Expiration>
                    <Days>61</Days>
                </Expiration>
                <NoncurrentVersionTransition>
                    <NoncurrentDays>100</NoncurrentDays>
                    <StorageClass>THREECOPIES</StorageClass>
                </NoncurrentVersionTransition>
                <NoncurrentVersionExpiration>
                    <NoncurrentDays>600</NoncurrentDays>
                </NoncurrentVersionExpiration>
                <NoncurrentVersionExpiration>
                    <NoncurrentDays>599</NoncurrentDays>
                </NoncurrentVersionExpiration>
            </Rule>
            """)
        rule = LifecycleRule.from_element(rule_elt)
        self.assertIsNotNone(rule)
        self.assertIsNotNone(rule.id)
        self.assertEqual('Test', rule.id)
        self.assertIsNotNone(rule.filter)
        self.assertFalse(rule.enabled)
        self.assertEqual(4, len(rule.actions))
        expiration = rule.actions[0]
        self.assertEqual(Expiration, type(expiration))
        self.assertEqual(61, expiration.filter.days)
        transition = rule.actions[1]
        self.assertEqual(Transition, type(transition))
        self.assertEqual(10, transition.filter.days)
        self.assertEqual('THREECOPIES', transition.policy)
        expiration = rule.actions[2]
        self.assertEqual(NoncurrentVersionExpiration, type(expiration))
        self.assertEqual(599, expiration.filter.days)
        transition = rule.actions[3]
        self.assertEqual(NoncurrentVersionTransition, type(transition))
        self.assertEqual(100, transition.filter.days)
        self.assertEqual('THREECOPIES', transition.policy)

        rule_elt = etree.XML(
            """
            <Rule>
                <ID>Test</ID>
                <Filter>
                </Filter>
                <Status>Disabled</Status>
                <Transition>
                    <Date>2018-10-15T02:34:56</Date>
                    <StorageClass>THREECOPIES</StorageClass>
                </Transition>
                <Expiration>
                    <Date>2018-10-31T02:34:56</Date>
                </Expiration>
                <Transition>
                    <Date>2018-10-30T02:34:56</Date>
                    <StorageClass>SINGLE</StorageClass>
                </Transition>
            </Rule>
            """)
        rule = LifecycleRule.from_element(rule_elt)
        self.assertIsNotNone(rule)
        self.assertIsNotNone(rule.id)
        self.assertEqual('Test', rule.id)
        self.assertIsNotNone(rule.filter)
        self.assertFalse(rule.enabled)
        self.assertEqual(3, len(rule.actions))
        expiration = rule.actions[0]
        self.assertEqual(Expiration, type(expiration))
        self.assertEqual(1540944000, expiration.filter.date)
        transition = rule.actions[1]
        self.assertEqual(Transition, type(transition))
        self.assertEqual(1540857600, transition.filter.date)
        self.assertEqual('SINGLE', transition.policy)
        transition = rule.actions[2]
        self.assertEqual(Transition, type(transition))
        self.assertEqual(1539561600, transition.filter.date)
        self.assertEqual('THREECOPIES', transition.policy)

    def test_DaysActionFilter_to_string(self):
        EXPECTED = '<Days>10</Days>'
        days = DaysActionFilter(10)
        self.assertEqual(EXPECTED, str(days))

    def test_NoncurrentDaysActionFilter_to_string(self):
        EXPECTED = '<NoncurrentDays>10</NoncurrentDays>'
        days = NoncurrentDaysActionFilter(10)
        self.assertEqual(EXPECTED, str(days))

    def test_DateActionFilter_to_string(self):
        EXPECTED = '<Date>2018-10-31T00:00:00</Date>'
        date = DateActionFilter(1540944000)
        self.assertEqual(EXPECTED, str(date))

    def test_NoncurrentCountActionFilter_to_string(self):
        EXPECTED = '<NoncurrentCount>1</NoncurrentCount>'
        count = NoncurrentCountActionFilter(1)
        self.assertEqual(EXPECTED, str(count))

    def test_Expiration_to_string(self):
        EXPECTED = '<Expiration><Days>10</Days></Expiration>'
        days = DaysActionFilter(10)
        exp = Expiration(days)
        self.assertEqual(EXPECTED, str(exp))

    def test_Transition_to_string(self):
        EXPECTED = '<Transition><StorageClass>SINGLE</StorageClass>' \
            + '<Days>10</Days></Transition>'
        days = DaysActionFilter(10)
        trans = Transition(days, 'SINGLE')
        self.assertEqual(EXPECTED, str(trans))

    def test_NoncurrentVersionExpiration_to_string(self):
        EXPECTED = '<NoncurrentVersionExpiration>' \
            + '<Days>10</Days></NoncurrentVersionExpiration>'
        days = DaysActionFilter(10)
        exp = NoncurrentVersionExpiration(days)
        self.assertEqual(EXPECTED, str(exp))

    def test_NoncurrentVersionTransition_to_string(self):
        EXPECTED = '<NoncurrentVersionTransition>' \
            + '<StorageClass>SINGLE</StorageClass>' \
            + '<Days>10</Days></NoncurrentVersionTransition>'
        days = DaysActionFilter(10)
        trans = NoncurrentVersionTransition(days, 'SINGLE')
        self.assertEqual(EXPECTED, str(trans))

    def test_LifecycleRuleFilter_to_string(self):
        EXPECTED = '<Filter></Filter>'
        filter_ = LifecycleRuleFilter(None, {})
        self.assertEqual(EXPECTED, str(filter_))

        EXPECTED = '<Filter><Prefix>documents/</Prefix></Filter>'
        filter_ = LifecycleRuleFilter('documents/', {})
        self.assertEqual(EXPECTED, str(filter_))

        EXPECTED = '<Filter><Tag><Key>key</Key><Value>value</Value>' \
            + '</Tag></Filter>'
        filter_ = LifecycleRuleFilter(None, {'key': 'value'})
        self.assertEqual(EXPECTED, str(filter_))

        EXPECTED = '<Filter><And>' \
            + '<Prefix>documents/</Prefix>' \
            + '<Tag><Key>key</Key><Value>value</Value></Tag>' \
            + '</And></Filter>'
        filter_ = LifecycleRuleFilter(
            'documents/', {'key': 'value'})
        self.assertEqual(EXPECTED, str(filter_))

    def test_LifecycleRule_to_string(self):
        EXPECTED = '<Rule><ID>Test</ID><Filter></Filter>' \
            + '<Status>Disabled</Status>' \
            + '<Expiration><Days>10</Days></Expiration>' \
            + '</Rule>'
        filter_ = LifecycleRuleFilter(None, {})
        actions = [Expiration(DaysActionFilter(10))]
        rule = LifecycleRule('Test', filter_, False, actions)
        self.assertEqual(EXPECTED, str(rule))

        EXPECTED = '<Rule><ID>Test</ID><Filter></Filter>' \
            + '<Status>Enabled</Status>' \
            + '<Expiration><Days>10</Days></Expiration>' \
            + '</Rule>'
        filter_ = LifecycleRuleFilter(None, {})
        actions = [Expiration(DaysActionFilter(10))]
        rule = LifecycleRule('Test', filter_, True, actions)
        self.assertEqual(EXPECTED, str(rule))

    def test_LifecycleRuleFilter_match(self):
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

        obj_meta = self.obj_meta.copy()
        obj_meta['name'] = 'documents/toto'
        obj_meta['properties'] = {TAGGING_KEY: """
            <Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <TagSet>
                    <Tag>
                        <Key>key1</Key>
                        <Value>value1</Value>
                    </Tag>
                    <Tag>
                        <Key>key2</Key>
                        <Value>value2</Value>
                    </Tag>
                </TagSet>
            </Tagging>
            """}
        self.assertTrue(filter_.match(obj_meta))

        obj_meta = self.obj_meta.copy()
        obj_meta['name'] = 'downloads/toto'
        obj_meta['properties'] = {TAGGING_KEY: """
            <Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <TagSet>
                    <Tag>
                        <Key>key1</Key>
                        <Value>value1</Value>
                    </Tag>
                    <Tag>
                        <Key>key2</Key>
                        <Value>value2</Value>
                    </Tag>
                </TagSet>
            </Tagging>
            """}
        self.assertFalse(filter_.match(obj_meta))

        obj_meta = self.obj_meta.copy()
        obj_meta['name'] = 'documents/toto'
        obj_meta['properties'] = {TAGGING_KEY: """
            <Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <TagSet>
                    <Tag>
                        <Key>key1</Key>
                        <Value>value1</Value>
                    </Tag>
                </TagSet>
            </Tagging>
            """}
        self.assertFalse(filter_.match(obj_meta))

        filter_elt = etree.XML(
            """
            <Filter>
                <And>
                    <Prefix>documents/</Prefix>
                </And>
            </Filter>
            """)
        filter_ = LifecycleRuleFilter.from_element(filter_elt)

        obj_meta = self.obj_meta.copy()
        obj_meta['name'] = 'documents/toto'
        obj_meta['properties'] = {TAGGING_KEY: """
            <Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <TagSet>
                    <Tag>
                        <Key>key1</Key>
                        <Value>value1</Value>
                    </Tag>
                    <Tag>
                        <Key>key2</Key>
                        <Value>value2</Value>
                    </Tag>
                </TagSet>
            </Tagging>
            """}
        self.assertTrue(filter_.match(obj_meta))

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

        obj_meta = self.obj_meta.copy()
        obj_meta['name'] = 'documents/toto'
        obj_meta['properties'] = {TAGGING_KEY: """
            <Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <TagSet>
                    <Tag>
                        <Key>key1</Key>
                        <Value>value1</Value>
                    </Tag>
                    <Tag>
                        <Key>key2</Key>
                        <Value>value2</Value>
                    </Tag>
                </TagSet>
            </Tagging>
            """}
        self.assertTrue(filter_.match(obj_meta))

    def test_DaysActionFilter_match(self):
        days_elt = etree.XML("<Days>1</Days>")
        days = DaysActionFilter.from_element(days_elt)
        self.assertIsNotNone(days)
        self.assertEqual(days.days, 1)

        obj_meta = self.obj_meta.copy()
        self.assertTrue(days.match(obj_meta))

        obj_meta['mtime'] = time.time()
        self.assertFalse(days.match(obj_meta))

    def test_DateActionFilter_match(self):
        date_elt = etree.XML(
            "<Date>2006-08-14T02:34:56</Date>")
        date = DateActionFilter.from_element(date_elt)
        self.assertIsNotNone(date)
        self.assertEqual(date.date, 1155513600)
        self.assertTrue(date.match(self.obj_meta))

        date_elt = etree.XML(
            "<Date>%s</Date>" %
            time.strftime("%Y-%m-%dT%H:%M:%S",
                          time.localtime(time.time() + 86400)))
        date = DateActionFilter.from_element(date_elt)
        self.assertFalse(date.match(self.obj_meta))

    def test_LifecycleRule_match(self):
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
                <NoncurrentVersionTransition>
                    <NoncurrentDays>1</NoncurrentDays>
                    <StorageClass>THREECOPIES</StorageClass>
                </NoncurrentVersionTransition>
                <NoncurrentVersionExpiration>
                    <NoncurrentDays>60</NoncurrentDays>
                </NoncurrentVersionExpiration>
            </Rule>
            """)
        rule = LifecycleRule.from_element(rule_elt)
        obj_meta = self.obj_meta.copy()
        self.assertFalse(rule.match(obj_meta))
        obj_meta['name'] = "documents/foo"
        self.assertFalse(rule.match(obj_meta))
        obj_meta['properties'][TAGGING_KEY] = """
            <Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <TagSet>
                    <Tag>
                        <Key>key1</Key>
                        <Value>value1</Value>
                    </Tag>
                </TagSet>
            </Tagging>
            """
        self.assertFalse(rule.match(obj_meta))
        obj_meta['properties'][TAGGING_KEY] = """
            <Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <TagSet>
                    <Tag>
                        <Key>key1</Key>
                        <Value>value1</Value>
                    </Tag>
                    <Tag>
                        <Key>key2</Key>
                        <Value>value2</Value>
                    </Tag>
                </TagSet>
            </Tagging>
            """
        self.assertTrue(rule.match(obj_meta))
