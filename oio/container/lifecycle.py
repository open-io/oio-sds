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
from functools import partial

# TODO(FVE): try/except, import xml.etree.cElementTree as etree
from lxml import etree

from oio.common.utils import get_logger


def iso8601_to_int(text):
    # FIXME: use dateutil.parser?
    return int(time.mktime(time.strptime(text, "%Y-%m-%dT%H:%M:%S")))


class ContainerLifecycle(object):

    def __init__(self, account, container, logger=None):
        self.account = account
        self.container = container
        self.logger = logger or get_logger(str(self.__class__))
        self._rules = dict()

    def load_xml(self, xml_str):
        """
        Load lifecycle rules from LifecycleConfiguration XML document.
        """
        tree = etree.fromstring(xml_str)
        if tree.tag != 'LifecycleConfiguration':
            raise ValueError(
                "Expected 'LifecycleConfiguration' as root tag, got '%s'" %
                tree.tag)
        for rule_elt in tree.findall('Rule'):
            rule = LifecycleRule.from_element(rule_elt)
            self._rules[rule.id] = rule


class LifecycleRule(object):
    """Combination of a filter and a set of lifecycle actions."""

    def __init__(self, filter_, id_=None, enabled=True, abort_multipart=None,
                 expiration=None, non_current_expiration=None,
                 non_current_transition=None, transition=None):
        self.filter = filter_
        self.id = id_ or self.filter.generate_id()
        self.enabled = enabled
        self.abort_multipart = abort_multipart
        self.expiration = expiration
        self.non_current_expiration = non_current_expiration
        self.non_current_transition = non_current_transition
        self.transition = transition

    @classmethod
    def from_element(cls, rule_elt):
        """
        Load the rule from an XML element.

        :type rule_elt: `lxml.etree.Element`
        """
        filter_elt = rule_elt.find('Filter')
        if filter_elt is None:
            raise ValueError("Missing 'Filter' element")
        rule_filter = LifecycleRuleFilter.from_element(filter_elt)
        id_elt = rule_elt.find('./ID')
        id_ = id_elt.text if id_elt is not None else None
        status_elt = rule_elt.find('Status')
        if status_elt is None:
            raise ValueError("Missing 'Status' element")
        exp_elt = rule_elt.find('Expiration')
        trans_elt = rule_elt.find('Transition')
        nce_elt = rule_elt.find('NoncurrentVersionExpiration')
        nct_elt = rule_elt.find('NoncurrentVersionTransition')
        if all(x is None for x in [exp_elt, trans_elt, nce_elt, nct_elt]):
            raise ValueError("Missing one of 'Expiration', 'Transition', "
                             "'NoncurrentVersionExpiration' or "
                             "'NoncurrentVersionTransition'")
        return cls(rule_filter, id_=id_,
                   enabled=(status_elt.text.lower() == "enabled"),
                   expiration=exp_elt, transition=trans_elt,
                   non_current_expiration=nce_elt,
                   non_current_transition=nct_elt)

    def match(self, obj_meta):
        """
        Check if the specified object passes the filter of this rule.
        """
        return self.filter(obj_meta)


class LifecycleRuleFilter(object):
    """Filter to determine on which objects to apply a lifecycle rule."""

    def __init__(self, prefix=None, tags=None):
        """
        :param prefix: prefix that objects must have to pass this filter
        :type prefix: `basestring`
        :param tags: tags that objects must have to pass this filter
        :type tags: `dict`
        """
        self.prefix = prefix
        self.tags = tags or dict()

    @classmethod
    def from_element(cls, filter_elt):
        """
        Load the filter from an XML element.

        :type filter_elt: `lxml.etree.Element`
        """
        prefix_elt = filter_elt.find('.//Prefix')
        prefix = prefix_elt.text if prefix_elt is not None else None

        tags = dict()
        for tag_elt in filter_elt.findall('.//Tag'):
            key_elt = tag_elt.find('Key')
            if key_elt is None:
                raise ValueError("Missing 'Key' element in 'Tag'")
            val_elt = tag_elt.find('Value')
            if val_elt is None:
                raise ValueError("Missing 'Value' element in 'Tag' (key=%s)" %
                                 key_elt.text)
            tags[key_elt.text] = val_elt.text

        return cls(prefix=prefix, tags=tags)

    def generate_id(self):
        """Generate a rule ID from prefix and/or tags."""
        parts = list()
        if self.prefix:
            parts.append('prefix=%s' % self.prefix)
        for kv in sorted(self.tags.items(), key=lambda x: x[0]):
            parts.append('='.join(kv))
        return ','.join(parts)

    def match(self, obj_meta):
        """
        Check if an object matches the conditions defined by this filter.
        """
        raise NotImplementedError


class Expiration(object):
    """Delete objects older than an specified date or delay."""

    def __init__(self, days=None, date=None):
        self.days = days
        self.date = date
        if days is not None and date is not None:
            raise ValueError(
                "'days' and 'date' cannot be provided at the same time")

    @classmethod
    def from_element(cls, expiration_elt):
        """
        Load the expiration from an XML element

        :type expiration_elt: `lxml.etree.Element`
        """
        days_elt = expiration_elt.find('Days')
        date_elt = expiration_elt.find('Date')
        # TODO: ExpiredObjectDeleteMarker
        if days_elt is None and date_elt is None:
            raise ValueError(
                "Missing 'Days' or 'Date' element in 'Expiration'")
        days = int(days_elt.text) if days_elt is not None else None
        date = (iso8601_to_int(date_elt.text)
                if date_elt is not None
                else None)
        return cls(days=days, date=date)

    def match(self, obj_meta):
        """
        Check if an object matches the age condition for expiration.
        """
        now = time.time()
        if self.date and now > self.date:
            return True

        return obj_meta['ctime'] + self.days * 86400 < now


class Transition(Expiration):
    """Change object storage policy after a specified delay or date."""

    def __init__(self, policy, days=None, date=None):
        super(Transition, self).__init__(days=days, date=date)
        self.policy = policy

    @classmethod
    def from_element(cls, transition_elt):
        stgcls_elt = transition_elt.find('StorageClass')
        if stgcls_elt is None:
            raise ValueError("Missing 'StorageClass' element in 'Transition'")
        sup_from_elt = getattr(super(Transition, cls), 'from_element')
        return sup_from_elt.__func__(partial(cls, policy=stgcls_elt.text),
                                     transition_elt)
