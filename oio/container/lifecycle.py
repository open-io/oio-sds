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

try:
    from lxml import etree
except ImportError:
    from xml.etree import cElementTree as etree

from oio.common.logger import get_logger
from oio.common.utils import cid_from_name


LIFECYCLE_PROPERTY_KEY = "X-Container-Sysmeta-Swift3-Lifecycle"


def iso8601_to_int(text):
    # FIXME: use dateutil.parser?
    return int(time.mktime(time.strptime(text, "%Y-%m-%dT%H:%M:%S")))


class ContainerLifecycle(object):

    def __init__(self, account, container, logger=None):
        self.account = account
        self.container = container
        self.logger = logger or get_logger(None, name=str(self.__class__))
        self._rules = dict()

    def load(self, api):
        """
        Load lifecycle rules from container property.
        """
        props = api.container_get_properties(self.account, self.container)
        xml_str = props['properties'].get(LIFECYCLE_PROPERTY_KEY)
        if xml_str:
            self.load_xml(xml_str, api)
        else:
            self.logger.info("No Lifecycle configuration for %s/%s",
                             self.account, self.container)

    def load_xml(self, xml_str, api=None):
        """
        Load lifecycle rules from LifecycleConfiguration XML document.
        """
        tree = etree.fromstring(xml_str)
        if tree.tag != 'LifecycleConfiguration':
            raise ValueError(
                "Expected 'LifecycleConfiguration' as root tag, got '%s'" %
                tree.tag)
        for rule_elt in tree.findall('Rule'):
            rule = LifecycleRule.from_element(rule_elt, api=api)
            self._rules[rule.id] = rule

    def apply(self, obj_meta, **kwargs):
        """
        Match then apply the set of rules of this lifecycle configuration
        on the specified object.
        """
        for rule in self._rules.values():
            rule.apply(self.account, self.container, obj_meta, **kwargs)
        # TODO: return something useful

    def execute(self, **kwargs):
        """
        Match then apply the set of rules of the lifecycle configuration
        on all objects of the container.
        """
        # TODO: implement


class LifecycleRule(object):
    """Combination of a filter and a set of lifecycle actions."""

    def __init__(self, filter_, id_=None, enabled=True, abort_multipart=None,
                 actions=None):
        self.filter = filter_
        self.id = id_ or self.filter.generate_id()
        self.enabled = enabled
        self.abort_multipart = abort_multipart
        self.actions = actions or dict()

    @classmethod
    def from_element(cls, rule_elt, api=None):
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
        actions = {name: action_from_element(element, api=api)
                   for name, element in {k: rule_elt.find(k)
                                         for k in ACTION_MAP.keys()}.items()
                   if element is not None}
        if not actions:
            raise ValueError("Missing one of %s" % ACTION_MAP.keys())
        return cls(rule_filter, id_=id_,
                   enabled=(status_elt.text.lower() == "enabled"),
                   actions=actions)

    def match(self, obj_meta, **kwargs):
        """
        Check if the specified object passes the filter of this rule.
        """
        if not self.filter.match(obj_meta):
            return False
        for action in self.actions.values():
            if action.match(obj_meta, **kwargs):
                return True
        return False

    def apply(self, account, container, obj_meta, **kwargs):
        """
        Apply the set of actions of this rule.
        """
        if self.filter.match(obj_meta):
            for action in self.actions.values():
                action.apply(account, container, obj_meta, **kwargs)


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
    def from_element(cls, filter_elt, **kwargs):
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

        return cls(prefix=prefix, tags=tags, **kwargs)

    def generate_id(self):
        """Generate a rule ID from prefix and/or tags."""
        parts = list()
        if self.prefix:
            parts.append('prefix=%s' % self.prefix)
        for kv in sorted(self.tags.items(), key=lambda x: x[0]):
            parts.append('='.join(kv))
        return ','.join(parts)

    def match(self, obj_meta, **kwargs):
        """
        Check if an object matches the conditions defined by this filter.
        """
        if self.prefix and not obj_meta['name'].startswith(self.prefix):
            return False
        for tagk in self.tags.keys():
            if obj_meta['properties'].get(tagk) != self.tags[tagk]:
                return False
        return True


class LifecycleAction(object):
    """Interface for Lifecycle actions"""

    def __init__(self, api=None, **_kwargs):
        self.api = api

    def match(self, obj_meta, now=None, **kwargs):
        """
        Check if an object matches the age and version conditions
        for expiration.
        """
        raise NotImplementedError

    def apply(self, account, container, obj_meta, **kwargs):
        """
        Match then apply the treatment on the object.
        """
        raise NotImplementedError


# TODO: implement AbortIncompleteMultipartUpload


class DelayExpiration(LifecycleAction):
    """Delete objects after a delay after their creation time."""

    DAYS_XML_TAG = 'Days'

    def __init__(self, days=None, api=None):
        super(DelayExpiration, self).__init__(api)
        self.days = days

    @classmethod
    def from_element(cls, expiration_elt, **kwargs):
        """
        Load the expiration from an XML element

        :type expiration_elt: `lxml.etree.Element`
        """
        days_elt = expiration_elt.find(cls.DAYS_XML_TAG)
        if days_elt is None:
            raise ValueError("Missing '%s' element in '%s'" %
                             (cls.DAYS_XML_TAG, expiration_elt.tag))
        days = int(days_elt.text)
        return cls(days=days, **kwargs)

    def match(self, obj_meta, now=None, **kwargs):
        """
        Check if an object matches the age condition for expiration.
        """
        now = now or time.time()
        return float(obj_meta['ctime']) + self.days * 86400 < now

    def apply(self, account, container, obj_meta, **kwargs):
        if self.match(obj_meta, **kwargs):
            return self.api.object_delete(account, container, obj_meta['name'],
                                          version=obj_meta.get('version'))
        return False


class Expiration(DelayExpiration):
    """Delete objects older than a specified date or delay."""

    DATE_XML_TAG = 'Date'

    def __init__(self, days=None, date=None, api=None):
        if days is not None and date is not None:
            raise ValueError(
                "'days' and 'date' cannot be provided at the same time")
        super(Expiration, self).__init__(days, api)
        if date is not None:
            self.date = (int(date) - (int(date) % 86400))
        else:
            self.date = None

    @classmethod
    def from_element(cls, expiration_elt, **kwargs):
        """
        Load the expiration from an XML element

        :type expiration_elt: `lxml.etree.Element`
        """
        days_elt = expiration_elt.find(cls.DAYS_XML_TAG)
        date_elt = expiration_elt.find(cls.DATE_XML_TAG)
        if days_elt is None and date_elt is None:
            raise ValueError(
                "Missing '%s' or '%s' element in '%s'" %
                (cls.DAYS_XML_TAG, cls.DATE_XML_TAG, expiration_elt.tag))
        days = int(days_elt.text) if days_elt is not None else None
        date = (iso8601_to_int(date_elt.text)
                if date_elt is not None
                else None)
        # TODO: ExpiredObjectDeleteMarker
        return cls(days=days, date=date, **kwargs)

    def match(self, obj_meta, now=None, **kwargs):
        """
        Check if an object matches the age condition for expiration.
        """
        now = now or time.time()
        if self.date is not None:
            return now > self.date

        return super(Expiration, self).match(obj_meta, now=now, **kwargs)


class Transition(Expiration):
    """Change object storage policy after a specified delay or date."""

    def __init__(self, policy=None, days=None, date=None, api=None):
        super(Transition, self).__init__(days=days, date=date, api=api)
        if policy is None:
            raise ValueError("'policy' must be specified")
        self.policy = policy
        if self.api:
            from oio.content.factory import ContentFactory
            self.factory = ContentFactory(api.container.conf,
                                          api.container)
        else:
            self.factory = None

    @classmethod
    def from_element(cls, transition_elt, **kwargs):
        stgcls_elt = transition_elt.find('StorageClass')
        if stgcls_elt is None:
            raise ValueError("Missing 'StorageClass' element in 'Transition'")
        sup_from_elt = getattr(super(Transition, cls), 'from_element')
        return sup_from_elt.__func__(cls, transition_elt,
                                     policy=stgcls_elt.text,
                                     **kwargs)

    def apply(self, account, container, obj_meta, **kwargs):
        if self.match(obj_meta, **kwargs):
            cid = cid_from_name(account, container)
            if not self.factory:
                return False
            # TODO: avoid loading content description a second time
            self.factory.change_policy(cid, obj_meta['id'], self.policy)
            return True
        return False


class NoncurrentAction(LifecycleAction):
    """
    An action to be executed on all versions of an object,
    except the latest.
    """

    def apply(self, account, container, obj_meta, **kwargs):
        if self.match(obj_meta, **kwargs):
            # Load the description of the latest object version
            # TODO: use a cache to avoid requesting each time
            descr = self.api.object_show(account, container,
                                         obj_meta['name'])
            if descr['version'] != obj_meta['version']:
                # Object is not the latest version, we can apply the treatment
                return super(NoncurrentAction, self).apply(
                    account, container, obj_meta, **kwargs)
        return False


class NoncurrentVersionExpiration(NoncurrentAction, DelayExpiration):
    """Delete objects old versions after a defined number of days."""

    DAYS_XML_TAG = 'NoncurrentDays'


class NoncurrentVersionTransition(NoncurrentAction, Transition):
    """
    Change object storage policy after a specified delay,
    for old versions of the object only.
    """

    DAYS_XML_TAG = 'NoncurrentDays'


ACTION_MAP = {a.__name__: a for a in
              (Expiration,
               Transition,
               NoncurrentVersionExpiration,
               NoncurrentVersionTransition)}


def action_from_element(element, api=None, **kwargs):
    """
    Create a new `LifecycleAction` subclass instance from an XML description.

    :param element: the XML description of the action
    :type element: `Element`
    """
    return ACTION_MAP[element.tag].from_element(element, api=api, **kwargs)
