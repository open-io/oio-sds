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

from oio.common.exceptions import OioException
from oio.common.logger import get_logger
from oio.common.utils import cid_from_name, depaginate


LIFECYCLE_PROPERTY_KEY = "X-Container-Sysmeta-Swift3-Lifecycle"
TAGGING_KEY = "x-object-sysmeta-swift3-tagging"
XMLNS_S3 = 'http://s3.amazonaws.com/doc/2006-03-01/'


def iso8601_to_int(text):
    # FIXME: use dateutil.parser?
    return int(time.mktime(time.strptime(text, "%Y-%m-%dT%H:%M:%S")))


class ContainerLifecycle(object):

    def __init__(self, api, account, container, logger=None):
        self.api = api
        self.account = account
        self.container = container
        self.logger = logger or get_logger(None, name=str(self.__class__))
        self._rules = dict()
        self.src_xml = None

    def load(self):
        """
        Load lifecycle rules from container property.

        :returns: True if a lifecycle configuration has been loaded
        """
        props = self.api.container_get_properties(self.account, self.container)
        xml_str = props['properties'].get(LIFECYCLE_PROPERTY_KEY)
        if xml_str:
            self.load_xml(xml_str)
            return True
        else:
            self.logger.info("No Lifecycle configuration for %s/%s",
                             self.account, self.container)
            return False

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
            rule = LifecycleRule.from_element(rule_elt, lifecycle=self)
            self._rules[rule.id] = rule
        self.src_xml = xml_str

    def save(self, xml_str=None):
        """
        Save the lifecycle configuration in container property.

        :param xml_str: the configuration to save, or None to save the
        configuration that has been loaded previously
        :type xml_str: `str`
        """
        xml_str = xml_str or self.src_xml
        if not xml_str:
            raise ValueError('You must call `load_xml()` or provide `xml_str`'
                             ' parameter before saving')
        self.api.container_set_properties(
            self.account, self.container,
            properties={LIFECYCLE_PROPERTY_KEY: xml_str})

    def apply(self, obj_meta, **kwargs):
        """
        Match then apply the set of rules of this lifecycle configuration
        on the specified object.

        :returns: tuples of (object metadata, rule name, action, status)
        :rtype: generator of 4-tuples

        :notice: you must consume the results or the rules won't be applied.
        """
        for rule in self._rules.values():
            res = rule.apply(obj_meta, **kwargs)
            if res:
                for action in res:
                    yield obj_meta, rule.id, action[0], action[1]
            else:
                yield obj_meta, rule.id, "n/a", "n/a"

    def execute(self, **kwargs):
        """
        Match then apply the set of rules of the lifecycle configuration
        on all objects of the container.

        :returns: tuples of (object metadata, rule name, action, status)
        :rtype: generator of 4-tuples
        :notice: you must consume the results or the rules won't be applied.
        """
        for obj_meta in depaginate(
                self.api.object_list,
                listing_key=lambda x: x['objects'],
                marker_key=lambda x: x.get('next_marker'),
                truncated_key=lambda x: x['truncated'],
                account=self.account,
                container=self.container,
                properties=True,
                versions=True,
                **kwargs):
            try:
                results = self.apply(obj_meta, **kwargs)
                for res in results:
                    yield res
            except Exception as exc:
                self.logger.warn(
                        "Failed to apply lifecycle rules on %s/%s/%s: %s",
                        self.account, self.container, obj_meta['name'], exc)
                yield obj_meta, "n/a", "n/a", exc


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
    def from_element(cls, rule_elt, lifecycle=None):
        """
        Load the rule from an XML element.

        :type rule_elt: `lxml.etree.Element`
        """
        filter_elt = rule_elt.find('Filter')
        if filter_elt is None:
            raise ValueError("Missing 'Filter' element")
        rule_filter = LifecycleRuleFilter.from_element(filter_elt)
        id_elt = rule_elt.find('ID')
        id_ = id_elt.text if id_elt is not None else None
        status_elt = rule_elt.find('Status')
        if status_elt is None:
            raise ValueError("Missing 'Status' element")
        actions = {name: action_from_element(element, lifecycle=lifecycle)
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
        return self.filter.match(obj_meta)

    def apply(self, obj_meta, **kwargs):
        """
        Apply the set of actions of this rule.

        :returns: the list of actions that have been applied
        :rtype: `list` of `tuple` of a class and a bool or
            a class and an exception instance
        """
        results = list()
        if self.enabled and self.match(obj_meta):
            for action in self.actions.values():
                try:
                    res = action.apply(obj_meta, **kwargs)
                    results.append((action.__class__.__name__, res))
                except OioException as exc:
                    results.append((action.__class__.__name__, exc))
        return results


class LifecycleRuleFilter(object):
    """Filter to determine on which objects to apply a lifecycle rule."""

    _rule_number = 0

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
        and_elt = filter_elt.find('And')
        if and_elt is None:
            if len(list(filter_elt)) > 1:
                raise ValueError("Too many filters, use <And>")
        else:
            filter_elt = and_elt
        prefix_elts = filter_elt.findall('Prefix')
        if len(prefix_elts) == 0:
            prefix = None
        elif len(prefix_elts) > 1:
            raise ValueError("Too many prefixes, only one is allowed")
        else:
            prefix = prefix_elts[0].text
        tags = cls._convert_tags_elt_to_tags_dict(filter_elt)
        return cls(prefix=prefix, tags=tags, **kwargs)

    def generate_id(self):
        """Generate a rule ID from prefix and/or tags."""
        parts = list()
        if self.prefix:
            parts.append('prefix=%s' % self.prefix)
        for kv in sorted(self.tags.items(), key=lambda x: x[0]):
            parts.append('='.join(kv))
        if not parts:
            id_ = self.__class__._rule_number
            self.__class__._rule_number += 1
            return "anonymous-rule-%s" % id_
        return ','.join(parts)

    def match(self, obj_meta, **kwargs):
        """
        Check if an object matches the conditions defined by this filter.
        """
        # Check the prefix
        if self.prefix and not obj_meta['name'].startswith(self.prefix):
            return False

        # Check the tags
        if self.tags:
            tags = dict()
            tagging_xml = obj_meta.get('properties', {}).get(TAGGING_KEY, None)
            if tagging_xml is not None:
                tagging_elt = etree.fromstring(tagging_xml)
                expected_tag = 'Tagging'
                root_ns = tagging_elt.nsmap.get(None)
                if root_ns is not None:
                    expected_tag = '{%s}%s' % (root_ns, expected_tag)
                if tagging_elt.tag != expected_tag:
                    raise ValueError(
                        "Expected 'Tagging' as root tag, got '%s'" %
                        tagging_elt.tag)
                tags_elt = tagging_elt.find('TagSet', tagging_elt.nsmap)
                if tags_elt is None:
                    raise ValueError("Missing 'TagSet' element in 'Tagging'")
                tags = self._convert_tags_elt_to_tags_dict(tags_elt)
            for tagk in self.tags.keys():
                if tags.get(tagk) != self.tags[tagk]:
                    return False

        return True

    @staticmethod
    def _convert_tags_elt_to_tags_dict(tags_elt):
        tags = dict()
        for tag_elt in tags_elt.findall('Tag', tags_elt.nsmap):
            key_elt = tag_elt.find('Key', tags_elt.nsmap)
            if key_elt is None:
                raise ValueError("Missing 'Key' element in 'Tag'")
            val_elt = tag_elt.find('Value', tags_elt.nsmap)
            if val_elt is None:
                raise ValueError("Missing 'Value' element in 'Tag' (key=%s)" %
                                 key_elt.text)
            tags[key_elt.text] = val_elt.text
        return tags


class LifecycleActionFilter(object):
    """
    Specify conditions when the specific rule action takes effect.
    """

    def __init__(self, lifecycle=None, **kwargs):
        self.lifecycle = lifecycle

    def match(self, obj_meta, now=None, **kwargs):
        """
        Check if an object matches the conditions.
        """
        raise NotImplementedError


class DaysActionFilter(LifecycleActionFilter):
    """
    Specify the number of days after object creation
    when the specific rule action takes effect.
    """

    XML_TAG = 'Days'

    def __init__(self, days_elt, **kwargs):
        super(DaysActionFilter, self).__init__(**kwargs)
        self.days = int(days_elt.text)

    def match(self, obj_meta, now=None, **kwargs):
        now = now or time.time()
        return float(obj_meta['ctime']) + self.days * 86400 < now


class DateActionFilter(LifecycleActionFilter):
    """
    Specify the date when the specific rule action takes effect.
    """

    XML_TAG = 'Date'

    def __init__(self, date_elt, **kwargs):
        super(DateActionFilter, self).__init__(**kwargs)
        date = iso8601_to_int(date_elt.text)
        self.date = (date - (date % 86400))

    def match(self, obj_meta, now=None, **kwargs):
        now = now or time.time()
        return now > self.date


class CountActionFilter(LifecycleActionFilter):

    XML_TAG = 'Count'

    def __init__(self, count_elt, **kwargs):
        super(CountActionFilter, self).__init__(**kwargs)
        count = int(count_elt.text)
        if count < 0:
            raise ValueError(
                "The count must be greater than or equal to zero.")
        self.count = count


class LifecycleAction(LifecycleActionFilter):
    """
    Interface for Lifecycle actions.
    """

    def __init__(self, filter, **kwargs):
        super(LifecycleAction, self).__init__(**kwargs)
        self.filter = filter

    def match(self, obj_meta, now=None, **kwargs):
        if self.filter is None:
            return True
        return self.filter.match(obj_meta, now=now, **kwargs)

    def apply(self, obj_meta, **kwargs):
        """
        Match then apply the treatment on the object.
        """
        raise NotImplementedError


# TODO: implement AbortIncompleteMultipartUpload


class Expiration(LifecycleAction):
    """
    Delete objects.
    """

    def apply(self, obj_meta, **kwargs):
        if self.match(obj_meta, **kwargs):
            res = self.lifecycle.api.object_delete(
                self.lifecycle.account, self.lifecycle.container,
                obj_meta['name'], version=obj_meta.get('version'))
            return "Deleted" if res else "Kept"
        return "Kept"

    @classmethod
    def from_element(cls, expiration_elt, **kwargs):
        """
        Load the expiration from an XML element

        :type expiration_elt: `lxml.etree.Element`
        """
        days_elt = expiration_elt.find(DaysExpiration.XML_TAG)
        date_elt = expiration_elt.find(DateExpiration.XML_TAG)
        if not ((days_elt is None) ^ (date_elt is None)):
            raise ValueError(
                "Missing '%s' or '%s' element in '%s'" %
                (DaysExpiration.XML_TAG, DateExpiration.XML_TAG,
                 expiration_elt.tag))

        if days_elt is not None:
            return DaysExpiration(days_elt, **kwargs)

        if date_elt is not None:
            return DateExpiration(date_elt, **kwargs)


class DaysExpiration(Expiration):
    """
    Delete objects older than a specified delay.
    """

    XML_TAG = DaysActionFilter.XML_TAG

    def __init__(self, days_elt, **kwargs):
        filter = DaysActionFilter(days_elt, **kwargs)
        super(DaysExpiration, self).__init__(filter, **kwargs)


class DateExpiration(Expiration):
    """
    Delete objects from the specified date.
    """

    XML_TAG = DateActionFilter.XML_TAG

    def __init__(self, date_elt, **kwargs):
        filter = DateActionFilter(date_elt, **kwargs)
        super(DateExpiration, self).__init__(filter, **kwargs)


class Transition(LifecycleAction):
    """
    Change object storage policy.
    """

    XML_POLICY = 'StorageClass'

    def __init__(self, filter, policy_elt, **kwargs):
        super(Transition, self).__init__(filter, **kwargs)
        self.policy = policy_elt.text
        if self.lifecycle and self.lifecycle.api:
            from oio.content.factory import ContentFactory
            self.factory = ContentFactory(self.lifecycle.api.container.conf,
                                          self.lifecycle.api.container)
        else:
            self.factory = None

    def apply(self, obj_meta, **kwargs):
        if self.match(obj_meta, **kwargs):
            cid = cid_from_name(self.lifecycle.account,
                                self.lifecycle.container)
            if not self.factory:
                return "Kept"
            # TODO: avoid loading content description a second time
            self.factory.change_policy(cid, obj_meta['id'], self.policy)
            return "Policy changed to %s" % self.policy
        return "Kept"

    @classmethod
    def from_element(cls, transition_elt, **kwargs):
        policy_elt = transition_elt.find(cls.XML_POLICY)
        if policy_elt is None:
            raise ValueError("Missing '%s' element in '%s'" %
                             (cls.XML_POLICY, transition_elt.tag))

        days_elt = transition_elt.find(DaysTransition.XML_TAG)
        date_elt = transition_elt.find(DateTransition.XML_TAG)
        if not ((days_elt is None) ^ (date_elt is None)):
            raise ValueError(
                "Missing '%s' or '%s' element in '%s'" %
                (DaysTransition.XML_TAG, DateTransition.XML_TAG,
                 transition_elt.tag))

        if days_elt is not None:
            return DaysTransition(days_elt, policy_elt, **kwargs)

        if date_elt is not None:
            return DateTransition(date_elt, policy_elt, **kwargs)


class DaysTransition(Transition):
    """
    Change object storage policy after a specified delay.
    """

    XML_TAG = DaysActionFilter.XML_TAG

    def __init__(self, days_elt, policy_elt, **kwargs):
        filter = DaysActionFilter(days_elt, **kwargs)
        super(DaysTransition, self).__init__(filter, policy_elt, **kwargs)


class DateTransition(Transition):
    """
    Change object storage policy from the specified date.
    """

    XML_TAG = DateActionFilter.XML_TAG

    def __init__(self, date_elt, policy_elt, **kwargs):
        filter = DateActionFilter(date_elt, **kwargs)
        super(DateTransition, self).__init__(filter, policy_elt, **kwargs)


class NoncurrentVersionActionFilter(LifecycleActionFilter):
    """
    Apply the action on all versions of an obejct, except the latest.
    """

    def __init__(self, **kwargs):
        super(NoncurrentVersionActionFilter, self).__init__(**kwargs)
        self.versioning = None

    def _match(self, obj_meta, now=None, **kwargs):
        """
        Check if versioning is enabled.
        """
        if self.versioning is None:
            data = self.lifecycle.api.container_get_properties(
                self.lifecycle.account, self.lifecycle.container)
            sys = data['system']
            version = sys.get('sys.m2.policy.version', None)
            if version is None:
                from oio.common.client import ProxyClient
                proxy_client = ProxyClient(
                    {"namespace": self.lifecycle.api.namespace},
                    no_ns_in_url=True)
                _, data = proxy_client._request('GET', "config")
                version = data['meta2.max_versions']
            version = int(version)
            self.versioning = version > 1 or version < 0
        return self.versioning

    def match(self, obj_meta, now=None, **kwargs):
        if self._match(obj_meta, now=now, **kwargs):
            # Load the description of the latest object version
            # TODO: use a cache to avoid requesting each time
            descr = self.lifecycle.api.object_show(self.lifecycle.account,
                                                   self.lifecycle.container,
                                                   obj_meta['name'])
            return str(descr['version']) != str(obj_meta['version'])
        return False


class NoncurrentVersionExpiration(Expiration):
    """
    Delete objects old versions.
    """

    def __init__(self, filter, **kwargs):
        super(NoncurrentVersionExpiration, self).__init__(filter, **kwargs)
        self.noncurrent_version = NoncurrentVersionActionFilter(**kwargs)

    def match(self, obj_meta, now=None, **kwargs):
        if self.noncurrent_version.match(obj_meta, now=now, **kwargs):
            return super(NoncurrentVersionExpiration, self).match(
                obj_meta, now=now, **kwargs)
        return False

    @classmethod
    def from_element(cls, expiration_elt, **kwargs):
        days_elt = expiration_elt.find(NoncurrentDaysExpiration.XML_TAG)
        count_elt = expiration_elt.find(
            NoncurrentCountExpiration.XML_TAG)
        if not ((days_elt is None) ^ (count_elt is None)):
            raise ValueError(
                "Missing '%s' or '%s' element in '%s'" %
                (NoncurrentDaysExpiration.XML_TAG,
                 NoncurrentCountExpiration.XML_TAG,
                 expiration_elt.tag))

        if days_elt is not None:
            return NoncurrentDaysExpiration(days_elt, **kwargs)

        if count_elt is not None:
            return NoncurrentCountExpiration(count_elt, **kwargs)


class NoncurrentDaysExpiration(NoncurrentVersionExpiration):
    """
    Delete objects old versions after a specified delay.
    """

    XML_TAG = 'NoncurrentDays'

    def __init__(self, days_elt, **kwargs):
        filter = DaysActionFilter(days_elt, **kwargs)
        super(NoncurrentDaysExpiration, self).__init__(filter, **kwargs)


class NoncurrentCountExpiration(NoncurrentVersionExpiration):
    """
    Delete exceeding versions, and keep a maximum number of versions.
    """

    XML_TAG = 'NoncurrentCount'

    def __init__(self, count_elt, **kwargs):
        filter = CountActionFilter(count_elt, **kwargs)
        super(NoncurrentCountExpiration, self).__init__(filter, **kwargs)
        self.last_object_name = None

    def match(self, obj_meta, now=None, **kwargs):
        return self.noncurrent_version._match(obj_meta, now=now, **kwargs)

    def apply(self, obj_meta, **kwargs):
        if self.match(obj_meta, **kwargs):
            object_name = obj_meta['name']
            if object_name != self.last_object_name:
                self.lifecycle.api.container.content_purge(
                    self.lifecycle.account, self.lifecycle.container,
                    object_name, maxvers=self.filter.count+1)
                self.last_object_name = object_name
            if not self.lifecycle.api.object_head(self.lifecycle.account,
                                                  self.lifecycle.container,
                                                  object_name,
                                                  version=obj_meta['version']):
                return "Deleted"
        return "Kept"


class NoncurrentVersionTransition(Transition):
    """
    Change object storage policy for old versions of the object only.
    """

    def __init__(self, filter, policy_elt, **kwargs):
        super(NoncurrentVersionTransition, self).__init__(
            filter, policy_elt, **kwargs)
        self.noncurrent = NoncurrentVersionActionFilter(**kwargs)

    def match(self, obj_meta, now=None, **kwargs):
        if self.noncurrent.match(obj_meta, now=now, **kwargs):
            return super(NoncurrentVersionTransition, self).match(
                obj_meta, now=now, **kwargs)
        return False

    @classmethod
    def from_element(cls, transition_elt, **kwargs):
        policy_elt = transition_elt.find(cls.XML_POLICY)
        if policy_elt is None:
            raise ValueError("Missing '%s' element in '%s'" %
                             (cls.XML_POLICY, transition_elt.tag))

        days_elt = transition_elt.find(NoncurrentDaysTransition.XML_TAG)
        if days_elt is None:
            raise ValueError(
                "Missing '%s' element in '%s'" %
                (NoncurrentDaysTransition.XML_TAG, transition_elt.tag))

        return NoncurrentDaysTransition(days_elt, policy_elt, **kwargs)


class NoncurrentDaysTransition(NoncurrentVersionTransition):
    """
    Change object storage policy after a specified delay,
    for old versions of the object only.
    """

    XML_TAG = 'NoncurrentDays'

    def __init__(self, days_elt, policy_elt, **kwargs):
        filter = DaysActionFilter(days_elt, **kwargs)
        super(NoncurrentDaysTransition, self).__init__(
            filter, policy_elt, **kwargs)


ACTION_MAP = {a.__name__: a for a in
              (Expiration,
               Transition,
               NoncurrentVersionExpiration,
               NoncurrentVersionTransition)}


def action_from_element(element, **kwargs):
    """
    Create a new `LifecycleAction` subclass instance from an XML description.

    :param element: the XML description of the action
    :type element: `Element`
    """
    return ACTION_MAP[element.tag].from_element(element, **kwargs)
