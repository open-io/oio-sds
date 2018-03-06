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
            rule = LifecycleRule.from_element(rule_elt, api=self.api)
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
            res = rule.apply(self.account, self.container, obj_meta,
                             **kwargs)
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

        :returns: the list of actions that have been applied
        :rtype: `list` of `tuple` of a class and a bool or
            a class and an exception instance
        """
        results = list()
        if self.filter.match(obj_meta):
            for action in self.actions.values():
                try:
                    res = action.apply(account, container, obj_meta, **kwargs)
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
        if not parts:
            id_ = self.__class__._rule_number
            self.__class__._rule_number += 1
            return "anonymous-rule-%s" % id_
        return ','.join(parts)

    def match(self, obj_meta, **kwargs):
        """
        Check if an object matches the conditions defined by this filter.
        """
        if self.prefix and not obj_meta['name'].startswith(self.prefix):
            return False
        for tagk in self.tags.keys():
            if obj_meta.get('properties', {}).get(tagk) != self.tags[tagk]:
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
            res = self.api.object_delete(account, container, obj_meta['name'],
                                         version=obj_meta.get('version'))
            return "Deleted" if res else "Kept"
        return "Kept"


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
                return "Kept"
            # TODO: avoid loading content description a second time
            self.factory.change_policy(cid, obj_meta['id'], self.policy)
            return "Policy changed to %s" % self.policy
        return "Kept"


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
            if str(descr['version']) != str(obj_meta['version']):
                # Object is not the latest version, we can apply the treatment
                return super(NoncurrentAction, self).apply(
                    account, container, obj_meta, **kwargs)
        return "Kept"


class NoncurrentVersionExpiration(NoncurrentAction, DelayExpiration):
    """Delete objects old versions after a defined number of days."""

    DAYS_XML_TAG = 'NoncurrentDays'


class NoncurrentVersionTransition(NoncurrentAction, Transition):
    """
    Change object storage policy after a specified delay,
    for old versions of the object only.
    """

    DAYS_XML_TAG = 'NoncurrentDays'


class ExceedingVersionExpiration(LifecycleAction):
    """
    Delete exceeding versions if versioning is enabled.
    """

    def __init__(self, api=None):
        super(ExceedingVersionExpiration, self).__init__(api)
        self.versioning = None
        self.last_object_name = None

    @classmethod
    def from_element(cls, unused, **kwargs):
        return cls(**kwargs)

    def match(self, account, container, **kwargs):
        if self.versioning is None:
            data = self.api.container_get_properties(account, container)
            sys = data['system']
            version = sys.get('sys.m2.policy.version', None)
            if version is None:
                from oio.common.client import ProxyClient
                proxy_client = ProxyClient({"namespace": self.api.namespace},
                                           no_ns_in_url=True)
                _, data = proxy_client._request('GET', "config")
                version = data['meta2.max_versions']
            version = int(version)
            self.versioning = version > 1 or version < 0
        return self.versioning

    def apply(self, account, container, obj_meta, **kwargs):
        if self.match(account, container, **kwargs):
            object_name = obj_meta['name']
            if object_name != self.last_object_name:
                self.api.container.content_purge(account, container,
                                                 object_name)
                self.last_object_name = object_name
            if not self.api.object_head(account, container, object_name,
                                        version=obj_meta['version']):
                return "Deleted"
        return "Kept"


ACTION_MAP = {a.__name__: a for a in
              (Expiration,
               Transition,
               NoncurrentVersionExpiration,
               NoncurrentVersionTransition,
               ExceedingVersionExpiration)}


def action_from_element(element, api=None, **kwargs):
    """
    Create a new `LifecycleAction` subclass instance from an XML description.

    :param element: the XML description of the action
    :type element: `Element`
    """
    return ACTION_MAP[element.tag].from_element(element, api=api, **kwargs)
