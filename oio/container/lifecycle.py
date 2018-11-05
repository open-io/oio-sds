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
import uuid

try:
    from lxml import etree
except ImportError:
    from xml.etree import cElementTree as etree

from oio.common.exceptions import OioException
from oio.common.logger import get_logger
from oio.common.utils import cid_from_name, depaginate


ALLOWED_STATUSES = ['enabled', 'disabled']
LIFECYCLE_PROPERTY_KEY = 'X-Container-Sysmeta-Swift3-Lifecycle'
TAGGING_KEY = 'x-object-sysmeta-swift3-tagging'
XMLNS_S3 = 'http://s3.amazonaws.com/doc/2006-03-01/'


def iso8601_to_int(text):
    # FIXME: use dateutil.parser?
    return int(time.mktime(time.strptime(text, "%Y-%m-%dT%H:%M:%S")))


class ProcessedVersions(object):
    """
    Save the processed versions of the last object
    """

    def __init__(self, **kwargs):
        self.name = None
        self.versions = None

    def is_already_processed(self, obj_meta, **kwargs):
        """
        Check if the version of this object is already processed.
        """
        return obj_meta['name'] == self.name \
            and int(obj_meta['version']) in self.versions

    def is_current(self, obj_meta, **kwargs):
        """
        Check if the object is the current version.
        """
        return self.name != obj_meta['name']

    def save_object(self, obj_meta, **kwargs):
        """
        Save object as processed.
        """
        if obj_meta['name'] != self.name:
            self.name = obj_meta['name']
            self.versions = [int(obj_meta['version'])]
        else:
            self.versions.append(int(obj_meta['version']))

    def nb_processed(self, obj_meta, **kwargs):
        """
        Get the number of processed versions.
        """
        if obj_meta['name'] != self.name:
            return 0
        return len(self.versions)


class ContainerLifecycle(object):

    def __init__(self, api, account, container, logger=None):
        self.api = api
        self.account = account
        self.container = container
        self.logger = logger or get_logger(None, name=str(self.__class__))
        self._rules = dict()
        self.src_xml = None
        self.processed_versions = None

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
                    if action[1] == 'Kept':
                        return
            else:
                yield obj_meta, rule.id, "n/a", "Kept"

    def execute(self, use_precessed_versions=True, **kwargs):
        """
        Match then apply the set of rules of the lifecycle configuration
        on all objects of the container.

        :returns: tuples of (object metadata, rule name, action, status)
        :rtype: generator of 4-tuples
        :notice: you must consume the results or the rules won't be applied.
        """
        if use_precessed_versions:
            self.processed_versions = ProcessedVersions()
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
                if obj_meta['deleted'] \
                        or (self.processed_versions is not None
                            and self.processed_versions.is_already_processed(
                                obj_meta, **kwargs)):
                    continue
                results = self.apply(obj_meta, **kwargs)
                for res in results:
                    yield res
            except Exception as exc:
                self.logger.warn(
                        "Failed to apply lifecycle rules on %s/%s/%s: %s",
                        self.account, self.container, obj_meta['name'], exc)
                yield obj_meta, "n/a", "n/a", exc
            if self.processed_versions is not None:
                self.processed_versions.save_object(obj_meta, **kwargs)
        self.processed_versions = None

    def is_current_version(self, obj_meta, **kwargs):
        """
        Check if the object is the current version
        """
        if self.processed_versions is None:
            current_obj = self.api.object_get_properties(
                self.account, self.container, obj_meta['name'])
            return current_obj['id'] == obj_meta['id']
        else:
            return self.processed_versions.is_current(obj_meta, **kwargs)


class LifecycleRule(object):
    """Combination of a filter and a set of lifecycle actions."""

    def __init__(self, id_, filter_, enabled, actions):
        self.id = id_
        self.filter = filter_
        self.enabled = enabled
        self.actions = actions

    @classmethod
    def from_element(cls, rule_elt, **kwargs):
        """
        Load the rule from an XML element.

        :type rule_elt: `lxml.etree.Element`
        """
        try:
            id_ = rule_elt.findall('ID')[-1].text
            if id_ is None:
                raise ValueError("Missing value for 'ID' element")
        except IndexError:
            id_ = "anonymous-rule-%s" % uuid.uuid4().hex

        try:
            filter_ = LifecycleRuleFilter.from_element(
                rule_elt.findall('Filter')[-1])
        except IndexError:
            raise ValueError("Missing 'Filter' element")

        try:
            status = rule_elt.findall('Status')[-1].text
            if status is None:
                raise ValueError("Missing value for 'Status' element")
            status = status.lower()
            if status not in ALLOWED_STATUSES:
                raise ValueError("Unknown 'Status' element")
            enabled = status == 'enabled'
        except IndexError:
            raise ValueError("Missing 'Status' element")

        actions = list()
        try:
            expiration = Expiration.from_element(
                rule_elt.findall('Expiration')[-1], **kwargs)
            action_filter_type = type(expiration.filter)
            actions.append(expiration)
        except IndexError:
            expiration = None
            action_filter_type = None

        transitions = list()
        for transition_elt in rule_elt.findall('Transition'):
            transition = Transition.from_element(transition_elt, **kwargs)
            if action_filter_type is None:
                action_filter_type = type(transition.filter)
            elif type(transition.filter) != action_filter_type:
                raise ValueError("'Date' and 'Days' in the same Rule")
            transitions.append(transition)
        if transitions:
            if action_filter_type == DateActionFilter:
                transitions = sorted(
                    transitions, key=lambda transition: transition.filter.date,
                    reverse=True)
            elif action_filter_type == DaysActionFilter:
                transitions = sorted(
                    transitions, key=lambda transition: transition.filter.days,
                    reverse=True)
            if expiration:
                if action_filter_type == DateActionFilter:
                    if expiration.filter.date <= transitions[0].filter.date:
                        raise ValueError(
                            "'Date' in the Expiration action "
                            "must be later than 'Date' "
                            "in the Transition action")
                elif action_filter_type == DaysActionFilter:
                    if expiration.filter.days <= transitions[0].filter.days:
                        raise ValueError(
                            "'Days' in the Expiration action "
                            "must be greater than 'Days' "
                            "in the Transition action")
            actions = actions + transitions

        try:
            expiration = NoncurrentVersionExpiration.from_element(
                rule_elt.findall('NoncurrentVersionExpiration')[-1], **kwargs)
            action_filter_type = type(expiration.filter)
            actions.append(expiration)
        except IndexError:
            expiration = None
            action_filter_type = None

        transitions = list()
        for transition_elt in rule_elt.findall('NoncurrentVersionTransition'):
            transition = NoncurrentVersionTransition.from_element(
                transition_elt, **kwargs)
            if action_filter_type is None:
                action_filter_type = type(transition.filter)
            elif type(transition.filter) != action_filter_type:
                raise ValueError(
                    "'NoncurrentDays' and 'NoncurrentCount' in the same Rule")
            transitions.append(transition)
        if transitions:
            if action_filter_type == DaysActionFilter:
                transitions = sorted(
                    transitions,
                    key=lambda transition: transition.filter.days,
                    reverse=True)
            elif action_filter_type == CountActionFilter:
                transitions = sorted(
                    transitions,
                    key=lambda transition: transition.filter.count,
                    reverse=True)
            if expiration:
                if action_filter_type == DaysActionFilter:
                    if expiration.filter.days <= transitions[0].filter.days:
                        raise ValueError(
                            "'NoncurrentDays' "
                            "in the NoncurrentVersionExpiration "
                            "action must be greater than 'NoncurrentDays' "
                            "in the NoncurrentVersionTransition action")
                elif action_filter_type == CountActionFilter:
                    if expiration.filter.count <= transitions[0].filter.count:
                        raise ValueError(
                            "'NoncurrentCount' "
                            "in the NoncurrentVersionExpiration "
                            "action must be greater than 'NoncurrentCount' "
                            "in the NoncurrentVersionTransition action")
            actions = actions + transitions

        if not actions:
            raise ValueError(
                "At least one action needs to be specified in a Rule")
        return cls(id_, filter_, enabled, actions)

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
            for action in self.actions:
                try:
                    res = action.apply(obj_meta, **kwargs)
                    results.append((action.__class__.__name__, res))
                    if res != 'Kept':
                        break
                except OioException as exc:
                    results.append((action.__class__.__name__, exc))
        return results


class LifecycleRuleFilter(object):
    """Filter to determine on which objects to apply a lifecycle rule."""

    def __init__(self, prefix, tags):
        """
        :param prefix: prefix that objects must have to pass this filter
        :type prefix: `basestring`
        :param tags: tags that objects must have to pass this filter
        :type tags: `dict`
        """
        self.prefix = prefix
        self.tags = tags

    @classmethod
    def from_element(cls, filter_elt, **kwargs):
        """
        Load the filter from an XML element.

        :type filter_elt: `lxml.etree.Element`
        """
        try:
            and_elt = filter_elt.findall('And')[-1]
            try:
                prefix = and_elt.findall('Prefix')[-1].text
                if prefix is None:
                    raise ValueError("Missing value for 'Prefix' element")
            except IndexError:
                prefix = None
            tags = cls._tags_from_element(and_elt)
        except IndexError:
            try:
                prefix = filter_elt.findall('Prefix')[-1].text
                if prefix is None:
                    raise ValueError("Missing value for 'Prefix' element")
            except IndexError:
                prefix = None
            try:
                k, v = cls._tag_from_element(filter_elt.findall('Tag')[-1])
                tags = {k: v}
            except IndexError:
                tags = {}
            if prefix and tags:
                raise ValueError("Too many filters, use <And>")

        return cls(prefix, tags, **kwargs)

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
                tags = self._tags_from_element(tags_elt, tags_elt.nsmap)
            for tagk in self.tags.keys():
                if tags.get(tagk) != self.tags[tagk]:
                    return False

        return True

    @staticmethod
    def _tag_from_element(tag_elt, nsmap=None):
        try:
            k = tag_elt.findall('Key', nsmap)[-1].text
            if k is None:
                raise ValueError("Missing value for 'Key' element")
        except IndexError:
            raise ValueError("Missing 'Key' element in 'Tag'")
        try:
            v = tag_elt.findall('Value', nsmap)[-1].text
            if v is None:
                raise ValueError("Missing value for 'Value' element")
        except IndexError:
            raise ValueError("Missing 'Value' element in 'Tag' (key=%s)" % k)
        return k, v

    @staticmethod
    def _tags_from_element(tags_elt, nsmap=None):
        tags = dict()
        for tag_elt in tags_elt.findall('Tag', tags_elt.nsmap):
            k, v = LifecycleRuleFilter._tag_from_element(tag_elt, nsmap=nsmap)
            if tags.get(k, None) is not None:
                raise ValueError("Duplicate Tag Keys are not allowed")
            tags[k] = v
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
    XML_NONCURRENT_TAG = 'NoncurrentDays'

    def __init__(self, days, **kwargs):
        super(DaysActionFilter, self).__init__(**kwargs)
        self.days = days

    @classmethod
    def from_element(cls, days_elt, **kwargs):
        try:
            days = int(days_elt.text or '')
            if days <= 0:
                raise ValueError()
        except ValueError:
            raise ValueError(
                "The days must be a positive integer")
        return cls(days, **kwargs)

    def match(self, obj_meta, now=None, **kwargs):
        now = now or time.time()
        return float(obj_meta['ctime']) + self.days * 86400 < now


class DateActionFilter(LifecycleActionFilter):
    """
    Specify the date when the specific rule action takes effect.
    """

    XML_TAG = 'Date'

    def __init__(self, date, **kwargs):
        super(DateActionFilter, self).__init__(**kwargs)
        self.date = date

    @classmethod
    def from_element(cls, date_elt, **kwargs):
        date = iso8601_to_int(date_elt.text or '')
        date = (date - (date % 86400))
        return cls(date, **kwargs)

    def match(self, obj_meta, now=None, **kwargs):
        now = now or time.time()
        return now > self.date and float(obj_meta['ctime']) < self.date


class CountActionFilter(LifecycleActionFilter):

    XML_NONCURRENT_TAG = 'NoncurrentCount'

    def __init__(self, count, **kwargs):
        super(CountActionFilter, self).__init__(**kwargs)
        self.count = count
        if self.lifecycle is None or self.lifecycle.processed_versions is None:
            self.last_object_name = None
            self.nb_noncurrent_version = 0

    @classmethod
    def from_element(cls, count_elt, **kwargs):
        try:
            count = int(count_elt.text or '')
            if count < 0:
                raise ValueError()
        except ValueError:
            raise ValueError(
                "The count must be greater than or equal to zero")
        return cls(count, **kwargs)

    def match(self, obj_meta, **kwargs):
        if self.lifecycle is None or self.lifecycle.processed_versions is None:
            if obj_meta['name'] != self.last_object_name:
                self.last_object_name = obj_meta['name']
                self.nb_noncurrent_version = 1
            else:
                self.nb_noncurrent_version += 1
            return self.count < self.nb_noncurrent_version

        processed = self.lifecycle.processed_versions.nb_processed(obj_meta)
        return self.count < processed


class LifecycleAction(LifecycleActionFilter):
    """
    Interface for Lifecycle actions.

    Apply the action on the latest version.
    """

    def __init__(self, filter_, **kwargs):
        super(LifecycleAction, self).__init__(**kwargs)
        self.filter = filter_

    def _match_filter(self, obj_meta, **kwargs):
        if self.filter is None:
            return True
        return self.filter.match(obj_meta, **kwargs)

    def match(self, obj_meta, **kwargs):
        return self.lifecycle.is_current_version(obj_meta, **kwargs) \
            and self._match_filter(obj_meta, **kwargs)

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

    @classmethod
    def from_element(cls, expiration_elt, **kwargs):
        """
        Load the expiration from an XML element

        :type expiration_elt: `lxml.etree.Element`
        """
        try:
            days_elt = expiration_elt.findall(DaysActionFilter.XML_TAG)[-1]
        except IndexError:
            days_elt = None
        try:
            date_elt = expiration_elt.findall(DateActionFilter.XML_TAG)[-1]
        except IndexError:
            date_elt = None

        if days_elt is None and date_elt is None:
            raise ValueError(
                "Missing '%s' or '%s' element in Expiration action" %
                (DaysActionFilter.XML_TAG, DateActionFilter.XML_TAG))
        elif days_elt is not None and date_elt is not None:
            raise ValueError(
                "'%s' and '%s' in same Expiration action" %
                (DaysActionFilter.XML_TAG, DateActionFilter.XML_TAG))

        if days_elt is not None:
            action_filter = DaysActionFilter.from_element(days_elt, **kwargs)
        elif date_elt is not None:
            action_filter = DateActionFilter.from_element(date_elt, **kwargs)
        return cls(action_filter, **kwargs)

    def apply(self, obj_meta, **kwargs):
        if self.match(obj_meta, **kwargs):
            res = self.lifecycle.api.object_delete(
                self.lifecycle.account, self.lifecycle.container,
                obj_meta['name'], version=obj_meta.get('version'))
            return "Deleted" if res else "Kept"
        return "Kept"


class Transition(LifecycleAction):
    """
    Change object storage policy.
    """

    XML_POLICY = 'StorageClass'

    def __init__(self, filter_, policy, **kwargs):
        super(Transition, self).__init__(filter_, **kwargs)
        self.policy = policy
        if self.lifecycle:
            from oio.content.factory import ContentFactory
            self.factory = ContentFactory(self.lifecycle.api.container.conf,
                                          self.lifecycle.api.container)

    @classmethod
    def from_element(cls, transition_elt, **kwargs):
        """
        Load the transition from an XML element

        :type transition_elt: `lxml.etree.Element`
        """
        try:
            policy = transition_elt.findall(cls.XML_POLICY)[-1].text
            if policy is None:
                raise ValueError("Missing value for '%s' element" %
                                 cls.XML_POLICY)
        except IndexError:
            raise ValueError("Missing '%s' element in Transition action" %
                             cls.XML_POLICY)

        try:
            days_elt = transition_elt.findall(DaysActionFilter.XML_TAG)[-1]
        except IndexError:
            days_elt = None
        try:
            date_elt = transition_elt.findall(DateActionFilter.XML_TAG)[-1]
        except IndexError:
            date_elt = None

        if days_elt is None and date_elt is None:
            raise ValueError(
                "Missing '%s' or '%s' element in Transition action" %
                (DaysActionFilter.XML_TAG, DateActionFilter.XML_TAG))
        elif days_elt is not None and date_elt is not None:
            raise ValueError(
                "'%s' and '%s' in same Transition action" %
                (DaysActionFilter.XML_TAG, DateActionFilter.XML_TAG))

        if days_elt is not None:
            action_filter = DaysActionFilter.from_element(days_elt, **kwargs)
        elif date_elt is not None:
            action_filter = DateActionFilter.from_element(date_elt, **kwargs)
        return cls(action_filter, policy, **kwargs)

    def apply(self, obj_meta, **kwargs):
        if self.match(obj_meta, **kwargs):
            cid = cid_from_name(self.lifecycle.account,
                                self.lifecycle.container)
            # TODO: avoid loading content description a second time
            self.factory.change_policy(cid, obj_meta['id'], self.policy)
            return "Policy changed to %s" % self.policy
        return "Kept"


class NoncurrentVersionExpiration(Expiration):
    """
    Delete objects old versions.
    """

    def match(self, obj_meta, **kwargs):
        return not self.lifecycle.is_current_version(
            obj_meta, **kwargs) and self._match_filter(obj_meta, **kwargs)

    @classmethod
    def from_element(cls, expiration_elt, **kwargs):
        """
        Load the expiration from an XML element

        :type expiration_elt: `lxml.etree.Element`
        """
        try:
            days_elt = expiration_elt.findall(
                DaysActionFilter.XML_NONCURRENT_TAG)[-1]
        except IndexError:
            days_elt = None
        try:
            count_elt = expiration_elt.findall(
                CountActionFilter.XML_NONCURRENT_TAG)[-1]
        except IndexError:
            count_elt = None

        if days_elt is None and count_elt is None:
            raise ValueError(
                "Missing '%s' or '%s' element " %
                (DaysActionFilter.XML_NONCURRENT_TAG,
                 CountActionFilter.XML_NONCURRENT_TAG)
                + "in NoncurrentVersionExpiration action")
        elif days_elt is not None and count_elt is not None:
            raise ValueError(
                "'%s' and '%s' " %
                (DaysActionFilter.XML_NONCURRENT_TAG,
                 CountActionFilter.XML_NONCURRENT_TAG)
                + "in same NoncurrentVersionExpiration action")

        if days_elt is not None:
            action_filter = DaysActionFilter.from_element(days_elt, **kwargs)
            return cls(action_filter, **kwargs)
        elif count_elt is not None:
            action_filter = CountActionFilter.from_element(count_elt, **kwargs)
            return cls(action_filter, **kwargs)


class NoncurrentVersionTransition(Transition):
    """
    Change object storage policy for old versions of the object only.
    """

    def match(self, obj_meta, **kwargs):
        return not self.lifecycle.is_current_version(
            obj_meta, **kwargs) and self._match_filter(obj_meta, **kwargs)

    @classmethod
    def from_element(cls, transition_elt, **kwargs):
        """
        Load the transition from an XML element

        :type transition_elt: `lxml.etree.Element`
        """
        try:
            policy = transition_elt.findall(cls.XML_POLICY)[-1].text
            if policy is None:
                raise ValueError("Missing value for '%s' element" %
                                 cls.XML_POLICY)
        except IndexError:
            raise ValueError(
                "Missing '%s' element in NoncurrentVersionTransition action" %
                (cls.XML_POLICY))

        try:
            days_elt = transition_elt.findall(
                DaysActionFilter.XML_NONCURRENT_TAG)[-1]
        except IndexError:
            days_elt = None

        if days_elt is None:
            raise ValueError(
                "Missing '%s' element in NoncurrentVersionTransition action" %
                (DaysActionFilter.XML_NONCURRENT_TAG))
        action_filter = DaysActionFilter.from_element(days_elt, **kwargs)
        return cls(action_filter, policy, **kwargs)
