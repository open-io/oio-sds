# Copyright (C) 2017-2019 OpenIO SAS, as part of OpenIO SDS
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
from datetime import datetime

try:
    from lxml import etree
except ImportError:
    from xml.etree import cElementTree as etree

from oio.common.exceptions import OioException
from oio.common.logger import get_logger
from oio.common.utils import depaginate
from oio.common.easy_value import true_value
from oio.common.constants import CH_ENCODED_SEPARATOR, CH_SEPARATOR


ALLOWED_STATUSES = ['enabled', 'disabled']
LIFECYCLE_PROPERTY_KEY = 'X-Container-Sysmeta-Swift3-Lifecycle'
TAGGING_KEY = 'x-object-sysmeta-swift3-tagging'
XMLNS_S3 = 'http://s3.amazonaws.com/doc/2006-03-01/'


def iso8601_to_int(when):
    # FIXME: use dateutil.parser?
    return int(time.mktime(time.strptime(when, "%Y-%m-%dT%H:%M:%S")))


def int_to_iso8601(when):
    return datetime.utcfromtimestamp(when).isoformat()


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

    def __init__(self, api, account, container, logger=None,
                 recursive=False):
        self.api = api
        self.account = account
        self.container = container
        self.logger = logger or get_logger(None, name=str(self.__class__))
        self.recursive = recursive
        self.rules = list()
        self.processed_versions = None

    def get_configuration(self):
        """
        Get lifecycle configuration from container property.
        """
        props = self.api.container_get_properties(self.account, self.container)
        return props['properties'].get(LIFECYCLE_PROPERTY_KEY)

    def load(self):
        """
        Load lifecycle rules from container property.

        :returns: True if a lifecycle configuration has been loaded
        """
        xml = self.get_configuration()
        if xml is None:
            self.logger.info("No Lifecycle configuration for %s/%s",
                             self.account, self.container)
            return False
        else:
            self.load_xml(xml)
            return True

    def load_xml(self, xml_str):
        """
        Load lifecycle rules from LifecycleConfiguration XML document.
        """
        tree = etree.fromstring(xml_str)
        root_ns = tree.nsmap.get(None)
        root_tag = 'LifecycleConfiguration'
        if root_ns is not None:
            root_tag = '{%s}%s' % (root_ns, root_tag)
        if tree.tag != root_tag:
            raise ValueError(
                "Expected 'LifecycleConfiguration' as root tag, got '%s'" %
                tree.tag)
        for rule_elt in tree.findall('Rule', tree.nsmap):
            rule = LifecycleRule.from_element(rule_elt, lifecycle=self)
            self.rules.append(rule)

    def _to_element_tree(self, **kwargs):
        lifecycle_elt = etree.Element('LifecycleConfiguration')

        for rule in self.rules:
            rule_elt = rule._to_element_tree(**kwargs)
            lifecycle_elt.append(rule_elt)

        return lifecycle_elt

    def __str__(self):
        return etree.tostring(self._to_element_tree()).decode("utf-8")

    def save(self, xml_str=None):
        """
        Save the lifecycle configuration in container property.

        :param xml_str: the configuration to save, or None to save the
        configuration that has been loaded previously
        :type xml_str: `str`
        """
        if not self.rules:
            raise ValueError('You must call `load_xml()`'
                             ' parameter before saving')
        self.api.container_set_properties(
            self.account, self.container,
            properties={LIFECYCLE_PROPERTY_KEY: str(self)})

    def apply(self, obj_meta, **kwargs):
        """
        Match then apply the set of rules of this lifecycle configuration
        on the specified object.

        :returns: tuples of (object metadata, rule name, action, status)
        :rtype: generator of 4-tuples

        :notice: you must consume the results or the rules won't be applied.
        """
        if true_value(obj_meta['deleted']):
            return
        for rule in self.rules:
            res = rule.apply(obj_meta, **kwargs)
            if res:
                for action in res:
                    yield obj_meta, rule.id, action[0], action[1]
                    if action[1] != 'Kept':
                        return
            else:
                yield obj_meta, rule.id, "n/a", "Kept"

    def process_container(self, container, **kwargs):
        """
        Match then apply the set of rules of the lifecycle configuration
        on all objects of the container.

        :returns: tuples of (object metadata, rule name, action, status)
        :rtype: generator of 4-tuples
        :notice: the results must be consumed or the rules won't be applied.
        """
        for obj_meta in depaginate(
                self.api.object_list,
                listing_key=lambda x: x['objects'],
                marker_key=lambda x: x.get('next_marker'),
                truncated_key=lambda x: x['truncated'],
                account=self.account,
                container=container,
                properties=True,
                versions=True,
                **kwargs):
            try:
                # Save the name of the object as it is in the container,
                # for later use.
                obj_meta['orig_name'] = obj_meta['name']
                # And reconstruct the name of the object as it is
                # when shown to the final user.
                if self.recursive and CH_ENCODED_SEPARATOR in container:
                    obj_meta['name'] = container.split(CH_ENCODED_SEPARATOR,
                                                       1)[1]
                    obj_meta['name'].replace(CH_ENCODED_SEPARATOR,
                                             CH_SEPARATOR)
                    obj_meta['name'] += CH_SEPARATOR + obj_meta['orig_name']
                obj_meta['container'] = container

                if self.processed_versions is not None \
                    and self.processed_versions.is_already_processed(
                        obj_meta, **kwargs):
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

    def execute(self, use_precessed_versions=True, **kwargs):
        """
        Match then apply the set of rules of the lifecycle configuration
        on all objects of the container (and its relatives, if recursive
        mode is enabled).

        :returns: tuples of (object metadata, rule name, action, status)
        :rtype: generator of 4-tuples
        :notice: the results must be consumed or the rules won't be applied.
        """
        if use_precessed_versions:
            self.processed_versions = ProcessedVersions()

        results = self.process_container(self.container, **kwargs)
        for res in results:
            yield res

        if self.recursive:
            for container in depaginate(
                    self.api.container_list,
                    item_key=lambda x: x[0],
                    marker_key=lambda x: x[-1][0],
                    account=self.account,
                    prefix=self.container + CH_ENCODED_SEPARATOR):

                results = self.process_container(container, **kwargs)
                for res in results:
                    yield res

        self.processed_versions = None

    def is_current_version(self, obj_meta, **kwargs):
        """
        Check if the object is the current version
        """
        if self.processed_versions is None:
            current_obj = self.api.object_get_properties(
                self.account, obj_meta['container'], obj_meta['orig_name'])
            return current_obj['version'] == obj_meta['version']
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
        nsmap = rule_elt.nsmap
        try:
            id_ = rule_elt.findall('ID', nsmap)[-1].text
            if id_ is None:
                raise ValueError("Missing value for 'ID' element")
        except IndexError:
            id_ = uuid.uuid4().hex

        try:
            filter_ = LifecycleRuleFilter.from_element(
                rule_elt.findall('Filter', nsmap)[-1])
        except IndexError:
            raise ValueError("Missing 'Filter' element")

        try:
            status = rule_elt.findall('Status', nsmap)[-1].text
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
                rule_elt.findall('Expiration', nsmap)[-1], **kwargs)
            action_filter_type = type(expiration.filter)
            actions.append(expiration)
        except IndexError:
            expiration = None
            action_filter_type = None

        transitions = list()
        for transition_elt in rule_elt.findall('Transition', nsmap):
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
                rule_elt.findall('NoncurrentVersionExpiration', nsmap)[-1],
                **kwargs)
            action_filter_type = type(expiration.filter)
            actions.append(expiration)
        except IndexError:
            expiration = None
            action_filter_type = None

        transitions = list()
        for transition_elt in rule_elt.findall('NoncurrentVersionTransition',
                                               nsmap):
            transition = NoncurrentVersionTransition.from_element(
                transition_elt, **kwargs)
            if action_filter_type is None:
                action_filter_type = type(transition.filter)
            elif type(transition.filter) != action_filter_type:
                raise ValueError(
                    "'NoncurrentDays' and 'NoncurrentCount' in the same Rule")
            transitions.append(transition)
        if transitions:
            if action_filter_type == NoncurrentDaysActionFilter:
                transitions = sorted(
                    transitions,
                    key=lambda transition: transition.filter.days,
                    reverse=True)
            elif action_filter_type == NoncurrentCountActionFilter:
                transitions = sorted(
                    transitions,
                    key=lambda transition: transition.filter.count,
                    reverse=True)
            if expiration:
                if action_filter_type == NoncurrentDaysActionFilter:
                    if expiration.filter.days <= transitions[0].filter.days:
                        raise ValueError(
                            "'NoncurrentDays' "
                            "in the NoncurrentVersionExpiration "
                            "action must be greater than 'NoncurrentDays' "
                            "in the NoncurrentVersionTransition action")
                elif action_filter_type == NoncurrentCountActionFilter:
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

    def _to_element_tree(self, **kwargs):
        rule_elt = etree.Element("Rule")

        id_elt = etree.Element("ID")
        id_elt.text = self.id
        rule_elt.append(id_elt)

        filter_elt = self.filter._to_element_tree(**kwargs)
        rule_elt.append(filter_elt)

        status_elt = etree.Element("Status")
        if self.enabled:
            status_elt.text = 'Enabled'
        else:
            status_elt.text = 'Disabled'
        rule_elt.append(status_elt)

        for action in self.actions:
            action_elt = action._to_element_tree(**kwargs)
            rule_elt.append(action_elt)

        return rule_elt

    def __str__(self):
        return etree.tostring(self._to_element_tree()).decode("utf-8")

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
        nsmap = filter_elt.nsmap
        try:
            and_elt = filter_elt.findall('And', nsmap)[-1]
            try:
                prefix = and_elt.findall('Prefix', nsmap)[-1].text
                if prefix is None:
                    raise ValueError("Missing value for 'Prefix' element")
            except IndexError:
                prefix = None
            tags = cls._tags_from_element(and_elt)
        except IndexError:
            try:
                prefix = filter_elt.findall('Prefix', nsmap)[-1].text
                if prefix is None:
                    raise ValueError("Missing value for 'Prefix' element")
            except IndexError:
                prefix = None
            try:
                k, v = cls._tag_from_element(
                    filter_elt.findall('Tag', nsmap)[-1])
                tags = {k: v}
            except IndexError:
                tags = {}
            if prefix and tags:
                raise ValueError("Too many filters, use <And>")

        return cls(prefix, tags, **kwargs)

    def _to_element_tree(self, **kwargs):
        filter_elt = _filter_elt = etree.Element('Filter')

        nb_filters = len(self.tags)
        if self.prefix is not None:
            nb_filters += 1
        if nb_filters == 0:
            filter_elt.text = ''
            return filter_elt
        if nb_filters > 1:
            and_elt = etree.Element('And')
            _filter_elt = and_elt
            filter_elt.append(and_elt)

        if self.prefix is not None:
            prefix_elt = etree.Element('Prefix')
            prefix_elt.text = self.prefix
            _filter_elt.append(prefix_elt)

        for k, v in self.tags.items():
            tag_elt = etree.Element('Tag')
            key_elt = etree.Element('Key')
            key_elt.text = k
            tag_elt.append(key_elt)
            value_elt = etree.Element('Value')
            value_elt.text = v
            tag_elt.append(value_elt)
            _filter_elt.append(tag_elt)

        return filter_elt

    def __str__(self):
        return etree.tostring(self._to_element_tree()).decode("utf-8")

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

    def _to_element_tree(self, **kwargs):
        raise NotImplementedError

    def __str__(self):
        return etree.tostring(self._to_element_tree()).decode("utf-8")

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

    def _to_element_tree(self, **kwargs):
        days_elt = etree.Element('Days')
        days_elt.text = str(self.days)
        return days_elt

    def match(self, obj_meta, now=None, **kwargs):
        now = now or time.time()
        return float(obj_meta['mtime']) + self.days * 86400 < now


class NoncurrentDaysActionFilter(DaysActionFilter):

    def _to_element_tree(self, **kwargs):
        days_elt = etree.Element('NoncurrentDays')
        days_elt.text = str(self.days)
        return days_elt


class DateActionFilter(LifecycleActionFilter):
    """
    Specify the date when the specific rule action takes effect.
    """

    def __init__(self, date, **kwargs):
        super(DateActionFilter, self).__init__(**kwargs)
        self.date = date

    @classmethod
    def from_element(cls, date_elt, **kwargs):
        date = iso8601_to_int(date_elt.text or '')
        date = (date - (date % 86400))
        return cls(date, **kwargs)

    def _to_element_tree(self, **kwargs):
        date_elt = etree.Element('Date')
        date_elt.text = int_to_iso8601(self.date)
        return date_elt

    def match(self, obj_meta, now=None, **kwargs):
        now = now or time.time()
        return now > self.date and float(obj_meta['mtime']) < self.date


class NoncurrentCountActionFilter(LifecycleActionFilter):

    def __init__(self, count, **kwargs):
        super(NoncurrentCountActionFilter, self).__init__(**kwargs)
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

    def _to_element_tree(self, **kwargs):
        count_elt = etree.Element('NoncurrentCount')
        count_elt.text = str(self.count)
        return count_elt

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
        nsmap = expiration_elt.nsmap
        try:
            days_elt = expiration_elt.findall('Days', nsmap)[-1]
        except IndexError:
            days_elt = None
        try:
            date_elt = expiration_elt.findall('Date', nsmap)[-1]
        except IndexError:
            date_elt = None

        if days_elt is None and date_elt is None:
            raise ValueError(
                "Missing 'Days' or 'Date' element in Expiration action")
        elif days_elt is not None and date_elt is not None:
            raise ValueError(
                "'Days' and 'Date' in same Expiration action")

        if days_elt is not None:
            action_filter = DaysActionFilter.from_element(days_elt, **kwargs)
        elif date_elt is not None:
            action_filter = DateActionFilter.from_element(date_elt, **kwargs)
        return cls(action_filter, **kwargs)

    def _to_element_tree(self, **kwargs):
        exp_elt = etree.Element('Expiration')
        filter_elt = self.filter._to_element_tree(**kwargs)
        exp_elt.append(filter_elt)
        return exp_elt

    def apply(self, obj_meta, version=None, **kwargs):
        if self.match(obj_meta, **kwargs):
            res = self.lifecycle.api.object_delete(
                self.lifecycle.account, obj_meta['container'],
                obj_meta['orig_name'], version=version)
            return "Deleted" if res else "Kept"
        return "Kept"


class Transition(LifecycleAction):
    """
    Change object storage policy.
    """

    STORAGE_POLICY_XML_TAG = 'StorageClass'

    def __init__(self, filter_, policy, **kwargs):
        super(Transition, self).__init__(filter_, **kwargs)
        self.policy = policy

    @classmethod
    def from_element(cls, transition_elt, **kwargs):
        """
        Load the transition from an XML element

        :type transition_elt: `lxml.etree.Element`
        """
        nsmap = transition_elt.nsmap
        try:
            policy = transition_elt.findall(
                cls.STORAGE_POLICY_XML_TAG, nsmap)[-1].text
            if policy is None:
                raise ValueError("Missing value for '%s' element" %
                                 cls.STORAGE_POLICY_XML_TAG)
        except IndexError:
            raise ValueError("Missing '%s' element in Transition action" %
                             cls.STORAGE_POLICY_XML_TAG)

        try:
            days_elt = transition_elt.findall('Days', nsmap)[-1]
        except IndexError:
            days_elt = None
        try:
            date_elt = transition_elt.findall('Date', nsmap)[-1]
        except IndexError:
            date_elt = None

        if days_elt is None and date_elt is None:
            raise ValueError(
                "Missing 'Days' or 'Date' element in Transition action")
        elif days_elt is not None and date_elt is not None:
            raise ValueError(
                "'Days' and 'Date' in same Transition action")

        if days_elt is not None:
            action_filter = DaysActionFilter.from_element(days_elt, **kwargs)
        elif date_elt is not None:
            action_filter = DateActionFilter.from_element(date_elt, **kwargs)
        return cls(action_filter, policy, **kwargs)

    def _to_element_tree(self, **kwargs):
        trans_elt = etree.Element('Transition')
        policy_elt = etree.Element(self.STORAGE_POLICY_XML_TAG)
        policy_elt.text = self.policy
        trans_elt.append(policy_elt)
        filter_elt = self.filter._to_element_tree(**kwargs)
        trans_elt.append(filter_elt)
        return trans_elt

    def apply(self, obj_meta, **kwargs):
        if self.match(obj_meta, **kwargs):
            if obj_meta['policy'] == self.policy:
                return "Policy already changed to %s" % self.policy
            self.lifecycle.api.object_change_policy(
                self.lifecycle.account, obj_meta['container'],
                obj_meta['orig_name'], self.policy,
                version=obj_meta['version'])
            return "Policy changed to %s" % self.policy
        return "Kept"


class NoncurrentVersionExpiration(Expiration):
    """
    Delete objects old versions.
    """

    @classmethod
    def from_element(cls, expiration_elt, **kwargs):
        """
        Load the expiration from an XML element

        :type expiration_elt: `lxml.etree.Element`
        """
        nsmap = expiration_elt.nsmap
        try:
            days_elt = expiration_elt.findall('NoncurrentDays', nsmap)[-1]
        except IndexError:
            days_elt = None
        try:
            count_elt = expiration_elt.findall('NoncurrentCount', nsmap)[-1]
        except IndexError:
            count_elt = None

        if days_elt is None and count_elt is None:
            raise ValueError(
                "Missing 'NoncurrentDays' or 'NoncurrentCount' element "
                "in NoncurrentVersionExpiration action")
        elif days_elt is not None and count_elt is not None:
            raise ValueError(
                "'NoncurrentDays' and 'NoncurrentCount' "
                "in same NoncurrentVersionExpiration action")

        if days_elt is not None:
            action_filter = NoncurrentDaysActionFilter.from_element(
                days_elt, **kwargs)
            return cls(action_filter, **kwargs)
        elif count_elt is not None:
            action_filter = NoncurrentCountActionFilter.from_element(
                count_elt, **kwargs)
            return cls(action_filter, **kwargs)

    def _to_element_tree(self, **kwargs):
        exp_elt = etree.Element('NoncurrentVersionExpiration')
        filter_elt = self.filter._to_element_tree(**kwargs)
        exp_elt.append(filter_elt)
        return exp_elt

    def match(self, obj_meta, **kwargs):
        return not self.lifecycle.is_current_version(
            obj_meta, **kwargs) and self._match_filter(obj_meta, **kwargs)

    def apply(self, obj_meta, **kwargs):
        return super(NoncurrentVersionExpiration, self).apply(
            obj_meta, version=obj_meta['version'], **kwargs)


class NoncurrentVersionTransition(Transition):
    """
    Change object storage policy for old versions of the object only.
    """

    @classmethod
    def from_element(cls, transition_elt, **kwargs):
        """
        Load the transition from an XML element

        :type transition_elt: `lxml.etree.Element`
        """
        nsmap = transition_elt.nsmap
        try:
            policy = transition_elt.findall(
                cls.STORAGE_POLICY_XML_TAG, nsmap)[-1].text
            if policy is None:
                raise ValueError("Missing value for '%s' element" %
                                 cls.STORAGE_POLICY_XML_TAG)
        except IndexError:
            raise ValueError(
                "Missing '%s' element in NoncurrentVersionTransition action" %
                (cls.STORAGE_POLICY_XML_TAG))

        try:
            days_elt = transition_elt.findall('NoncurrentDays', nsmap)[-1]
        except IndexError:
            days_elt = None

        if days_elt is None:
            raise ValueError(
                "Missing 'NoncurrentDays' element "
                "in NoncurrentVersionTransition action")
        action_filter = NoncurrentDaysActionFilter.from_element(
            days_elt, **kwargs)
        return cls(action_filter, policy, **kwargs)

    def _to_element_tree(self, **kwargs):
        trans_elt = etree.Element('NoncurrentVersionTransition')
        policy_elt = etree.Element(self.STORAGE_POLICY_XML_TAG)
        policy_elt.text = self.policy
        trans_elt.append(policy_elt)
        filter_elt = self.filter._to_element_tree(**kwargs)
        trans_elt.append(filter_elt)
        return trans_elt

    def match(self, obj_meta, **kwargs):
        return not self.lifecycle.is_current_version(
            obj_meta, **kwargs) and self._match_filter(obj_meta, **kwargs)
