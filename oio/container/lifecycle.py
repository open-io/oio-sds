# Copyright (C) 2017-2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2024 OVH SAS
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

import json

from oio.common.logger import get_logger

LIFECYCLE_PROPERTY_KEY = "X-Container-Sysmeta-S3Api-Lifecycle"
TAGGING_KEY = "x-object-sysmeta-s3api-tagging"


class ContainerLifecycle(object):
    def __init__(self, api, account, container, logger=None):
        self.api = api
        self.account = account
        self.container = container
        self.logger = logger or get_logger(None, name=str(self.__class__))
        self.conf_json = None

    def get_configuration(self):
        """
        Get lifecycle configuration from container property.
        """
        props = self.api.container_get_properties(self.account, self.container)
        return props["properties"].get(LIFECYCLE_PROPERTY_KEY)

    def load(self):
        """
        Load lifecycle conf from container property.

        :returns: True if a lifecycle configuration has been loaded
        """
        json_conf = self.get_configuration()
        if not json_conf:
            self.logger.info(
                "No Lifecycle configuration for %s/%s", self.account, self.container
            )
            return False
        try:
            self.load_json(json_conf)
        except ValueError as err:
            self.logger.warning("Failed to decode JSON configuration: %s", err)
            return False
        return True

    def load_json(self, json_str):
        """
        Load lifecycle json dict from LifecycleConfiguration string.

        :raises ValueError: if the string is not decodable as JSON
        """
        json_conf = json.loads(json_str)
        self.conf_json = json_conf

    def __str__(self):
        return json.dumps(self.conf_json)

    def save(self, json_str=None):
        """
        Save the lifecycle configuration in container property.

        :param json_str: the configuration to save, or None to save the
        configuration that has been loaded previously
        :type json_str: `str`
        """
        if json_str is None:
            json_str = str(self)
        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: json_str}
        )

    def build_sql_query(self, rule_filter, formated_time=None, **kwargs):
        # _query = 'SELECT * FROM aliases AS al '
        # Beginning of query will be force by meta2 code to avoid
        # update or delete queries

        rule = RuleFilter(rule_filter)
        _query = ""
        nb_filters = len(rule.tags)
        if rule.prefix is not None:
            nb_filters += 1
        if rule.lesser is not None:
            nb_filters += 1
        if rule.greater is not None:
            nb_filters += 1
        if nb_filters == 0:
            # No filter condition is equivalent to empty filter
            return _query

        _slo_cond = (
            " LEFT JOIN properties pr ON al.alias=pr.alias AND"
            " al.version=pr.version AND pr.key='x-object-sysmeta-slo-size'"
            " INNER JOIN contents ct ON al.content = ct.id "
        )

        _lesser = ""
        if rule.lesser is not None:
            _lesser = (
                f" AND "
                f"((ct.size <{rule.lesser} AND pr.value IS NULL) OR "
                f"pr.value < {rule.lesser})"
            )

        _greater = ""
        if rule.greater is not None:
            _greater = (
                f" AND "
                f"((ct.size >{rule.greater} AND pr.value IS NULL) OR "
                f"pr.value > {rule.greater}) "
            )

        if len(rule.tags) > 0:
            _base_tag = (
                " INNER JOIN properties pr2 ON al.alias = pr2.alias"
                " AND al.version=pr2.version "
            )

            _tags = f" AND pr2.key='{TAGGING_KEY}'"
            for el in rule.tags:
                for k, v in el.items():
                    _tag_key_cond = (
                        " AND CAST(pr2.value as nvarchar(10000)) "
                        f"LIKE '%<Tag><Key>{k}</Key>"
                    )
                    _tag_val_cond = f"<Value>{v}</Value></Tag>%'"
                    _tags = f"{_tags}{_tag_key_cond}{_tag_val_cond}"

            if _tags:
                _query = f"{_query}{_base_tag}{_tags}"

        if _lesser or _greater:
            _query = f"{_query}{_slo_cond}"
            if _lesser:
                _query = f"{_query}{_lesser}"
            if _greater:
                _query = f"{_query}{_greater}"

        if rule.prefix is not None:
            _prefix_cond = f" WHERE ( al.alias LIKE '{rule.prefix}%'"
            _query = f"{_query}{_prefix_cond}"
        if formated_time is not None:
            _time_cond = (
                f" AND (al.mtime + {formated_time}) < (CAST "
                "(strftime('%s', 'now') AS INTEGER ))"
            )
            _query = f"{_query}{_time_cond}"
        # close WHERE clause
        if rule.prefix is not None:
            _query = f"{_query} )"
        return _query


class RuleFilter(object):
    def __init__(self, rule_filter):
        self.prefix = rule_filter.get("Prefix", None) or rule_filter.get(
            "Filter", {}
        ).get("Prefix", None)
        self.greater = rule_filter.get("Filter", {}).get("ObjectSizeGreaterThan", None)
        self.lesser = rule_filter.get("Filter", {}).get("ObjectSizeLessThan", None)
        # Build a list of tags:
        # Tags has two representations => Tags: List of tags if there are several tags
        # otherwise single Tag: {}
        self.tags = []
        if rule_filter.get("Filter", {}).get("Tags") is not None:
            self.tags = rule_filter.get("Filter", {}).get("Tags")
