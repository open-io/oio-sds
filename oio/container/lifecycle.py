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

LIFECYCLE_SPECIAL_KEY_TAG = "'__processed_lifecycle'"


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

    def _processed_sql_condition(self):
        return (
            f"( al.alias||al.version||{LIFECYCLE_SPECIAL_KEY_TAG} "
            "NOT IN (SELECT alias||version||key FROM properties))"
        )

    def build_sql_query(
        self,
        rule,
        formated_days=None,
        date=None,
        non_current=False,
        versioned=False,
        expired_delete_marker=None,
        **kwargs,
    ):
        # Beginning of query will be force by meta2 code to avoid
        # update or delete queries
        rule_filter = RuleFilter(rule)
        _query = " "
        skip_size_and_tag = False
        if expired_delete_marker:
            skip_size_and_tag = True

        time_flag = False
        if formated_days is not None:
            time_flag = True
        if date is not None:
            time_flag = True

        nb_filters = len(rule_filter.tags)
        if rule_filter.prefix is not None:
            nb_filters += 1
        if rule_filter.lesser is not None:
            nb_filters += 1
        if rule_filter.greater is not None:
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
        # bypass size when dealing with delete marker
        if not skip_size_and_tag:
            if rule_filter.lesser is not None:
                _lesser = (
                    f" AND "
                    f"((ct.size <{rule_filter.lesser} AND pr.value IS NULL) OR "
                    f"pr.value < {rule_filter.lesser})"
                )

        _greater = ""
        # bypass size and tags when dealing with delete marker
        if not skip_size_and_tag:
            if rule_filter.greater is not None:
                _greater = (
                    f" AND "
                    f"((ct.size >{rule_filter.greater} AND pr.value IS NULL) OR "
                    f"pr.value > {rule_filter.greater}) "
                )

            if len(rule_filter.tags) > 0:
                _base_tag = (
                    " INNER JOIN properties pr2 ON al.alias ="
                    "pr2.alias AND al.version=pr2.version "
                )

                _tags = f" AND pr2.key='{TAGGING_KEY}'"
                for el in rule_filter.tags:
                    ((k, v),) = el.items()
                    _tag_key_cond = (
                        " AND CAST(pr2.value as nvarchar(10000))"
                        f" LIKE '%<Tag><Key>{k}</Key>"
                    )
                    _tag_val_cond = f"<Value>{v}</Value></Tag>%'"
                    _tags = f"{_tags}{_tag_key_cond}{_tag_val_cond}"

                _query = f"{_query}{_base_tag}{_tags}"

        if _lesser or _greater:
            _query = f"{_query}{_slo_cond}"
            if _lesser:
                _query = f"{_query}{_lesser}"
            if _greater:
                _query = f"{_query}{_greater}"

        if rule_filter.prefix is not None or time_flag:
            _query = f"{_query} WHERE ("

        if rule_filter.prefix is not None:
            _prefix_cond = f"( al.alias LIKE '{rule_filter.prefix}%')"
            _query = f"{_query}{_prefix_cond}"
        if expired_delete_marker is None:
            if rule_filter.prefix is not None and time_flag:
                _query = f"{_query}  AND "
            if formated_days is not None:
                _time_cond = (
                    f" ((al.mtime + {formated_days}) < (CAST "
                    f"(strftime('%s', 'now') AS INTEGER )))"
                )
                _query = f"{_query}{_time_cond}"
            elif date is not None:
                _time_cond = (
                    f" ((CAST "
                    f"(strftime('%s', '{date}') AS INTEGER )) < (CAST "
                    f"(strftime('%s', 'now') AS INTEGER )))"
                )
                _query = f"{_query}{_time_cond}"
            else:
                # Condition shouldn't occur
                # (days or date is present except in case of
                # expired delete marker)
                raise ValueError(
                    "Configuration needs days or date in filter ",
                )

        # close WHERE clause
        if rule_filter.prefix is not None or time_flag:
            _query = f"{_query} )"
        if non_current or versioned:
            _query = f"{_query} GROUP BY al.alias"
        return _query

    def create_noncurrent_view(self, rule, formated_time=None, **kwargs):
        rule_filter = RuleFilter(rule)
        # Create forced on meta2 side
        _query = (
            "VIEW noncurrent_view AS SELECT *, "
            "ROW_NUMBER() OVER (PARTITION BY al.alias) AS row_id FROM aliases"
            " AS al"
        )

        _slo_cond = (
            " LEFT JOIN properties pr ON al.alias=pr.alias AND"
            " al.version=pr.version AND pr.key='x-object-sysmeta-slo-size'"
            " INNER JOIN contents ct ON al.content = ct.id "
        )

        _lesser = ""
        # bypass size when dealing with delete marker
        if rule_filter.lesser is not None:
            _lesser = (
                f" AND "
                f"((ct.size <{rule_filter.lesser} AND pr.value IS NULL) OR "
                f"pr.value < {rule_filter.lesser})"
            )

        _greater = ""
        # bypass size when dealing with delete marker
        if rule_filter.greater is not None:
            _greater = (
                f" AND "
                f"((ct.size >{rule_filter.greater} AND pr.value IS NULL) OR "
                f"pr.value > {rule_filter.greater}) "
            )

        if len(rule_filter.tags) > 0:
            _base_tag = (
                " INNER JOIN properties pr2 ON al.alias="
                "pr2.alias AND al.version=pr2.version "
            )

            _tags = f" AND pr2.key='{TAGGING_KEY}'"
            for el in rule_filter.tags:
                ((k, v),) = el.items()
                _tag_key_cond = (
                    " AND CAST(pr2.value as nvarchar(10000))"
                    f" LIKE '%<Tag><Key>{k}</Key>"
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

        if rule_filter.prefix is not None or formated_time is not None:
            _query = f"{_query} WHERE ("

        if rule_filter.prefix is not None:
            _prefix_cond = "( al.alias LIKE '" f"{rule_filter.prefix}" "%')"
            _query = f"{_query}{_prefix_cond}"

        if rule_filter.prefix is not None and formated_time is not None:
            _query = f"{_query}  AND "
        if formated_time is not None:
            _time_cond = (
                f" ((al.mtime + {formated_time}) < (CAST "
                f"(strftime('%s', 'now') AS INTEGER )))"
            )
            _query = f"{_query}{_time_cond}"
        # close WHERE clause
        if rule_filter.prefix is not None or formated_time is not None:
            _query = f"{_query} )"
        _query = f"{_query} ORDER BY al.version ASC"
        return _query

    def create_common_views(
        self, view_name, rule, formated_time=None, date=None, deleted=None, **kwargs
    ):
        if not view_name:
            raise ValueError("Lifecycle views, empty view name!")
        rule_filter = RuleFilter(rule)
        # CREATE forced on meta2 side
        _query = (
            f"VIEW {view_name} AS SELECT *, "
            "COUNT(*) AS nb_versions from aliases AS al"
        )
        _query = f"{_query} GROUP BY al.alias HAVING MAX(al.version)"

        if deleted is not None:
            if deleted:
                _query = f"{_query} AND (al.deleted=1)"
            else:
                _query = f"{_query} AND (al.deleted=0)"

        if rule_filter.prefix is not None:
            _prefix_cond = " AND ( al.alias LIKE '" f"{rule_filter.prefix}" "%')"
            _query = f"{_query}{_prefix_cond}"
        if formated_time is not None:
            _time_cond = (
                f" AND ( (al.mtime + {formated_time}) < (CAST "
                f"(strftime('%s', 'now') AS INTEGER )))"
            )
            _query = f"{_query}{_time_cond}"
        elif date is not None:
            _time_cond = (
                f" AND ( (CAST "
                f"(strftime('%s', '{date}') AS INTEGER )) < (CAST "
                f"(strftime('%s', 'now') AS INTEGER )))"
            )
            _query = f"{_query}{_time_cond}"
        else:
            # Condition shouldn't occur
            # (days or date is present except in case of
            # expired delete marker)
            raise ValueError(
                "Configuration needs days or date in filter %s",
                str(self),
            )
        return _query

    def noncurrent_query(self, noncurrent_versions):
        """
        Deal with non current versions
        """

        #
        if noncurrent_versions is None:
            noncurrent_versions = 0
        # SELECT is forced on meta2 side
        query = (
            f" , (cv.nb_versions - 1 - {noncurrent_versions}) AS"
            " noncurrent_nb_candidates,"
            " (SELECT COUNT(*) FROM noncurrent_view WHERE alias=al.alias)"
            " AS count, row_id FROM noncurrent_view AS al"
            " INNER JOIN current_view AS cv ON "
            " al.alias=cv.alias WHERE ((row_id <= noncurrent_nb_candidates)"
            f" AND {self._processed_sql_condition()})"
        )
        return query

    def markers_query(self):
        """
        Get expired delete markers
        """

        # SELECT is forced on meta2 side
        query = " WHERE nb_versions=1"
        return query


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
