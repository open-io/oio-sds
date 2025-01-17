# Copyright (C) 2017-2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2025 OVH SAS
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

from oio.common.constants import (
    LIFECYCLE_PROPERTY_KEY,
    TAGGING_KEY,
)
from oio.common.logger import get_logger
from oio.lifecycle.metrics import LifecycleAction

LIFECYCLE_SPECIAL_KEY_TAG = "'__processed_lifecycle'"


class _LifecycleAction:
    step = None
    accelerator = None
    field = None
    current = True

    def __init__(self, rule_id, action_id):
        self.rule_id = rule_id
        self.action_id = action_id

    def __str__(self):
        return (
            f"{self.__class__.__name__}(rule={self.rule_id}, action={self.action_id})"
        )


class AbortMpuAction(_LifecycleAction):
    step = LifecycleAction.ABORT_MPU
    accelerator = "_abort_mpu_rules"
    field = "AbortIncompleteMultipartUpload"


class ExpirationAction(_LifecycleAction):
    step = LifecycleAction.DELETE
    accelerator = "_expiration_rules"
    field = "Expiration"


class DeleteMarkerAction(_LifecycleAction):
    step = LifecycleAction.DELETE
    accelerator = "_delete_marker_rules"
    field = "Expiration"


class TransitionAction(_LifecycleAction):
    step = LifecycleAction.TRANSITION
    accelerator = "_transition_rules"
    field = "Transition"


class NonCurrentExpirationAction(_LifecycleAction):
    step = LifecycleAction.DELETE
    accelerator = "_non_current_expiration_rules"
    field = "NoncurrentVersionExpiration"
    current = False


class NonCurrentTransitionAction(_LifecycleAction):
    step = LifecycleAction.TRANSITION
    accelerator = "_non_current_transition_rules"
    field = "NoncurrentVersionTransition"
    current = False


class LifecycleConfigurationInvalid(Exception):
    pass


class LifecycleConfigurationNotFound(Exception):
    pass


def lifecycle_backup_path(account, bucket):
    """
    Compute the path of lifecycle configuration backup stored in the technical bucket.
    """
    return f"{account}/{bucket}/lifecycle-config"


class ContainerLifecycle(object):
    # List lifecycle configuration versions supported by filter
    SUPPORTED_CONFIGURATION_VERSIONS = (1,)

    def __init__(self, api, account, container, logger=None):
        self.api = api
        self.account = account
        self.container = container
        self.logger = logger or get_logger(None, name=str(self.__class__))
        self.lifecycle_conf = None

    def get_configuration(self):
        """
        Get lifecycle configuration from container property.
        """
        props = self.api.container_get_properties(self.account, self.container)
        return props["properties"].get(LIFECYCLE_PROPERTY_KEY)

    def load(self, conf=None):
        """
        Load lifecycle conf from provided conf or container property.

        :returns: True if a lifecycle configuration has been loaded
        """
        if conf is None:
            conf = self.get_configuration()

        if not conf:
            raise LifecycleConfigurationInvalid("Configuration is empty")
        if isinstance(conf, dict):
            self.lifecycle_conf = conf
        else:
            try:
                self.load_json(conf)
            except ValueError as exc:
                raise LifecycleConfigurationInvalid(
                    "Unable to parse configuration"
                ) from exc

        schema_version = self.lifecycle_conf.get("_schema_version", -1)
        if schema_version not in self.SUPPORTED_CONFIGURATION_VERSIONS:
            raise LifecycleConfigurationInvalid(
                f"Schema version {schema_version} is not supported"
            )

    def load_json(self, json_str):
        """
        Load lifecycle json dict from LifecycleConfiguration string.

        :raises ValueError: if the string is not decodable as JSON
        """
        conf = json.loads(json_str)
        self.lifecycle_conf = conf

    def __str__(self):
        return json.dumps(self.lifecycle_conf)

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

    def _actions_to_apply(self, use_versioning, is_mpu_container):
        if is_mpu_container:
            return (AbortMpuAction,)

        if use_versioning:
            return (
                DeleteMarkerAction,
                NonCurrentExpirationAction,
                TransitionAction,
                NonCurrentTransitionAction,
                ExpirationAction,
            )
        return (
            TransitionAction,
            ExpirationAction,
        )

    def actions_iter(self, use_versioning, is_mpu_container):
        for action_class in self._actions_to_apply(use_versioning, is_mpu_container):
            actions = self.lifecycle_conf.get(action_class.accelerator, [])
            if isinstance(actions, dict):
                actions = [v for a in actions.values() for v in a]
            for rule_action_id in actions:
                rule_id, action_id = rule_action_id.split("-")
                rule = self.lifecycle_conf["Rules"][rule_id]
                action = rule[action_class.field][action_id]

                yield rule_action_id, action_class(rule_id, action_id), rule, action

    def build_sql_query(
        self,
        rule_filter,
        formated_days=None,
        date=None,
        non_current=False,
        versioned=False,
        expired_delete_marker=None,
    ):
        # Beginning of query will be force by meta2 code to avoid
        # update or delete queries
        _query = " "

        _slo_cond = (
            " LEFT JOIN properties pr ON al.alias=pr.alias AND"
            " al.version=pr.version AND pr.key='x-object-sysmeta-slo-size'"
            " INNER JOIN contents ct ON al.content = ct.id "
        )

        _lesser = ""
        _greater = ""
        # bypass size and tags when dealing with delete marker
        if not expired_delete_marker:
            if rule_filter.lesser is not None:
                _lesser = (
                    f" AND "
                    f"((ct.size <{rule_filter.lesser} AND pr.value IS NULL) OR "
                    f"pr.value < {rule_filter.lesser})"
                )

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
                for k, v in rule_filter.tags.items():
                    _tag_key_cond = (
                        " AND CAST(pr2.value as nvarchar(10000))"
                        f" LIKE '%<Tag><Key>{k}</Key>"
                    )
                    _tag_val_cond = f"<Value>{v}</Value></Tag>%'"
                    _tags = f"{_tags}{_tag_key_cond}{_tag_val_cond}"

                _query = f"{_query}{_base_tag}{_tags}"

            if _lesser or _greater:
                _query = f"{_query}{_slo_cond} {_lesser} {_greater}"

        # Create WHERE clause
        where_clauses = []
        if rule_filter.prefix:
            where_clauses.append("( al.alias LIKE ?||'%')")
        if formated_days is not None:
            where_clauses.append(
                f" ((al.mtime + {formated_days}) < (CAST "
                f"(strftime('%s', 'now') AS INTEGER )))"
            )
        elif date is not None:
            where_clauses.append(
                f" ((CAST (strftime('%s', '{date}') AS INTEGER )) < (CAST "
                "(strftime('%s', 'now') AS INTEGER )))"
            )
        where_clauses.append(self._processed_sql_condition())
        # close WHERE clause
        _query = f"{_query} WHERE ({' AND '.join(where_clauses)})"

        if non_current or versioned:
            _query = f"{_query} GROUP BY al.alias"
        return _query

    def create_noncurrent_view(self, rule_filter):
        # Create forced on meta2 side
        _query = (
            "VIEW noncurrent_view AS SELECT *, "
            "LAG(al.mtime, 1, -1) OVER (PARTITION BY al.alias ORDER BY al.version DESC)"
            " AS non_current_since, "
            "ROW_NUMBER() OVER (PARTITION BY al.alias ORDER BY al.version DESC)"
            " AS row_id "
            "FROM aliases AS al"
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
            _query = f"{_query}{_slo_cond} {_lesser} {_greater}"

        return _query

    def create_common_views(
        self, view_name, formated_time=None, date=None, deleted=None
    ):
        if not view_name:
            raise ValueError("Lifecycle views, empty view name!")
        # CREATE forced on meta2 side
        _query = (
            f"VIEW {view_name} AS SELECT *, "
            "COUNT(*) AS nb_versions FROM aliases AS al "
            "GROUP BY al.alias HAVING MAX(al.version)"
        )

        if deleted is not None:
            if deleted:
                _query = f"{_query} AND (al.deleted=1)"
            else:
                _query = f"{_query} AND (al.deleted=0)"
        elif formated_time is not None:
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

        return _query

    def noncurrent_query(self, rule_filter, noncurrent_versions, formated_time):
        """
        Deal with non current versions
        """

        if noncurrent_versions is None:
            noncurrent_versions = 0
        # SELECT is forced on meta2 side
        query = (
            "FROM noncurrent_view AS al "
            f"WHERE (row_id > {1 + noncurrent_versions}) "
            f"AND {self._processed_sql_condition()} "
        )
        if formated_time is not None:
            _time_cond = (
                f" AND ((al.non_current_since + {formated_time}) < "
                f"CAST(strftime('%s', 'now') AS INTEGER)) "
            )
            query = f"{query}{_time_cond}"
        if rule_filter.prefix:
            query = f"{query} AND (al.alias LIKE ?||'%')"
        return query

    def markers_query(self, rule_filter):
        """
        Get expired delete markers
        """

        # SELECT is forced on meta2 side
        query = f" WHERE nb_versions=1 AND {self._processed_sql_condition()} "

        if rule_filter.prefix:
            query = f"{query} AND (al.alias LIKE ?||'%')"

        return query

    def abort_incomplete_query(self, rule_filter, formated_days=None):
        # Beginning of query will be force by meta2 code to avoid
        # update or delete queries
        _query = " "

        _upload_finished_cond = (
            " INNER JOIN properties pr ON al.alias=pr.alias AND"
            " al.version=pr.version AND"
            " pr.key='x-object-sysmeta-s3api-has-content-type'"
            " AND CAST(pr.value AS TEXT)='no'"
        )

        _query = f"{_query}{_upload_finished_cond}"

        _query = f"{_query} WHERE ("
        # Time condition is always present via DaysaAfterInitiation
        _time_cond = (
            f" ((al.mtime + {formated_days}) < (CAST "
            f"(strftime('%s', 'now') AS INTEGER )))"
        )
        _query = f"{_query}{_time_cond}"
        _query = f"{_query} AND {self._processed_sql_condition()} "

        if rule_filter.prefix:
            _prefix_cond = " AND ( al.alias LIKE ?||'%')"
            _query = f"{_query}{_prefix_cond}"
        _query = f"{_query} )"

        return _query


class Tags:
    def __init__(self, tags):
        self.tags = {}
        for tag in tags:
            tag = {**tag}
            key = tag.pop("Key", None)
            value = tag.pop("Value", "")
            if key is None:
                raise ValueError("Key 'Key' not found in Tag")
            if tag:
                raise ValueError(
                    f"Unsupported fields in Tag: {', '.join((k for k in tag))}"
                )
            self.tags[key] = value

    def items(self):
        return self.tags.items()

    def __len__(self):
        return len(self.tags)


class RuleFilter:
    def __init__(self, rule):
        rule_filter = {**rule.get("Filter", {})}
        rule_id = rule.get("ID")
        self.prefix = rule.get("Prefix", None) or rule_filter.pop("Prefix", None)
        self.greater = rule_filter.pop("ObjectSizeGreaterThan", None)
        self.lesser = rule_filter.pop("ObjectSizeLessThan", None)
        # Build a list of tags:
        self.tags = Tags(rule_filter.pop("Tag", []))

        if rule_filter:
            raise ValueError(
                f"Unsupported fields in 'Filter' for rule '{rule_id}': "
                f"{', '.join((k for k in rule_filter))}"
            )
