# Copyright (C) 2024 OVH SAS
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

import os
import time

from oio.common.client import ProxyClient
from oio.common.constants import (
    M2_PROP_SHARDING_LOWER,
    M2_PROP_SHARDING_UPPER,
    M2_PROP_VERSIONING_POLICY,
    MULTIUPLOAD_SUFFIX,
    SHARDING_ACCOUNT_PREFIX,
)
from oio.common.easy_value import int_value
from oio.common.exceptions import NotFound

from oio.container.client import ContainerClient

from oio.crawler.common.base import Filter
from oio.crawler.meta2.meta2db import Meta2DB
from oio.container.lifecycle import (
    ContainerLifecycle,
    LIFECYCLE_PROPERTY_KEY,
    RuleFilter,
)

from oio.directory.admin import AdminClient


class Lifecycle(Filter):
    """Lifecycle filter.

    Load lifecycle configuration
    Order rules, actions
    Generate and send queries to meta2
    """

    NAME = "Lifecycle"

    # Maximum number of versions to handle in NoncurrentVersion actions is
    # limited to 50.
    LIMIT = 50

    def init(self):
        self.api = self.app_env["api"]
        self.retry_delay = int_value(self.conf.get("retry_delay"), 30)
        self.proxy_client = ProxyClient(
            self.conf, pool_manager=self.api.container.pool_manager, logger=self.logger
        )
        admin_args = {}
        admin_args["force_master"] = True
        self.admin_client = AdminClient(self.conf, logger=self.logger, **admin_args)
        container_args = {}
        self.container = ContainerClient(
            self.conf,
            pool_manager=self.api.container.pool_manager,
            logger=self.logger,
            **container_args,
        )

        self.batch_size = int_value(self.conf.get("lifecycle_batch_size"), 1000)

        self.reorder_rules = False

        # Crawler can remove local copy directly without
        # make an extra http call
        self.direct_remove = True

        # batch_size is equal to the number of objects that match rule when
        # dealing with current versions.
        # This is not the case when we deal with noncurrent versions and the
        # the number of versions can vary from one object to another
        self.noncurrent_limit = self.LIMIT * self.batch_size

        now = time.strftime("%Y-%m-%d")
        self.suffix = f"lifecycle-{now}"

        self.successes = 0
        self.errors = 0

        # Current container peer
        self.peer_to_use = None

        # Current container type and info
        self.is_mpu_container = False
        self.is_shard_container = False
        self.lower = None
        self.upper = None

        # Current container stats
        self.total_events = 0
        # Stats of rule actions
        self.rules_stats = {}
        # Aggregated stats per rule
        self.aggregated_stats = {}

        # To have a ratio of finished actions
        self.count_actions = 0
        self.finished_actions = 0
        # Updated when using user defined order
        self.finished_rules = 0
        self.count_disabled_rules = 0

        self.conf_not_found = 0

    def _get_main_container_props(self, account, container):
        """Get properties from main container.

        Main container could be the container itself,
        Root container in case of shard,
        Associated container if +sgement
        """
        main_account = None
        root_container = None
        props = {}
        # container is +segment: load lifecycle configuration from
        # main container
        if container.endswith(MULTIUPLOAD_SUFFIX):
            # Load configuration from main container
            self.logger.info("Lifeycle processing +segment %s", container)
            main_account = account
            root_container = container[: -len(MULTIUPLOAD_SUFFIX)]
            self.is_mpu_container = True
        # Container is a shard: load lifecycle configuration from
        # root container
        elif account.startswith(SHARDING_ACCOUNT_PREFIX):
            # Load config from root container
            self.logger.info("Lifeycle processing shard %s", container)
            main_account = account[len(SHARDING_ACCOUNT_PREFIX) :]
            root_container = container.rsplit("-", 3)[0]
            self.is_shard_container = True
        else:
            self.logger.info("Lifeycle processing container %s", container)
            main_account = account
            root_container = container
        try:
            props = self.api.container_get_properties(main_account, root_container)
        except NotFound:
            self.logger.warning(
                "Associated container for %s in account %s not found",
                container,
                account,
            )
            raise
        except Exception as exc:
            self.logger.warning(
                "Error occured %s for container %s in account %s ",
                exc,
                container,
                account,
            )
            raise
        return (props, main_account, root_container)

    def process(self, env, cb):
        """Process current container:

        Get information about container from associated main container
        Get and load lifecycle configuratiion
        Reorder rules and apply each one in defined order
        """
        meta2db = Meta2DB(self.app_env, env)
        self.peer_to_use = env["volume_id"]
        self.is_mpu_container = False
        self.is_shard_container = False

        try:
            account, container = self.api.resolve_cid(meta2db.cid)
            if account is None or container is None:
                self.logger.warning(
                    "Account, container not resoloved for cid %s", meta2db.cid
                )
                return self.app(env, cb)
            # Get properties from main container (if Lifecycle config is removed?)
            (props, main_account, root_container) = self._get_main_container_props(
                account, container
            )
            lifecycle_config = props["properties"].get(LIFECYCLE_PROPERTY_KEY)
            versioning = props["system"].get(M2_PROP_VERSIONING_POLICY)
            if lifecycle_config is None:
                self.logger.warning(
                    "No lifecycle configuration for given container: %s, "
                    " account: %s, cid: %s",
                    container,
                    account,
                    meta2db.cid,
                )
                self.conf_not_found += 1
                return self.app(env, cb)

            lc_instance = ContainerLifecycle(
                self.api, main_account, root_container, logger=self.logger
            )

            lc_instance.load()

            if self.is_shard_container:
                self.lower, self.upper = self._get_shard_range(meta2db.cid)

                # Trim < and > from lower and upper
                self.lower = self.lower[1:]
                self.upper = self.upper[1:]

            # init stats
            self._init_container_stats(lc_instance)

            # Reorder rules and apply them by priority
            if self.reorder_rules:
                rules = lc_instance.order_rules(versioning)
                if versioning:
                    self._exec_rules_versioned(
                        lc_instance,
                        meta2db.cid,
                        account,
                        container,
                        rules,
                        versioning,
                    )
                else:
                    self._exec_rules_non_versioned(
                        lc_instance,
                        meta2db.cid,
                        account,
                        container,
                        rules,
                        versioning,
                    )
            else:  # Apply rules/actions as defined in configuration
                self._exec_rules_user_defined_order(
                    lc_instance,
                    meta2db.cid,
                    account,
                    container,
                    versioning,
                )
            self.successes += 1
        except NotFound as exc:
            self.logger.warning(
                "Failed to find local copy cid=%s, msg=%s",
                meta2db.cid,
                str(exc),
            )
        except Exception as exc:
            self.errors += 1
            self.logger.warning(
                "Failed to apply lifecycle on local copy cid=%s, msg=%s",
                meta2db.cid,
                str(exc),
            )
        finally:
            # Make call to remove local copy*
            if not self.direct_remove:
                params = {
                    "service_type": "meta2",
                    "cid": meta2db.cid,
                    "service_id": self.peer_to_use,
                    "suffix": self.suffix,
                }
                res = self.admin_client.remove_base(**params)
                res_master = res.get(self.peer_to_use, {})
                if res_master["status"]["status"] != 200:
                    self.logger.warning(
                        "Failed to remove the local copy cid: %s msg: %s",
                        meta2db.cid,
                        res_master["status"]["message"],
                    )

            # Remove directory if no original copy (container was
            # sharded/shrinked,...)
            full_path_copy = meta2db.path
            if os.path.islink(full_path_copy):
                real_copy_path = os.path.realpath(full_path_copy)

                # meta2 db without lifecycle suffix
                original_meta2_db = real_copy_path.rsplit(".", 1)[0]
                # Remove directory if it doesn't contain original meta2 db
                if not os.path.exists(original_meta2_db):
                    # get base directory of meta2 db
                    base_dir = original_meta2_db.rsplit("/", 1)[0]

                    # Remove local lifecycle copy
                    if self.direct_remove:
                        os.unlink(real_copy_path)
                    # Add security check
                    check_based_dir = base_dir.rsplit("/", 1)
                    if len(check_based_dir) > 1 and len(check_based_dir[1]) == 3:
                        os.rmdir(base_dir)
                else:
                    self.logger.warning(
                        "Link to original meta2 db %s still exist", original_meta2_db
                    )
            else:
                self.logger.warning(
                    "Not a sym link to local copy of meta2 db %s",
                    full_path_copy,
                )
        return self.app(env, cb)

    def _get_shard_range(self, cid, **kwargs):
        props = self.container.container_get_properties(
            cid=cid, service_id=self.peer_to_use, suffix=self.suffix, **kwargs
        )
        lower = props.get("system").get(M2_PROP_SHARDING_LOWER)
        upper = props.get("system").get(M2_PROP_SHARDING_UPPER)
        return (lower, upper)

    def _gen_views_non_current_action(self, lc, rule, non_current_days_in_sec):
        """Generate views for NoncurrentExpiration/NoncurrentTransition.

        noncurrent_view depends on current_view.
        """
        view_queries = {}
        noncurrent_view = lc.create_noncurrent_view(rule, non_current_days_in_sec)
        current_view = lc.create_common_views(
            "current_view", rule, non_current_days_in_sec
        )
        view_queries["noncurrent_view"] = noncurrent_view
        view_queries["current_view"] = current_view

        return view_queries

    def _gen_views_current_action(self, lc, rule, days_in_sec, date):
        """Generate views to handle current version and delete marker

        Current views are used in case of versioned container.
        No need to create them for non versioned container
        """
        view_queries = {}
        delete_marker_view = lc.create_common_views(
            "marker_view", rule, days_in_sec, date, deleted=True
        )
        vesioned_view = lc.create_common_views(
            "versioned_view", rule, days_in_sec, deleted=False
        )

        view_queries["marker_view"] = delete_marker_view
        view_queries["versioned_view"] = vesioned_view

        return view_queries

    def _is_non_current(self, act):
        act_type = next(iter(act))
        if act_type in ("NoncurrentVersionExpiration", "NoncurrentVersionTransitions"):
            return True
        return False

    def _is_abort_impu(self, act):
        act_type = next(iter(act))
        if act_type == "AbortIncompleteMultipartUpload":
            return True
        return False

    def _get_non_current_days(self, act):
        act_type = next(iter(act))
        if self._is_non_current(act):
            return act[act_type].get("NoncurrentDays")
        return None

    def _get_non_current_versions(self, act):
        act_type = next(iter(act))
        if self._is_non_current(act):
            return act[act_type].get("NewerNoncurrentVersions")
        return None

    def _get_policy(self, act):
        act_type = next(iter(act))
        if act_type in ("Transitions", "NoncurrentVersionTransitions"):
            return act[act_type].get("StorageClass")
        return None

    def _get_action_name(self, act):
        if isinstance(act, dict):
            action_name = next(iter(act))
        else:
            action_name = act
        if action_name in ("Transitions", "NoncurrentVersionTransitions"):
            action_name = action_name[:-1]
        return action_name

    def _is_prefix_outside_range(self, rule):
        if self.is_shard_container:
            rule_filter = RuleFilter(rule)
            if rule_filter.prefix:
                if (self.lower and rule_filter.prefix < self.lower) or (
                    self.upper and rule_filter.prefix >= self.upper
                ):
                    self.logger.info(
                        "Skipped rule %s, prefix %s is outside of range [%s: %s]",
                        rule,
                        rule_filter.prefix,
                        self.lower,
                        self.upper,
                    )
                    return True
        return False

    def _get_actions(self, rule):
        """
        Note the changes:
        """
        actions = {}
        expiration = rule.get("Expiration", None)
        transitions = rule.get("Transitions", [])
        noncurrent_expiration = rule.get("NoncurrentVersionExpiration", None)
        noncurrent_transitions = rule.get("NoncurrentVersionTransitions", [])
        abort_mpu = rule.get("AbortIncompleteMultipartUpload", None)
        if expiration is not None:
            actions["Expiration"] = [expiration]
        if len(transitions) > 0:
            actions["Transitions"] = transitions
        if noncurrent_expiration is not None:
            actions["NoncurrentVersionExpiration"] = [noncurrent_expiration]
        if len(noncurrent_transitions) > 0:
            actions["NoncurrentVersionTransitions"] = noncurrent_transitions

        if abort_mpu is not None:
            actions["AbortIncompleteMultipartUpload"] = [abort_mpu]
        return actions

    def _exec_rules_non_versioned(
        self, lc, cid, account, container, rules, versioning_enabled
    ):
        """Order to execute action for non versioned container:

        Only current actions, rules are executed in the following order:
        - IncompleteMpuabort
        - Expirations
        - Transitions
        """
        mpu_abort_actions = rules[3]
        current_actions = rules[0]

        # IncompleteMpuabort actions ordered by days
        for _, item in mpu_abort_actions.items():
            rule_id = item[0]
            action_type = item[1]
            action = item[2]
            rule = item[3]
            rule["ID"] = rule_id

            if rule.get("Status") == "Disabled":
                self.logger.info("Lifecycle rule with id %s is disabled ", rule_id)
                self.count_disabled_rules += 1
                continue

            if not self.is_mpu_container:
                break

            if self._is_prefix_outside_range(rule):
                continue

            current_action = {action_type: action}
            self._process_action(
                lc,
                cid,
                account,
                container,
                rule,
                current_action,
                versioning_enabled,
                **kwargs,
            )
            self.finished_actions += 1

        # Expirations/Transitions are ordered by days/date with
        # priority to Expirations
        for _, item in current_actions.items():
            rule_id = item[0]
            action_type = item[1]
            action = item[2]
            rule = item[3]
            rule["ID"] = rule_id

            if rule.get("Status") == "Disabled":
                self.logger.info("Lifecycle rule with id %s is disabled ", rule_id)
                self.count_disabled_rules += 1
                continue

            if self.is_mpu_container:
                break

            if self._is_prefix_outside_range(rule):
                continue

            current_action = {action_type: action}
            self._process_action(
                lc,
                cid,
                account,
                container,
                rule,
                current_action,
                versioning_enabled,
                **kwargs,
            )
            self.finished_actions += 1

    def _exec_rules_versioned(
        self, lc, cid, account, container, rules, versioning_enabled
    ):
        """Order to execute actions for versioned container:

        - Expired delete marker, this is a particular case of expiration
        - Mpu abort
        - Non current Expirations
        - Non current Transitions
        - current Transitions
        - current Expirations {Expirations only do a marker insert}

        """

        current_actions = rules[0]
        noncurrent_actions = rules[1]
        expired_delete_marker_actions = rules[2]
        mpu_abort_actions = rules[3]

        for _, item in expired_delete_marker_actions.items():
            rule_id = item[0]
            action_type = item[1]
            action = item[2]
            rule = item[3]
            rule["ID"] = rule_id

            if rule.get("Status") == "Disabled":
                self.logger.info("Lifecycle rule with id %s is disabled ", rule_id)
                self.count_disabled_rules += 1
                continue

            if self.is_mpu_container:
                break

            if self._is_prefix_outside_range(rule):
                continue

            current_action = {action_type: action}
            self._process_current_action(
                lc,
                cid,
                account,
                container,
                rule,
                current_action,
                versioning_enabled,
                **kwargs,
            )
            self.finished_actions += 1

        # AbortIncompleteMultiPartUpload doesn't depend on versioning
        # It applies on +segments container
        for _, item in mpu_abort_actions.items():
            rule_id = item[0]
            action_type = item[1]
            action = item[2]
            rule = item[3]
            rule["ID"] = rule_id

            if rule.get("Status") == "Disabled":
                self.logger.info("Lifecycle rule with id %s is disabled ", rule_id)
                self.count_disabled_rules += 1
                continue

            if not self.is_mpu_container:
                break

            if self._is_prefix_outside_range(rule):
                continue

            current_action = {action_type: action}
            self._process_action(
                lc,
                cid,
                account,
                container,
                rule,
                current_action,
                versioning_enabled,
                **kwargs,
            )
            self.finished_actions += 1

        for _, item in noncurrent_actions.items():
            rule_id = item[0]
            action_type = item[1]
            action = item[2]
            rule = item[3]
            rule["ID"] = rule_id

            if rule.get("Status") == "Disabled":
                self.logger.info("Lifecycle rule with id %s is disabled ", rule_id)
                self.count_disabled_rules += 1
                continue

            if self.is_mpu_container:
                break

            if self._is_prefix_outside_range(rule):
                continue

            current_action = {action_type: action}
            self._process_noncurrent_action(
                lc,
                cid,
                account,
                container,
                rule,
                current_action,
                versioning_enabled,
                **kwargs,
            )
            self.finished_actions += 1

        # Expirations/Transitions are ordered by days/date with
        # priority to Transitions
        for _, item in current_actions.items():
            rule_id = item[0]
            action_type = item[1]
            action = item[2]
            rule = item[3]
            rule["ID"] = rule_id

            if rule.get("Status") == "Disabled":
                self.logger.info("Lifecycle rule with id %s is disabled ", rule_id)
                self.count_disabled_rules += 1
                continue

            if self.is_mpu_container:
                break

            if self._is_prefix_outside_range(rule):
                continue

            current_action = {action_type: action}
            self._process_current_action(
                lc,
                cid,
                account,
                container,
                rule,
                current_action,
                versioning_enabled,
                **kwargs,
            )
            self.finished_actions += 1

    def _process_current_action(
        self, lc, cid, account, container, rule, act, versioning_enabled
    ):
        rule_id = rule.get("ID")
        days_in_sec = None
        base_sql_query = None
        queries = {}
        view_queries = {}
        action = self._get_action_name(act)
        days, date, delete_marker = self._get_action_parameters(act)
        policy = self._get_policy(act)

        if not versioning_enabled and action in (
            "NoncurrentVersionTransition",
            "NoncurrentVersionExpiration",
        ):
            self.logger.warning(
                "Unsupported action %s for non versioned container %s," " account %s ",
                action,
                container,
                account,
            )
            return

        # Versioning
        if versioning_enabled:
            # Current versions: Expiration/Transition
            if days is not None:
                days_in_sec = self._days_to_seconds(days)
            view_queries = self._gen_views_current_action(lc, rule, days_in_sec, date)

            if delete_marker is not None:
                if delete_marker:
                    queries["marker"] = lc.markers_query(rule)
                else:
                    self.logger.warning(
                        "Skip Expiration with delete marker set to false "
                        " action %s rule %s",
                        action,
                        rule,
                    )
                    return True
            else:
                queries["base"] = lc.build_sql_query(
                    rule, days_in_sec, None, False, True
                )
        else:  # non versioned
            if days is not None:
                days_in_sec = self._days_to_seconds(days)
            base_sql_query = lc.build_sql_query(rule, days_in_sec, date)
            queries["base"] = base_sql_query

        self._send_query_events(
            cid,
            queries,
            act,
            view_queries,
            policy,
            rule_id,
        )

    def _process_noncurrent_action(
        self, lc_instance, cid, account, container, rule, act, versioning_enabled
    ):
        self.logger.info("rule %s, action %s", rule, act)

        rule_id = rule.get("ID")
        queries = {}
        view_queries = {}
        action = self._get_action_name(act)
        # Default value for NoncurrentExpiration/ is zero
        newer_non_current_versions = self._get_non_current_versions(act)
        non_current_days = self._get_non_current_days(act)
        policy = self._get_policy(act)

        if not versioning_enabled and action in (
            "NoncurrentVersionTransition",
            "NoncurrentVersionExpiration",
        ):
            self.logger.warning(
                "Unsupported action %s for non versioned container %s, acount %s",
                action,
                container,
                account,
            )
            return

        # NoncurrentVersions, NoncurrentVersions doesn't support dates
        if non_current_days is None:
            return
        non_current_days_in_sec = self._days_to_seconds(non_current_days)

        # Create views
        view_queries = self._gen_views_non_current_action(
            lc_instance, rule, non_current_days_in_sec
        )
        queries["base"] = rule.filter.noncurrent_query(newer_non_current_versions)

        self._send_query_events(
            cid,
            queries,
            act,
            view_queries,
            policy,
            rule_id,
        )

    def _process_action(
        self, lc_instance, cid, account, container, rule, action, versioning_enabled
    ):
        """Process one action by batches.
        Handle different types of actions and versioned/not versioned container
        """

        rule_id = rule.get("ID")
        days_in_sec = None
        base_sql_query = None
        queries = {}
        view_queries = {}
        action_name = self._get_action_name(action)
        non_current = self._is_non_current(action)
        abort_action = self._is_abort_impu(action)

        # Default value for NoncurrentExpiration/ is zero
        newer_non_current_versions = self._get_non_current_versions(action)
        non_current_days = self._get_non_current_days(action)
        days, date, delete_marker = self._get_action_parameters(action)
        policy = self._get_policy(action)

        if not versioning_enabled and action_name in (
            "NoncurrentVersionTransitions",
            "NoncurrentVersionExpiration",
        ):
            self.logger.warning(
                "Unsupported action %s in rule_id %s for non versioned container: "
                "%s account: %s",
                action_name,
                rule_id,
                container,
                account,
            )
            return False

        # AbortIncompleteMultiPartUpload doesn't depend on versioning
        if abort_action:
            days_in_sec = self._days_to_seconds(days)
            base_sql_query = lc_instance.abort_incomplete_query(rule, days_in_sec)
            queries["base"] = base_sql_query
            self._send_query_events(
                cid,
                queries,
                action,
                view_queries,
                policy,
                rule_id,
            )
            return

        # Versioning
        if versioning_enabled:
            if non_current:
                # NoncurrentVersions, NoncurrentVersions doesn't support dates
                if non_current_days is None:
                    self.logger.warning(
                        "Shouldn't occur no non_current_days of  action %s "
                        "  rule_id %s for non versioned bucket %s ",
                        action_name,
                        rule_id,
                        container,
                    )
                    return False
                non_current_days_in_sec = self._days_to_seconds(non_current_days)

                # Create views
                view_queries = self._gen_views_non_current_action(
                    lc_instance, rule, non_current_days_in_sec
                )
                queries["base"] = lc_instance.noncurrent_query(
                    newer_non_current_versions
                )
            # Current versions: Expiration/Transition
            else:
                if days is not None:
                    days_in_sec = self._days_to_seconds(days)
                view_queries = self._gen_views_current_action(
                    lc_instance, rule, days_in_sec, date
                )

                if delete_marker is None:
                    queries["base"] = lc_instance.build_sql_query(
                        rule, days_in_sec, None, False, True, True
                    )
                elif delete_marker:
                    queries["marker"] = lc_instance.markers_query()
                else:
                    self.logger.warning(
                        "Skip Expiration with deletemarker set to false rule_id %s,"
                        " action %s",
                        rule_id,
                        action_name,
                    )
                    return False

        else:  # non versioned
            if days is not None:
                days_in_sec = self._days_to_seconds(days)
            base_sql_query = lc_instance.build_sql_query(rule, days_in_sec, date)
            queries["base"] = base_sql_query

        self._send_query_events(
            cid,
            queries,
            action,
            view_queries,
            policy,
            rule_id,
        )

    def _exec_rules_user_defined_order(
        self, lc, cid, account, container, versioning_enabled
    ):
        json_dict = lc.conf_json

        for rule_id, rule in json_dict["Rules"].items():
            rule["ID"] = rule_id

            if rule["Status"] == "Disabled":
                self.logger.info(
                    "Lifecycle rule with id %s is disabled ", rule.get("ID")
                )
                self.count_disabled_rules += 1
                continue

            if self._is_prefix_outside_range(rule):
                continue
            actions = self._get_actions(rule)
            for act_type, act_list in actions.items():
                if self.is_mpu_container:
                    if act_type != "AbortIncompleteMultipartUpload":
                        continue
                else:
                    if act_type == "AbortIncompleteMultipartUpload":
                        continue
                for act in act_list:
                    current_action = {act_type: act}
                    self._process_action(
                        lc,
                        cid,
                        account,
                        container,
                        rule,
                        current_action,
                        versioning_enabled,
                    )
                    self.finished_actions += 1
        self.finished_rules += 1

    def _create_views_request(self, cid, view_queries, **kwargs):
        """Create views

        Views depends on rules and actions parameters, they
        are created at the begining of action.
        """

        params = {"cid": cid, "service_id": self.peer_to_use}
        create_views_data = {}
        create_views_data["suffix"] = self.suffix
        for key, val in view_queries.items():
            create_views_data[key] = val

        resp, _ = self.proxy_client._request(
            "POST",
            "/container/lifecycle/views/create",
            params=params,
            json=create_views_data,
            **kwargs,
        )
        return resp

    def _send_query_events(
        self,
        cid,
        queries,
        action,
        view_queries,
        policy,
        rule_id,
        **kwargs,
    ):
        action_name = self._get_action_name(action)
        for key_query, val_query in queries.items():
            offset = 0
            while True:
                sql_query = val_query
                if action_name in (
                    "NoncurrentVersionExpiration",
                    "NoncurrentVersionTransition",
                ):
                    sql_query = (
                        f"{sql_query} limit {self.noncurrent_limit}"
                        f" offset {offset} "
                    )
                else:
                    sql_query = (
                        f"{sql_query} limit {self.batch_size}" f" offset {offset} "
                    )
                params = {"cid": cid, "service_id": self.peer_to_use}
                if action_name in (
                    "NoncurrentVersionExpiration",
                    "NoncurrentVersionTransition",
                ):
                    params["action_type"] = "noncurrent"
                else:
                    params["action_type"] = "current"

                data = {}
                data["action"] = action_name
                data["suffix"] = self.suffix
                if offset == 0 and key_query in ("base", "marker"):
                    resp = self._create_views_request(cid, view_queries, **kwargs)
                    if resp.status != 204:
                        self.logger.error(
                            "Failed to create views for rule %s," " action %s",
                            rule_id,
                            action_name,
                        )
                        break
                if key_query == "marker":
                    data["is_markers"] = 1

                data["query"] = sql_query
                data["query_set_tag"] = val_query
                data["storage_class"] = policy
                data["batch_size"] = self.batch_size
                data["rule_id"] = rule_id

                resp, _ = self.proxy_client._request(
                    "POST",
                    "/container/lifecycle/apply",
                    params=params,
                    json=data,
                    **kwargs,
                )

                if resp.status != 204:
                    self.logger.error(
                        "Failed to apply batch for rule %s, " " action %s",
                        rule_id,
                        action_name,
                    )
                    break

                count = int(resp.getheader("x-oio-count"))
                offset += count
                self._update_container_stats(rule_id, action_name, count)
                if count == 0:
                    break

    def _is_last_action_last_rule(self, rules, actions, count_rules, count_actions):
        if (count_rules == len(rules) - 1) and (count_actions == len(actions) - 1):
            return True
        else:
            return False

    def _init_container_stats(self, lc_instance):
        self.total_events = 0
        self.count_actions = 0
        self.finished_actions = 0
        self.finished_rules = 0
        self.rules_stats = {}
        self.aggregated_stats = {}

        conf_json = lc_instance.conf_json
        for rule_id, rule in conf_json["Rules"].items():
            # rule_id is unique
            rule_id = rule["ID"] = rule_id
            self.rules_stats[rule_id] = {}
            self.aggregated_stats[rule_id] = 0
            actions = self._get_actions(rule)
            for act_type, act_list in actions.items():
                for act in act_list:
                    # Full action string is used as key
                    action_name = self._get_action_name(act_type)
                    self.rules_stats[rule_id][action_name] = 0
                    self.count_actions += 1

    def _update_container_stats(self, rule_id, action_name, value):
        self.rules_stats[rule_id][action_name] += value
        self.aggregated_stats[rule_id] += value
        self.total_events += value

    def _get_action_parameters(self, act):
        days = None
        date = None
        delete_marker = None
        act_type = next(iter(act))
        if act_type == "Expiration":
            days = act[act_type].get("Days", None)
            date = act[act_type].get("Date", None)
            delete_marker = act[act_type].get("ExpiredObjectDeleteMarker", None)
        elif act_type == "Transitions":
            days = act[act_type].get("Days", None)
            date = act[act_type].get("Date", None)
        elif act_type == "AbortIncompleteMultipartUpload":
            days = act[act_type].get("DaysAfterInitiation", None)
        else:
            raise ValueError("Unsopported action %s", act)

        return [days, date, delete_marker]

    def _days_to_seconds(self, days):
        return 86400 * int(days)

    def _get_filter_stats(self):
        main_stats = {
            "successes": self.successes,
            "errors": self.errors,
            "total_events": self.total_events,
            "count_actions": self.count_actions,
            "finished_actions": self.finished_actions,
            "finished_rules": self.finished_rules,
            "count_disabled_rules": self.count_disabled_rules,
        }
        # (TODO) append agregated stats per rule/action??
        return main_stats

    def _reset_filter_stats(self):
        self.successes = 0
        self.errors = 0
        self.total_events = 0
        self.count_actions = 0
        self.finished_actions = 0
        self.finished_rules = 0
        self.count_disabled_rules = 0


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def lifecycle_filter(app):
        return Lifecycle(app, conf)

    return lifecycle_filter