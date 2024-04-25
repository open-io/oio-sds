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
    MULTIUPLOAD_SUFFIX,
    SHARDING_ACCOUNT_PREFIX,
    VERSIONING_PROPERTY_KEY,
)
from oio.common.easy_value import int_value
from oio.common.exceptions import NotFound

from oio.container.client import ContainerClient

from oio.crawler.common.base import Filter
from oio.crawler.meta2.meta2db import Meta2DB
from oio.container.lifecycle import (
    AbortIncompleteMultipartUpload,
    ContainerLifecycle,
    DateActionFilter,
    DaysActionFilter,
    DeletedMarkerActionFilter,
    Expiration,
    LIFECYCLE_PROPERTY_KEY,
    NoncurrentCountActionFilter,
    NoncurrentVersionExpiration,
    NoncurrentVersionTransition,
    Transition,
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

        # Budget per container (not bucket), as containers of same bucket would be
        # handled by different workers.
        self.budget_per_container = int_value(
            self.conf.get("budget_per_container"), 25000
        )

        self.reorder_rules = True

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
        self.volume_id = self.app_env["volume_id"]

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

        self.nb_match_per_container = 0

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
        return props

    def process(self, env, cb):
        """Process current container:

        Get information about container from associated main container
        Get and load lifecycle configuratiion
        Reorder rules and apply each one in defined order
        """
        meta2db = Meta2DB(self.app_env, env)
        self.peer_to_use = self.volume_id
        self.is_mpu_container = False
        self.is_shard_container = False

        self.nb_match_per_container = 0
        try:
            account, container = self.api.resolve_cid(meta2db.cid)
            if account is None or container is None:
                self.logger.warning(
                    "Account, container not resoloved for cid %s", meta2db.cid
                )
                return self.app(env, cb)
            # Get properties from main container (if Lifecycle configis removed between)
            props = self._get_main_container_props(account, container)
            lifecycle_config = props["properties"].get(LIFECYCLE_PROPERTY_KEY)

            versioning = props["properties"].get(VERSIONING_PROPERTY_KEY)

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
                self.api, account, container, logger=self.logger
            )

            lc_instance.load_xml(lifecycle_config)

            if self.is_shard_container:
                self.lower, self.upper = self._get_shard_range(meta2db.cid)

                # Trim < and > from lower and upper
                self.lower = self.lower[1:]
                self.upper = self.upper[1:]

            # init stats
            self._init_container_stats(lc_instance)

            # Reorder rules and apply them by priority
            if self.reorder_rules:
                for rule in lc_instance.rules:
                    if not rule.enabled:
                        self.logger.info(
                            "Lifecycle rule with id %s is disabled ", rule.id
                        )
                        self.count_disabled_rules += 1
                        continue
                rules = lc_instance.order_rules(versioning)
                if versioning:
                    self._exec_rules_versioned(
                        meta2db.cid,
                        account,
                        container,
                        rules,
                        versioning,
                    )
                else:
                    self._exec_rules_non_versioned(
                        meta2db.cid,
                        account,
                        container,
                        rules,
                        versioning,
                    )
            else:  # Apply rules/actions as defined in configuration
                self._exec_rules_user_defined_order(
                    meta2db.cid,
                    account,
                    container,
                    lc_instance,
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

    def _gen_views_non_current_action(self, rule, non_current_days_in_sec):
        """Generate views for NoncurrentExpiration/NoncurrentTransition.

        noncurrent_view depends on current_view.
        """
        view_queries = {}
        noncurrent_view = rule.filter.create_noncurrent_view(non_current_days_in_sec)
        current_view = rule.filter.create_common_views(
            "current_view", non_current_days_in_sec
        )
        view_queries["noncurrent_view"] = noncurrent_view
        view_queries["current_view"] = current_view

        return view_queries

    def _gen_views_current_action(self, rule, days_in_sec, date):
        """Generate views to handle current version and delete marker

        Current views are used in case of versioned container.
        No need to create them for non versioned container
        """
        view_queries = {}
        delete_marker_view = rule.filter.create_common_views(
            "marker_view", days_in_sec, date, deleted=True
        )
        vesioned_view = rule.filter.create_common_views(
            "versioned_view", days_in_sec, deleted=False
        )

        view_queries["marker_view"] = delete_marker_view
        view_queries["versioned_view"] = vesioned_view

        return view_queries

    def _is_non_current(self, act):
        if (
            type(act) is NoncurrentVersionExpiration
            or type(act) is NoncurrentVersionTransition
        ):
            return True
        return False

    def _is_abort_impu(self, act):
        if type(act) is AbortIncompleteMultipartUpload:
            return True
        return False

    def _get_non_current_days(self, act):
        if self._is_non_current(act):
            return act.non_current_days
        return None

    def _get_non_current_versions(self, act):
        if self._is_non_current(act):
            return act.newer_non_current_versions
        return None

    def _get_policy(self, act):
        if isinstance(act, NoncurrentVersionTransition):
            return act.policy
        if isinstance(act, Transition):
            return act.policy
        return None

    def _get_action(self, act):
        return act.__class__.__name__

    def _is_prefix_outside_range(self, rule):
        if self.is_shard_container:
            if (
                rule.filter is not None
                and rule.filter.prefix < self.lower
                or rule.filter.prefix > self.upper
            ):
                self.logger.info(
                    "Skipped rule %s, prefix %s is outside of range [%s: %s]",
                    rule,
                    rule.filter.prefix,
                    self.lower,
                    self.upper,
                )
                return True
        return False

    def _is_budget_reached(self):
        if self.budget_per_container:
            if self.nb_match_per_container >= self.budget_per_container:
                return True
        return False

    def _exec_rules_non_versioned(
        self, cid, account, container, rules, versioning_enabled
    ):
        """Order to execute action for non versioned contaienr:

        Only current actions, rules are executed in the following order:
        - IncompleteMpuabort
        - Expirations
        - Transitions
        """
        mpu_abort_actions = rules[3]
        current_actions = rules[0]

        # IncompleteMpuabort actions ordered by days
        for _, item in mpu_abort_actions.items():
            rule = item[0]
            action = item[1]

            if not self.is_mpu_container:
                break

            if self._is_prefix_outside_range(rule):
                continue

            self._process_action(
                cid, account, container, rule, action, versioning_enabled
            )
            self.finished_actions += 1

        # Expirations/Transitions are ordered by days/date with
        # priority to Expirations
        for _, item in current_actions.items():
            rule = item[0]
            action = item[1]

            if self.is_mpu_container:
                break

            if self._is_prefix_outside_range(rule):
                continue

            self._process_action(
                cid, account, container, rule, action, versioning_enabled
            )
            self.finished_actions += 1

    def _exec_rules_versioned(self, cid, account, container, rules, versioning_enabled):
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
            rule = item[0]
            action = item[1]

            if self.is_mpu_container:
                break

            if self._is_prefix_outside_range(rule):
                continue

            self._process_current_action(
                cid, account, container, rule, action, versioning_enabled
            )
            self.finished_actions += 1

        # AbortIncompleteMultiPartUpload doesn't depend on versioning
        # It applies on +segments container
        for _, item in mpu_abort_actions.items():
            rule = item[0]
            action = item[1]
            if not self.is_mpu_container:
                break

            if self._is_prefix_outside_range(rule):
                continue

            self._process_action(
                cid, account, container, rule, action, versioning_enabled
            )
            self.finished_actions += 1

        for _, item in noncurrent_actions.items():
            rule = item[0]
            action = item[1]

            if self.is_mpu_container:
                break

            if self._is_prefix_outside_range(rule):
                continue

            self._process_noncurrent_action(
                cid, account, container, rule, action, versioning_enabled
            )
            self.finished_actions += 1

        # Expirations/Transitions are ordered by days/date with
        # priority to Transitions
        for _, item in current_actions.items():
            rule = item[0]
            action = item[1]

            if self.is_mpu_container:
                break

            if self._is_prefix_outside_range(rule):
                continue

            self._process_current_action(
                cid, account, container, rule, action, versioning_enabled
            )
            self.finished_actions += 1

    def _process_current_action(
        self, cid, account, container, rule, act, versioning_enabled
    ):
        rule_id = rule.id
        days_in_sec = None
        base_sql_query = None
        queries = {}
        view_queries = {}
        action = self._get_action(act)
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
            view_queries = self._gen_views_current_action(rule, days_in_sec, date)

            if type(act.filter) is DeletedMarkerActionFilter:
                if delete_marker:
                    queries["base"] = rule.filter.to_sql_query(
                        days_in_sec, None, False, True, True
                    )
                    queries["marker"] = rule.filter.markers_query()
                else:
                    self.logger.warning(
                        "Skip Expiration with delete marker set to false "
                        " action %s rule %s",
                        action,
                        rule,
                    )
                    return True
            else:
                queries["base"] = rule.filter.to_sql_query(
                    days_in_sec, None, False, True
                )
                queries["marker"] = rule.filter.markers_query()
        else:  # non versioned
            if days is not None:
                days_in_sec = self._days_to_seconds(days)
            base_sql_query = rule.filter.to_sql_query(days_in_sec, date)
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
        self, cid, account, container, rule, act, versioning_enabled
    ):
        self.logger.info("rule %s, action %s", rule, act)

        rule_id = rule.id
        queries = {}
        view_queries = {}
        action = self._get_action(act)
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
        view_queries = self._gen_views_non_current_action(rule, non_current_days_in_sec)
        queries["base"] = rule.filter.noncurrent_query(newer_non_current_versions)

        self._send_query_events(
            cid,
            queries,
            act,
            view_queries,
            policy,
            rule_id,
        )

    def _process_action(self, cid, account, container, rule, act, versioning_enabled):
        """Process one action by batches.
        Handle different types of actions and versioned/not versioned container
        """
        rule_id = rule.id
        days_in_sec = None
        base_sql_query = None
        queries = {}
        view_queries = {}
        action = self._get_action(act)
        non_current = self._is_non_current(act)
        abort_action = self._is_abort_impu(act)

        # Default value for NoncurrentExpiration/ is zero
        newer_non_current_versions = self._get_non_current_versions(act)
        non_current_days = self._get_non_current_days(act)
        days, date, delete_marker = self._get_action_parameters(act)
        policy = self._get_policy(act)

        if not versioning_enabled and action in (
            "NoncurrentVersionTransition",
            "NoncurrentVersionExpiration",
        ):
            self.logger.warning(
                "Unsupported action %s for non versioned container %s account %s",
                action,
                container,
                account,
            )
            return False

        # AbortIncompleteMultiPartUpload doesn't depend on versioning
        if abort_action:
            days_in_sec = self._days_to_seconds(days)
            base_sql_query = rule.filter.abort_incomplete_query(days_in_sec)
            queries["base"] = base_sql_query

            self._send_query_events(
                cid,
                queries,
                act,
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
                        "  rule %s for non versioned bucket %s ",
                        action,
                        rule,
                        container,
                    )
                    return False
                non_current_days_in_sec = self._days_to_seconds(non_current_days)

                # Create views
                view_queries = self._gen_views_non_current_action(
                    rule, non_current_days_in_sec
                )
                queries["base"] = rule.filter.noncurrent_query(
                    newer_non_current_versions
                )
            # Current versions: Expiration/Transition
            else:
                if days is not None:
                    days_in_sec = self._days_to_seconds(days)

                view_queries = self._gen_views_current_action(rule, days_in_sec, date)

                if type(act.filter) is DeletedMarkerActionFilter:
                    if delete_marker:
                        queries["base"] = rule.filter.to_sql_query(
                            days_in_sec, None, False, True, True
                        )
                        queries["marker"] = rule.filter.markers_query()
                    else:
                        print("Skip Expiration with deletemarker set to false")
                        return False
                else:
                    queries["base"] = rule.filter.to_sql_query(
                        days_in_sec, None, False, True
                    )
                    queries["marker"] = rule.filter.markers_query()
        else:  # non versioned
            if days is not None:
                days_in_sec = self._days_to_seconds(days)
            base_sql_query = rule.filter.to_sql_query(days_in_sec, date)
            queries["base"] = base_sql_query

        self._send_query_events(
            cid,
            queries,
            act,
            view_queries,
            policy,
            rule_id,
        )

    def _exec_rules_user_defined_order(
        self, cid, account, container, lc, versioning_enabled
    ):
        for rule in lc.rules:
            if not rule.enabled:
                self.logger.info("Lifecycle rule with id %s is disabled ", rule.id)
                self.count_disabled_rules += 1
                continue

            if self._is_prefix_outside_range(rule):
                continue

            for act in rule.actions:
                if self.is_mpu_container:
                    if not isinstance(act, AbortIncompleteMultipartUpload):
                        continue
                else:
                    if isinstance(act, AbortIncompleteMultipartUpload):
                        continue
                self._process_action(
                    cid, account, container, rule, act, versioning_enabled
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

    def _get_offest(self, cid, action, rule):
        key = "-".join(["offsets", action, rule])
        params = {"cid": cid, "service_id": self.peer_to_use, "suffix": self.suffix}
        resp, body = self.proxy_client._request(
            "POST",
            "/container/get_properties",
            params=params,
        )
        offset = body.get("properties", {}).get(key)
        if offset is None:
            return 0
        else:
            return int(offset)

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
        action_type = self._get_action(action)
        for key_query, val_query in queries.items():
            offset = self._get_offest(cid, action_type, rule_id)
            while True:
                # Check budget first
                if self._is_budget_reached():
                    self.logger.info(
                        "Budget is reached for container cid %s rule %s, action %s",
                        cid,
                        rule_id,
                        action,
                    )
                    return

                sql_query = val_query
                if action_type in (
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
                if action_type in (
                    "NoncurrentVersionExpiration",
                    "NoncurrentVersionTransition",
                ):
                    params["action_type"] = "noncurrent"
                else:
                    params["action_type"] = "current"

                data = {}
                data["action"] = action_type
                data["suffix"] = self.suffix
                if offset == 0 and key_query == "base":
                    resp = self._create_views_request(cid, view_queries, **kwargs)
                    if resp.status != 204:
                        self.logger.error(
                            "Failed to create views for rule %s," " action %s",
                            rule_id,
                            action_type,
                        )
                        break
                if key_query == "marker":
                    data["is_markers"] = 1

                data["query"] = sql_query
                data["query_set_tag"] = val_query
                data["storage_class"] = policy
                data["batch_size"] = self.batch_size
                data["rule_id"] = rule_id
                # last_rule_action could be used to remove copy at last request
                #  if last_rule_action:
                #       data["last_action"] = 1
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
                        action_type,
                    )
                    break

                count = int(resp.getheader("x-oio-count"))
                offset += count

                self.nb_match_per_container += count
                self._update_container_stats(rule_id, action, count)
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

        for rule in lc_instance.rules:
            # rule_id is unique
            rule_id = rule.id
            self.rules_stats[rule_id] = {}
            self.aggregated_stats[rule_id] = 0
            for act in rule.actions:
                # Full action string is used as key
                self.rules_stats[rule_id][str(act)] = 0
                self.count_actions += 1

    def _update_container_stats(self, rule_id, action, value):
        self.rules_stats[rule_id][str(action)] += value
        self.aggregated_stats[rule_id] += value
        self.total_events += value

    def _get_action_parameters(self, act):
        days = None
        date = None
        delete_marker = None
        if isinstance(act, Expiration):
            if type(act.filter) is DaysActionFilter:
                days = act.filter.days
            elif type(act.filter) is DateActionFilter:
                date = act.filter.date
            elif type(act.filter) is NoncurrentCountActionFilter:
                days = act.filter.days
            elif type(act.filter) is DeletedMarkerActionFilter:
                delete_marker = act.filter.expired_object_deleted_marker
        elif isinstance(act, Transition):
            if type(act.filter) is DaysActionFilter:
                days = act.filter.days
            elif type(act.filter) is DateActionFilter:
                date = act.filter.date
            elif type(act.filter) is NoncurrentCountActionFilter:
                days = act.filter.days
            else:
                raise ValueError(
                    "Unsopported filter %s for action %s", type(act.filter), act
                )
        elif isinstance(act, AbortIncompleteMultipartUpload):
            if type(act.filter) is DaysActionFilter:
                days = act.filter.days
            else:
                raise ValueError(
                    "Unsopported filter %s for action %s", type(act.filter), act
                )
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
