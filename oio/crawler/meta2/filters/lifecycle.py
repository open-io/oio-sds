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

import datetime
from collections import Counter

from oio.common.client import ProxyClient
from oio.common.constants import (
    LOGGING_PROPERTY_KEY,
    M2_PROP_SHARDING_LOWER,
    M2_PROP_SHARDING_UPPER,
    M2_PROP_VERSIONING_POLICY,
    MULTIUPLOAD_SUFFIX,
    SHARDING_ACCOUNT_PREFIX,
)
from oio.common.easy_value import debinarize, int_value
from oio.common.exceptions import NotFound
from oio.common.utils import request_id

from oio.container.client import ContainerClient

from oio.crawler.meta2.filters.base import Meta2Filter
from oio.crawler.meta2.meta2db import Meta2DB
from oio.container.lifecycle import (
    ContainerLifecycle,
    RuleFilter,
    lifecycle_backup_path,
)

from oio.directory.admin import AdminClient
from oio.lifecycle.metrics import LifecycleMetricTracker, LifecycleStep
from oio.container.lifecycle import (
    AbortMpuAction,
    DeleteMarkerAction,
)


class Context:
    def __init__(self, run_id, account_id, bucket_id, container_id):
        self.run_id = run_id
        self.account_id = account_id
        self.bucket_id = bucket_id
        self.container_id = container_id


class Lifecycle(Meta2Filter):
    """Lifecycle filter.

    Load lifecycle configuration
    Order rules, actions
    Generate and send queries to meta2
    """

    NAME = "Lifecycle"
    PROCESS_COPY = True
    PROCESS_ORIGINAL = False
    PROGRESSION_MARKER_PREFIX = "lifecycle.processed."

    # Maximum number of versions to handle in NoncurrentVersion actions is
    # limited to 50.
    LIMIT = 50

    def __init__(self, app, conf, logger=None):
        self.progression = []
        self.lifecycle_backup_account = None
        self.lifecycle_backup_bucket = None
        super().__init__(app, conf, logger=logger)

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
        # Lifecycle backup bucket credentials
        self.lifecycle_backup_account = self.conf.get(
            "lifecycle_configuration_backup_account"
        )
        if not self.lifecycle_backup_account:
            raise ValueError(
                "Missing value for 'lifecycle_configuration_backup_account'"
            )
        self.lifecycle_backup_bucket = self.conf.get(
            "lifecycle_configuration_backup_bucket"
        )
        if not self.lifecycle_backup_bucket:
            raise ValueError(
                "Missing value for 'lifecycle_configuration_backup_bucket'"
            )

        # Metrics helper
        self._metrics = LifecycleMetricTracker(self.conf)
        self._context = None

        self.batch_size = int_value(self.conf.get("lifecycle_batch_size"), 1000)

        # Budget per container (not bucket), as containers of same bucket would be
        # handled by different workers.
        self.budget_per_container = int_value(
            self.conf.get("budget_per_container"), 25000
        )

        self.budget_per_bucket = int_value(self.conf.get("budget_per_bucket"), 500000)
        # Crawler can remove local copy directly without
        # make an extra http call
        self.direct_remove = True

        # batch_size is equal to the number of objects that match rule when
        # dealing with current versions.
        # This is not the case when we deal with noncurrent versions and the
        # the number of versions can vary from one object to another
        self.noncurrent_limit = self.LIMIT * self.batch_size

        # Bypass any days/dates fields and apply a delay of 1 seconds instead
        # Objectiva is to trigger lifecycle immediately and apply
        # time comparaison.
        self.bypass_days_dates = boolean_value(self.conf.get("bypass_days_dates"), True)

        # shorten days / dates
        self.shorten_days_dates = int_value(self.conf.get("shorten_days_dates"), 1440)
        if not self.bypass_days_dates:
            self.shorten_days_dates = 1

        self.suffix = None

        self.successes = 0
        self.skipped = 0
        self.errors = 0

        # Current container peer
        self.peer_to_use = None

        # Current container type and info
        self.is_mpu_container = False
        self.lower = None
        self.upper = None

        # Current container stats
        self.total_events = 0
        self.total_expirations = 0
        self.total_transitions = 0
        self.total_abort_mpu = 0
        # Stats of rule actions
        self.rules_stats = {}
        # Aggregated stats per rule
        self.aggregated_stats = {}

        # To have a ratio of finished actions
        self.count_actions = 0
        self.finished_actions = 0

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

    def _get_run_id(self):
        "suffix pattern: Lifecycle-{run_id}-{timestamp}"
        suffix_parts = self.suffix.split("-")
        if len(suffix_parts) == 3:
            return suffix_parts[1]
        return None

    def _retrieve_lifecycle_config(self, account, bucket, reqid=None):
        _, stream = self.api.object_fetch(
            self.lifecycle_backup_account,
            self.lifecycle_backup_bucket,
            lifecycle_backup_path(account, bucket),
            properties=False,
            reqid=reqid,
        )
        config = b""
        for chunk in stream:
            config += chunk
        return config

    def _process(self, env, cb):
        """Process current container:

        Get information about container from associated main container
        Get and load lifecycle configuratiion
        Reorder rules and apply each one in defined order
        """
        meta2db = Meta2DB(self.app_env, env)
        if not meta2db.suffix.startswith("Lifecycle-"):
            self.logger.debug(
                "Container copy '%s' is not a lifecycle copy. Skip.", meta2db.path
            )
            return self.app(env, cb)

        self.peer_to_use = env["volume_id"]
        self.is_mpu_container = False

        reqid = request_id("tx")

        self.suffix = meta2db.suffix

        run_id = self._get_run_id()
        if run_id is None:
            self.logger.error(
                "Failed to extract 'run_id' from suffix, meta2db: %s", meta2db.path
            )
            self.errors += 1
            return self.app(env, cb)

        # Get progression from meta2db
        self._load_progression(meta2db)
        # Check if container is fully processed
        if self._is_processed("container"):
            self.logger.info("Container '%s' already processed", meta2db.path)
            return self.app(env, cb)

        try:
            account, container = self.api.resolve_cid(meta2db.cid)
            if account is None or container is None:
                self.logger.error(
                    "Account, container not resolved for cid '%s'", meta2db.cid
                )
                self.errors += 1
                return self.app(env, cb)

            # Get properties from main container (if Lifecycle config is removed?)
            props, main_account, root_container = self._get_main_container_props(
                account, container
            )
            # Retrieve versioning status
            status = props["system"].get(M2_PROP_VERSIONING_POLICY)
            versioning = status is not None and int(status) != 0

            logging_config = props["properties"].get(LOGGING_PROPERTY_KEY)
            has_bucket_logging = logging_config is not None
            if has_bucket_logging:
                self.logger.info(
                    "Access logging enabled for root_container %s, account: %s",
                    root_container,
                    account,
                )

            self._context = Context(run_id, main_account, root_container, container)

            kwargs = {
                "run_id": run_id,
                "main_account": main_account,
            }
            # If number of matches from metrics >= self.budget_per_bucket
            try:
                metrics = self._metrics.get_bucket_metrics(
                    run_id, main_account, root_container
                )
                stats = metrics.get(LifecycleStep.SUBMITTED, {})
                total = 0
                for _, value in stats.items():
                    total += int(value)
                if total >= self.budget_per_bucket:
                    self.logger.warning(
                        "Account:%s Bucket:%s reached day budget %s",
                        main_account,
                        root_container,
                        self.budget_per_bucket,
                    )
                    return self.app(env, cb)
            except NotFound:
                pass

            lifecycle_conf = self._retrieve_lifecycle_config(
                main_account, root_container, reqid=reqid
            )
            if lifecycle_conf is None:
                self.logger.error(
                    "No lifecycle configuration for given container: %s, "
                    " account: %s, cid: %s",
                    container,
                    account,
                    meta2db.cid,
                )
                self.errors += 1
                return self.app(env, cb)

            lc_instance = ContainerLifecycle(
                self.api, main_account, root_container, logger=self.logger
            )
            if not lc_instance.load(json_conf=lifecycle_conf):
                self.logger.error("Failed to load lifecycle configuration")
                self.errors += 1
                return self.app(env, cb)

            self.lower, self.upper = self._get_container_range(meta2db.cid, reqid=reqid)

            # init stats
            self._init_container_stats(lc_instance)
            # Budget tracking
            self.nb_match_per_container = 0
            # Apply rules/actions as defined in configuration
            self._apply_rules(
                lc_instance,
                meta2db,
                account,
                container,
                versioning,
                reqid=reqid,
                has_bucket_logging=has_bucket_logging,
                **kwargs,
            )
            self.successes += 1
        except NotFound as exc:
            self.logger.warning(
                "Failed to find local copy cid=%s, msg=%s",
                meta2db.cid,
                str(exc),
            )
        return self.app(env, cb)

    def _get_container_range(self, cid, **kwargs):
        props = self.container.container_get_properties(
            cid=cid, service_id=self.peer_to_use, suffix=self.suffix, **kwargs
        )
        lower = props.get("system").get(M2_PROP_SHARDING_LOWER) or ""
        upper = props.get("system").get(M2_PROP_SHARDING_UPPER) or ""
        if lower.startswith(">"):
            lower = lower[1:]
        if upper.startswith("<"):
            upper = upper[1:]
        return (lower, upper)

    def _gen_views_non_current_action(
        self, lc, rule, non_current_days_in_sec, **kwargs
    ):
        """Generate views for NoncurrentExpiration/NoncurrentTransition.

        noncurrent_view depends on current_view.
        """
        noncurrent_view = lc.create_noncurrent_view(rule, non_current_days_in_sec)
        current_view = lc.create_common_views(
            "current_view", rule, non_current_days_in_sec
        )
        return {
            "noncurrent_view": noncurrent_view,
            "current_view": current_view,
        }

    def _gen_views_current_action(self, lc, rule, days_in_sec, date):
        """Generate views to handle current version and delete marker

        Current views are used in case of versioned container.
        No need to create them for non versioned container
        """
        delete_marker_view = lc.create_common_views(
            "marker_view", rule, days_in_sec, date, deleted=True
        )
        versioned_view = lc.create_common_views(
            "versioned_view", rule, days_in_sec, deleted=False
        )
        return {
            "marker_view": delete_marker_view,
            "versioned_view": versioned_view,
        }

    def _get_policy(self, action):
        return action.get("StorageClass")

    def _get_action_name(self, act):
        if isinstance(act, dict):
            action_name = next(iter(act))
        else:
            action_name = act
        if action_name in ("Transitions", "NoncurrentVersionTransitions"):
            action_name = action_name[:-1]
        return action_name

    def _is_prefix_outside_range(self, rule):
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

    def _is_budget_reached(self):
        if self.budget_per_container:
            return self.nb_match_per_container >= self.budget_per_container
        return False

    def _get_days(self, action):
        for field in ("Days", "DaysAfterInitiation", "NoncurrentDays"):
            days = action.get(field)
            if days is None:
                continue
            return 86400 * int(days) / self.shorten_days_dates
        return None

    def _get_date(self, action):
        date = action.get("Date")
        if date is not None:
            return self._date_or_bypass(date)
        return None

    def _process_action(
        self,
        lc_instance,
        cid,
        account,
        container,
        action_class,
        rule,
        action,
        versioning_enabled,
        **kwargs,
    ):
        """Process one action by batches.
        Handle different types of actions and versioned/not versioned container
        """
        rule_id = rule.get("ID")
        rule_filter = RuleFilter(rule)
        view_queries = {}

        if isinstance(action_class, AbortMpuAction):
            # AbortIncompleteMultiPartUpload doesn't depend on versioning
            query = lc_instance.abort_incomplete_query(rule, self._get_days(action))
        elif versioning_enabled:
            # Versioned
            if isinstance(action_class, DeleteMarkerAction):
                query = lc_instance.markers_query()
                view_queries = self._gen_views_current_action(
                    lc_instance, rule, None, None
                )
            elif not action_class.current:
                # Non current
                newer_non_current_versions = action.get("NewerNoncurrentVersions")
                # Create views
                view_queries = self._gen_views_non_current_action(
                    lc_instance, rule, self._get_days(action)
                )
                query = lc_instance.noncurrent_query(rule, newer_non_current_versions)
            else:
                # Current versions: Expiration/Transition
                days_in_sec = self._get_days(action)
                date = self._get_date(action)
                view_queries = self._gen_views_current_action(
                    lc_instance, rule, days_in_sec, date
                )
                query = lc_instance.build_sql_query(
                    rule, days_in_sec, date, False, True, True
                )
        else:
            # Non versioned
            days_in_sec = self._get_days(action)
            date = self._get_date(action)
            query = lc_instance.build_sql_query(rule, days_in_sec, date)

        return self._send_query_events(
            cid,
            query,
            action,
            view_queries,
            self._get_policy(action),
            rule_filter.prefix,
            rule_id,
            action_class,
            **kwargs,
        )

    def _apply_rules(
        self, lc, meta2db, account, container, versioning_enabled, **kwargs
    ):
        for action_id, action_class, rule, action in lc.actions_iter(
            use_versioning=versioning_enabled, is_mpu_container=self.is_mpu_container
        ):
            if self._is_processed(action_id):
                self.logger.debug("Action '%s' already processed", action_class)
                continue

            self.logger.info(
                "Processing action %s for container: %s",
                action_class,
                meta2db.path,
            )

            if self._is_prefix_outside_range(rule):
                continue

            is_finished_action = self._process_action(
                lc,
                meta2db.cid,
                account,
                container,
                action_class,
                rule,
                action,
                versioning_enabled,
                **kwargs,
            )
            if not is_finished_action:
                self.logger.warning("Budget reached for container %s", meta2db.path)
                break
            self._set_finished_status(meta2db, action_id)
            self.logger.info(
                "Container %s action %s processed", meta2db.path, action_class
            )
        else:
            # All action are processed
            self.logger.info("Container '%s' fully processed", meta2db.path)
            self._set_finished_status(meta2db, "container")

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

    def _get_offest(self, cid, action, rule, **kwargs):
        key = "-".join(["offsets", action, rule])
        params = {"cid": cid, "service_id": self.peer_to_use, "suffix": self.suffix}
        resp, body = self.proxy_client._request(
            "POST",
            "/container/get_properties",
            params=params,
            **kwargs,
        )
        offset = body.get("properties", {}).get(key)
        if offset is None:
            return 0
        else:
            return int(offset)

    def _set_finished_status(self, meta2db, key):
        """
        Store {key, 1} in admin table, the key reflects a finished action,
        finished rule or finished processing
        """
        statement = (
            "INSERT OR REPLACE INTO admin(k,v) "
            f'VALUES ("{self.PROGRESSION_MARKER_PREFIX}{key}", "1");'
        )
        res = meta2db.execute_sql(statement, open_mode="rw")
        return res

    def _load_progression(self, meta2db):
        """
        Load progression from database
        """
        statement = (
            f'SELECT k, v FROM admin where k LIKE "{self.PROGRESSION_MARKER_PREFIX}%";'
        )
        processed = []
        for key, _value in meta2db.execute_sql(statement, open_mode="ro"):
            processed.append(key[len(self.PROGRESSION_MARKER_PREFIX) :])
        self.progression = debinarize(processed)

    def _is_processed(self, key):
        """
        Check if a container, rule action is done.
        This is accomplished by setting a specific key in admin table.
        """
        return key in self.progression

    def _send_query_events(
        self,
        cid,
        query,
        action,
        view_queries,
        policy,
        prefix,
        rule_id,
        action_class,
        **kwargs,
    ):
        # Create view
        # TODO: Install only if not already present
        resp = self._create_views_request(cid, view_queries, **kwargs)
        if resp.status != 204:
            self.logger.error(
                "Failed to create views for rule %s, action %s",
                rule_id,
                action_class,
            )
            return False

        while True:
            # Check budget first
            if self._is_budget_reached():
                self.logger.info(
                    "Budget is reached for container cid %s rule %s, action %s",
                    cid,
                    rule_id,
                    action,
                )
                return False

            if not action_class.current:
                limit = self.noncurrent_limit
            else:
                limit = self.batch_size

            sql_query = f"{query} LIMIT {limit} "

            data = {
                "action": action_class.field,
                "suffix": self.suffix,
                "query": sql_query,
                "query_set_tag": sql_query,
                "storage_class": policy,
                "batch_size": self.batch_size,
                "rule_id": rule_id,
                "has_bucket_logging": kwargs.get("has_bucket_logging", False),
            }
            if isinstance(action_class, DeleteMarkerAction):
                data["is_markers"] = 1

            if prefix:
                data["prefix"] = prefix

            data["run_id"] = kwargs.get("run_id")
            data["main_account"] = kwargs.get("main_account")

            params = {
                "cid": cid,
                "service_id": self.peer_to_use,
                "action_type": "current" if action_class.current else "noncurrent",
            }

            resp, _ = self.proxy_client._request(
                "POST",
                "/container/lifecycle/apply",
                params=params,
                json=data,
                **kwargs,
            )
            if resp.status != 204:
                self.logger.error(
                    "Failed to apply batch for rule %s, action %s",
                    rule_id,
                    action_class.field,
                )
                return False

            count = int(resp.getheader("x-oio-count"))
            self._update_container_stats(rule_id, action_class, count)
            self.nb_match_per_container += count
            if count == 0:
                # No matches means we are done with this action
                return True

    def _init_container_stats(self, lc_instance):
        self.total_events = 0
        self.total_expirations = 0
        self.total_transitions = 0
        self.total_abort_mpu = 0
        self.count_actions = 0
        self.finished_actions = 0
        self.rules_stats = {}
        self.aggregated_stats = Counter()

    def _update_container_stats(self, rule_id, action_class, value):
        rule_stats = self.rules_stats.setdefault(rule_id, Counter())
        rule_stats[action_class.field] += value
        self.aggregated_stats[rule_id] += value
        self.total_events += value
        step = LifecycleStep.SUBMITTED
        self._metrics.increment_counter(
            self._context.run_id,
            self._context.account_id,
            self._context.bucket_id,
            self._context.container_id,
            step,
            action_class.step,
            value=value,
        )

    def _days_to_seconds(self, days):
        return 86400 * int(days)

    def _get_filter_stats(self):
        main_stats = {
            "successes": self.successes,
            "errors": self.errors,
            "total_events": self.total_events,
            "count_actions": self.count_actions,
            "finished_actions": self.finished_actions,
        }
        # (TODO) append agregated stats per rule/action??
        return main_stats

    def _reset_filter_stats(self):
        self.successes = 0
        self.errors = 0
        self.total_events = 0
        self.total_expirations = 0
        self.total_transitions = 0
        self.total_abort_mpu = 0
        self.count_actions = 0
        self.finished_actions = 0


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def lifecycle_filter(app):
        return Lifecycle(app, conf)

    return lifecycle_filter
