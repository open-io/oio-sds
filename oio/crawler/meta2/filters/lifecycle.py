# Copyright (C) 2024-2025 OVH SAS
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

from oio.common.client import ProxyClient
from oio.common.constants import (
    ACL_PROPERTY_KEY,
    LOGGING_PROPERTY_KEY,
    M2_PROP_LIFECYCLE_TIME_BYPASS,
    M2_PROP_SHARDING_LOWER,
    M2_PROP_SHARDING_UPPER,
    M2_PROP_VERSIONING_POLICY,
    MULTIUPLOAD_SUFFIX,
    SHARDING_ACCOUNT_PREFIX,
)
from oio.common.easy_value import debinarize, int_value
from oio.common.exceptions import NoSuchContainer, NotFound, OioException
from oio.common.utils import get_bucket_owner_from_acl, request_id
from oio.container.client import ContainerClient
from oio.container.lifecycle import (
    AbortMpuAction,
    ContainerLifecycle,
    DeleteMarkerAction,
    RuleFilter,
    lifecycle_backup_path,
)
from oio.crawler.meta2.filters.base import Meta2Filter
from oio.crawler.meta2.meta2db import Meta2DB, Meta2DBError
from oio.directory.admin import AdminClient
from oio.lifecycle.metrics import LifecycleAction, LifecycleMetricTracker, LifecycleStep


class LifecycleBudgetReached(Exception):
    pass


class BucketBudgetReached(LifecycleBudgetReached):
    pass


class ContainerPassBudgetReached(LifecycleBudgetReached):
    pass


class RootContainerNotFound(Exception):
    pass


def extract_run_id(suffix):
    suffix_parts = suffix.split("-")
    if len(suffix_parts) == 3:
        return suffix_parts[1]
    raise ValueError(f"Unable to extract run_id from '{suffix}'")


class Context:
    def __init__(self, meta2db, account, container):
        self._meta2db = meta2db
        self.reqid = request_id()
        self.run_id = extract_run_id(self.suffix)
        self.account = account
        self.container = container
        self.has_versioning = False
        self.has_bucket_logging = False
        self.bucket_owner = None
        self.has_time_bypass = False

    @property
    def root_account(self):
        if self.account.startswith(SHARDING_ACCOUNT_PREFIX):
            return self.account[len(SHARDING_ACCOUNT_PREFIX) :]
        return self.account

    @property
    def root_container(self):
        root_container = self.container
        if self.account.startswith(SHARDING_ACCOUNT_PREFIX):
            root_container = root_container.rsplit("-", 3)[0]
        # Handle +segments
        if root_container.endswith(MULTIUPLOAD_SUFFIX):
            root_container = root_container[: -len(MULTIUPLOAD_SUFFIX)]
        return root_container

    @property
    def path(self):
        return self._meta2db.path

    @property
    def cid(self):
        return self._meta2db.cid

    @property
    def volume_id(self):
        return self._meta2db.volume_id

    @property
    def suffix(self):
        return self._meta2db.suffix

    @property
    def is_mpu(self):
        container = self.container
        if self.account.startswith(SHARDING_ACCOUNT_PREFIX):
            container = container.rsplit("-", 3)[0]
        return container.endswith(MULTIUPLOAD_SUFFIX)

    @property
    def lower(self):
        lower = self._meta2db.system.get(M2_PROP_SHARDING_LOWER, "")
        if lower.startswith(">"):
            lower = lower[1:]
        return lower

    @property
    def upper(self):
        upper = self._meta2db.system.get(M2_PROP_SHARDING_UPPER, "")
        if upper.startswith("<"):
            upper = upper[1:]
        return upper


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

    ACTIONS_ALLOWED = (
        LifecycleAction.ABORT_MPU,
        LifecycleAction.DELETE,
        LifecycleAction.TRANSITION,
    )

    def __init__(self, app, conf, logger=None):
        self.progression = []
        self.lifecycle_backup_account = None
        self.lifecycle_backup_bucket = None
        self.context = None
        # Progress tracking
        self.events_produced_for_container = 0
        # Stats
        self.successes = 0
        self.errors = 0
        self.skipped = 0
        self.processed = 0
        self.bucket_budget_reached = 0
        self.container_budget_reached = 0
        self.events_count = {}

        super().__init__(app, conf, logger=logger)

    def init(self):
        self.api = self.app_env["api"]
        # Clients
        self.proxy_client = ProxyClient(
            self.conf, pool_manager=self.api.container.pool_manager, logger=self.logger
        )
        self.admin_client = AdminClient(
            self.conf, logger=self.logger, force_master=True
        )
        self.container = ContainerClient(
            self.conf,
            pool_manager=self.api.container.pool_manager,
            logger=self.logger,
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
        # Batch size
        self.batch_size = int_value(self.conf.get("lifecycle_batch_size"), 1000)
        # Budget per bucket
        self.budget_per_bucket = int_value(self.conf.get("budget_per_bucket"), 500000)
        # Container budget per pass
        self.container_budget_per_pass = int_value(
            self.conf.get("container_budget_per_pass"), 10000
        )
        # Bypass any days/dates fields and apply a delay of 1 seconds instead
        # Objective is to trigger lifecycle immediately and apply
        # time comparison.
        self.shorten_days_dates_factor = int_value(
            self.conf.get("shorten_days_dates_factor"), 1
        )
        self.reset_stats()

    def _get_main_container_props(self):
        """Get properties from main container.

        Main container could be the container itself,
        Root container in case of shard,
        Associated container if +sgement
        """
        try:
            # Retrieve properties from root container
            props = self.api.container_get_properties(
                self.context.root_account, self.context.root_container
            )
        except (NotFound, NoSuchContainer):
            self.logger.warning(
                "Associated container for %s in account %s not found",
                self.context.container,
                self.context.account,
            )
            raise RootContainerNotFound(
                f"Root container ct={self.context.container}"
                f"acct={self.context.account} not found"
            )
        except Exception as exc:
            self.logger.warning(
                "Error occurred %s for container %s in account %s ",
                exc,
                self.context.container,
                self.context.account,
            )
            raise
        return props

    def _retrieve_lifecycle_config(self):
        _, stream = self.api.object_fetch(
            self.lifecycle_backup_account,
            self.lifecycle_backup_bucket,
            lifecycle_backup_path(
                self.context.root_account, self.context.root_container
            ),
            properties=False,
            reqid=self.context.reqid,
        )
        config = b""
        for chunk in stream:
            config += chunk

        if not config:
            self.logger.error(
                "No lifecycle configuration for given container: %s, "
                " account: %s, cid: %s",
                self.context.root_container,
                self.context.root_account,
                self.context.cid,
            )
            raise ValueError("Lifecycle configuration is empty")
        return config

    def _get_bucket_budget_left(self):
        try:
            metrics = self._metrics.get_bucket_metrics(
                self.context.run_id,
                self.context.root_account,
                self.context.root_container,
            )
            stats = metrics.get(LifecycleStep.SUBMITTED, {})
            total = 0
            for key, value in stats.items():
                if key not in self.ACTIONS_ALLOWED:
                    continue
                total += int(value)
            budget_left = max(0, self.budget_per_bucket - total)

            if budget_left == 0:
                raise BucketBudgetReached(
                    f"Budget reached for bucket {self.context.root_container} "
                    f"(produced={total} budget={self.budget_per_bucket}) "
                    f"for run {self.context.run_id}"
                )
            return budget_left
        except NotFound:
            return self.batch_size

    def _get_container_budget_left(self):
        budget_left = max(
            0, self.container_budget_per_pass - self.events_produced_for_container
        )
        if budget_left == 0:
            raise ContainerPassBudgetReached(
                f"Budget reached for container {self.context.container}"
                f"(produced={self.events_produced_for_container} "
                f" budget={self.container_budget_per_pass}) "
                f"for run {self.context.run_id}"
            )
        return budget_left

    def _get_next_limit(self):
        return min(
            self._get_container_budget_left(),
            self._get_bucket_budget_left(),
            self.batch_size,
        )

    def _prepare_context(self, meta2db):
        account, container = self.api.resolve_cid(meta2db.cid)
        self.context = Context(meta2db, account, container)

        # Extract properties from live container
        # Get properties from main container (if Lifecycle config is removed?)
        properties = self._get_main_container_props()
        # Retrieve versioning status
        status = properties["system"].get(M2_PROP_VERSIONING_POLICY)
        self.context.has_versioning = status is not None and int(status) != 0
        # Rerieve logging status
        logging_config = properties["properties"].get(LOGGING_PROPERTY_KEY)
        self.context.has_bucket_logging = logging_config is not None
        if self.context.has_bucket_logging:
            self.logger.info(
                "Access logging enabled for root_container %s, account: %s",
                self.context.root_container,
                self.context.root_account,
            )
        # Retrieve acl
        acl_config = properties["properties"].get(ACL_PROPERTY_KEY)
        self.context.bucket_owner = get_bucket_owner_from_acl(acl_config)

        # Retrieve time bypass status
        time_bypass_property = properties["system"].get(M2_PROP_LIFECYCLE_TIME_BYPASS)
        self.context.has_time_bypass = time_bypass_property == "1"
        if self.context.has_time_bypass:
            self.logger.warning(
                "Time bypass enabled for root_container %s, account: %s",
                self.context.root_container,
                self.context.root_account,
            )
        return True

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
            self.skipped += 1
            return self.app(env, cb)

        try:
            if not self._prepare_context(meta2db):
                raise OioException("Unable to initialize context")

            # New container, reset events count
            self.events_produced_for_container = 0

            # Get progression from meta2db
            self._load_progression(meta2db)

            # Check if container is fully processed
            if self._is_processed("container"):
                self.logger.info("Container '%s' already processed", meta2db.path)
                self.processed += 1
                return self.app(env, cb)

            # Ensure budgets are not reached
            _ = self._get_next_limit()

            lifecycle_conf = self._retrieve_lifecycle_config()
            # Create lifecycle helper
            lc_instance = ContainerLifecycle(
                self.api,
                self.context.root_account,
                self.context.root_container,
                logger=self.logger,
            )
            lc_instance.load(lifecycle_conf)

            # Apply rules/actions as defined in configuration
            self._apply_rules(lc_instance)
        except RootContainerNotFound as exc:
            self.logger.warning(
                "Database copy %s is obsolete, reason: %s", meta2db.path, exc
            )
            meta2db.to_remove = True
            self.skipped += 1
            # Do not return an error to let next filters to process copy
            return self.app(env, cb)
        except (BucketBudgetReached, ContainerPassBudgetReached) as exc:
            self.logger.info("Budget reached: %s", exc)
            if isinstance(exc, BucketBudgetReached):
                self.bucket_budget_reached += 1
            elif isinstance(exc, ContainerPassBudgetReached):
                self.container_budget_reached += 1
        except Exception as exc:
            self.logger.error(
                "Failed to process container: %s, reason: %s", meta2db.path, exc
            )
            self.errors += 1
            resp = Meta2DBError(
                meta2db,
                body=(
                    f"Failed to process {self.NAME} "
                    f"for the container {meta2db.cid}: {exc}"
                ),
            )
            return resp(env, cb)
        self.successes += 1
        return self.app(env, cb)

    def _gen_views_non_current_action(self, lc, rule_filter, non_current_days_in_sec):
        """Generate views for NoncurrentExpiration/NoncurrentTransition.

        noncurrent_view depends on current_view.
        """
        noncurrent_view = lc.create_noncurrent_view(rule_filter)
        current_view = lc.create_common_views(
            "current_view", formated_time=non_current_days_in_sec
        )
        return {
            "noncurrent_view": noncurrent_view,
            "current_view": current_view,
        }

    def _gen_views_current_action(self, lc, days_in_sec, date):
        """Generate views to handle current version and delete marker

        Current views are used in case of versioned container.
        No need to create them for non versioned container
        """
        delete_marker_view = lc.create_common_views(
            "marker_view", days_in_sec, date, deleted=True
        )
        versioned_view = lc.create_common_views(
            "versioned_view", days_in_sec, deleted=False
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

    def _is_prefix_outside_range(self, rule_filter):
        if rule_filter.prefix:
            prefix = rule_filter.prefix
            if (self.context.lower and prefix < self.context.lower[: len(prefix)]) or (
                self.context.upper and prefix > self.context.upper[: len(prefix)]
            ):
                return True
        return False

    def _get_time_factor(self):
        if self.context.has_time_bypass:
            return self.shorten_days_dates_factor
        return 1

    def _days_to_seconds(self, days):
        return 86400 * int(days)

    def _get_days(self, action):
        for field in ("Days", "DaysAfterInitiation", "NoncurrentDays"):
            days = action.get(field)
            if days is None:
                continue
            return int(self._days_to_seconds(days) / self._get_time_factor())
        return None

    def _date_or_bypass(self, date):
        time_factor = self._get_time_factor()
        if time_factor != 1:
            wait_seconds = int(self._days_to_seconds(1) / time_factor)
            now = datetime.datetime.now()
            delayed = now + datetime.timedelta(seconds=wait_seconds)
            return delayed.strftime("%Y-%m-%dT%H:%M:%SZ")
        return date

    def _get_date(self, action):
        date = action.get("Date")
        if date is not None:
            return self._date_or_bypass(date)
        return None

    def _process_action(self, lc_instance, action_class, rule_id, rule_filter, action):
        """Process one action by batches.
        Handle different types of actions and versioned/not versioned container
        """
        view_queries = {}

        if isinstance(action_class, AbortMpuAction):
            # AbortIncompleteMultiPartUpload doesn't depend on versioning
            query = lc_instance.abort_incomplete_query(
                rule_filter, self._get_days(action)
            )
        elif self.context.has_versioning:
            # Versioned
            if isinstance(action_class, DeleteMarkerAction):
                query = lc_instance.markers_query(rule_filter)
                view_queries = self._gen_views_current_action(lc_instance, None, None)
            elif not action_class.current:
                # Non current
                newer_non_current_versions = action.get("NewerNoncurrentVersions")
                # Create views
                view_queries = self._gen_views_non_current_action(
                    lc_instance, rule_filter, self._get_days(action)
                )
                query = lc_instance.noncurrent_query(
                    rule_filter, newer_non_current_versions, self._get_days(action)
                )
            else:
                # Current versions: Expiration/Transition
                days_in_sec = self._get_days(action)
                date = self._get_date(action)
                view_queries = self._gen_views_current_action(
                    lc_instance, days_in_sec, date
                )
                query = lc_instance.build_sql_query(
                    rule_filter, days_in_sec, date, False, True
                )
        else:
            # Non versioned
            days_in_sec = self._get_days(action)
            date = self._get_date(action)
            query = lc_instance.build_sql_query(rule_filter, days_in_sec, date)

        return self._send_query_events(
            query,
            view_queries,
            self._get_policy(action),
            rule_filter.prefix,
            rule_id,
            action_class,
        )

    def _apply_rules(self, lc):
        for action_id, action_class, rule, action in lc.actions_iter(
            use_versioning=self.context.has_versioning,
            is_mpu_container=self.context.is_mpu,
        ):
            if self._is_processed(action_id):
                self.logger.debug("Action '%s' already processed", action_class)
                continue

            self.logger.info(
                "Processing action %s for container: %s",
                action_class,
                self.context.path,
            )

            rule_id = rule.get("ID")
            try:
                rule_filter = RuleFilter(rule)
            except ValueError as exc:
                self.logger.error(
                    "Rule %s filter interpreted as an empty filter but some fields are"
                    " present: %s",
                    rule_id,
                    exc,
                )
                raise

            if self._is_prefix_outside_range(rule_filter):
                self.logger.info(
                    "Skipped rule %s, prefix '%s' is outside of range [%s: %s]",
                    rule_id,
                    rule_filter.prefix,
                    self.context.lower,
                    self.context.upper,
                )
                continue

            is_finished_action = self._process_action(
                lc, action_class, rule_id, rule_filter, action
            )
            if not is_finished_action:
                self.logger.warning(
                    "Budget reached for container %s", self.context.path
                )
                break
            self._set_finished_status(self.context._meta2db, action_id)
            self.logger.info(
                "Container %s action %s processed", self.context.path, action_class
            )
        else:
            # All action are processed
            self.logger.info("Container '%s' fully processed", self.context.path)
            self._set_finished_status(self.context._meta2db, "container")

    def _create_views_request(self, view_queries):
        """Create views

        Views depends on rules and actions parameters, they
        are created at the beginning of action.
        """

        params = {
            "cid": self.context.cid,
            "service_id": self.context.volume_id,
        }
        create_views_data = {
            "suffix": self.context.suffix,
        }
        for key, val in view_queries.items():
            create_views_data[key] = val

        resp, _ = self.proxy_client._request(
            "POST",
            "/container/lifecycle/views/create",
            params=params,
            json=create_views_data,
            reqid=self.context.reqid,
        )
        return resp

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
        query,
        view_queries,
        policy,
        prefix,
        rule_id,
        action_class,
    ):
        # Create view
        resp = self._create_views_request(view_queries)
        if resp.status != 204:
            self.logger.error(
                "Failed to create views for rule %s, action %s",
                rule_id,
                action_class,
            )
            return False

        while True:
            next_batch_size = self._get_next_limit()
            sql_query = f"{query} LIMIT {next_batch_size} "

            data = {
                "action": action_class.field,
                "suffix": self.context.suffix,
                "query": sql_query,
                "query_set_tag": sql_query,
                "storage_class": policy,
                "batch_size": next_batch_size,
                "rule_id": rule_id,
                "run_id": self.context.run_id,
                "main_account": self.context.root_account,
                "has_bucket_logging": self.context.has_bucket_logging,
                "bucket_owner": self.context.bucket_owner,
            }
            if isinstance(action_class, DeleteMarkerAction):
                data["is_markers"] = 1
            if prefix:
                data["prefix"] = prefix

            params = {
                "cid": self.context.cid,
                "service_id": self.context.volume_id,
                "action_type": "current" if action_class.current else "noncurrent",
            }

            resp, _ = self.proxy_client._request(
                "POST",
                "/container/lifecycle/apply",
                params=params,
                json=data,
                reqid=self.context.reqid,
            )
            if resp.status != 204:
                self.logger.error(
                    "Failed to apply batch for rule %s, action %s",
                    rule_id,
                    action_class.field,
                )
                return False

            count = int(resp.headers.get("x-oio-count", default=0))

            self._update_container_stats(action_class, count)
            if count == 0:
                # No matches means we are done with this action
                return True

    def _update_container_stats(self, action_class, value):
        if value == 0:
            return
        self.events_count[action_class.step.value] += value
        self.events_produced_for_container += value
        step = LifecycleStep.SUBMITTED
        self._metrics.increment_counter(
            self.context.run_id,
            self.context.root_account,
            self.context.root_container,
            self.context.cid,
            step,
            action_class.step,
            value=value,
        )

    def _get_filter_stats(self):
        total = 0
        events_count = {}
        for key, value in self.events_count.items():
            events_count[f"total_{key}"] = value
            total += value

        return {
            "successes": self.successes,
            "errors": self.errors,
            "skipped": self.skipped,
            "processed": self.processed,
            "bucket_budget_reached": self.bucket_budget_reached,
            "container_budget_reached": self.container_budget_reached,
            "total_events": total,
            **events_count,
        }

    def _reset_filter_stats(self):
        self.successes = 0
        self.errors = 0
        self.skipped = 0
        self.processed = 0
        self.bucket_budget_reached = 0
        self.container_budget_reached = 0
        self.events_count = {a.value: 0 for a in self.ACTIONS_ALLOWED}


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def lifecycle_filter(app):
        return Lifecycle(app, conf)

    return lifecycle_filter
