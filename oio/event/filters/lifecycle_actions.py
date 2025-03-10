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

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from urllib.parse import quote

from urllib3.util.request import make_headers

from oio.common.constants import LIFECYCLE_USER_AGENT, OBJECT_REPLICATION_PENDING
from oio.common.easy_value import boolean_value, int_value
from oio.common.exceptions import (
    NotFound,
    OioNetworkException,
    OioTimeout,
    ServiceBusy,
)
from oio.common.kafka import get_retry_delay
from oio.common.logger import S3AccessLogger
from oio.common.utils import oio_versionid_to_str_versionid, request_id
from oio.container.client import ContainerClient
from oio.event.evob import (
    Event,
    EventError,
    EventTypes,
    RetryableEventError,
)
from oio.event.filters.base import Filter, FilterContext
from oio.lifecycle.metrics import LifecycleAction, LifecycleMetricTracker, LifecycleStep


class DeleteMarkerExists(Exception):
    """Exception raised when a delete marker is the last version"""


class RecentVersionExists(Exception):
    """Exception raised when we find a recent version than one
    delete marker
    """


class TransitionSamePolicy(Exception):
    """Exception raised when we try to transition a version to same
    policy
    """


class LifecycleOperationLog(str, Enum):
    """
    S3 Lifecycle actions. Ref:
    https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-and-other-bucket-config.html
    """

    EXPIRE_OBJECT = "S3.EXPIRE.OBJECT"
    CREATE_DELETEMARKER = "S3.CREATE.DELETEMARKER"
    TRANSITION_SIA = "S3.TRANSITION_SIA.OBJECT"  # Standard IA
    TRANSITION_ZIA = "S3.TRANSITION_ZIA.OBJECT"  # One zone IA
    TRANSITION_INT = "S3.TRANSITION_INT.OBJECT"  # Intelligent Tiering
    TRANSITION_GIR = "S3.TRANSITION_GIR.OBJECT"  # Glacier Instant
    TRANSITION_OBJECT = "S3.TRANSITION.OBJECT"  # Glacier Flexible Retrival
    TRANSITION_GDA = "S3.TRANSITION_GDA.OBJECT"  # Glacier Deep Archive
    DELETE_UPLOAD = "S3.DELETE.UPLOAD"


DEFAULT_REQUESTER = "OVHcloudS3"


def event_to_s3_operation(event):
    """
    Mapping from an event to a S3 Lifecycle action
    """
    action = event.data.get("action")
    if action in ("Transition", "NoncurrentVersionTransition"):
        storage_class = event.data.get("storage_class")
        if storage_class == "STANDARD_IA":
            return LifecycleOperationLog.TRANSITION_SIA
        return LifecycleOperationLog.TRANSITION_ZIA
    if action in ("Expiration", "NoncurrentVersionExpiration"):
        add_delete_marker = event.data.get("add_delete_marker")
        if add_delete_marker:
            return LifecycleOperationLog.CREATE_DELETEMARKER
        return LifecycleOperationLog.EXPIRE_OBJECT
    if action in ("AbortIncompleteMultipartUpload",):
        return LifecycleOperationLog.DELETE_UPLOAD
    raise ValueError("No mapping to S3 Operation found")


class LifecycleActionContext:
    def __init__(self, event: Event):
        self.event = event
        self.reqid = event.reqid or request_id("Lifecycle-actions-")

    @property
    def run_id(self):
        return self.event.data.get("run_id")

    @property
    def account(self):
        return self.event.data.get("account")

    @property
    def container(self):
        return self.event.data.get("container")

    @property
    def bucket(self):
        return self.event.data.get("bucket")

    @property
    def path(self):
        return self.event.data.get("object")

    @property
    def version(self):
        return self.event.data.get("version")

    @property
    def storage_class(self):
        return self.event.data.get("storage_class")

    @property
    def action(self):
        return self.event.data.get("action")

    @property
    def rule_id(self):
        return self.event.data.get("rule_id")


@dataclass(init=True)
class LifecycleFilterContext(FilterContext):
    action: str = None
    rule_id: str = None
    run_id: str = None


class LifecycleActions(Filter):
    """Filter to execute Lifecycle actions"""

    MPU_MAX_PART = "10000"
    DEFAULT_EXTRA_LOG_FORMAT = "\t".join(
        (
            "action:%(action)s",
            "rule_id:%(rule_id)s",
            "run_id:%(run_id)s",
        )
    )

    def __init__(self, app, conf, logger=None):
        self.retry_delay = None
        self.limit_listing = None
        self.container_client = None
        self.metrics = None
        self.s3_access_logger = None
        self.s3_access_requester = None
        super().__init__(app, conf, logger=logger)

    def init(self):
        self.retry_delay = get_retry_delay(self.conf)
        self.limit_listing = int_value(self.conf.get("limit_listing"), 100)
        self.container_client = ContainerClient(self.conf, logger=self.logger)
        self.metrics = LifecycleMetricTracker(self.conf)
        self.s3_access_logger = S3AccessLogger(self.conf)
        self.s3_access_requester = self.conf.get(
            "s3_access_requester", DEFAULT_REQUESTER
        )
        self.stg_classes = {}
        for stg_class_conf, pol_conf in self.conf.items():
            if not stg_class_conf.startswith("storage_class."):
                continue
            storage_class = stg_class_conf[14:].upper()
            auto_storage_policies = []
            policies = [x.strip() for x in pol_conf.split(",")]
            for storage_policy in policies:
                if ":" in storage_policy:
                    name, offset = storage_policy.split(":")
                    name = name.strip()
                    if not name:
                        raise ValueError("Offset without storage policy")
                    auto_storage_policies.append((name, int(offset)))
                else:
                    auto_storage_policies.append((storage_policy, -1))
            auto_storage_policies.sort(key=lambda x: x[1])
            self.stg_classes[storage_class] = auto_storage_policies

    def _get_headers(self):
        return make_headers(user_agent=LIFECYCLE_USER_AGENT)

    def _process_expiration(self, context: LifecycleActionContext):
        add_delete_marker = context.event.data.get("add_delete_marker")
        version = None if add_delete_marker else context.version
        if add_delete_marker:
            # Get last version info
            obj_meta = self.container_client.content_get_properties(
                account=context.account,
                reference=context.container,
                path=context.path,
                force_master=True,
                reqid=context.reqid,
            )
            is_last_delete_marker = boolean_value(obj_meta["deleted"]) or None
            if is_last_delete_marker:
                raise DeleteMarkerExists()
            if obj_meta["version"] != str(context.version):
                raise RecentVersionExists()

        self.container_client.content_delete(
            context.account,
            context.container,
            context.path,
            version=version,
            reqid=context.reqid,
            headers=self._get_headers(),
        )

    def _process_transition(self, context: LifecycleActionContext, object_size, policy):
        if object_size is None:
            raise ValueError("Missing object size for transition object")
        storage_class = context.storage_class
        policies = self.stg_classes.get(storage_class, None)
        if policies is None:
            raise ValueError(
                "No policies for storage_class transition %s", storage_class
            )
        target_policy = None
        for pol, size in reversed(policies):
            if int(object_size) >= size:
                target_policy = pol
                break
        if target_policy is None:
            raise ValueError("No policy found for storage class %s ", storage_class)
        if target_policy == policy:
            raise TransitionSamePolicy()

        self.container_client.content_request_transition(
            account=context.account,
            reference=context.container,
            path=context.path,
            policy=target_policy,
            version=context.version,
            reqid=context.reqid,
        )

    def _process_abort_mpu(self, context: LifecycleActionContext):
        marker = None
        while True:
            headers, content_list = self.container_client.content_list(
                account=context.account,
                reference=context.container,
                limit=self.limit_listing,
                marker=marker,
                prefix=f"{context.path}/",
            )
            paths = []
            for obj in content_list["objects"]:
                # What's after the prefix should be an integer (the part number)
                part_number = obj["name"].rsplit("/", 1)[-1]
                try:
                    part_number_int = int(part_number)
                    if part_number_int < 1 or part_number_int > 10000:
                        raise ValueError("part number should be between 1 and 10000")
                    paths.append(obj["name"])
                except ValueError:
                    # Ignore this object (not a part of the MPU)
                    continue
            if not paths:
                break
            self.container_client.content_delete_many(
                account=context.account,
                reference=context.container,
                paths=paths,
                reqid=context.reqid,
            )
            truncated = boolean_value(headers.get("x-oio-list-truncated"))
            marker = headers.get("x-oio-list-marker")
            if not truncated:
                break
        self.container_client.content_delete(
            context.account,
            context.container,
            context.path,
            version=context.version,
            reqid=context.reqid,
        )

    def _should_log(self, context: LifecycleActionContext):
        if not context.event.data:
            return False
        return context.event.data.get(
            "has_bucket_logging", False
        ) and context.event.data.get("bucket")

    def _log_event(self, context: LifecycleActionContext):
        current_time = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S %z")
        key = context.path
        if key:
            key = quote(quote(key))
        bucket_owner = context.event.data.get("bucket_owner", "unknown")

        self.s3_access_logger.log(
            {
                "bucket_owner": bucket_owner,
                "bucket": context.bucket,
                "time": current_time,
                "remote_ip": None,  # ignored
                "requester": self.s3_access_requester,
                "request_id": context.reqid,
                "operation": event_to_s3_operation(context.event),
                "key": key,
                "request_uri": None,  # ignored
                "http_status": None,  # ignored
                "error_code": None,  # ignored
                "bytes_sent": None,  # ignored
                "object_size": None,  # ignored
                "total_time": None,  # ignored
                "turn_around_time": None,  # ignored
                "referer": None,  # ignored
                "user_agent": None,  # ignored
                "version_id": oio_versionid_to_str_versionid(context.version),
                "host_id": None,  # ignored
                "signature_version": None,  # ignored
                "cipher_suite": None,  # ignored
                "authentication_type": None,  # ignored
                "host_header": None,  # ignored
                "tls_version": None,  # ignored
                "access_point_arn": None,  # ignored
            }
        )

        # Metrics helper
        self._metrics = LifecycleMetricTracker(self.conf)

    def log_context_from_env(self, env):
        ctx = super().log_context_from_env(env, LifecycleFilterContext)
        data = env.get("data", {})
        ctx.action = data.get("action")
        ctx.rule_id = data.get("rule_id")
        ctx.run_id = data.get("run_id")
        ctx.bucket = data.get("bucket")
        ctx.account = data.get("main_account", data.get("account"))
        ctx.path = data.get("object")
        ctx.version = data.get("version")
        return ctx

    def process(self, env, cb):
        event = Event(env)

        if event.event_type != EventTypes.LIFECYCLE_ACTION:
            return self.app(env, cb)

        context = LifecycleActionContext(event)

        if not context.action:
            self.logger.error("Missing 'action' field in context.")
            return self.app(env, cb)

        action_type = None
        try:
            # Check if given object version still exists
            obj_meta = self.container_client.content_get_properties(
                account=context.account,
                reference=context.container,
                path=context.path,
                version=context.version,
                force_master=True,
                reqid=context.reqid,
            )
            object_size = obj_meta.get("size", None)
            policy = obj_meta.get("policy", None)
            metadata = obj_meta.get("properties") or {}
            replication_status = metadata.get(
                "x-object-sysmeta-s3api-replication-status"
            )
            if replication_status == OBJECT_REPLICATION_PENDING:
                self.logger.info("Lifecycle postponed, replication pending")
                resp = RetryableEventError(
                    event=event,
                    body=(
                        "Unable to process lifecycle event (retry),"
                        "reason: Replication pending"
                    ),
                    delay=self.retry_delay,
                )
                return resp(env, cb)

            self.logger.info("Processing started")
            if context.action in ("Expiration", "NoncurrentVersionExpiration"):
                action_type = LifecycleAction.DELETE
                self._process_expiration(context)
            elif context.action in ("Transition", "NoncurrentVersionTransition"):
                action_type = LifecycleAction.TRANSITION
                self._process_transition(context, object_size, policy)
            elif context.action == "AbortIncompleteMultipartUpload":
                action_type = LifecycleAction.ABORT_MPU
                self._process_abort_mpu(context)
            else:
                self.logger.error(
                    "Unsupported lifecycle event action %s", context.action
                )
                raise ValueError(f"Unsupported action '{context.action}'")

            if self._should_log(context):
                self._log_event(context)

        except NotFound:
            # The action should have already been processed
            self.logger.warning(
                "object %s with version %s not found in container %s",
                context.path,
                context.version,
                context.container,
            )
        except (DeleteMarkerExists, RecentVersionExists, TransitionSamePolicy):
            self.metrics.increment_counter(
                context.run_id,
                context.account,
                context.bucket,
                context.container,
                LifecycleStep.SKIPPED,
                action_type,
            )
        except (ServiceBusy, OioNetworkException, OioTimeout) as exc:
            resp = RetryableEventError(
                event=event,
                body=f"Failed to process lifecycle event (retry), reason: {exc}",
                delay=self.retry_delay,
            )
            return resp(env, cb)
        except Exception as exc:
            resp = EventError(
                event=event, body=f"Failed to process lifecycle event, reason: {exc}"
            )
            if action_type is not None:
                self.metrics.increment_counter(
                    context.run_id,
                    context.account,
                    context.bucket,
                    context.container,
                    LifecycleStep.ERROR,
                    action_type,
                )
            return resp(event.env, cb)

        self.metrics.increment_counter(
            context.run_id,
            context.account,
            context.bucket,
            context.container,
            LifecycleStep.PROCESSED,
            action_type,
        )
        self.logger.info("Processing complete")
        return self.app(env, cb)

    def _update_metrics(self, account, bucket, container, run_id, action):
        # update metrics
        step = LifecycleStep.PROCESSED
        if action in ("Expiration", "NoncurrentVersionExpiration"):
            action = LifecycleAction.DELETE
        elif action in ("Transition", "NoncurrentVersionTransition"):
            action = LifecycleAction.TRANSITION
        elif action in ("AbortIncompleteMultipartUpload",):
            action = LifecycleAction.ABORT_MPU
        else:
            raise ValueError("Unsopported action  %s for stats ", action)
        self._metrics.increment_counter(
            run_id,
            account,
            bucket,
            container,
            step,
            action,
            value=1,
        )


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def lifecycle_actions_filter(app):
        return LifecycleActions(app, conf)

    return lifecycle_actions_filter
