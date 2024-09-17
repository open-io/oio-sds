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

from oio.common.easy_value import boolean_value, int_value
from oio.common.exceptions import BadRequest, Forbidden, NotFound
from oio.common.utils import request_id
from oio.container.client import ContainerClient
from oio.event.evob import Event, EventTypes
from oio.event.filters.base import Filter
from oio.event.kafka_consumer import RejectMessage
from oio.lifecycle.metrics import LifecycleAction, LifecycleMetricTracker, LifecycleStep


class LifecycleActions(Filter):
    """Filter to execute Lifecycle actions"""

    MULTIUPLOAD_SUFFIX = "+segments"
    MPU_MAX_PART = "10000"

    def init(self):
        self.limit_listing = int_value(self.conf.get("limit_listing"), 100)
        self.container_client = ContainerClient(self.conf, logger=self.logger)

        # Metrics helper
        self._metrics = LifecycleMetricTracker(self.conf)

    def process(self, env, cb):
        event = Event(env)
        ev_type = event.event_type
        if ev_type != EventTypes.LIFECYCLE_ACTION:
            return self.app(env, cb)
        action = event.data.get("action")
        if action is None:
            return self.app(env, cb)

        reqid = event.reqid
        if not reqid:
            reqid = request_id("Lifecycle-actions-")

        data = event.data
        account = data.get("account")
        container = data.get("container")
        path = data.get("object")
        version = data.get("version")
        storage_class = data.get("storage_class")
        main_account = data.get("main_account", None)
        bucket = data.get("bucket", None)
        run_id = data.get("run_id")

        main_account = main_account or account
        bucket = bucket or container
        try:
            # Check if given object version still exists
            content_meta, chunks = self.container_client.content_locate(
                account=main_account,
                reference=bucket,
                path=path,
                version=version,
                force_master=True,
                reqid=reqid,
            )

        except NotFound:
            self.logger.warning(
                "object %s with version %s not found in container %s",
                path,
                version,
                container,
            )
            return self.app(env, cb)

        if action == "Expiration":
            add_delete_marker = data.get("add_delete_marker")
            try:
                if add_delete_marker:
                    self.container_client.content_delete(
                        main_account,
                        bucket,
                        path,
                        reqid=reqid,
                    )
                else:
                    self.container_client.content_delete(
                        main_account,
                        bucket,
                        path,
                        version=version,
                        reqid=reqid,
                    )
            except NotFound:
                pass
        elif action in ("Transition", "NoncurrentVersionTransition"):
            idx = content_meta.get("id")
            try:
                self.container_client.content_create(
                    main_account,
                    bucket,
                    path,
                    size=content_meta.get("size"),
                    hash=content_meta.get("hash"),
                    version=version,
                    data={"chunks": chunks},
                    content_id=idx,
                    stgpol=storage_class,
                    change_policy=True,
                    meta_pos=1,
                    reqid=reqid,
                )
            except (BadRequest, Forbidden) as exc:
                raise exc

        elif action == "AbortIncompleteMultipartUpload":
            try:
                truncated = True
                marker = None
                while truncated:
                    try:
                        headers, content_list = self.container_client.content_list(
                            account=main_account,
                            reference=container,
                            limit=self.limit_listing,
                            marker=marker,
                            prefix=path,
                        )
                    except NotFound as exc:
                        raise RejectMessage from exc
                    paths = []

                    for obj in content_list["objects"]:
                        if obj["name"] == path:
                            # Delete base object name as last
                            continue
                        # What's after the prefix should be an integer (the part number)
                        part_number = obj["name"].rsplit("/", 2)[-1]
                        try:
                            part_number_int = int(part_number)
                            if part_number_int < 1 or part_number_int > 10000:
                                raise ValueError(
                                    "part number should be between 1 and 10000"
                                )
                            paths.append(obj["name"])
                        except ValueError:
                            # Ignore this object (not a part of the MPU)
                            continue

                    if not paths:
                        # Mpu is initiated but no parts
                        break

                    self.container_client.content_delete_many(
                        account=main_account,
                        reference=container,
                        paths=paths,
                        reqid=reqid,
                    )

                    truncated = boolean_value(headers.get("x-oio-list-truncated"))
                    marker = headers.get("x-oio-list-marker")

                self.container_client.content_delete(
                    account,
                    container,
                    path,
                    version=version,
                    reqid=reqid,
                )

            except NotFound:
                pass
        elif action == "NoncurrentVersionExpiration":
            try:
                self.container_client.content_delete(
                    main_account,
                    bucket,
                    path,
                    version=version,
                )
            except NotFound:
                pass
        else:
            self.logger.warning("Unsupported lifecycle event action %s", action)
        self._update_metrics(main_account, bucket, container, run_id, action)

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
