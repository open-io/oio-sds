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

import hashlib
from copy import deepcopy

from oio.common.exceptions import ClientException, Conflict
from oio.common.kafka import KafkaSender, KafkaSendException, get_retry_delay
from oio.common.statsd import get_statsd
from oio.container.client import ContainerClient
from oio.container.sharding import ContainerSharding
from oio.event.evob import Event, RetryableEventError
from oio.event.filters.base import Filter
from oio.lifecycle.metrics import (
    LifecycleAction,
    LifecycleMetricTracker,
    LifecycleStep,
    statsd_key,
)


class Context:
    def __init__(
        self,
        run_id,
        account_id,
        bucket_id,
        container_id,
        root_container_id,
        request_id=None,
    ):
        self.run_id = run_id
        self.account_id = account_id
        self.bucket_id = bucket_id
        self.container_id = container_id
        self.root_container_id = root_container_id
        self.container_to_process = None
        self.request_id = request_id


class CheckpointCreatorFilter(Filter):
    """
    Create Meta2 database checkpoint for lifecycle processing
    """

    _DEFAULT_CHECKPOINT_SUFFIX = "Lifecycle"

    def __init__(self, *args, endpoint=None, **kwargs):
        self._retry_delay = None
        self._checkpoint_suffix = None
        self._endpoint = endpoint
        self._producer = None
        self._topic = None
        self._metrics = None
        self._statsd = None
        self._event_context = None
        super().__init__(*args, **kwargs)

    def init(self):
        self._retry_delay = get_retry_delay(self.conf)
        self._checkpoint_suffix = self.conf.get(
            "checkpoint_suffix", self._DEFAULT_CHECKPOINT_SUFFIX
        )
        self._topic = self.conf.get("topic")
        self._sharding_client = ContainerSharding(self.conf, logger=self.logger)
        self._container_client = ContainerClient(self.conf, logger=self.logger)
        self._metrics = LifecycleMetricTracker(self.conf)
        self._statsd = get_statsd(self.conf)

    def _send_sub_events(self, events):
        if not self._producer:
            self._producer = KafkaSender(
                self._endpoint, logger=self.logger, app_conf=self.conf
            )
        try:
            self.logger.debug("Produce %d events", len(events))
            for evt in events:
                self._producer.send(self._topic, evt)
            self._producer.flush(1.0)
        except KafkaSendException as exc:
            self.logger.error(
                "Failed to produce sub-events for container %s, reason: %s",
                self._event_context.container_id,
                exc,
            )
            msg = f"Topic {self._topic}: {exc!r}"
            return msg, exc.retriable
        return None, False

    def _check_no_sharding(self):
        cid = self._event_context.container_id

        # Retrieve container status
        meta = self._container_client.container_get_properties(
            cid=cid, params={"urgent": 1}, reqid=self._event_context.request_id
        )

        # Ensure no sharding is in progress
        if self._sharding_client.sharding_in_progress(meta):
            self.logger.warning("Sharding in progress, cid=%s", cid)
            return RetryableEventError(f"Sharding in progress for {cid}")
        return None

    def _check_container_up_to_date(self, root_cid, cid, bounds, env):
        lower, upper = bounds
        shards = self._sharding_client.get_shards_in_range(
            None,
            None,
            lower,
            upper,
            root_cid=root_cid,
            reqid=self._event_context.request_id,
        )
        shards = [s for s in shards]
        err_resp = None
        cid_to_process = None
        has_shards = False
        if not shards:
            # There are no shards. We can checkpoint the root container
            cid_to_process = root_cid
        elif len(shards) == 1 and bounds == (shards[0]["lower"], shards[0]["upper"]):
            # The shard is up to date.
            cid_to_process = cid
        else:
            # Container has been sharded or shrunk
            err_resp = self._generate_sub_events(shards, env)
            if not err_resp and root_cid == cid:
                has_shards = True
                cid_to_process = root_cid

        return cid_to_process, has_shards, err_resp

    def _generate_sub_events(self, shards, env):
        events = []
        for shard in shards:
            evt = deepcopy(env)
            evt["data"]["cid"] = shard["cid"]
            evt["data"]["bounds"]["lower"] = shard["lower"]
            evt["data"]["bounds"]["upper"] = shard["upper"]
            events.append(evt)
        err, retriable = self._send_sub_events(events)
        err_resp = None
        if err:
            delay = self._retry_delay if retriable else 0
            err_resp = RetryableEventError(event=Event(env), body=err, delay=delay)
        else:
            for shard in shards:
                self._update_metrics(LifecycleStep.SUBMITTED, cid=shard["cid"])
        return err_resp

    def _create_checkpoint(self, suffix):
        cid = self._event_context.container_to_process
        run_id = self._event_context.run_id

        self.logger.debug(
            "Create a checkpoint for container %s in lifecycle run: %s", cid, run_id
        )
        try:
            checkpoint_suffix = f"{self._checkpoint_suffix}-{run_id}-{suffix}"
            _ = self._container_client.container_checkpoint(
                cid=cid,
                suffix=checkpoint_suffix,
                reqid=self._event_context.request_id,
            )
        except Conflict:
            self.logger.debug(
                "Checkpoint already exists for container %s (suffix=%s)",
                cid,
                checkpoint_suffix,
            )
        except ClientException as exc:
            self.logger.error(
                f"Unable to create checkpoint for container {cid}, reason: {exc}"
            )
            self._statsd.incr(
                statsd_key(run_id, LifecycleStep.ERROR, LifecycleAction.CHECKPOINT)
            )
            return RetryableEventError(
                f"Unable to create checkpoint for container {cid}"
            )

        return None

    def _update_metrics(self, step, cid=None):
        if cid is None:
            cid = self._event_context.container_id
            if self._event_context.container_to_process:
                cid = self._event_context.container_to_process

        self._statsd.incr(
            statsd_key(self._event_context.run_id, step, LifecycleAction.CHECKPOINT)
        )
        self._metrics.increment_counter(
            self._event_context.run_id,
            self._event_context.account_id,
            self._event_context.bucket_id,
            cid,
            step,
            LifecycleAction.CHECKPOINT,
        )

    def _get_suffix_hash(self, has_shards, bounds):
        hash_ = hashlib.new("sha256")
        hash_.update(str(has_shards).encode("utf-8"))
        hash_.update(b"\0")
        hash_.update(bounds[0].encode("utf-8"))
        hash_.update(b"\0")
        hash_.update(bounds[1].encode("utf-8"))
        return hash_.hexdigest().upper()[:32]

    def process(self, env, cb):
        try:
            event = Event(env)
            data = event.data
            account_id = data.get("account")
            bucket_id = data.get("bucket")
            run_id = data.get("run_id")
            root_cid = data.get("root_cid")
            cid = data.get("cid")

            self._event_context = Context(
                run_id, account_id, bucket_id, cid, root_cid, request_id=event.reqid
            )

            err = self._check_no_sharding()
            if err:
                return err(env, cb)

            # Retrieve container bounds
            _bounds = data.get("bounds", {})
            bounds = (_bounds.get("lower", ""), _bounds.get("upper", ""))

            # Ensure bounds are up to date (container has not been sharded nor shrunk)
            cid_to_process, has_shards, err = self._check_container_up_to_date(
                root_cid, cid, bounds, env
            )

            if err:
                return err(env, cb)
            step = LifecycleStep.PROCESSED
            if cid_to_process is None:
                # Container has been replaced (sharding or shrinking), new chetkpoint
                # events should have been issued
                step = LifecycleStep.SKIPPED
            else:
                self._event_context.container_to_process = cid_to_process
                suffix_hash = self._get_suffix_hash(has_shards, bounds)
                err = self._create_checkpoint(suffix_hash)
                if err:
                    return err(env, cb)

            self._update_metrics(step)
            return self.app(env, cb)
        finally:
            self._event_context = None


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    endpoint = conf.get("broker_endpoint")

    if not endpoint:
        raise ValueError("Broker endpoint is missing")

    def checkpoint_creator_filter(app):
        if endpoint.startswith("kafka://"):
            return CheckpointCreatorFilter(app, conf, endpoint=endpoint)
        raise NotImplementedError()

    return checkpoint_creator_filter
