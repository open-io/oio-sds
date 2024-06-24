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


from oio.event.filters.base import Filter
from oio.event.evob import Event, RetryableEventError, EventError
from oio.common.exceptions import ClientException
from oio.common.kafka import KafkaSender, KafkaSendException, get_retry_delay
from oio.container.client import ContainerClient
from oio.container.sharding import ContainerSharding


DEFAULT_CHECKPOINT_PREFIX = "lifecycle"


class CheckpointCreatorFilter(Filter):
    """
    Create Meta2 database checkpoint for lifecycle processing
    """

    def __init__(self, *args, endpoint=None, **kwargs):
        self._retry_delay = None
        self._checkpoint_prefix = None
        self._endpoint = endpoint
        self._producer = None
        self._topic = None
        super().__init__(*args, **kwargs)

    def init(self):
        self._retry_delay = get_retry_delay(self.conf)
        self._checkpoint_prefix = self.conf.get(
            "checkpoint_prefix", DEFAULT_CHECKPOINT_PREFIX
        )
        self._topic = self.conf.get("topic")
        self._sharding_client = ContainerSharding(self.conf, logger=self.logger)
        self._container_client = ContainerClient(self.conf, logger=self.logger)

    def _send_events(self, events):
        if not self._producer:
            self._producer = KafkaSender(
                self._endpoint, logger=self.logger, app_conf=self.conf
            )
        try:
            for evt in events:
                self._producer.send(self._topic, evt)
            self._producer.flush()
        except KafkaSendException as exc:
            msg = f"Topic {self._topic}: {exc!r}"
            return msg, exc.retriable
        return None, False

    def _check_container_up_to_date(self, root_cid, cid, bounds, env):
        lower, upper = bounds
        shards = self._sharding_client.get_shards_in_range(
            None, None, lower, upper, root_cid=root_cid
        )
        shards = [s for s in shards]
        if not shards:
            # Verify if container is not a non-sharded container
            return root_cid == cid and bounds == ("", ""), None
        else:
            # Container has been sharded or shrunk
            events = []
            for shard in shards:
                evt = env.copy()
                evt["data"]["cid"] = shard["cid"]
                evt["data"]["bounds"]["lower"] = shard["lower"]
                evt["data"]["bounds"]["upper"] = shard["upper"]
                events.append(evt)
            err, retriable = self._send_events(events)
            err_resp = None
            if err:
                delay = self._retry_delay if retriable else 0
                err_resp = RetryableEventError(event=Event(env), body=err, delay=delay)
            return False, err_resp
        return True, None

    def process(self, env, cb):
        event = Event(env)
        data = event.data
        run_id = data.get("run_id")
        root_cid = data.get("root_cid")
        cid = data.get("cid")

        # Retrieve container status
        meta = self._container_client.container_get_properties(
            cid=cid,
            params={"urgent": 1},
        )

        # Ensure no sharding is in progress
        if self._sharding_client.sharding_in_progress(meta):
            self.logger.warning("Sharding on progress, cid=%s", cid)
            return RetryableEventError(f"Sharding in progress for {cid}")(env, cb)

        # Retrieve container bounds
        _bounds = data.get("bounds", {})
        bounds = (_bounds.get("lower", ""), _bounds.get("upper", ""))

        # Ensure bounds are up to date (container has not been sharded nor shrunk)
        up_to_date, err = self._check_container_up_to_date(root_cid, cid, bounds, env)
        if err:
            return err(env, cb)
        if not up_to_date:
            return self.app(env, cb)

        try:
            _ = self._container_client.container_checkpoint(
                cid=cid, prefix=f"{self._checkpoint_prefix}", suffix=f"{run_id}"
            )
        except ClientException as exc:
            return EventError(
                f"Unable to create checkpoint for container {cid}, reason: {exc}"
            )(env, cb)

        return self.app(env, cb)


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
