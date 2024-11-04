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

from enum import Enum

from oio.common.easy_value import int_value
from oio.common.exceptions import NotFound
from oio.common.logger import get_logger
from oio.common.redis_conn import RedisConnection, catch_service_errors


class LifecycleStep(str, Enum):
    ERROR = "error"
    PROCESSED = "processed"
    SUBMITTED = "submitted"
    SKIPPED = "skipped"


class LifecycleAction(str, Enum):
    CHECKPOINT = "checkpoint"
    DELETE = "delete"
    TRANSITION = "transition"
    ABORT_MPU = "abortmpu"


def statsd_key(run_id, step, action):
    """
    Forge a statsd key
    """
    return ".".join(
        [
            f if f is not None else "-"
            for f in ("openio", "lifecycle", run_id, action, step)
        ]
    )


class LifecycleMetricTracker:
    """Helper class to manage lifecycle metrics"""

    SET_CONTAINER_OBJECTS = """
    local value = redis.call('SET', KEYS[1], ARGV[1], 'NX', 'EX', ARGV[2]);
    if value == nil or value == false then
        return false;
    end;
    redis.call('SET', KEYS[2], '0', 'NX', 'EX', ARGV[2]);
    redis.call('INCRBY', KEYS[2], ARGV[1]);
    return true;
    """

    SCAN_COUNT = 1000

    DEFAULT_METRICS_EXPIRATION = 3600 * 24 * 5  # Keep metrics for 5 days

    def __init__(self, conf, logger=None):
        self._conf = conf
        self._logger = logger or get_logger(self._conf)
        self._metrics_expiration = int_value(
            self._conf.get("lifecycle_metrics_expiration"),
            self.DEFAULT_METRICS_EXPIRATION,
        )

        redis_conf = {k[6:]: v for k, v in self._conf.items() if k.startswith("redis_")}
        self._redis_client = RedisConnection(**redis_conf)

        # Register scripts
        self._script_set_container_objects = self._redis_client.register_script(
            self.SET_CONTAINER_OBJECTS
        )

    def __key(self, *fields, separator="/"):
        return separator.join([f for f in fields if f is not None])

    def __get_metrics(self, run_id, account_id, bucket_id, container_id=None):
        metrics = {}

        # Retrieve global container objects count
        key = self.__key(
            run_id,
            account_id,
            bucket_id,
            "container" if container_id else None,
            container_id,
        )
        value = self._redis_client.conn.get(key)
        if value is not None:
            metrics["objects"] = value

        for step in LifecycleStep:
            for action in LifecycleAction:
                key = self.__key(
                    run_id,
                    account_id,
                    bucket_id,
                    "container" if container_id else None,
                    container_id,
                    step,
                    action,
                )
                value = self._redis_client.conn.get(key)
                if value is None:
                    continue
                metrics_step = metrics.setdefault(step, {})
                metrics_step[action] = value

        if not metrics:
            ref = self.__key(run_id, account_id, bucket_id, container_id, separator=":")
            raise NotFound(f"No metrics found for reference '{ref}'")
        return metrics if metrics else None

    def __increment_counter(self, conn, key, value):
        self._logger.debug("Increment counter '%s' by %d", key, value)
        conn.set(key, 0, ex=self._metrics_expiration, nx=True).incr(key, value)

    def set_container_objects(self, run_id, account_id, bucket_id, container_id, value):
        """
        Set the number of objects belonging to container and update aggregated
        counter accordingly.
        """
        # Set container objects count
        key_container = self.__key(
            run_id,
            account_id,
            bucket_id,
            "container",
            container_id,
        )

        key_bucket = self.__key(
            run_id,
            account_id,
            bucket_id,
        )

        self._script_set_container_objects(
            keys=[key_container, key_bucket],
            args=[value, self._metrics_expiration],
            client=self._redis_client.conn,
        )

    @catch_service_errors
    def increment_counter(
        self, run_id, account_id, bucket_id, container_id, step, action, value=1
    ):
        """Increment counter for a container and the aggregated bucket counter."""
        pipeline = self._redis_client.conn.pipeline()
        # Increment container counter
        key_container = self.__key(
            run_id, account_id, bucket_id, "container", container_id, step, action
        )
        self.__increment_counter(pipeline, key_container, value)

        # Increment bucket global counter
        key_bucket = self.__key(run_id, account_id, bucket_id, step, action)
        self.__increment_counter(pipeline, key_bucket, value)
        pipeline.execute()

    @catch_service_errors
    def get_container_metrics(self, run_id, account_id, bucket_id, container_id):
        """Retrieve metrics for specific container."""
        return self.__get_metrics(
            run_id, account_id, bucket_id, container_id=container_id
        )

    @catch_service_errors
    def get_bucket_metrics(self, run_id, account_id, bucket_id):
        """Retrieve aggregated metrics for bucket."""
        return self.__get_metrics(run_id, account_id, bucket_id)

    @catch_service_errors
    def get_containers(self, run_id, account_id, bucket_id):
        """Retrieve containers belonging to bucket."""
        pattern = self.__key(run_id, account_id, bucket_id, "container", "*")
        containers = set()
        for key in self._redis_client.conn.scan_iter(
            match=pattern, count=self.SCAN_COUNT
        ):
            _, _, _, _, container, *_ = key.split(b"/", 5)
            containers.add(container.decode("utf-8"))

        return containers
