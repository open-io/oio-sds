# Copyright (C) 2023-2025 OVH SAS
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import json
import time
from datetime import datetime
from urllib.parse import urlparse

from confluent_kafka import (
    OFFSET_INVALID,
    Consumer,
    KafkaException,
    Producer,
    TopicPartition,
)

from oio.common.configuration import load_namespace_conf
from oio.common.easy_value import int_value
from oio.common.exceptions import OioException
from oio.event.evob import EventTypes

DEFAULT_ENDPOINT = "kafka://127.0.0.1:19092"
DEFAULT_TOPIC = "oio"
DEFAULT_PRESERVED_TOPIC = "oio-preserved"
DEFAULT_REPLICATION_TOPIC = "oio-replication"
DEFAULT_LIFECYCLE_TOPIC = "oio-lifecycle"
DEFAULT_LIFECYCLE_BACKUP_TOPIC = "oio-lifecycle-backup"
DEFAULT_LIFECYCLE_RESTORE_TOPIC = "oio-lifecycle-restore"
DEFAULT_LIFECYCLE_CHECKPOINT_TOPIC = "oio-lifecycle-checkpoint"
DEFAULT_TRANSITION_TOPIC = "oio-transitioned"
DEFAULT_DELAYED_TOPIC = "oio-delayed"
DEFAULT_DELETE_TOPIC_PREFIX = "oio-delete-"
DEFAULT_REBUILD_TOPIC = "oio-rebuild"
DEFAULT_DEADLETTER_TOPIC = "oio-deadletter"
DEFAULT_XCUTE_JOB_TOPIC = "oio-xcute-job"
DEFAULT_XCUTE_JOB_REPLY_TOPIC = DEFAULT_XCUTE_JOB_TOPIC + "-reply"
DEFAULT_DELAY_GRANULARITY = 60
KAFKA_CONF_COMMON_PREFIX = "kafka_common_"
KAFKA_CONF_CONSUMER_PREFIX = "kafka_consumer_"
KAFKA_CONF_PRODUCER_PREFIX = "kafka_producer_"
POLL_TIMEOUT = 0
FLUSH_TIMEOUT = 10


def get_delay_granularity(conf):
    granularity = conf.get("delay_granularity")
    if granularity is None:
        namespace = conf.get("namespace")
        ns_conf = load_namespace_conf(namespace, failsafe=True)
        granularity = ns_conf.get("ns.delay_granularity")
    return int_value(granularity, DEFAULT_DELAY_GRANULARITY)


def get_retry_delay(conf, default_delay=None):
    """Retrieve the delay before an event is reemited"""
    if default_delay is None:
        default_delay = get_delay_granularity(conf)
    return int_value(conf.get("retry_delay"), default_delay)


def kafka_options_from_conf(app_conf):
    """Retrieve kafka option from app configuration"""
    kafka_conf = {}

    for key, value in app_conf.items():
        for prefix in (
            KAFKA_CONF_COMMON_PREFIX,
            KAFKA_CONF_CONSUMER_PREFIX,
            KAFKA_CONF_PRODUCER_PREFIX,
        ):
            if key.startswith(prefix):
                prefix_conf = kafka_conf.setdefault(prefix, {})
                key = key[len(prefix) :]
                prefix_conf[key] = value
                break

    # Reduce confs
    consumer_conf = {
        **(kafka_conf.get(KAFKA_CONF_COMMON_PREFIX, {})),
        **(kafka_conf.get(KAFKA_CONF_CONSUMER_PREFIX, {})),
    }

    producer_conf = {
        **(kafka_conf.get(KAFKA_CONF_COMMON_PREFIX, {})),
        **(kafka_conf.get(KAFKA_CONF_PRODUCER_PREFIX, {})),
    }

    return consumer_conf, producer_conf


class KafkaBaseException(OioException):
    pass


class KafkaSendException(KafkaBaseException):
    def __init__(self, *args, retriable=False):
        super().__init__(args)
        self.retriable = retriable


class KafkaTopicNotFoundException(KafkaBaseException):
    pass


class KafkaPartitionNotAssignedException(KafkaBaseException):
    pass


class KafkaFatalException(KafkaBaseException):
    pass


class KafkaClient:
    def __init__(self, endpoint, client_class, logger, app_conf, kafka_conf):
        self.__client_class = client_class
        self._client = None
        self._endpoint = endpoint
        self._logger = logger
        self.app_conf = app_conf or {}
        self.kafka_conf = kafka_conf or {}

    @classmethod
    def _cleanup_endpoint(cls, endpoint):
        # Remove protocol prefix
        endpoints = endpoint.split(",")
        endpoints = (
            e[len("kafka://") :] if e.startswith("kafka://") else e for e in endpoints
        )
        return ",".join(endpoints)

    def _connect(self, options=None):
        if self._client is not None:
            return
        if not options:
            options = {}

        conf = {
            "bootstrap.servers": self._cleanup_endpoint(self._endpoint),
            **options,
        }

        self._logger.debug(
            "Instantiate %s (options: %s)",
            self.__client_class.__name__,
            ", ".join(f"{k}={v}" for k, v in conf.items()),
        )
        try:
            self._client = self.__client_class(conf)
        except KafkaException as exc:
            self._logger.error(
                "Failed to start Kafka client (%s), reason: %s",
                self.__client_class.__name__,
                exc,
            )
            err = exc.args[0]
            if not err.retriable():
                raise KafkaFatalException() from exc

    def ensure_topics_exist(self, topics):
        for topic in topics:
            try:
                self._client.list_topics(topic=topic, timeout=1)
            except KafkaException as exc:
                self._logger.error("Topic '%s' not found", topic)
                raise KafkaTopicNotFoundException(f"Topic {topic} not found") from exc

    def close(self):
        if self._client is None:
            return
        self._close()
        self._client = None

    def _close(self):
        raise NotImplementedError()

    def _kafka_options_from_conf(self):
        return kafka_options_from_conf(self.app_conf)

    def _get_conf(self):
        raise NotImplementedError()


class KafkaSender(KafkaClient):
    def __init__(self, endpoint, logger, app_conf=None, kafka_conf=None):
        super(KafkaSender, self).__init__(
            endpoint, Producer, logger, app_conf, kafka_conf
        )
        self._delayed_topic = self.app_conf.get("delayed_topic", DEFAULT_DELAYED_TOPIC)
        self._delay_granularity = get_delay_granularity(self.app_conf)

        self._connect(
            {
                "acks": "all",
                **self.kafka_conf,
                **(self._get_conf()),
            }
        )

    @property
    def producer(self):
        return self._client

    def _connect(self, options={}):
        super()._connect(options)
        self.ensure_topics_exist([self._delayed_topic])

    def _produce_callback(self, err, msg):
        if err:
            if not err.retriable():
                self._logger.error("Unable to produce event, reason: %s", str(err))
                raise KafkaFatalException(err)
            else:
                self._logger.warning(
                    "Unable to produce event, retry later. Reason: %s", str(err)
                )

    def _send(self, topic, data, key=None, flush=False):
        try:
            if isinstance(data, str):
                data = data.encode("utf8")
            elif isinstance(data, dict):
                data = json.dumps(data, separators=(",", ":")).encode("utf8")

            # Data is neither string nor dict nor bytes, discard it
            if not isinstance(data, bytes):
                self._logger.error(
                    "Event data is not bytes, refusing to send it to topic %s: %r",
                    topic,
                    data,
                )
                return

            self._client.produce(topic, data, key=key, callback=self._produce_callback)

            if flush:
                nb_msg = self._client.flush(1.0)
                if nb_msg > 0:
                    self._logger.warning(
                        "All events are not flushed. %d are still in queue", nb_msg
                    )
            else:
                self._client.poll(POLL_TIMEOUT)

        except (BufferError, KafkaException) as exc:
            self._logger.warning(
                "Failed to send event to topic %s, reason: %s", topic, exc
            )
            if isinstance(exc, KafkaException):
                err = exc.args[0]
                retriable = err.retriable()
            else:  # Internal queue is full, we can retry later
                retriable = True
            raise KafkaSendException(
                "Failed to send event", retriable=retriable
            ) from exc

    def _generate_delayed_event(self, topic, event, delay, key=None):
        if delay < self._delay_granularity:
            self._logger.warning(
                "Delay(%ds) is not a multiple of delay granularity(%ds). "
                "Extra delay may be induced: %ds",
                delay,
                self._delay_granularity,
                self._delay_granularity - delay,
            )
        if isinstance(event, bytes):
            event = json.loads(event)
        now = datetime.now().timestamp()

        delayed_event = {
            "event": EventTypes.DELAYED,
            "data": {
                "dest_topic": topic,
                "next_due_time": now + self._delay_granularity,
                "due_time": now + delay,
                "source_event": event,
            },
        }

        if key is not None:
            delayed_event["data"]["key"] = key

        return delayed_event

    def send(self, topic, data, delay=0, key=None, flush=False):
        # Strip any _internal field
        if isinstance(data, dict) and "_internal" in data:
            data = {
                **data,
            }
            del data["_internal"]

        if delay > 0:
            # Encapsulate event in a delayed one
            data = self._generate_delayed_event(topic, data, delay, key=key)
            topic = self._delayed_topic
            key = None

        self._send(topic, data, key=key, flush=flush)

    def flush(self, timeout):
        return self._client.flush(timeout)

    def _close(self):
        remaining = self._client.flush(FLUSH_TIMEOUT)
        if remaining > 0:
            self._logger.error(
                "Some produced events may not be acknowledged (%d)", remaining
            )

    def _get_conf(self):
        _, producer_conf = self._kafka_options_from_conf()
        return producer_conf


class KafkaConsumer(KafkaClient):
    def __init__(
        self,
        endpoint,
        topics,
        group_id,
        logger,
        app_conf=None,
        kafka_conf=None,
        format_args=None,
    ):
        super().__init__(endpoint, Consumer, logger, app_conf, kafka_conf)
        self.client_conf = {
            **self.kafka_conf,
            **(self._get_conf()),
            "group.id": group_id,
        }
        self._format_args = format_args or {}
        self._resolve_conf()

        self._connect(self.client_conf)

        if topics:
            self.ensure_topics_exist(topics)
            self._client.subscribe(topics)

    @property
    def consumer(self):
        return self._client

    def _resolve_conf(self):
        for key in ("client.id", "group.instance.id"):
            if key in self.client_conf:
                while True:
                    try:
                        self.client_conf[key] = self.client_conf[key].format(
                            **self._format_args
                        )
                        break
                    except KeyError as exc:
                        missing_key = exc.args[0]
                        self._format_args[missing_key](f"{missing_key}")

    def fetch_events(self):
        while True:
            try:
                yield self._client.poll(1.0)
            except KafkaException as exc:
                self._logger.error("Failed to fetch event, reason %s", exc)
                error = exc.args[0]
                if not error.retriable():
                    raise KafkaFatalException() from exc
                yield None

    def _is_valid_offset(self):
        return self.consumer.assignment()[0].offset != OFFSET_INVALID

    def get_partition_lag(self, partition):
        """Get the number for specified partition
        in the specified topic

        :param partition: TopicPartition instance
        :type partition: TopicPartition
        """
        # Get the total number of events
        low_offset, high_offset = self.consumer.get_watermark_offsets(partition)
        if high_offset < 0:
            lag = 0
        elif partition.offset < 0:
            # No committed offset defined for the given partition.
            lag = high_offset - low_offset
        else:
            # The committed offset is known,
            # the lag is total number of events - events already consumed
            lag = high_offset - partition.offset
        return lag

    def get_topic_lag(self, topic):
        """Get lag of all partitions of the specified topic

        :param topic: topic name
        :type topic: str
        :return: dict of partition_id and corresponding lag
        :rtype: dict
        """
        lags = {}
        # List of partitions defined in the topic
        partitions = [
            TopicPartition(topic, p)
            for p in self.consumer.list_topics(topic).topics[topic].partitions
        ]
        # Partitions with the right offset committed
        committed = self.consumer.committed(partitions)
        for topic_partition in committed:
            lag = self.get_partition_lag(topic_partition)
            lags[topic_partition.partition] = lag
        return lags

    def _close(self):
        self._client.close()

    def commit(self, message=None, offsets=None):
        """
        Acknowledge message or a list of offsets
        """
        kwargs = {"asynchronous": False}
        if offsets is not None:
            kwargs["offsets"] = offsets
            log_message = f"offsets: {offsets}"
        else:
            kwargs["message"] = message
            log_message = f"message: {message}"
        self._logger.debug("Committing %s", log_message)
        try:
            start = time.monotonic()
            partitions = self._client.commit(**kwargs)
            log_message += f" ({time.monotonic() - start:.4f}s)"
            errors = [p.error for p in partitions if p.error]
            if errors:
                self._logger.error(
                    "Failed to commit %s, errors: %s", log_message, errors
                )
                return False

        except KafkaException as exc:
            self._logger.error("Failed to commit %s, reason: %s", log_message, str(exc))
            err = exc.args[0]
            if not err.retriable():
                raise KafkaFatalException() from exc
            return False
        self._logger.debug("Successfully commit %s", log_message)
        return True

    def _get_conf(self):
        consumer_conf, _ = self._kafka_options_from_conf()
        return consumer_conf


class KafkaProducerMixin:
    def __init__(self, logger, conf, endpoint=None):
        if not endpoint:
            ns_conf = load_namespace_conf(conf["namespace"], failsafe=True)
            endpoint = ns_conf.get("event-agent", DEFAULT_ENDPOINT)
        self.endpoint = endpoint
        self.logger = logger
        self.conf = conf
        self._producer = None

    def _connect_producer(self):
        if self._producer is None:
            self._producer = KafkaSender(self.endpoint, self.logger, app_conf=self.conf)

    def close_producer(self):
        if self._producer is not None:
            self._producer.close()

    def send(self, topic, data, callback=None):
        try:
            self._connect_producer()
            if not self._producer:
                raise SystemError("No producer available")

            self._producer.send(topic, data, flush=True)
            if callback:
                callback(data)
            return True
        except Exception:
            self.logger.exception(
                "Failed to send message topic=%s",
                topic,
            )
            return False


class GetTopicMixin:
    """
    Used to retrieve the topic dedicated to delete chunks on specific rawx
    """

    CACHE_UPDATE_COOLDOWN = 10
    DEFAULT_CACHE_DURATION = 3600
    SLOT_SEPATATORS = (".", "-", "_")

    def __init__(self, conscience_client, conf, logger) -> None:
        self._conscience_client = conscience_client
        self.logger = logger
        # Cache related
        self._cache_duration = None
        self._last_cache_update = -1
        self._rawx_services_per_id = {}
        self._rawx_services_per_addr = {}
        self._cache_duration = int_value(
            conf.get("services_cache_duration"), self.DEFAULT_CACHE_DURATION
        )
        self._topic_prefix = conf.get("topic_prefix", DEFAULT_DELETE_TOPIC_PREFIX)

    def _update_rawx_services(self, force=False):
        now = time.monotonic()
        if not force and now < (self._last_cache_update + self._cache_duration):
            # No need to update cache
            return

        if now < (self._last_cache_update + self.CACHE_UPDATE_COOLDOWN):
            # Slowdown
            return

        try:
            services = self._conscience_client.all_services("rawx")
            rawx_services_per_id = {}
            rawx_services_per_addr = {}
            for svc in services:
                svc_id = svc.get("id", "").lower()
                svc_addr = svc.get("addr")
                svc_ip = svc_addr.split(":")[0]
                all_slots = svc.get("tags", {}).get("tag.slots", "").split(",")
                slots = []
                for slot in all_slots:
                    if slot.startswith("rawx"):
                        slot = slot[4:]
                    if not slot:
                        continue
                    if slot[0] in self.SLOT_SEPATATORS:
                        slot = slot[1:]
                    slots.append(slot)
                slots.sort()
                topic_name = svc_ip
                if slots:
                    topic_name += f"-{'-'.join(slots)}"

                rawx_services_per_id[svc_id] = topic_name
                rawx_services_per_addr[svc_addr] = topic_name
            # Update cache
            self._rawx_services_per_addr = rawx_services_per_addr
            self._rawx_services_per_id = rawx_services_per_id
        except OioException as exc:
            self.logger.error("Failed to refresh services, reason: %s", exc)
        # Cache updated
        self._last_cache_update = time.monotonic()

    def get_topic_from_service_name(self, svc_name):
        """
        Get the topic name dedicated to a rawx service.
        Topic name is forged with <host_ip_addr>-<nvme|hdd>

        This method use a cached rawx services to topic name mapping. The cache may be
        updated if it expires.
        """
        for force_refresh in (False, True):
            self._update_rawx_services(force=force_refresh)
            services_sources = (
                self._rawx_services_per_addr,
                self._rawx_services_per_id,
            )
            for src in services_sources:
                topic = src.get(svc_name)
                if topic:
                    return topic
        return None

    def get_service_name(self, url):
        url_parts = urlparse(url)
        name = url_parts.hostname
        if url_parts.port:
            name += f":{url_parts.port}"
        return name

    def get_topic_name(self, svc_name):
        topic_name = self.get_topic_from_service_name(svc_name=svc_name)
        return f"{self._topic_prefix}{topic_name}"
