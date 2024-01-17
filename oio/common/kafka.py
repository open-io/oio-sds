# Copyright (C) 2023-2024 OVH SAS
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

from datetime import datetime
import json

from confluent_kafka import (
    Consumer,
    Producer,
    KafkaException,
    TopicPartition,
    OFFSET_INVALID,
)
from oio.common.configuration import load_namespace_conf
from oio.common.easy_value import int_value
from oio.common.exceptions import OioException
from oio.event.evob import EventTypes

DEFAULT_ENDPOINT = "kafka://127.0.0.1:19092"
DEFAULT_TOPIC = "oio"
DEFAULT_PRESERVED_TOPIC = "oio-preserved"
DEFAULT_REPLICATION_TOPIC = "oio-replication"
DEFAULT_DELAYED_TOPIC = "oio-delayed"
DEFAULT_DELETE_TOPIC_PREFIX = "oio-delete-"
DEFAULT_REBUILD_TOPIC = "oio-rebuild"
DEFAULT_DEADLETTER_TOPIC = "oio-deadletter"
DEFAULT_XCUTE_JOB_TOPIC = "oio-xcute"
DEFAULT_XCUTE_JOB_REPLY_TOPIC = DEFAULT_XCUTE_JOB_TOPIC + "-reply"
DEFAULT_DELAY_GRANULARITY = 60
KAFKA_CONF_COMMON_PREFIX = "kafka_common_"
KAFKA_CONF_CONSUMER_PREFIX = "kafka_consumer_"
KAFKA_CONF_PRODUCER_PREFIX = "kafka_producer_"
POLL_TIMEOUT = 10


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


class KafkaError(OioException):
    pass


class KafkaSendException(KafkaError):
    def __init__(self, *args, retriable=False):
        super().__init__(args)
        self.retriable = retriable


class KafkaTopicNotFoundException(KafkaError):
    pass


class KafkaPartitionNotAssignedException(KafkaError):
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

        for key, value in conf.items():
            self._logger.info("Setting option %s=%s", key, value)
        try:
            self._client = self.__client_class(conf, logger=self._logger)
        except KafkaException as err:
            self._logger.error(
                "Failed to start Kafka client (%s), reason: %s",
                self.__client_class.__name__,
                str(err),
            )

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
        kafka_conf = {}

        for key, value in self.app_conf.items():
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

    def _send(self, topic, data, flush=False, callback=None):
        try:
            if isinstance(data, str):
                data = data.encode("utf8")
            elif isinstance(data, dict):
                data = json.dumps(data, separators=(",", ":")).encode("utf8")

            self._client.produce(topic, data, callback=callback)
            self._client.poll(0)

            if flush:
                nb_msg = self._client.flush(10.0)
                if nb_msg > 0:
                    self._logger.warning(
                        "All events are not flushed. %d are still in queue", nb_msg
                    )
        except KafkaException as exc:
            self._logger.warning(
                "Failed to send event to topic %s, reason: %s", topic, exc
            )
            raise KafkaSendException(
                "Failed to send event", retriable=exc.retriable()
            ) from exc

    def _generate_delayed_event(self, topic, event, delay):
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

        return delayed_event

    def send(self, topic, data, delay=0, flush=False, callback=None):
        if delay > 0:
            # Encapsulate event in a delayed one
            data = self._generate_delayed_event(topic, data, delay)
            topic = self._delayed_topic

        self._send(topic, data, flush=flush, callback=callback)

    def flush(self, timeout=None):
        return self._client.flush(timeout)

    def _close(self):
        self._client.poll(POLL_TIMEOUT)
        self._client.flush()

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
            yield self._client.poll(1.0)

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
        Aknowledge message or a list of offsets
        """
        kwargs = {"asynchronous": False}
        if offsets:
            kwargs["offsets"] = offsets
        else:
            kwargs["message"] = message
        try:
            partitions = self._client.commit(**kwargs)
            errors = [p.error for p in partitions if p.error]

            if errors:
                self._logger.error("Failed to commit partitions: %s", errors)
        except KafkaException as err:
            self._logger.error("Failed to commit: %s", str(err))

    def _get_conf(self):
        consumer_conf, _ = self._kafka_options_from_conf()
        return consumer_conf
