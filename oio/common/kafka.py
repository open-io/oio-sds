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

# pylint: disable-next=unused-import
from datetime import datetime
import json
import time
from math import ceil

from confluent_kafka import (
    Consumer,
    Producer,
    KafkaException,
    TopicPartition,
    OFFSET_BEGINNING,
    OFFSET_INVALID,
)
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
KAFKA_CONF_PREFIX = "kafka_"
POLL_TIMEOUT = 10


def get_delay_granularity(conf):
    return conf.get("delay_granularity", DEFAULT_DELAY_GRANULARITY)


class KafkaSendException(OioException):
    ...


class KafkaTopicNotFoundException(OioException):
    ...


class KafkaPartitionNotAssignedException(OioException):
    ...


def kafka_options_from_conf(conf):
    if conf is None:
        conf = {}
    return {
        k[len(KAFKA_CONF_PREFIX) :]: v
        for k, v in conf.items()
        if k.startswith(KAFKA_CONF_PREFIX)
    }


class KafkaClient:
    def __init__(self, endpoint, client_class, logger):
        self.__client_class = client_class
        self._client = None
        self._endpoint = endpoint
        self._logger = logger

    @classmethod
    def _cleanup_endpoint(cls, endpoint):
        # Remove protocol prefix
        endpoints = endpoint.split(",")
        endpoints = (
            e[len("kafka://") :] if e.startswith("kafka://") else e for e in endpoints
        )
        return ",".join(endpoints)

    def _connect(self, options={}):
        if self._client is not None:
            return

        conf = {
            "bootstrap.servers": self._cleanup_endpoint(self._endpoint),
            **options,
        }

        for key, value in conf.items():
            self._logger.info("Setting option %s=%s", key, value)

        self._client = self.__client_class(conf, logger=self._logger)

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


class KafkaSender(KafkaClient):
    def __init__(self, endpoint, logger, conf={}):
        super(KafkaSender, self).__init__(endpoint, Producer, logger)
        self._delayed_topic = conf.get("delayed_topic", DEFAULT_DELAYED_TOPIC)
        self._delay_granularity = get_delay_granularity(conf)

        self._connect(
            {
                "acks": "all",
                **conf,
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
                data = json.dumps(data).encode("utf8")

            self._client.produce(topic, data, callback=callback)
            self._client.poll(0)

            if flush:
                nb_msg = self._client.flush(10.0)
                if nb_msg > 0:
                    self._logger.warn(
                        "All events are not flushed. %d are still in queue", nb_msg
                    )
        except KafkaException as exc:
            raise KafkaSendException("Failed to send event") from exc

    def _generate_delayed_event(self, topic, event, delay):
        delays = ceil(delay / self._delay_granularity)
        if isinstance(event, bytes):
            event = json.loads(event)

        delayed_event = {
            "event": EventTypes.DELAYED,
            "data": {
                "delay": delays,
                "dest_topic": topic,
                "due_time": datetime.now().timestamp() + self._delay_granularity,
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


class KafkaConsumer(KafkaClient):
    def __init__(self, endpoint, topics, group_id, logger, conf={}):
        super(KafkaConsumer, self).__init__(endpoint, Consumer, logger)

        client_conf = {
            **conf,
            "group.id": group_id,
        }

        self._connect(client_conf)

        if topics:
            self.ensure_topics_exist(topics)
            self._client.subscribe(topics)

    @property
    def consumer(self):
        return self._client

    def fetch_events(self):
        while True:
            yield self._client.poll(1.0)

    def _is_valid_offset(self):
        return self.consumer.assignment()[0].offset != OFFSET_INVALID

    def fetch_n_events(self, nb_events, partition_id, topic, offset=None):
        """Fetch event starting from the n-th event (nb_events).
        If offset is defined, returned events will be starting from the
        given offset position.

        :param nb_msg: number of expected events
        :type nb_events: int
        :param partition_id: partition assigned
        :type partition_id: TopicPartition
        :param topic: the name of the topic from which to poll
        :type topic: str
        :param offset: the starting position when polling
        :type offset: int
        :return: events
        :rtype: generator of events
        """
        partition = TopicPartition(topic, partition_id)
        desired_offset = offset if offset else OFFSET_BEGINNING
        low_offset, high_offset = self.consumer.get_watermark_offsets(partition)
        if nb_events and not offset:
            # Set the offset just on the n-th event
            desired_offset = (
                high_offset - nb_events if high_offset >= nb_events else low_offset
            )
            if desired_offset <= low_offset:
                desired_offset = OFFSET_BEGINNING

        partition.offset = desired_offset
        self.consumer.assign([partition])
        is_assigned = False
        while not all([is_assigned, self._is_valid_offset()]):
            try:
                # wait a little bit the time the partition is assigned
                time.sleep(1.0)
                self.consumer.seek(partition)
                is_assigned = True
            except KafkaException:
                continue
            except Exception as exc:
                raise KafkaPartitionNotAssignedException from exc
        nb_poll = (
            high_offset - desired_offset
            if desired_offset != OFFSET_BEGINNING
            else high_offset
        )
        for _ in range(nb_poll):
            msg = self.consumer.poll(1.0)
            if msg is None:
                # we probably already polled the latest event
                break
            elif msg.error():
                self._logger.error("Failed to fetch message, reason: %s", msg.error())
                continue
            yield msg

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
        kwargs = {"asynchronous": False}
        if offsets:
            kwargs["offsets"] = offsets
        else:
            kwargs["message"] = message
        self._client.commit(**kwargs)
