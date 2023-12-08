# Copyright (C) 2023 OVH SAS
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
from math import ceil

from confluent_kafka import Consumer, Producer, KafkaException
from oio.common.exceptions import OioException
from oio.event.evob import EventTypes

DEFAULT_ENDPOINT = "kafka://127.0.0.1:19092"
DEFAULT_TOPIC = "oio"
DEFAULT_REPLICATION_TOPIC = "oio-replication"
DEFAULT_DELAYED_TOPIC = "oio-delayed"
DEFAULT_DELETE_TOPIC_PREFIX = "oio-delete-"
DEFAULT_REBUILD_TOPIC = "oio-rebuild"
DEFAULT_DEADLETTER_TOPIC = "oio-deadletter"
DEFAULT_XCUTE_JOB_TOPIC = "oio-xcute-job"
DEFAULT_XCUTE_JOB_REPLY_TOPIC = DEFAULT_XCUTE_JOB_TOPIC + "-reply"
DEFAULT_DELAY_GRANULARITY = 60
KAFKA_CONF_PREFIX = "kafka_"
POLL_TIMEOUT = 10 * 1000


def get_delay_granularity(conf):
    return conf.get("delay_granularity", DEFAULT_DELAY_GRANULARITY)


class KafkaSendException(OioException):
    ...


class KafkaTopicNotFoundException(OioException):
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
    def __init__(self, endpoint, topics, logger, conf={}):
        super(KafkaConsumer, self).__init__(endpoint, Consumer, logger)

        self._connect(conf)

        self.ensure_topics_exist(topics)
        self._client.subscribe(topics)

    @property
    def consumer(self):
        return self._client

    def fetch_events(self):
        while True:
            yield self._client.poll(1.0)

    def _close(self):
        self._client.poll(POLL_TIMEOUT)
        self._client.close()

    def commit(self, message):
        self._client.commit(message, asynchronous=False)
