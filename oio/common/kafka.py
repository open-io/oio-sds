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

DEFAULT_ENDPOINT = "kafka://127.0.0.1:19092"
DEFAULT_TOPIC = "oio"
DEFAULT_REPLICATION_TOPIC = "oio-replication"
DEFAULT_DELAYED_TOPIC = "oio-delayed"
DEFAULT_DELAY_GRANULARITY = 60
POLL_TIMEOUT = 10 * 1000


def get_delay_granularity(conf):
    return conf.get("delay_granularity", DEFAULT_DELAY_GRANULARITY)


class KafkaSendException(OioException):
    ...


class KafkaClient:
    def __init__(self, endpoint, client_class):
        self.__client_class = client_class
        self._client = None
        self._endpoint = endpoint

    @classmethod
    def _cleanup_endpoint(cls, endpoint):
        # Remove protocol prefix
        endpoints = endpoint.split(";")
        endpoints = (
            e[len("kafka://") :] if e.startswith("kafka://") else e for e in endpoints
        )
        return ";".join(endpoints)

    def _connect(self, options=None):
        if self._client is not None:
            return

        if options is None:
            options = {}

        conf = {
            "bootstrap.servers": self._cleanup_endpoint(self._endpoint),
            "debug": "broker, cgrp",
        }

        conf.update(options)

        print(conf)
        self._client = self.__client_class(conf)

    def close(self):
        if self._client is None:
            return
        self._close()
        self._client = None

    def _close(self):
        raise NotImplementedError()


class KafkaSender(KafkaClient):
    def __init__(self, endpoint, conf={}):
        super(KafkaSender, self).__init__(endpoint, Producer)
        self._delayed_topic = conf.get("delayed_topic", DEFAULT_DELAYED_TOPIC)
        self._delay_granularity = get_delay_granularity(conf)
        self._connect(conf)

    @property
    def producer(self):
        return self._client

    def _send(self, topic, data, flush=False, callback=None):
        try:
            if isinstance(data, str):
                data = data.encode("utf8")
            elif isinstance(data, dict):
                data = json.dumps(data).encode("utf8")

            self._client.produce(topic, data, callback=callback)
            self._client.poll(POLL_TIMEOUT)

            if flush:
                self._client.flush()
        except KafkaException as exc:
            raise KafkaSendException("Failed to send event") from exc

    def _generate_delayed_event(self, topic, data, delay):
        delays = ceil(delay / self._delay_granularity)
        return {
            "dest_topic": topic,
            "delay": delays,
            "data": data,
            "due_time": datetime.now().timestamp() + self._delay_granularity,
        }

    def send(self, topic, data, delay=0, flush=False, callback=None):
        if delay > 0:
            # Encapsulate event in a delayed one
            data = self._generate_delayed_event(topic, data, delay)
            topic = self._delayed_topic

        return self._send(topic, data, flush=flush, callback=callback)

    def _close(self):
        self._client.poll(POLL_TIMEOUT)
        self._client.flush()


class KafkaConsumer(KafkaClient):
    def __init__(self, endpoint, topics, logger, conf={}):
        super(KafkaConsumer, self).__init__(endpoint, Consumer)

        self._connect(conf)
        self._logger = logger
        self._client.subscribe(topics)

    @property
    def consumer(self):
        return self._client

    def fetch_events(self):
        while True:
            msg = self._client.poll(1.0)
            if msg is None:
                continue
            elif msg.error():
                self._logger.error("Failed to fetch message, reason: %s", msg.error())
                continue
            yield msg

    def _close(self):
        self._client.poll(POLL_TIMEOUT)
        self._client.close()

    def commit(self, message):
        self._client.commit(message)
