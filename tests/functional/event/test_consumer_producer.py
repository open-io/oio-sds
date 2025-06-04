# -*- coding: utf-8 -*-

# Copyright (C) 2025 OVH SAS
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

from oio.common.exceptions import OioTimeout
from oio.common.kafka import KafkaTopicNotFoundException
from tests.utils import BaseTestCase


class TestKafkaConsumer(BaseTestCase):
    def test_ensure_topics_exists(self):
        res = self._cls_kafka_consumer.ensure_topics_exist(["oio-deadletter"])
        self.assertIsNone(res)

    def test_ensure_topics_exists_bad_topic(self):
        consumer = self._cls_kafka_consumer
        self.assertRaisesRegex(
            KafkaTopicNotFoundException,
            r".*Topic whatever not found.*",
            consumer.ensure_topics_exist,
            ["whatever"],
        )

    def test_ensure_topics_exists_timeout(self):
        consumer = self._cls_kafka_consumer
        self.assertRaises(
            OioTimeout, consumer.ensure_topics_exist, ["whatever"], timeout=0.0005
        )
