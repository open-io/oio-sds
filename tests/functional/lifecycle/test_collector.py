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
import json
from tempfile import NamedTemporaryFile

from oio.common.constants import LIFECYCLE_PROPERTY_KEY, M2_PROP_BUCKET_NAME
from oio.common.kafka import DEFAULT_LIFECYCLE_CHECKPOINT_TOPIC
from oio.event.evob import EventTypes
from tests.functional.cli import execute
from tests.utils import BaseTestCase, random_str


class TestLifecycleCheckpointCollector(BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._cls_checkpoint_consumer = cls._register_consumer(
            topic=DEFAULT_LIFECYCLE_CHECKPOINT_TOPIC
        )

    def setUp(self):
        super().setUp()
        self.run_id = f"runid_{random_str(4)}"

    def _create_container(self, container, with_lifecycle):
        system = {M2_PROP_BUCKET_NAME: container}
        self.storage.container_create(self.account, container, system=system)
        self.storage.bucket.bucket_create(container, self.account)
        self.clean_later(container)
        self.bucket_clean_later(container)
        if with_lifecycle:
            self.storage.container_set_properties(
                self.account,
                container,
                properties={LIFECYCLE_PROPERTY_KEY: json.dumps({"Rules": []})},
            )

    def openio_checkpoint_collector(self, coverage="--coverage", **kwargs):
        conf = (
            "[checkpoint-collector]",
            f"namespace = {self.conf['namespace']}",
            "concurrency = 1",
            f"endpoint = {self.conf['kafka_endpoints']}",
            f"topic = {DEFAULT_LIFECYCLE_CHECKPOINT_TOPIC}",
            f"redis_host = {self.conf['services']['redis'][0]['addr']}",
            f"syslog_prefix = OIO,{self.conf['namespace']},checkpoint-collector",
            "log_level = DEBUG",
            "lifecycle_configuration_backup_account = internal",
            "lifecycle_configuration_backup_bucket = internal_lifecycle",
        )
        with NamedTemporaryFile("w") as temp_conf:
            temp_conf.write("\n".join(conf))
            temp_conf.flush()

            return execute(
                " ".join(
                    (
                        "oio-checkpoint-collector",
                        temp_conf.name,
                        coverage,
                        "-v",
                        f"--run-id {self.run_id}",
                    )
                ),
                **kwargs,
            )[0]

    def test_multiple_calls(self):
        for i in range(0, 10):
            self._create_container(f"container_{i}", i < 5)
        self.openio_checkpoint_collector()
        for i in range(0, 5):
            evt = self.wait_for_kafka_event(
                kafka_consumer=self._cls_checkpoint_consumer,
                types=[EventTypes.LIFECYCLE_CHECKPOINT],
                data_fields={
                    "run_id": self.run_id,
                    "account": self.account,
                    "bucket": f"container_{i}",
                },
            )
            self.assertIsNotNone(evt)

        self.openio_checkpoint_collector()
        evt = self.wait_for_kafka_event(
            kafka_consumer=self._cls_checkpoint_consumer,
            types=[EventTypes.LIFECYCLE_CHECKPOINT],
            data_fields={
                "run_id": self.run_id,
            },
            timeout=5.0,
        )
        self.assertIsNone(evt)
