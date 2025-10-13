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

from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

from oio.common.constants import (
    ARCHIVE_RESTORE_USER_AGENT,
    RESTORE_PROPERTY_KEY,
    S3StorageClasses,
)
from oio.common.kafka import KafkaSender
from oio.common.properties import RestoreProperty
from oio.common.utils import request_id
from oio.event.evob import EventTypes
from oio.event.filters.archive_restore import ArchiveRestore
from oio.event.filters.object_restore_detection import ObjectRestoreDetection
from tests.utils import BaseTestCase, random_str


class _App:
    def __init__(self, app_env):
        self.app_env = app_env

    def __call__(self, env, cb):
        self.env = env
        self.cb = cb


class TestArchiveRestore(BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._producer = KafkaSender(cls._cls_conf["kafka_endpoints"], cls._cls_logger)

    @classmethod
    def tearDownClass(cls):
        cls._producer.close()
        return super().tearDownClass()

    def setUp(self):
        super().setUp()
        self.patcher = patch("oio.event.filters.archive_restore.RestoreBillingClient")
        self.mock = self.patcher.start()
        self.statsd_mock = Mock()

        self.mock.return_value = self.mock
        self.app = _App(
            {
                "api": self.storage,
                "statsd_client": self.statsd_mock,
            }
        )
        self.account = f"archive-restore-acct-{random_str(4)}"
        self.container = f"archive-restore-ct-{random_str(4)}"
        self.clean_later(self.container)

    def tearDown(self):
        self.patcher.stop()
        super().tearDown()

    def _create_object(self, name, properties=None, policy="THREECOPIES_DA"):
        return self.storage.object_create_ext(
            account=self.account,
            container=self.container,
            obj_name=name,
            data="test",
            policy=policy,
            properties=properties,
        )

    def _craft_event(
        self,
        meta,
        restore_property=None,
        reqid=None,
        delay_bypass=False,
    ):
        if reqid is None:
            reqid = request_id()
        evt = {
            "event": "storage.content.update",
            "when": 1759269345455196,
            "url": {
                "ns": "OPENIO",
                "account": self.account,
                "user": self.container,
                "id": meta["container_id"],
                "path": "my-object",
                "content": meta["id"],
                "version": meta["version"],
                "bucket": self.container,
            },
            "request_id": reqid,
            "origin": "python-urllib3/1.26.20",
            "part": 0,
            "parts": 1,
            "data": [
                {
                    "type": "aliases",
                    "name": "my-object",
                    "version": meta["version"],
                    "ctime": meta["ctime"],
                    "mtime": meta["mtime"],
                    "deleted": False,
                    "header": meta["id"],
                },
            ],
        }
        if restore_property is not None:
            evt["data"].append(
                {
                    "type": "properties",
                    "alias": "my-object",
                    "version": meta["version"],
                    "key": "x-object-sysmeta-s3api-restore",
                    "value": restore_property.dump(),
                    "_delay_bypass": delay_bypass,
                },
            )
        return evt

    def test_delay_event_invalid(self):
        archive_filter = ArchiveRestore(
            self.app,
            {
                "redis_host": self.conf["services"]["redis"][0]["addr"],
            },
        )
        mock_cb = Mock()
        archive_filter.process({}, mock_cb)
        mock_cb.assert_called_once_with(
            500,
            "Property 'x-object-sysmeta-s3api-restore' missing in event",
            delay=None,
            topic=None,
        )

    def test_delay_event_postpone(self):
        archive_filter = ArchiveRestore(
            self.app,
            {
                "redis_host": self.conf["services"]["redis"][0]["addr"],
                "storage_class.DEEP_ARCHIVE": "THREECOPIES_DA",
                "restorable_storage_classes": "DEEP_ARCHIVE",
                "restore_delay.DEEP_ARCHIVE": "5,15,1",
            },
        )
        mock_cb = Mock()
        with patch(
            "oio.event.filters.archive_restore.randrange", Mock(return_value=2880)
        ):
            now = datetime(2025, 6, 5, 11, 12, 1, tzinfo=timezone.utc)

            with patch(
                "oio.event.filters.archive_restore.ArchiveRestore._now",
                Mock(return_value=now),
            ):
                restore_props = RestoreProperty()
                restore_props.days = 3
                restore_props.ongoing = True
                restore_props.request_date = datetime(
                    2025, 6, 5, 11, 12, 0, tzinfo=timezone.utc
                ).timestamp()
                event = self._craft_event(
                    self._create_object("my-object")[3], restore_property=restore_props
                )
                archive_filter.process(event, mock_cb)
                mock_cb.assert_called_once_with(
                    503,
                    "Delay to simulate object restoration",
                    delay=2879.0,
                    topic="oio-archive-delayed",
                )
                self.mock.add_restore.assert_not_called()

    def test_delay_event_replay(self):
        _, size, _, meta = self._create_object("my-object")

        archive_filter = ArchiveRestore(
            self.app,
            {
                "redis_host": self.conf["services"]["redis"][0]["addr"],
                "storage_class.DEEP_ARCHIVE": "THREECOPIES_DA",
                "restorable_storage_classes": "DEEP_ARCHIVE",
            },
        )
        mock_cb = Mock()
        reqid = request_id("delay-event-")

        now = datetime(2025, 6, 5, 16, 43, 1, tzinfo=timezone.utc)
        expected_restore_duration = 3 * 24 + 8

        with patch(
            "oio.event.filters.archive_restore.ArchiveRestore._now",
            Mock(return_value=now),
        ):
            restore_props = RestoreProperty()
            restore_props.days = 3
            restore_props.ongoing = False
            restore_props.request_date = datetime(
                2025, 6, 5, 11, 12, 0, tzinfo=timezone.utc
            ).timestamp()
            event = self._craft_event(meta, restore_property=restore_props, reqid=reqid)

            archive_filter.process(event, mock_cb)
            mock_cb.assert_not_called()
            self.mock.add_restore.assert_called_once_with(
                self.account,
                self.container,
                S3StorageClasses.DEEP_ARCHIVE.name,
                requests=1,
                transfer=size,
                storage=size * expected_restore_duration,
            )

            evt = self.wait_for_kafka_event(
                types=[EventTypes.CONTENT_UPDATE],
                fields={
                    "account": self.account,
                    "user": self.container,
                    "path": "my-object",
                    "version": meta.get("version"),
                },
                origin=ARCHIVE_RESTORE_USER_AGENT,
                reqid=reqid,
            )
            self.assertIsNotNone(evt)
            meta = self.storage.object_get_properties(
                self.account,
                self.container,
                "my-object",
                version=meta.get("version"),
            )

            self.assertIn("properties", meta)
            properties = meta["properties"]
            self.assertIn(RESTORE_PROPERTY_KEY, properties)
            restore = RestoreProperty.load(properties[RESTORE_PROPERTY_KEY])
            self.assertEqual(
                int(
                    (
                        now.replace(hour=0, minute=0, second=0, microsecond=0)
                        + timedelta(days=4)
                    ).timestamp()
                ),
                restore.expiry_date,
            )
            self.assertFalse(restore.ongoing)
            self.statsd_mock.timing.assert_called_with(
                "openio.restore.DEEP_ARCHIVE.process", 19861.0
            )

    def test_delay_event_update_expiry(self):
        _, size, _, meta = self._create_object("my-object")

        archive_filter = ArchiveRestore(
            self.app,
            {
                "redis_host": self.conf["services"]["redis"][0]["addr"],
                "storage_class.DEEP_ARCHIVE": "THREECOPIES_DA",
                "restorable_storage_classes": "DEEP_ARCHIVE",
            },
        )
        mock_cb = Mock()
        reqid = request_id("delay-event-")

        restore_props = RestoreProperty()
        restore_props.days = 10
        restore_props.expiry_date = int(
            datetime(2025, 6, 10, 0, 0, 0, tzinfo=timezone.utc).timestamp()
        )
        restore_props.ongoing = False
        restore_props.request_date = datetime(
            2025, 6, 5, 11, 12, 0, tzinfo=timezone.utc
        ).timestamp()
        event = self._craft_event(meta, restore_property=restore_props, reqid=reqid)

        now = datetime(2025, 6, 5, 11, 12, 1, tzinfo=timezone.utc)

        with patch(
            "oio.event.filters.archive_restore.ArchiveRestore._now",
            Mock(return_value=now),
        ):
            archive_filter.process(event, mock_cb)
            mock_cb.assert_not_called()

            evt = self.wait_for_kafka_event(
                types=[EventTypes.CONTENT_UPDATE],
                fields={
                    "account": self.account,
                    "user": self.container,
                    "path": "my-object",
                    "version": meta.get("version"),
                },
                origin=ARCHIVE_RESTORE_USER_AGENT,
                reqid=reqid,
            )
            self.assertIsNotNone(evt)
            self.mock.add_restore.assert_called_once_with(
                self.account,
                self.container,
                S3StorageClasses.DEEP_ARCHIVE.name,
                requests=1,
                transfer=0,
                storage=6 * 24 * size,
            )
            meta = self.storage.object_get_properties(
                self.account,
                self.container,
                "my-object",
                version=meta.get("version"),
            )

            self.assertIn("properties", meta)
            properties = meta["properties"]
            self.assertIn(RESTORE_PROPERTY_KEY, properties)
            restore = RestoreProperty.load(properties[RESTORE_PROPERTY_KEY])
            self.assertEqual(
                int(
                    (
                        now.replace(hour=0, minute=0, second=0, microsecond=0)
                        + timedelta(days=11)
                    ).timestamp()
                ),
                restore.expiry_date,
            )
            self.assertFalse(restore.ongoing)
            self.statsd_mock.timing.assert_not_called()

    def test_delay_event_restore_previously_restored(self):
        _, size, _, meta = self._create_object("my-object")

        archive_filter = ArchiveRestore(
            self.app,
            {
                "redis_host": self.conf["services"]["redis"][0]["addr"],
                "storage_class.DEEP_ARCHIVE": "THREECOPIES_DA",
                "restorable_storage_classes": "DEEP_ARCHIVE",
            },
        )
        mock_cb = Mock()
        reqid = request_id("delay-event-")
        restore_props = RestoreProperty()
        restore_props.days = 10
        restore_props.expiry_date = int(
            datetime(2024, 6, 10, 0, 0, 0, tzinfo=timezone.utc).timestamp()
        )
        restore_props.request_date = datetime(
            2025, 6, 5, 11, 12, 0, tzinfo=timezone.utc
        ).timestamp()
        restore_props.ongoing = False
        event = self._craft_event(meta, restore_property=restore_props, reqid=reqid)

        now = datetime(2025, 6, 5, 11, 12, 1, tzinfo=timezone.utc)

        with patch(
            "oio.event.filters.archive_restore.ArchiveRestore._now",
            Mock(return_value=now),
        ):
            archive_filter.process(event, mock_cb)
            mock_cb.assert_not_called()

            evt = self.wait_for_kafka_event(
                types=[EventTypes.CONTENT_UPDATE],
                fields={
                    "account": self.account,
                    "user": self.container,
                    "path": "my-object",
                    "version": meta.get("version"),
                },
                origin=ARCHIVE_RESTORE_USER_AGENT,
                reqid=reqid,
            )
            self.assertIsNotNone(evt)
            self.mock.add_restore.assert_called_once_with(
                self.account,
                self.container,
                S3StorageClasses.DEEP_ARCHIVE.name,
                requests=1,
                transfer=size,
                storage=(13 + 240) * size,
            )
            meta = self.storage.object_get_properties(
                self.account,
                self.container,
                "my-object",
                version=meta.get("version"),
            )

            self.assertIn("properties", meta)
            properties = meta["properties"]
            self.assertIn(RESTORE_PROPERTY_KEY, properties)
            restore = RestoreProperty.load(properties[RESTORE_PROPERTY_KEY])
            self.assertEqual(
                int(
                    (
                        now.replace(hour=0, minute=0, second=0, microsecond=0)
                        + timedelta(days=11)
                    ).timestamp()
                ),
                restore.expiry_date,
            )
            self.assertFalse(restore.ongoing)
            self.statsd_mock.timing.called_once_with(
                "openio.restore.DEEP_ARCHIVE.process", 1.0
            )

    def test_restore_event_processing(self):
        reqid = request_id("delay-event-")
        _, _, _, meta = self._create_object("my-object", policy="THREECOPIES_DA")

        restore_prop = RestoreProperty()
        restore_prop.days = 10
        restore_prop.ongoing = True
        restore_prop.request_date = datetime.now(tz=timezone.utc).timestamp()
        event = self._craft_event(
            meta, restore_property=restore_prop, reqid=reqid, delay_bypass=True
        )

        self._producer.send(ObjectRestoreDetection.DEFAULT_TOPIC, event, flush=True)

        # Original event, before delay
        evt = self.wait_for_kafka_event(
            types=[EventTypes.CONTENT_UPDATE],
            fields={
                "account": self.account,
                "user": self.container,
                "path": "my-object",
                "version": meta.get("version"),
            },
            origin="python-urllib3/1.26.20",
            reqid=reqid,
        )
        self.assertIsNotNone(evt)
        self.assertEqual("properties", evt.data[1]["type"])
        self.assertIn("_postponed", evt.data[1])

        evt = self.wait_for_kafka_event(
            types=[EventTypes.CONTENT_UPDATE],
            fields={
                "account": self.account,
                "user": self.container,
                "path": "my-object",
                "version": meta.get("version"),
            },
            origin=ARCHIVE_RESTORE_USER_AGENT,
            reqid=reqid,
        )
        self.assertIsNotNone(evt)
        self.assertEqual("properties", evt.data[1]["type"])
        self.assertNotIn("_postponed", evt.data[1])
