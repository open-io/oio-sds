# Copyright (C) 2025 OVH SAS
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

import json
from datetime import datetime, timedelta, timezone
from math import ceil
from unittest.mock import Mock, patch

import pytest

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

    def _create_object(self, name, properties=None, policy="THREECOPIES_DA", slo=False):
        data = "test"
        mime_type = "binary/octet-stream"
        if slo:
            data = json.dumps(
                [
                    {
                        "name": (
                            f"/{self.container}+segments/{name}/"
                            "YTc0ZDJlMDctMjdmZi00ZjgwLWI1NzAtMDc5ZDVmMGM1MjFl/1"
                        ),
                        "bytes": 8388608,
                        "hash": "087b6f114cf78c022a0a3bec421b4d1b",
                        "content_type": "application/octet-stream",
                        "last_modified": "2025-11-05T12:55:52.000000",
                    },
                    {
                        "name": (
                            f"/{self.container}+segments/{name}/"
                            "YTc0ZDJlMDctMjdmZi00ZjgwLWI1NzAtMDc5ZDVmMGM1MjFl/2"
                        ),
                        "bytes": 8388608,
                        "hash": "79f201c9668ab33821fc711883bd006a",
                        "content_type": "application/octet-stream",
                        "last_modified": "2025-11-05T12:55:52.000000",
                    },
                ]
            )
            if properties is None:
                properties = {}
            properties.update(
                {
                    "x-object-sysmeta-s3api-upload-id": (
                        "YTc0ZDJlMDctMjdmZi00ZjgwLWI1NzAtMDc5ZDVmMGM1MjFl"
                    ),
                    "x-object-sysmeta-s3api-etag": "ce723f0dc5628e29a065f44a3fde31f9-2",
                    "x-object-sysmeta-s3api-checksum-crc32": "tO7oJg==-2",
                    "x-object-sysmeta-container-update-override-etag": (
                        "f4aca38f03ff4c52e5eae8987ee38ff9; "
                        "s3_etag=ce723f0dc5628e29a065f44a3fde31f9-2; "
                        "s3_crc32=tO7oJg==-2; "
                        "slo_etag=d47b64792b7f75234fb1fa89d53f6b59"
                    ),
                    "x-object-sysmeta-slo-etag": "d47b64792b7f75234fb1fa89d53f6b59",
                    "x-object-sysmeta-slo-size": "16777216",
                    "x-static-large-object": "True",
                }
            )
            mime_type += ";swift_bytes=16777216"
        _, size, _, meta = self.storage.object_create_ext(
            account=self.account,
            container=self.container,
            obj_name=name,
            data=data,
            policy=policy,
            properties=properties,
            mime_type=mime_type,
        )
        if slo:
            size = 16777216
        return size, meta

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
                    self._create_object("my-object")[1], restore_property=restore_props
                )
                archive_filter.process(event, mock_cb)
                mock_cb.assert_called_once_with(
                    503,
                    "Delay to simulate object restoration",
                    delay=2880,
                    topic="oio-archive-delayed",
                )
                self.mock.add_restore.assert_not_called()

    @pytest.mark.flaky(reruns=1)
    def test_delay_event_replay_with_simple_object(self):
        self._test_delay_event_replay(slo=False)

    @pytest.mark.flaky(reruns=1)
    def test_delay_event_replay_with_mpu_object(self):
        self._test_delay_event_replay(slo=True)

    def _test_delay_event_replay(self, slo=False):
        size, meta = self._create_object("my-object", slo=slo)
        mtime = int(meta.get("mtime"))

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

        now = datetime.fromtimestamp(mtime, tz=timezone.utc) + timedelta(
            days=10, hours=5
        )
        expected_restore_duration = ceil(
            (
                (
                    now.replace(hour=0, minute=0, second=0, microsecond=0)
                    + timedelta(days=1 + 3)
                ).timestamp()
                - now.timestamp()
            )
            / 3600
        )

        with patch(
            "oio.event.filters.archive_restore.ArchiveRestore._now",
            Mock(return_value=now),
        ):
            restore_props = RestoreProperty()
            restore_props.days = 3
            restore_props.ongoing = False
            restore_props.request_date = (
                datetime.fromtimestamp(mtime, tz=timezone.utc)
                + timedelta(days=10, hours=4)
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
            self.assertListEqual(
                [
                    ("openio.restore.deep_archive.duration", 3600.0),
                    (
                        "openio.restore.deep_archive.archived.duration",
                        878400.0,  # Sometimes 878399.0
                    ),
                ],
                [c.args for c in self.statsd_mock.timing.call_args_list],
            )

            self.assertListEqual(
                [
                    ("openio.restore.deep_archive.volume",),
                    ("openio.restore.deep_archive.requests.restore",),
                ],
                [c.args for c in self.statsd_mock.incr.call_args_list],
            )

    def test_delay_event_update_expiry_with_simple_object(self):
        self._test_delay_event_update_expiry(slo=False)

    def test_delay_event_update_expiry_with_mpu_object(self):
        self._test_delay_event_update_expiry(slo=True)

    def _test_delay_event_update_expiry(self, slo=False):
        size, meta = self._create_object("my-object", slo=slo)

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

    def test_delay_event_restore_previously_restored_with_simple_object(self):
        self._test_delay_event_restore_previously_restored(slo=False)

    def test_delay_event_restore_previously_restored_with_mpu_object(self):
        self._test_delay_event_restore_previously_restored(slo=True)

    def _test_delay_event_restore_previously_restored(self, slo=False):
        size, meta = self._create_object("my-object", slo=slo)

        archive_filter = ArchiveRestore(
            self.app,
            {
                "redis_host": self.conf["services"]["redis"][0]["addr"],
                "storage_class.DEEP_ARCHIVE": "THREECOPIES_DA",
                "restorable_storage_classes": "DEEP_ARCHIVE",
            },
        )
        mtime = int(meta.get("mtime"))
        now = datetime.fromtimestamp(mtime, tz=timezone.utc) + timedelta(
            days=10, hours=6
        )

        mock_cb = Mock()
        reqid = request_id("delay-event-")
        restore_props = RestoreProperty()
        restore_props.days = 10
        restore_props.expiry_date = int((now - timedelta(days=10)).timestamp())
        restore_props.request_date = int((now - timedelta(hours=1)).timestamp())
        restore_props.ongoing = False
        event = self._craft_event(meta, restore_property=restore_props, reqid=reqid)

        expected_restore_duration = ceil(
            (
                (
                    now.replace(hour=0, minute=0, second=0, microsecond=0)
                    + timedelta(days=1 + 10)
                ).timestamp()
                - now.timestamp()
            )
            / 3600
        )

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
                storage=expected_restore_duration * size,
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
            self.assertListEqual(
                [
                    ("openio.restore.deep_archive.volume",),
                    ("openio.restore.deep_archive.requests.restore",),
                ],
                [c.args for c in self.statsd_mock.incr.call_args_list],
            )

    def test_restore_event_processing(self):
        reqid = request_id("delay-event-")
        _, meta = self._create_object("my-object", policy="THREECOPIES_DA")

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
