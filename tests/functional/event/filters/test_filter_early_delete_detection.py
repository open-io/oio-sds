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

from unittest.mock import Mock, patch

from oio.common.statsd import get_statsd
from oio.event.evob import EventTypes
from oio.event.filters.early_delete_detection import EarlyDeleteDetection
from tests.utils import BaseTestCase


class _App:
    def __init__(self, app_env):
        self.app_env = app_env

    def __call__(self, env, cb):
        self.env = env
        self.cb = cb


class TestFilterEarlyDeleteDetection(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.app = _App(
            {
                "api": self.storage,
                "statsd_client": get_statsd(),
            }
        )
        self.conf["redis_host"] = "127.0.0.1:6379"
        self.conf["storage_class.STANDARD"] = "EC21,TWOCOPIES:0"
        self.conf["storage_class.STANDARD_IA"] = "SINGLE"
        self.conf["storage_class_minimal_duration.STANDARD_IA"] = "10000"

    def _create_event(
        self,
        account=None,
        container=None,
        mtime=None,
        ttime=None,
        policy=None,
        mpu_size=None,
        when=18200000000,
        delete_marker=False,
    ):
        event = {
            "event": EventTypes.CONTENT_DELETED,
            "url": {},
            "data": [],
            "when": when,
        }
        if account:
            event["url"]["account"] = account
        if container:
            event["url"]["user"] = container
        if policy:
            headers = {
                "type": "contents_headers",
                "policy": policy,
                "size": 10,
            }
            if mpu_size is not None:
                headers["mime-type"] = f"binary/octet-stream;swift_bytes={mpu_size}"
            event["data"].append(headers)

        aliases = {"type": "aliases", "name": "magic", "version": 1759397659443254}
        if mtime:
            aliases["mtime"] = mtime
        event["data"].append(aliases)
        if ttime:
            event["data"].append(
                {
                    "type": "properties",
                    "key": "ttime",
                    "value": f"{ttime}",
                }
            )
        if delete_marker:
            # delete-marker should have an empty data field
            event["data"] = []
        return event

    def test_no_account(self):
        mock_cb = Mock()
        event_filter = EarlyDeleteDetection(self.app, self.conf)
        event_filter.process(self._create_event(container="foo"), mock_cb)
        mock_cb.assert_called_once_with(
            500, "Account is missing in event", delay=None, topic=None
        )

    def test_no_user(self):
        mock_cb = Mock()
        event_filter = EarlyDeleteDetection(self.app, self.conf)
        event_filter.process(self._create_event(account="foo"), mock_cb)
        mock_cb.assert_called_once_with(
            500, "Container is missing in event", delay=None, topic=None
        )

    def test_no_when(self):
        mock_cb = Mock()
        event_filter = EarlyDeleteDetection(self.app, self.conf)
        event_filter.process(
            self._create_event(account="foo", container="bar", when=None),
            mock_cb,
        )
        mock_cb.assert_called_once_with(
            500, "When is missing in event", delay=None, topic=None
        )

    def test_no_mtime_nor_ttime(self):
        mock_cb = Mock()
        event_filter = EarlyDeleteDetection(self.app, self.conf)
        event_filter.process(
            self._create_event(account="foo", container="bar"),
            mock_cb,
        )
        mock_cb.assert_called_once_with(
            500, "Unable to extract object age", delay=None, topic=None
        )

    def test_delete_marker(self):
        mock_cb = Mock()
        event_filter = EarlyDeleteDetection(self.app, self.conf)
        event_filter.process(
            self._create_event(account="foo", container="bar", delete_marker=True),
            mock_cb,
        )
        mock_cb.assert_not_called()

    def test_no_policy(self):
        mock_cb = Mock()
        event_filter = EarlyDeleteDetection(self.app, self.conf)
        event_filter.process(
            self._create_event(account="foo", container="bar", mtime=123),
            mock_cb,
        )
        mock_cb.assert_called_once_with(
            500, "Unable to extract object policy", delay=None, topic=None
        )

    def test_early_mtime(self):
        mock_cb = Mock()
        with patch(
            "oio.billing.helpers.BillingAdjustmentClient.add_adjustment"
        ) as mock_add_adjustment:
            event_filter = EarlyDeleteDetection(self.app, self.conf)
            event_filter.process(
                self._create_event(
                    account="foo", container="bar", policy="SINGLE", mtime=10000
                ),
                mock_cb,
            )
            mock_cb.assert_not_called()
            mock_add_adjustment.assert_called_once_with("foo", "bar", "STANDARD_IA", 5)

    def test_early_ttime(self):
        mock_cb = Mock()
        with patch(
            "oio.billing.helpers.BillingAdjustmentClient.add_adjustment"
        ) as mock_add_adjustment:
            event_filter = EarlyDeleteDetection(self.app, self.conf)
            event_filter.process(
                self._create_event(
                    account="foo",
                    container="bar",
                    policy="SINGLE",
                    mtime=1000,
                    ttime=10000,
                ),
                mock_cb,
            )
            mock_cb.assert_not_called()
            mock_add_adjustment.assert_called_once_with("foo", "bar", "STANDARD_IA", 5)

    def test_early_shards(self):
        mock_cb = Mock()
        with patch(
            "oio.billing.helpers.BillingAdjustmentClient.add_adjustment"
        ) as mock_add_adjustment:
            event_filter = EarlyDeleteDetection(self.app, self.conf)
            event_filter.process(
                self._create_event(
                    account=".shards_foo",
                    container="bar-CID-timestamp-index",
                    policy="SINGLE",
                    mtime=1000,
                    ttime=10000,
                ),
                mock_cb,
            )
            mock_cb.assert_not_called()
            mock_add_adjustment.assert_called_once_with("foo", "bar", "STANDARD_IA", 5)

    def test_early_mpu_manifest(self):
        mock_cb = Mock()
        with patch(
            "oio.billing.helpers.BillingAdjustmentClient.add_adjustment"
        ) as mock_add_adjustment:
            event_filter = EarlyDeleteDetection(self.app, self.conf)
            event_filter.process(
                self._create_event(
                    account=".shards_foo",
                    container="bar",
                    policy="SINGLE",
                    mtime=1000,
                    ttime=10000,
                    mpu_size=400,
                ),
                mock_cb,
            )
            mock_cb.assert_not_called()
            mock_add_adjustment.assert_called_once_with(
                "foo", "bar", "STANDARD_IA", 200
            )

    def test_early_parts_skipped(self):
        mock_cb = Mock()
        with patch(
            "oio.billing.helpers.BillingAdjustmentClient.add_adjustment"
        ) as mock_add_adjustment:
            event_filter = EarlyDeleteDetection(self.app, self.conf)
            event_filter.process(
                self._create_event(
                    account="foo",
                    container="bar+segments",
                    policy="SINGLE",
                    mtime=1000,
                    ttime=9000,
                ),
                mock_cb,
            )
            mock_cb.assert_not_called()
            mock_add_adjustment.assert_not_called()

    def test_over_storage_threshold(self):
        mock_cb = Mock()
        with patch(
            "oio.billing.helpers.BillingAdjustmentClient.add_adjustment"
        ) as mock_add_adjustment:
            event_filter = EarlyDeleteDetection(self.app, self.conf)
            event_filter.process(
                self._create_event(
                    account=".shards_foo",
                    container="bar+segments",
                    policy="SINGLE",
                    mtime=1000,
                    ttime=20000,
                ),
                mock_cb,
            )
            mock_cb.assert_not_called()
            mock_add_adjustment.assert_not_called()
