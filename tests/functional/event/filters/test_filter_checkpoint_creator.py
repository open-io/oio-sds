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

from oio.common.constants import M2_PROP_SHARDING_STATE
from oio.common.exceptions import NotFound
from oio.common.statsd import get_statsd
from oio.event.filters.checkpoint_creator import CheckpointCreatorFilter
from oio.lifecycle.metrics import LifecycleStep
from tests.utils import BaseTestCase


class _App:
    def __init__(self, app_env):
        self.app_env = app_env

    def __call__(self, env, cb):
        self.env = env
        self.cb = cb


class TestFilterCheckpointCreator(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.app = _App(
            {
                "api": self.storage,
                "statsd_client": get_statsd(),
            }
        )
        self.filter = CheckpointCreatorFilter(
            app=self.app, conf={"redis_host": "127.0.0.1:6379", **self.conf}
        )
        self.filter._generate_sub_events = Mock(return_value=None)
        self.filter._update_metrics = Mock()

    def test_bucket_delete(self):
        env = {
            "data": {
                "account": "acct-1",
                "bucket": "bucket-1",
                "run_id": "run-1",
                "root_cid": "AAAA",
                "cid": "BBBB",
            }
        }
        mock_cb = Mock()
        self.filter._create_checkpoint = Mock()
        self.assertIsNone(self.filter.process(env, mock_cb))
        mock_cb.assert_not_called()
        self.filter._create_checkpoint.assert_not_called()

    def test_sharding_root_not_updated(self):
        env = {
            "data": {
                "account": "acct-1",
                "bucket": "bucket-1",
                "run_id": "run-1",
                "root_cid": "AAAA",
                "cid": "BBBB",
            }
        }

        mock_cb = Mock()
        self.filter._create_checkpoint = Mock()
        with patch(
            "oio.container.sharding.ContainerSharding.get_shards_in_range",
            Mock(return_value=[]),
        ):
            with patch(
                "oio.container.client.ContainerClient.container_get_properties",
                Mock(return_value={"system": {M2_PROP_SHARDING_STATE: 2}}),
            ):
                self.filter.process(env, mock_cb)
        mock_cb.assert_called_once_with(503, "Sharding in progress for BBBB", delay=60)
        self.filter._create_checkpoint.assert_not_called()
        self.filter._update_metrics.assert_not_called()

    def test_sharding_container_missing(self):
        env = {
            "data": {
                "account": "acct-1",
                "bucket": "bucket-1",
                "run_id": "run-1",
                "root_cid": "AAAA",
                "cid": "BBBB",
                "bounds": {"lower": "", "upper": "foo"},
            }
        }
        mock_cb = Mock()
        self.filter._create_checkpoint = Mock()
        with patch(
            "oio.container.sharding.ContainerSharding.get_shards_in_range",
            Mock(
                side_effect=[
                    [{"cid": "BBBB", "lower": "", "upper": "foo"}],
                    [{"cid": "CCCC", "lower": "", "upper": "foo"}],
                ]
            ),
        ):
            with patch(
                "oio.container.client.ContainerClient.container_get_properties",
                Mock(side_effect=NotFound("Container missing")),
            ):
                self.filter.process(env, mock_cb)
        mock_cb.assert_not_called()
        self.filter._generate_sub_events.assert_called_once()
        self.filter._create_checkpoint.assert_not_called()
        self.filter._update_metrics.assert_called_once_with(LifecycleStep.SKIPPED)

    def test_sharding_container_not_initialized(self):
        env = {
            "data": {
                "account": "acct-1",
                "bucket": "bucket-1",
                "run_id": "run-1",
                "root_cid": "AAAA",
                "cid": "BBBB",
                "bounds": {"lower": "", "upper": "foo"},
            }
        }
        mock_cb = Mock()
        self.filter._create_checkpoint = Mock()
        with patch(
            "oio.container.sharding.ContainerSharding.get_shards_in_range",
            Mock(
                side_effect=[
                    [{"cid": "BBBB", "lower": "", "upper": "foo"}],
                    [{"cid": "BBBB", "lower": "", "upper": "foo"}],
                ]
            ),
        ):
            with patch(
                "oio.container.client.ContainerClient.container_get_properties",
                Mock(side_effect=NotFound("Container missing")),
            ):
                self.assertRaises(Exception, self.filter.process, env, mock_cb)
        mock_cb.assert_not_called()
        self.filter._generate_sub_events.assert_not_called()
        self.filter._create_checkpoint.assert_not_called()
        self.filter._update_metrics.assert_called_once_with(LifecycleStep.ERROR)

    def test_sharding_root_deleted_with_bad_timing(self):
        env = {
            "data": {
                "account": "acct-1",
                "bucket": "bucket-1",
                "run_id": "run-1",
                "root_cid": "AAAA",
                "cid": "BBBB",
                "bounds": {"lower": "", "upper": "foo"},
            }
        }
        mock_cb = Mock()
        self.filter._create_checkpoint = Mock()
        with patch(
            "oio.container.sharding.ContainerSharding.get_shards_in_range",
            Mock(
                side_effect=[
                    [{"cid": "BBBB", "lower": "", "upper": "foo"}],
                    NotFound(),
                ]
            ),
        ):
            with patch(
                "oio.container.client.ContainerClient.container_get_properties",
                Mock(side_effect=NotFound("Container missing")),
            ):
                self.filter.process(env, mock_cb)
        mock_cb.assert_not_called()
        self.filter._generate_sub_events.assert_not_called()
        self.filter._create_checkpoint.assert_not_called()
        self.filter._update_metrics.assert_called_once_with(LifecycleStep.SKIPPED)

    def test_sharding_last_shard_removed(self):
        env = {
            "data": {
                "account": "acct-1",
                "bucket": "bucket-1",
                "run_id": "run-1",
                "root_cid": "AAAA",
                "cid": "BBBB",
                "bounds": {"lower": "", "upper": ""},
            }
        }
        mock_cb = Mock()

        with patch(
            "oio.container.sharding.ContainerSharding.get_shards_in_range",
            Mock(
                side_effect=[
                    [],
                ]
            ),
        ):
            with patch(
                "oio.container.client.ContainerClient.container_get_properties",
                Mock(side_effect=[{"system": {M2_PROP_SHARDING_STATE: 0}}]),
            ):
                with patch(
                    "oio.container.client.ContainerClient.container_checkpoint",
                    Mock(),
                ) as checkpoint_mock:
                    self.filter.process(env, mock_cb)
                    checkpoint_mock.assert_called_once_with(
                        cid="AAAA",
                        suffix="Lifecycle-run-1-416110333A9AFC096EC19D9C024314DC",
                        reqid=None,
                    )
        mock_cb.assert_not_called()
        self.filter._generate_sub_events.assert_not_called()
        self.filter._update_metrics.assert_called_once_with(LifecycleStep.PROCESSED)

    def test_sharding_last_shards_removed(self):
        env = {
            "data": {
                "account": "acct-1",
                "bucket": "bucket-1",
                "run_id": "run-1",
                "root_cid": "AAAA",
                "cid": "BBBB",
                "bounds": {"lower": "", "upper": "foo"},
            }
        }
        mock_cb = Mock()

        with patch(
            "oio.container.sharding.ContainerSharding.get_shards_in_range",
            Mock(
                side_effect=[
                    [],
                ]
            ),
        ):
            with patch(
                "oio.container.client.ContainerClient.container_get_properties",
                Mock(side_effect=[{"system": {M2_PROP_SHARDING_STATE: 0}}]),
            ):
                with patch(
                    "oio.container.client.ContainerClient.container_checkpoint",
                    Mock(),
                ) as checkpoint_mock:
                    self.filter.process(env, mock_cb)
                    checkpoint_mock.assert_called_once_with(
                        cid="AAAA",
                        suffix="Lifecycle-run-1-416110333A9AFC096EC19D9C024314DC",
                        reqid=None,
                    )
        mock_cb.assert_not_called()
        self.filter._generate_sub_events.assert_not_called()
        self.filter._update_metrics.assert_called_once_with(LifecycleStep.PROCESSED)
