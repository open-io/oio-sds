# Copyright (C) 2026 OVH SAS
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

import unittest
from unittest.mock import MagicMock, patch

from oio.common.exceptions import (
    DeadlineReached,
    OioNetworkException,
    OioTimeout,
    ServiceBusy,
)
from oio.common.statsd import get_statsd
from oio.event.evob import EventTypes
from oio.event.filters.account_update import AccountUpdateFilter
from oio.event.filters.base import Filter
from oio.event.filters.content_cleaner import ContentReaperFilter


class MockApp:
    """Mock application for testing filters."""

    app_env = {
        "statsd_client": get_statsd(),
        "watchdog": None,
        "account_client": MagicMock(),
        "bucket_client": MagicMock(),
    }

    def __init__(self):
        self.called = False
        self.last_env = None
        self.last_cb = None

    def __call__(self, env, cb):
        self.called = True
        self.last_env = env
        self.last_cb = cb
        return None


class TestFilterSafeProcess(unittest.TestCase):
    """Tests for the Filter.__safe_process method.

    The __safe_process method should catch retryable exceptions
    (ServiceBusy, OioNetworkException, OioTimeout, DeadlineReached)
    and convert them into RetryableEventError responses with status 503.
    """

    def setUp(self):
        self.app = MockApp()
        self.conf = {"ctx_name": "test_filter"}
        self.filter = Filter(app=self.app, conf=self.conf)

    def _create_event(self, event_type=EventTypes.CONTENT_NEW):
        """Create a basic event for testing."""
        return {
            "event": event_type,
            "when": 1234567890,
            "request_id": "test-req-id",
            "url": {
                "account": "test_account",
                "user": "test_container",
                "id": "test_cid",
                "content": "test_content_id",
                "path": "test/path",
                "version": "1234567890123456",
            },
            "data": {},
        }

    def _create_mock_callback(self):
        """Create a mock callback that tracks calls."""
        cb = MagicMock()
        cb.update_handlers = MagicMock()
        return cb

    def test_safe_process_catches_service_busy(self):
        """
        Test that ServiceBusy exception is caught and
        converted to RetryableEventError.
        """
        env = self._create_event()
        cb = self._create_mock_callback()

        # Mock process to raise ServiceBusy
        with patch.object(
            self.filter, "process", side_effect=ServiceBusy(message="Service is busy")
        ):
            # Call the filter (which internally calls __safe_process)
            self.filter(env, cb)

        # Verify the callback was called with status 503 (retryable error)
        cb.assert_called_once()
        call_args = cb.call_args
        self.assertEqual(call_args[0][0], 503)  # status code
        self.assertIn("Retryable error", call_args[0][1])  # message
        self.assertIn("Service is busy", call_args[0][1])

    def test_safe_process_catches_oio_network_exception(self):
        """
        Test that OioNetworkException is caught and
        converted to RetryableEventError.
        """
        env = self._create_event()
        cb = self._create_mock_callback()

        # Mock process to raise OioNetworkException
        with patch.object(
            self.filter,
            "process",
            side_effect=OioNetworkException("Network error"),
        ):
            self.filter(env, cb)

        # Verify the callback was called with status 503
        cb.assert_called_once()
        call_args = cb.call_args
        self.assertEqual(call_args[0][0], 503)
        self.assertIn("Retryable error", call_args[0][1])
        self.assertIn("Network error", call_args[0][1])

    def test_safe_process_catches_oio_timeout(self):
        """
        Test that OioTimeout exception is caught and
        converted to RetryableEventError.
        """
        env = self._create_event()
        cb = self._create_mock_callback()

        # Mock process to raise OioTimeout
        with patch.object(
            self.filter,
            "process",
            side_effect=OioTimeout("Oio timed out"),
        ):
            self.filter(env, cb)

        # Verify the callback was called with status 503
        cb.assert_called_once()
        call_args = cb.call_args
        self.assertEqual(call_args[0][0], 503)
        self.assertIn("Retryable error", call_args[0][1])
        self.assertIn("Oio timed out", call_args[0][1])

    def test_safe_process_catches_deadline_reached(self):
        """
        Test that DeadlineReached exception is caught and
        converted to RetryableEventError.
        """
        env = self._create_event()
        cb = self._create_mock_callback()

        # Mock process to raise DeadlineReached
        with patch.object(
            self.filter,
            "process",
            side_effect=DeadlineReached("Deadline exceeded"),
        ):
            self.filter(env, cb)

        # Verify the callback was called with status 503
        cb.assert_called_once()
        call_args = cb.call_args
        self.assertEqual(call_args[0][0], 503)
        self.assertIn("Retryable error", call_args[0][1])
        self.assertIn("Deadline exceeded", call_args[0][1])

    def test_safe_process_includes_retry_delay(self):
        """
        Test that RetryableEventError includes the configured retry delay.
        """
        # Set a specific retry delay
        self.filter._retry_delay = 5.0

        env = self._create_event()
        cb = self._create_mock_callback()

        with patch.object(
            self.filter, "process", side_effect=ServiceBusy(message="Service is busy")
        ):
            self.filter(env, cb)

        # Verify the delay is passed to the callback
        cb.assert_called_once()
        call_kwargs = cb.call_args[1]
        self.assertEqual(call_kwargs.get("delay"), 5.0)

    def test_safe_process_passes_through_on_success(self):
        """
        Test that normal processing passes through without modification.
        """
        env = self._create_event()
        cb = self._create_mock_callback()

        # The default process just calls app(env, cb), which returns None
        self.filter(env, cb)

        # Verify the app was called (normal flow)
        self.assertTrue(self.app.called)
        self.assertEqual(self.app.last_env, env)

    def test_safe_process_does_not_catch_other_exceptions(self):
        """
        Test that non-retryable exceptions are not caught by __safe_process.
        """
        env = self._create_event()
        cb = self._create_mock_callback()

        # Mock process to raise a generic exception
        with patch.object(
            self.filter, "process", side_effect=ValueError("Generic error")
        ):
            # This should raise the exception, not catch it
            with self.assertRaises(ValueError) as context:
                self.filter(env, cb)
            self.assertIn("Generic error", str(context.exception))

    def test_safe_process_preserves_exception_message(self):
        """
        Test that the original exception message is
        preserved in the retryable error.
        """
        env = self._create_event()
        cb = self._create_mock_callback()

        error_message = "Service is busy"
        with patch.object(
            self.filter, "process", side_effect=ServiceBusy(message=error_message)
        ):
            self.filter(env, cb)

        # Verify the original message is included
        cb.assert_called_once()
        call_args = cb.call_args
        self.assertIn(error_message, call_args[0][1])


class TestFilterSafeProcessWithDifferentEvents(unittest.TestCase):
    """Tests for __safe_process with different event types."""

    def _create_mock_callback(self):
        cb = MagicMock()
        cb.update_handlers = MagicMock()
        return cb

    def test_safe_process_with_content_deleted_event(self):
        """Test retryable error handling with CONTENT_DELETED event."""
        app = MockApp()
        conf = {"ctx_name": "content_reaper_filter"}

        # Mock BlobClient to avoid real initialization
        with patch("oio.event.filters.content_cleaner.BlobClient") as mock_blob_client:
            mock_blob_client.return_value = MagicMock()
            filter_instance = ContentReaperFilter(app=app, conf=conf)

            env = {
                "event": EventTypes.CONTENT_DELETED,
                "when": 1234567890,
                "request_id": "test-req-id",
                "url": {"account": "test_account", "user": "test_container"},
                "data": {},
            }
            cb = self._create_mock_callback()

            with patch.object(
                filter_instance,
                "process",
                side_effect=OioTimeout("Timeout during delete"),
            ):
                filter_instance(env, cb)

            cb.assert_called_once()
            self.assertEqual(cb.call_args[0][0], 503)
            self.assertIn("Retryable error", cb.call_args[0][1])

    def test_safe_process_with_container_new_event(self):
        """Test retryable error handling with CONTAINER_NEW event."""
        app = MockApp()
        # AccountUpdateFilter requires region in namespace conf
        app.app_env["account_client"].region = "test-region"
        conf = {"ctx_name": "account_update_filter"}
        filter_instance = AccountUpdateFilter(app=app, conf=conf)

        env = {
            "event": EventTypes.CONTAINER_NEW,
            "when": 1234567890,
            "request_id": "test-req-id",
            "url": {"account": "test_account", "user": "new_container"},
            "data": {},
        }
        cb = self._create_mock_callback()

        with patch.object(
            filter_instance,
            "process",
            side_effect=DeadlineReached("Deadline during create"),
        ):
            filter_instance(env, cb)

        cb.assert_called_once()
        self.assertEqual(cb.call_args[0][0], 503)
        self.assertIn("Retryable error", cb.call_args[0][1])
