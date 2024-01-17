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

import time

from oio.account.client import AccountClient
from oio.common.easy_value import float_value
from oio.common.green import get_watchdog
from oio.conscience.client import ConscienceClient
from oio.event.kafka_consumer import KafkaConsumerWorker, RejectMessage, RetryLater
from oio.event.evob import is_success, is_retryable
from oio.event.loader import loadhandlers
from oio.rdir.client import RdirClient
from oio.common.logger import get_logger
from oio.common.statsd import get_statsd


class KafkaEventWorker(KafkaConsumerWorker):
    def __init__(
        self,
        endpoint,
        topic,
        logger,
        events_queue,
        offsets_queue,
        worker_id,
        *args,
        app_conf=None,
        **kwargs,
    ):
        super().__init__(
            endpoint,
            topic,
            logger,
            events_queue,
            offsets_queue,
            worker_id,
            *args,
            app_conf=app_conf,
            **kwargs,
        )

        self.conf = app_conf
        acct_refresh_interval = float_value(
            self.conf.get("acct_refresh_interval"), 3600.0
        )
        rdir_refresh_interval = float_value(
            self.conf.get("rdir_refresh_interval"), 3600.0
        )
        self.app_env = {}
        self.app_env["account_client"] = AccountClient(
            self.conf,
            logger=self.logger,
            refresh_delay=acct_refresh_interval,
            pool_connections=3,  # 1 account, 1 proxy, 1 extra
        )
        rdir_kwargs = {k: v for k, v in self.conf.items() if k.startswith("rdir_")}
        self.app_env["rdir_client"] = RdirClient(
            self.conf,
            logger=self.logger,
            cache_duration=rdir_refresh_interval,
            **rdir_kwargs,
        )
        self.app_env["conscience_client"] = ConscienceClient(
            self.conf,
            logger=self.logger,
        )
        self.app_env["watchdog"] = get_watchdog(called_from_main_application=True)

        template = self.conf.get("log_request_format")
        if template is not None:
            self.logger_request = get_logger(self.conf, name="request", fmt=template)
        else:
            self.logger_request = None

        self.statsd = get_statsd(conf=app_conf)

        if "handlers_conf" not in self.conf:
            raise ValueError("'handlers_conf' path not defined in conf")
        self.handlers = loadhandlers(
            self.conf.get("handlers_conf"), global_conf=self.conf, app=self
        )

    def log_and_statsd(self, start, status, _extra):
        extra = {
            "request_id": "-",
            "tube": "-",
            "topic": "-",
            "event": "-",
            **_extra,
        }

        extra["duration"] = time.monotonic() - start
        extra["status"] = status
        if self.logger_request is not None:
            self.logger_request.info("", extra=extra)
        self.statsd.timing(
            f"openio.event.{extra['topic']}.{extra['event']}.{extra['status']}"
            ".duration",
            extra["duration"] * 1000,
        )

    def process_message(self, message, _properties):
        start = time.monotonic()
        reqid = message.get("request_id")
        event = message.get("event").replace(".", "-")

        replacements = {
            "request_id": reqid,
            "tube": self.topic,
            "topic": self.topic,
            "event": event,
        }

        handler = self.handlers.get(message.get("event"), None)
        if not handler:
            self.log_and_statsd(start, 404, replacements)
            raise RejectMessage

        def cb(status, msg, **kwargs):
            self.log_and_statsd(start, status, replacements)
            if is_success(status):
                return

            if is_retryable(status):
                self.logger.warn(
                    "event handling failure (release with delay): (%s) %s reqid=%s",
                    status,
                    msg,
                    reqid,
                )
                self.statsd.timing(
                    f"event.{self.topic}.{event}.retry",
                    int((time.monotonic() - start) * 1000),
                )

                raise RetryLater(delay=kwargs.get("delay"))
            else:
                self.logger.error(
                    "event handling failure (rejecting): %s reqid=%s", msg, reqid
                )
                raise RejectMessage

        handler(message, cb)
