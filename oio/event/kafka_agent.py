# Copyright (C) 2023-2025 OVH SAS
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
from dataclasses import asdict

from oio.account.bucket_client import BucketClient
from oio.account.client import AccountClient
from oio.api.object_storage import ObjectStorageApi
from oio.common.easy_value import float_value
from oio.common.green import get_watchdog
from oio.common.logger import get_logger
from oio.common.statsd import get_statsd
from oio.conscience.client import ConscienceClient
from oio.event.evob import EventTypes, ResponseCallBack, is_retryable, is_success
from oio.event.filters.base import Filter
from oio.event.kafka_consumer import KafkaConsumerWorker, RejectMessage, RetryLater
from oio.event.loader import loadhandlers
from oio.event.utils import log_context_from_msg
from oio.rdir.client import RdirClient


def pipeline_use_internal_event(handler):
    while True:
        if not isinstance(handler, Filter):
            break
        if not handler.skip_end_batch_event():
            return True
        handler = handler.app
    return False


class KafkaEventWorker(KafkaConsumerWorker):
    def __init__(
        self,
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
        bucket_refresh_interval = float_value(
            self.conf.get("bucket_refresh_interval"), 3600.0
        )
        rdir_refresh_interval = float_value(
            self.conf.get("rdir_refresh_interval"), 3600.0
        )
        self.app_env = {
            "logger": self.logger,
        }
        self.app_env["statsd_client"] = get_statsd(app_conf)
        self.app_env["account_client"] = AccountClient(
            self.conf,
            logger=self.logger,
            refresh_delay=acct_refresh_interval,
            pool_connections=3,  # 1 account, 1 proxy, 1 extra
        )
        self.app_env["bucket_client"] = BucketClient(
            self.conf,
            refresh_delay=bucket_refresh_interval,
            pool_manager=self.app_env["account_client"].pool_manager,
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
        self.app_env["api"] = ObjectStorageApi(
            self.conf["namespace"],
            logger=self.logger,
            pool_manager=self.app_env["account_client"].pool_manager,
        )
        self.app_env["watchdog"] = get_watchdog(called_from_main_application=True)

        self.app_env["worker_id"] = self.name
        self.app_env["topic"] = self.topic

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
        self.handlers_with_internal = [
            h for h in self.handlers.values() if pipeline_use_internal_event(h)
        ]

    def log_and_statsd(self, start, status, _extra):
        extra = {
            "worker_id": "-",
            "request_id": "-",
            "tube": "-",
            "topic": "-",
            "event_type": "-",
            "cid": "-",
            "root_cid": "-",
            "container": "-",
            "account": "-",
            "bucket": "-",
            "path": "-",
            "content": "-",
            "version": "-",
            "action": "-",
            "rule_id": "-",
            "run_id": "-",
        }
        extra.update({k: v for k, v in _extra.items() if v is not None})

        extra["duration"] = time.monotonic() - start
        extra["status"] = status
        extra["event_type"] = str(extra["event_type"]).replace(".", "-")
        if self.logger_request is not None:
            self.logger_request.info("", extra=extra)
        self.statsd.timing(
            f"openio.event.{extra['topic']}.{extra['event_type']}.{extra['status']}"
            ".duration",
            extra["duration"] * 1000,
        )

    def process_message(self, message, _properties):
        if not isinstance(message, dict):
            raise RejectMessage("Malformed")

        start = time.monotonic()
        reqid = message.get("request_id")
        event = message.get("event")
        ctx = log_context_from_msg(message)
        replacements = {
            "tube": self.topic,
            "topic": self.topic,
            "handlers": None,
            "worker_id": self.name,
            **asdict(ctx),
        }

        def _cb(status, msg, **kwargs):
            if "handlers" in kwargs:
                replacements["handlers"] = kwargs["handlers"]
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
                raise RejectMessage(
                    f"Failed to process message {msg}: ({reqid}) {status}"
                )

        if event in EventTypes.INTERNAL_EVENTS:
            handlers = self.handlers_with_internal
            if not handlers:
                return None
        else:
            handler = self.handlers.get(event, None)
            if not handler:
                self.log_and_statsd(start, 404, replacements)
                raise RejectMessage(f"No handler for {event}")
            handlers = [handler]

        for handler in handlers:
            resp_cb = ResponseCallBack(_cb, handlers="")
            handler(message, resp_cb)

        return None
