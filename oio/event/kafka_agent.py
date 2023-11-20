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

import time

from oio.account.client import AccountClient
from oio.common.easy_value import float_value
from oio.common.green import get_watchdog
from oio.common.json import json
from oio.common.kafka import kafka_options_from_conf
from oio.event.kafka_consumer import KafkaConsumerWorker, RejectMessage, RetryLater
from oio.event.evob import is_success, is_retryable
from oio.event.loader import loadhandlers
from oio.rdir.client import RdirClient
from oio.common.statsd import get_statsd


class KafkaEventWorker(KafkaConsumerWorker):
    def __init__(self, *args, app_conf=None, **kwargs):
        kafka_conf = kafka_options_from_conf(app_conf)
        super().__init__(*args, **kwargs, kafka_conf=kafka_conf)

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
        self.app_env["watchdog"] = get_watchdog(called_from_main_application=True)

        self.statsd = get_statsd(conf=app_conf)

        if "handlers_conf" not in self.conf:
            raise ValueError("'handlers_conf' path not defined in conf")
        self.handlers = loadhandlers(
            self.conf.get("handlers_conf"), global_conf=self.conf, app=self
        )

    def process_message(self, message: bytes, _properties):
        start = time.monotonic()
        decoded = json.loads(message)
        reqid = decoded.get("request_id")
        handler = self.handlers.get(decoded.get("event"), None)
        if not handler:
            self.statsd.timing(
                f"event.{self.topic_name}.rejected",
                int((time.monotonic() - start) * 1000),
            )
            raise RejectMessage

        event = decoded.get("event").replace(".", "-")

        def cb(status, msg):
            if is_success(status):
                self.statsd.timing(
                    f"event.{self.topic_name}.{event}.ok",
                    int((time.monotonic() - start) * 1000),
                )
            elif is_retryable(status):
                self.logger.warn(
                    "event handling failure (release with delay): (%s) %s reqid=%s",
                    status,
                    msg,
                    reqid,
                )
                self.statsd.timing(
                    f"event.{self.topic_name}.{event}.retry",
                    int((time.monotonic() - start) * 1000),
                )
                raise RetryLater
            else:
                self.logger.error(
                    "event handling failure (rejecting): %s reqid=%s", msg, reqid
                )
                self.statsd.timing(
                    f"event.{self.topic_name}.{event}.rejected",
                    int((time.monotonic() - start) * 1000),
                )
                raise RejectMessage

        handler(decoded, cb)
