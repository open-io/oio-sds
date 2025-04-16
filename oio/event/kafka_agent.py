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

from oio.account.bucket_client import BucketClient
from oio.account.client import AccountClient
from oio.api.object_storage import ObjectStorageApi
from oio.common.easy_value import float_value
from oio.common.green import get_watchdog
from oio.common.logger import OioAccessLog, get_oio_log_context
from oio.common.statsd import StatsdTiming, get_statsd
from oio.conscience.client import ConscienceClient
from oio.event.evob import (
    EventTypes,
    is_outdated,
    is_retryable,
    is_success,
)
from oio.event.filters.base import Filter
from oio.event.kafka_consumer import (
    KafkaConsumerWorker,
    OutdatedMessage,
    RejectMessage,
    RetryLater,
)
from oio.event.loader import loadhandlers
from oio.event.utils import extract_log_ctx_from_event
from oio.rdir.client import RdirClient


def pipeline_use_internal_event(handler):
    while True:
        if not isinstance(handler, Filter):
            break
        if handler.handle_end_batch_events:
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
            logger=self.logger,
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

        self.statsd = get_statsd(conf=app_conf)

        if "handlers_conf" not in self.conf:
            raise ValueError("'handlers_conf' path not defined in conf")
        self.handlers = loadhandlers(
            self.conf.get("handlers_conf"), global_conf=self.conf, app=self
        )
        handlers_with_internal = {
            k: v for k, v in self.handlers.items() if pipeline_use_internal_event(v)
        }
        self.handlers_with_internal = list(handlers_with_internal.values())

        if (
            self.handlers_with_internal
            and not self._events_queue.produce_internal_events
        ):
            raise ValueError(
                f"Event queue '{self._events_queue.__class__.__name__}' does not "
                " support internal events. "
                f"Required for handlers: {','.join(handlers_with_internal)}"
            )

    def process_message(self, message, _properties):
        if not isinstance(message, dict):
            raise RejectMessage("Malformed")

        reqid = message.get("request_id")
        event = message.get("event")
        event_type = str(event).replace(".", "-")
        with get_oio_log_context(
            worker_id=self.name,
            **extract_log_ctx_from_event(message),
            pipeline="",
        ):
            with OioAccessLog(self.logger) as access_log:
                with StatsdTiming(
                    self.statsd,
                    f"openio.event.{self.topic}.{event_type}.{{code}}.duration",
                ) as stats_timing:

                    def _cb(status, msg, **kwargs):
                        stats_timing.code = access_log.status = status
                        if is_success(status):
                            return
                        if is_retryable(status):
                            self.logger.warn(
                                "event handling failure (release with delay): %s",
                                msg,
                            )
                            raise RetryLater(delay=kwargs.get("delay"))
                        if is_outdated(status):
                            raise OutdatedMessage("Message requeued for too long")
                        self.logger.debug(
                            "event handling failure (rejecting): %s ", msg
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
                            stats_timing.code = access_log.status = 404
                            raise RejectMessage(f"No handler for {event}")
                        handlers = [handler]
                    for handler in handlers:
                        handler(message, _cb)
                    return None
