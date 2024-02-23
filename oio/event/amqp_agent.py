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

from oio.account.client import AccountClient
from oio.common.easy_value import float_value
from oio.common.green import get_watchdog
from oio.common.json import json
from oio.event.amqp_consumer import AmqpConsumerWorker, RejectMessage, RetryLater
from oio.event.evob import is_success, is_retryable
from oio.event.loader import loadhandlers
from oio.rdir.client import RdirClient


class AmqpEventWorker(AmqpConsumerWorker):
    """
    A worker class dedicated to handle OpenIO SDS internal events.
    """

    def __init__(self, *args, app_conf=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.conf = app_conf
        acct_refresh_interval = float_value(
            self.conf.get("acct_refresh_interval"), 3600.0
        )
        rdir_refresh_interval = float_value(
            self.conf.get("rdir_refresh_interval"), 3600.0
        )
        self.app_env = {
            "logger": self.logger,
        }
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

        if "handlers_conf" not in self.conf:
            raise ValueError("'handlers_conf' path not defined in conf")
        self.handlers = loadhandlers(
            self.conf.get("handlers_conf"), global_conf=self.conf, app=self
        )

    def post_connect(self):
        # This queue has probably already been declared by meta2 processes,
        # but it's considered good practice to redeclare it.
        self.declare_queue()

    def process_message(self, message: bytes, properties):
        decoded = json.loads(message)
        reqid = decoded.get("request_id")
        handler = self.handlers.get(decoded.get("event"), None)
        if not handler:
            raise RejectMessage

        # TODO(FVE): provide a way to send new events
        # event["queue_connector"] = beanstalk

        def cb(status, msg):
            if is_success(status):
                # Nothing special to do
                pass
            elif is_retryable(status):
                self.logger.warn(
                    "event handling failure (release with delay): (%s) %s reqid=%s",
                    status,
                    msg,
                    reqid,
                )
                raise RetryLater
            else:
                self.logger.error(
                    "event handling failure (rejecting): %s reqid=%s", msg, reqid
                )
                raise RejectMessage

        handler(decoded, cb)
