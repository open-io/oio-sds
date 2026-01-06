# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2022-2026 OVH SAS
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
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from uuid import uuid4

from oio.common.exceptions import (
    DeadlineReached,
    OioException,
    OioNetworkException,
    OioTimeout,
    ServiceBusy,
)
from oio.common.kafka import get_retry_delay
from oio.common.logger import LTSVFormatter, get_logger
from oio.event.evob import (
    Event,
    EventTypes,
    RetryableEventError,
    add_pipeline_to_resume,
    is_pausable,
)
from oio.event.utils import MsgContext, log_context_from_msg

# from oio.common.statsd import StatsdTiming


class PausePipeline(Exception):
    """
    Pause a pipeline
    """

    def __init__(self, next_filter=None):
        self.id = uuid4().hex
        self.next_filter = next_filter


@dataclass(init=True)
class FilterContext(MsgContext):
    filter_name: str = None


ctx_filter = ContextVar("filter", default=FilterContext())


class FilterLTSVFormater(LTSVFormatter):
    def get_extras(self):
        ctx = ctx_filter.get()
        return asdict(ctx)


class Filter(object):
    DEFAULT_LOG_FORMAT = "\t".join(
        (
            "pid:%(process)d",
            "log_level:%(levelname)s",
            "filter:%(filter_name)s",
            "event_type:%(event_type)s",
            "request_id:%(request_id)s",
            "account:%(account)s",
            "container:%(container)s",
            "cid:%(cid)s",
            "bucket:%(bucket)s",
            "object:%(path)s",
            "content_id:%(content)s",
            "version_id:%(version)s",
            "exc_text:%(exc_text)s",
            "exc_filename:%(exc_filename)s",
            "exc_lineno:%(exc_lineno)s",
            "message:%(message)s",
        )
    )

    DEFAULT_EXTRA_LOG_FORMAT = ""
    handle_end_batch_events = False

    def __init__(self, app, conf, logger=None):
        self.app = app
        self.app_env = app.app_env
        self.statsd = self.app_env["statsd_client"]
        self.conf = conf
        log_format_parts = [
            self.conf.get("log_format", self.DEFAULT_LOG_FORMAT),
            self.conf.get("log_format_extra", self.DEFAULT_EXTRA_LOG_FORMAT),
        ]
        log_format = "\t".join((p for p in log_format_parts if p))
        # XXX: we could check that the log format does not contain unknown fields,
        # however since the configuration is shared by several classes there will
        # be unknown fields most of the time. It has been chosen to set them to "-"
        # by default in the LTSVFormatter class.
        formatter = FilterLTSVFormater(fmt=log_format)
        self.logger = get_logger(
            conf,
            name=self.__class__.__name__,
            formatter=formatter,
        )

        self._pipelines_on_hold = []
        self._pause_allowed = False
        self._retry_delay = get_retry_delay(self.conf)

        self.init()

    def init(self):
        pass

    def log_context_from_env(self, env, context_class=FilterContext):
        ctx = log_context_from_msg(env, context_class)
        ctx.filter_name = self.conf.get("ctx_name")
        return ctx

    def request_pause(self):
        """
        Pause pipeline if allowed
        """
        if self._pause_allowed:
            raise PausePipeline()
        return

    def __safe_process(self, env, cb):
        """Call process with error handling"""
        try:
            return self.process(env, cb)
        except (ServiceBusy, OioNetworkException, OioTimeout, DeadlineReached) as exc:
            event = Event(env)
            resp = RetryableEventError(
                event=event,
                body=f"Retryable error: {exc}",
                delay=self._retry_delay,
            )
            return resp(env, cb)

    def process(self, env, cb):
        return self.app(env, cb)

    def __process(self, env, cb):
        self._pause_allowed = self.handle_end_batch_events and is_pausable(env)
        evt = Event(env)
        if (
            evt.event_type == EventTypes.INTERNAL_BATCH_END
            and not self.handle_end_batch_events
        ):
            return self.app(env, cb)
        context = self.log_context_from_env(env)
        ctx_filter.set(context)
        cb.update_handlers(context.filter_name)
        return self.__safe_process(env, cb)

    def __attach_pipelines_to_event(self, env):
        if self._pipelines_on_hold:
            for p in self._pipelines_on_hold:
                add_pipeline_to_resume(env, p)
            self._pipelines_on_hold.clear()

    def __call__(self, env, cb):
        name = self.conf.get("ctx_name", self.__class__.__name__)
        # evt = Event(env)
        # name = name.replace(".", "-")
        # event_type = evt.event_type.replace(".", "-")
        # topic = self.app_env["topic"]
        # with StatsdTiming(
        #     self.statsd,
        #     f"openio.event.{topic}.filter.{event_type}.{name}.{{code}}.duration",
        # ) as st:
        try:
            res = self.__process(env, cb)
            self.__attach_pipelines_to_event(env)
        except PausePipeline as exc:
            # st.code = 307
            exc.next_filter = lambda e: self.app(e, cb)
            # Register paused pipeline
            self._pipelines_on_hold.append(exc.id)
            raise exc
        except Exception:
            # st.code = 500
            self.__attach_pipelines_to_event(env)
            raise

        if res is not None:
            raise OioException(
                f"Unexpected return value when filter {name} processed an event: {res}"
            )
