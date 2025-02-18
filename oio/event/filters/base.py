# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2022-2025 OVH SAS
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

from oio.common.exceptions import OioException
from oio.common.logger import LTSVFormatter, get_logger
from oio.event.utils import MsgContext, log_context_from_msg


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

    def __init__(self, app, conf, logger=None):
        self.app = app
        self.app_env = app.app_env
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

        self.init()

    def init(self):
        pass

    def log_context_from_env(self, env, context_class=FilterContext):
        ctx = log_context_from_msg(env, context_class)
        ctx.filter_name = self.__class__.__name__
        return ctx

    def process(self, env, cb):
        return self.app(env, cb)

    def __process(self, env, cb):
        context = self.log_context_from_env(env)
        ctx_filter.set(context)
        return self.process(env, cb)

    def __call__(self, env, cb):
        res = self.__process(env, cb)
        if res is not None:
            raise OioException(
                f"Unexpected return value when filter {self.__class__.__name__} "
                f"processed an event: {res}"
            )
