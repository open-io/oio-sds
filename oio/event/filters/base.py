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
from dataclasses import dataclass
from logging import makeLogRecord

from oio.common.exceptions import OioException
from oio.common.logger import LTSVFormatter, get_logger


@dataclass(init=True)
class FilterContext:
    request_id: str = None
    event_type: str = None
    user: str = None
    container: str = None
    bucket: str = None
    path: str = None
    version: str = None

    def items(self):
        return self.__dict__.items()


ctx_filter = ContextVar("filter", default=FilterContext())


class FilterLTSVFormater(LTSVFormatter):
    def get_extras(self):
        ctx = ctx_filter.get()
        return ctx.items()


class Filter(object):
    DEFAULT_LOG_FORMAT = "\t".join(
        (
            "pid:%(pid)d",
            "log_level:%(levelname)s",
            "event_type:%(event_type)s",
            "request_id:%(request_id)s",
            "container:%(container)s",
            "object:%(path)s",
            "version_id:%(version)s",
            "exc_text:%(exc_text)s",
            "exc_filename:%(exc_filename)s",
            "exc_lineno:%(exc_lineno)s",
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
            "message:%(message)s",
        ]
        log_format = "\t".join((p for p in log_format_parts if p))

        formatter = FilterLTSVFormater(fmt=log_format)
        # Ensure log format can be populated
        record = makeLogRecord({})
        formatter.format(record, extras=self.log_context_from_env({}).__dict__)

        self.logger = get_logger(
            conf,
            name=self.__class__.__name__,
            formatter=formatter,
        )

        self.init()

    def init(self):
        pass

    def log_context_from_env(self, env):
        ctx = FilterContext()
        ctx.request_id = env.get("request_id")
        ctx.event_type = env.get("event")
        url = env.get("url")
        if url:
            ctx.path = url.get("path")
            ctx.container = url.get("user")
            ctx.account = url.get("account")
            ctx.version = url.get("version")
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
