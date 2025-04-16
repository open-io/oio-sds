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
from uuid import uuid4

from oio.common.exceptions import OioException
from oio.common.logger import get_oio_log_context, get_oio_logger
from oio.event.evob import Event, EventTypes, add_pipeline_to_resume, is_pausable

# from oio.common.statsd import StatsdTiming


class PausePipeline(Exception):
    """
    Pause a pipeline
    """

    def __init__(self, next_filter=None):
        self.id = uuid4().hex
        self.next_filter = next_filter


class Filter(object):
    handle_end_batch_events = False

    def __init__(self, app, conf, logger=None):
        self.app = app
        self.app_env = app.app_env
        self.statsd = self.app_env["statsd_client"]
        self.conf = conf
        self.logger = logger or get_oio_logger(conf)

        self._pipelines_on_hold = []
        self._pause_allowed = False

        self.init()

    def init(self):
        pass

    def request_pause(self):
        """
        Pause pipeline if allowed
        """
        if self._pause_allowed:
            raise PausePipeline()
        return

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
        return self.process(env, cb)

    def __attach_pipelines_to_event(self, env):
        if self._pipelines_on_hold:
            for p in self._pipelines_on_hold:
                add_pipeline_to_resume(env, p)
            self._pipelines_on_hold.clear()

    def __call__(self, env, cb):
        name = self.conf.get("ctx_name", self.__class__.__name__)
        with get_oio_log_context(reuse=True) as log_ctx:
            log_ctx.amend(filter=name)
            try:
                res = self.__process(env, cb)
                self.__attach_pipelines_to_event(env)
            except PausePipeline as exc:
                exc.next_filter = lambda e: self.app(e, cb)
                # Register paused pipeline
                self._pipelines_on_hold.append(exc.id)
                raise exc
            except Exception:
                self.__attach_pipelines_to_event(env)
                raise
            finally:
                log_ctx.amend(filter=None)
                pipeline = log_ctx.attributes.get("pipeline", "")
                if pipeline:
                    pipeline = f"{name},{pipeline}"
                else:
                    pipeline = name
                log_ctx.amend(propagate=True, pipeline=pipeline)

            if res is not None:
                raise OioException(
                    f"Unexpected return value when filter {name} processed an event:"
                    f"{res}"
                )
