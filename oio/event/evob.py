# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2025 OVH SAS
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

from functools import partial


def is_success(status):
    return 200 <= status <= 299


def is_error(status):
    return 500 <= status <= 599


def is_retryable(status):
    return status == 503


def is_outdated(status):
    return status == 410


def is_pausable(event):
    return event.get("_internal", {}).get("allow_pause", False)


def set_pausable_flag(event, pausable):
    internal = event.setdefault("_internal", {})
    internal["allow_pause"] = pausable


def add_pipeline_to_resume(event, pipeline_id):
    internal = event.setdefault("_internal", {})
    pipelines = internal.setdefault("pipelines_to_resume", [])
    pipelines.append(pipeline_id)


def get_pipelines_to_resume(event):
    internal = event.setdefault("_internal", {})
    return internal.pop("pipelines_to_resume", [])


def _event_env_property(field, default=None):
    def getter(self):
        return self.env.get(field, default)

    def setter(self, value):
        self.env[field] = value

    return property(getter, setter)


class Event(object):
    job_id = _event_env_property("job_id")
    event_type = _event_env_property("event")
    data = _event_env_property("data", default={})
    reqid = _event_env_property("request_id")
    svcid = _event_env_property("service_id")
    url = _event_env_property("url", default={})
    when = _event_env_property("when")
    repli = _event_env_property("repli")
    origin = _event_env_property("origin")

    def __init__(self, env):
        self.env = env

    def __repr__(self):
        return f"Event [{self.job_id},{self.reqid}]({self.event_type})"


class ResponseCallBack(object):
    def __init__(self, cb=None, **kwargs):
        self.cb = cb
        self.extra_kwargs = kwargs

    def update_handlers(self, handler):
        """Add handler to list of processed event handlers"""
        if self.extra_kwargs.get("handlers"):
            self.extra_kwargs["handlers"] = ", ".join(
                (self.extra_kwargs["handlers"], handler)
            )
            return
        self.extra_kwargs["handlers"] = handler

    def __call__(self, status, msg, **kwargs):
        for key, value in kwargs.items():
            if key == "handlers":
                self.update_handlers(value)
            self.extra_kwargs[key] = value
        return self.cb(status, msg, **self.extra_kwargs)


class Response(object):
    def __init__(self, body=None, status=200, event=None, **kwargs):
        self.status = status
        self.event = event
        if event:
            self.env = event.env
        else:
            self.env = {}
        self.body = body
        self.delay = None
        if "delay" in kwargs:
            self.delay = kwargs["delay"]

    def __call__(self, env, cb):
        if not self.event:
            self.event = Event(env)
        if not self.body:
            self.body = ""
        cb(self.status, self.body, delay=self.delay)


class EventException(Response, Exception):
    def __init__(self, *args, **kwargs):
        Response.__init__(self, *args, **kwargs)
        Exception.__init__(self, self.status)


class EventTypes(object):
    """Enum class for event type names."""

    ACCOUNT_SERVICES = "account.services"
    CHUNK_DELETED = "storage.chunk.deleted"
    CHUNK_NEW = "storage.chunk.new"
    CONTAINER_DELETED = "storage.container.deleted"
    CONTAINER_NEW = "storage.container.new"
    CONTAINER_STATE = "storage.container.state"
    CONTAINER_UPDATE = "storage.container.update"
    CONTENT_APPEND = "storage.content.append"
    CONTENT_BROKEN = "storage.content.broken"
    CONTENT_DELETED = "storage.content.deleted"
    CONTENT_DRAINED = "storage.content.drained"
    CONTENT_UPDATE = "storage.content.update"
    CONTENT_TRANSITIONED = "storage.content.transitioned"
    CONTENT_NEW = "storage.content.new"
    CONTENT_REBUILT = "storage.content.rebuilt"
    DELAYED = "delayed"
    MANIFEST_DELETED = "storage.manifest.deleted"
    META2_DELETED = "storage.meta2.deleted"
    XCUTE_TASKS = "xcute.tasks"
    LIFECYCLE_CHECKPOINT = "lifecycle.checkpoint"
    LIFECYCLE_ACTION = "storage.lifecycle.action"

    # Internal events
    INTERNAL_BATCH_END = "internal.batch.end"

    ALL_EVENTS = (
        ACCOUNT_SERVICES,
        CHUNK_DELETED,
        CHUNK_NEW,
        CONTAINER_DELETED,
        CONTAINER_NEW,
        CONTAINER_STATE,
        CONTAINER_UPDATE,
        CONTENT_APPEND,
        CONTENT_BROKEN,
        CONTENT_DELETED,
        CONTENT_DRAINED,
        CONTENT_UPDATE,
        CONTENT_NEW,
        CONTENT_REBUILT,
        DELAYED,
        META2_DELETED,
        XCUTE_TASKS,
        LIFECYCLE_CHECKPOINT,
        LIFECYCLE_ACTION,
        INTERNAL_BATCH_END,
    )
    CONTAINER_EVENTS = (
        CONTAINER_DELETED,
        CONTAINER_NEW,
        CONTAINER_STATE,
        CONTAINER_UPDATE,
    )
    CONTENT_EVENTS = (
        CONTENT_APPEND,
        CONTENT_BROKEN,
        CONTENT_DELETED,
        CONTENT_NEW,
        CONTENT_REBUILT,
        CONTENT_UPDATE,
    )

    INTERNAL_EVENTS = (INTERNAL_BATCH_END,)


class StatusMap(object):
    def __getitem__(self, key):
        return partial(EventException, status=key)


status_map = StatusMap()
EventOk = status_map[200]
EventError = status_map[500]
RetryableEventError = status_map[503]
