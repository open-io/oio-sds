# Copyright (C) 2025 OVH SAS
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
from dataclasses import dataclass


@dataclass(init=True)
class MsgContext:
    request_id: str = None
    event_type: str = None
    content: str = None
    cid: str = None
    container: str = None
    account: str = None
    bucket: str = None
    path: str = None
    version: str = None

    def items(self):
        return self.__dict__.items()


def log_context_from_msg(message, context_class=MsgContext):
    ctx = context_class()
    ctx.request_id = message.get("request_id")
    ctx.event_type = message.get("event")
    url = message.get("url", {})
    shard = url.get("shard", {})
    data = message.get("data", {})
    match_ctx_name = {
        "user": "container",
        "id": "cid",
        "root_cid": "cid",
        "object": "path",
    }
    for key in (
        "path",
        "object",
        "content",
        "version",
        "user",
        "account",
        "bucket",
        "id",
        "root_cid",
    ):
        if key in url or key in shard or key in data:
            value = shard.get(key) or url.get(key) or data.get(key)
            if key in match_ctx_name:
                key = match_ctx_name[key]
            setattr(ctx, key, value)
    return ctx
