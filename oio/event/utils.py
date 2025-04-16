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


def extract_log_ctx_from_event(event):
    url = event.get("url", {})
    shard = url.get("shard", {})
    data = event.get("data", {})
    match_ctx_name = {
        "user": "container",
        "id": "cid",
        "object": "path",
        "main_account": "account",
    }
    ctx = {
        "request_id": event.get("request_id"),
        "event_type": event.get("event"),
    }
    for key in (
        "path",
        "object",
        "content",
        "version",
        "user",
        "account",
        "main_account",
        "bucket",
        "id",
        "cid",
        "root_cid",
        "action",
        "rule_id",
        "run_id",
    ):
        if key in url or key in shard or key in data:
            value = shard.get(key) or url.get(key) or data.get(key)
            if key in match_ctx_name:
                key = match_ctx_name[key]
            ctx[key] = value
    return ctx
