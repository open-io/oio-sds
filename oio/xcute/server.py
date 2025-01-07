# Copyright (C) 2019-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2024 OVH SAS
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

from functools import wraps

from werkzeug.exceptions import (
    BadRequest as HTTPBadRequest,
)
from werkzeug.exceptions import (
    Forbidden as HTTPForbidden,
)
from werkzeug.exceptions import (
    HTTPException,
)
from werkzeug.exceptions import (
    InternalServerError as HTTPInternalServerError,
)
from werkzeug.exceptions import (
    NotFound as HTTPNotFound,
)
from werkzeug.routing import Map, Rule, Submount
from werkzeug.wrappers import Response

from oio.common.easy_value import boolean_value, int_value
from oio.common.exceptions import Forbidden, NotFound
from oio.common.json import json
from oio.common.logger import get_logger
from oio.common.wsgi import WerkzeugApp
from oio.xcute.common.backend import XcuteBackend
from oio.xcute.jobs import JOB_TYPES


def handle_exceptions(func):
    @wraps(func)
    def handle_exceptions_wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except HTTPException:
            raise
        except NotFound as exc:
            raise HTTPNotFound(exc.message)
        except Forbidden as exc:
            raise HTTPForbidden(exc.message)
        except Exception as exc:
            self.logger.exception("Internal error: %s", exc)
            raise HTTPInternalServerError(str(exc))

    return handle_exceptions_wrapper


class XcuteServer(WerkzeugApp):
    def __init__(self, conf, logger=None):
        self.conf = conf
        self.logger = logger or get_logger(self.conf)
        self.backend = XcuteBackend(self.conf, logger=self.logger)

        url_map = Map(
            [
                Rule("/status", endpoint="status"),
                Submount(
                    "/v1.0/xcute",
                    [
                        Rule("/job/list", endpoint="job_list", methods=["GET"]),
                        Rule("/job/create", endpoint="job_create", methods=["POST"]),
                        Rule("/job/show", endpoint="job_show", methods=["GET"]),
                        Rule("/job/pause", endpoint="job_pause", methods=["POST"]),
                        Rule("/job/resume", endpoint="job_resume", methods=["POST"]),
                        Rule("/job/update", endpoint="job_update", methods=["POST"]),
                        Rule("/job/abort", endpoint="job_abort", methods=["POST"]),
                        Rule("/job/delete", endpoint="job_delete", methods=["DELETE"]),
                        Rule("/lock/list", endpoint="lock_list", methods=["GET"]),
                        Rule("/lock/show", endpoint="lock_show", methods=["GET"]),
                    ],
                ),
            ]
        )

        super(XcuteServer, self).__init__(url_map, logger)

    @handle_exceptions
    def on_status(self, req):
        status = self.backend.status()
        return Response(json.dumps(status), mimetype="application/json")

    @handle_exceptions
    def on_job_list(self, req):
        limit = int_value(req.args.get("limit"), None)
        prefix = req.args.get("prefix")
        marker = req.args.get("marker")
        job_status = req.args.get("status")
        job_type = req.args.get("type")
        job_lock = req.args.get("lock")

        job_infos, next_marker = self.backend.list_jobs(
            limit=limit,
            prefix=prefix,
            marker=marker,
            job_status=job_status,
            job_type=job_type,
            job_lock=job_lock,
        )
        jobs = {}
        jobs["jobs"] = job_infos
        if next_marker is not None:
            jobs["next_marker"] = next_marker
            jobs["truncated"] = True
        else:
            jobs["truncated"] = False
        return Response(json.dumps(jobs), mimetype="application/json")

    @handle_exceptions
    def on_job_create(self, req):
        job_type = req.args.get("type")
        if not job_type:
            raise HTTPBadRequest("Missing job type")
        job_class = JOB_TYPES.get(job_type)
        if job_class is None:
            raise HTTPBadRequest("Unknown job type")
        put_on_hold_if_locked = boolean_value(req.args.get("put_on_hold_if_locked"))

        job_config, lock = job_class.sanitize_config(json.loads(req.data or "{}"))

        job_id = self.backend.create(
            job_type, job_config, lock, put_on_hold_if_locked=put_on_hold_if_locked
        )
        job_info = self.backend.get_job_info(job_id)
        return Response(json.dumps(job_info), mimetype="application/json", status=202)

    def _get_job_id(self, req):
        """Fetch job ID from request query string."""
        job_id = req.args.get("id")
        if not job_id:
            raise HTTPBadRequest("Missing job ID")
        return job_id

    @handle_exceptions
    def on_job_show(self, req):
        job_id = self._get_job_id(req)
        job_info = self.backend.get_job_info(job_id)
        return Response(json.dumps(job_info), mimetype="application/json")

    @handle_exceptions
    def on_job_pause(self, req):
        job_id = self._get_job_id(req)
        self.backend.request_pause(job_id)
        job_info = self.backend.get_job_info(job_id)
        return Response(json.dumps(job_info), mimetype="application/json", status=202)

    @handle_exceptions
    def on_job_resume(self, req):
        job_id = self._get_job_id(req)
        self.backend.resume(job_id)
        job_info = self.backend.get_job_info(job_id)
        return Response(json.dumps(job_info), mimetype="application/json", status=202)

    @handle_exceptions
    def on_job_update(self, req):
        job_id = self._get_job_id(req)

        job_info = self.backend.get_job_info(job_id)
        job_type = job_info["job"]["type"]
        job_class = JOB_TYPES.get(job_type)
        if job_class is None:
            raise HTTPBadRequest("Unknown job type")

        job_config, lock = job_class.sanitize_config(
            job_class.merge_config(job_info["config"], json.loads(req.data or "{}"))
        )
        if lock != job_info["job"].get("lock"):
            raise ValueError("New configuration can not change the lock")

        self.backend.update_config(job_id, job_config)
        return Response(json.dumps(job_config), mimetype="application/json", status=202)

    @handle_exceptions
    def on_job_abort(self, req):
        job_id = self._get_job_id(req)
        self.backend.fail(job_id)
        job_info = self.backend.get_job_info(job_id)
        return Response(json.dumps(job_info), mimetype="application/json", status=202)

    @handle_exceptions
    def on_job_delete(self, req):
        job_id = self._get_job_id(req)
        self.backend.delete(job_id)
        return Response(status=204)

    @handle_exceptions
    def on_lock_list(self, req):
        locks = self.backend.list_locks()
        return Response(json.dumps(locks), mimetype="application/json")

    @handle_exceptions
    def on_lock_show(self, req):
        lock = req.args.get("lock")
        if not lock:
            raise HTTPBadRequest("Missing lock")
        lock_info = self.backend.get_lock_info(lock)
        return Response(json.dumps(lock_info), mimetype="application/json")


def create_app(conf):
    logger = get_logger(conf)
    app = XcuteServer(conf, logger)

    return app
