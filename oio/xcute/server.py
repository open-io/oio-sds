# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
#
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

from functools import wraps
from werkzeug.exceptions import HTTPException, \
    BadRequest as HTTPBadRequest, Forbidden as HTTPForbidden, \
    NotFound as HTTPNotFound, InternalServerError as HTTPInternalServerError
from werkzeug.routing import Map, Rule, Submount
from werkzeug.wrappers import Response

from oio.common.easy_value import int_value
from oio.common.exceptions import Forbidden, NotFound
from oio.common.green import time
from oio.common.json import json
from oio.common.logger import get_logger
from oio.common.wsgi import WerkzeugApp
from oio.xcute.common.backend import XcuteBackend
from oio.xcute.jobs import JOB_TYPES


def access_log(func):
    @wraps(func)
    def access_log_wrapper(self, req, *args, **kwargs):
        code = -1
        pre = time.time()
        try:
            rc = func(self, req, *args, **kwargs)
            code = rc._status_code
            return rc
        except HTTPException as exc:
            code = exc.code
            raise
        finally:
            post = time.time()
            # remote method code time size user reqid uri
            self.logger.info(
                '%s %s %d %d %s %s %s %s',
                req.environ['HTTP_HOST'], req.environ['REQUEST_METHOD'],
                code, int((post - pre) * 1000000), '-', '-', '-',
                req.environ['RAW_URI'])
    return access_log_wrapper


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
            self.logger.exception('Internal error: %s', exc)
            raise HTTPInternalServerError(str(exc))
    return handle_exceptions_wrapper


class XcuteServer(WerkzeugApp):
    def __init__(self, conf, logger=None):
        self.conf = conf
        self.logger = logger or get_logger(self.conf)
        self.backend = XcuteBackend(self.conf, logger=self.logger)

        url_map = Map([
            Rule('/status', endpoint='status'),
            Submount('/v1.0/xcute', [
                Rule('/job/list', endpoint='job_list',
                     methods=['GET']),
                Rule('/job/create', endpoint='job_create',
                     methods=['POST']),
                Rule('/job/show', endpoint='job_show',
                     methods=['GET']),
                Rule('/job/pause', endpoint='job_pause',
                     methods=['POST']),
                Rule('/job/resume', endpoint='job_resume',
                     methods=['POST']),
                Rule('/job/delete', endpoint='job_delete',
                     methods=['DELETE']),
                Rule('/lock/list', endpoint='lock_list',
                     methods=['GET']),
                Rule('/lock/show', endpoint='lock_show',
                     methods=['GET']),
            ])
        ])

        super(XcuteServer, self).__init__(url_map, logger)

    @handle_exceptions
    def on_status(self, req):
        status = self.backend.status()
        return Response(json.dumps(status), mimetype='application/json')

    @access_log
    @handle_exceptions
    def on_job_list(self, req):
        limit = int_value(req.args.get('limit'), None)
        marker = req.args.get('marker')

        job_infos = self.backend.list_jobs(limit=limit, marker=marker)
        return Response(
            json.dumps(job_infos), mimetype='application/json')

    @access_log
    @handle_exceptions
    def on_job_create(self, req):
        job_type = req.args.get('type')
        if not job_type:
            raise HTTPBadRequest('Missing job type')
        job_class = JOB_TYPES.get(job_type)
        if job_class is None:
            raise HTTPBadRequest('Unknown job type')

        job_config, lock = job_class.sanitize_config(
            json.loads(req.data or '{}'))

        job_id = self.backend.create(job_type, job_config, lock)
        job_info = self.backend.get_job_info(job_id)
        return Response(
            json.dumps(job_info), mimetype='application/json', status=202)

    def _get_job_id(self, req):
        """Fetch job ID from request query string."""
        job_id = req.args.get('id')
        if not job_id:
            raise HTTPBadRequest('Missing job ID')
        return job_id

    @access_log
    @handle_exceptions
    def on_job_show(self, req):
        job_id = self._get_job_id(req)
        job_info = self.backend.get_job_info(job_id)
        return Response(json.dumps(job_info), mimetype='application/json')

    @access_log
    @handle_exceptions
    def on_job_pause(self, req):
        job_id = self._get_job_id(req)
        self.backend.request_pause(job_id)
        job_info = self.backend.get_job_info(job_id)
        return Response(
            json.dumps(job_info), mimetype='application/json', status=202)

    @access_log
    @handle_exceptions
    def on_job_resume(self, req):
        job_id = self._get_job_id(req)
        self.backend.resume(job_id)
        job_info = self.backend.get_job_info(job_id)
        return Response(
            json.dumps(job_info), mimetype='application/json', status=202)

    @access_log
    @handle_exceptions
    def on_job_delete(self, req):
        job_id = self._get_job_id(req)
        self.backend.delete(job_id)
        return Response(status=204)

    @access_log
    @handle_exceptions
    def on_lock_list(self, req):
        locks = self.backend.list_locks()
        return Response(json.dumps(locks), mimetype='application/json')

    @access_log
    @handle_exceptions
    def on_lock_show(self, req):
        lock = req.args.get('lock')
        if not lock:
            raise HTTPBadRequest('Missing lock')
        lock_info = self.backend.get_lock_info(lock)
        return Response(json.dumps(lock_info), mimetype='application/json')


def create_app(conf):
    logger = get_logger(conf)
    app = XcuteServer(conf, logger)

    return app
