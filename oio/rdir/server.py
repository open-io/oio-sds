# Copyright (C) 2015 OpenIO, original work as part of
# OpenIO Software Defined Storage
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

import time

from functools import wraps

from werkzeug.wrappers import Request, Response
from werkzeug.routing import Map, Rule
from werkzeug.exceptions import HTTPException, NotFound, BadRequest, \
    InternalServerError

from oio.rdir.server_db import RdirBackend, NoSuchDb
from oio.common.utils import json, get_logger


def handle_no_such_db(func):
    @wraps(func)
    def _wrapped(self, req, *args, **kwargs):
        try:
            return func(req, *args, **kwargs)
        except NoSuchDb:
            vol = req.args.get('vol')
            raise NotFound("No such volume: %s" % vol)

    return _wrapped


class Rdir(object):
    def __init__(self, conf, backend, logger=None):
        self.conf = conf
        self.logger = logger or get_logger(conf)
        self.backend = backend
        self.ns = conf['namespace']
        self.url_map = Map([
            Rule('/status', endpoint='status'),
            Rule('/v1/rdir/admin/show', endpoint='rdir_admin_show'),
            Rule('/v1/rdir/admin/unlock', endpoint='rdir_admin_unlock'),
            Rule('/v1/rdir/admin/lock', endpoint='rdir_admin_lock'),
            Rule('/v1/rdir/create', endpoint='rdir_create'),
            Rule('/v1/rdir/push', endpoint='rdir_push'),
            Rule('/v1/rdir/delete', endpoint='rdir_delete'),
            Rule('/v1/rdir/fetch', endpoint='rdir_fetch'),
            Rule('/v1/rdir/status', endpoint='rdir_status'),
            Rule('/v1/rdir/admin/clear', endpoint='rdir_admin_clear'),
            Rule('/v1/rdir/admin/incident',
                 endpoint='rdir_admin_incident'),
        ])
        self.adapter = None

    def _get_volume(self, req):
        volume = req.args.get('vol')
        if not volume:
            raise BadRequest('Missing volume id')
        return volume

    def on_status(self, req):
        status = self.backend.status()
        return Response(json.dumps(status), mimetype='application/json')

    def on_rdir_admin_show(self, req):
        volume = self._get_volume(req)
        data = self.backend.admin_show(volume)
        return Response(json.dumps(data), mimetype='application/json')

    def on_rdir_admin_unlock(self, req):
        volume = self._get_volume(req)
        self.backend.admin_unlock(volume)
        return Response(status=204)

    def on_rdir_admin_lock(self, req):
        volume = self._get_volume(req)
        decoded = json.loads(req.get_data())
        who = decoded.get('who')
        if who is None:
            return BadRequest('Missing token who')

        desc = self.backend.admin_lock(volume, who)

        if desc is not None:
            message = "Already locked by %s" % desc
            return Response(message, 403)

        return Response(status=204)

    def on_rdir_create(self, req):
        volume = self._get_volume(req)
        self.backend.create(volume)
        return Response(status=201)

    def _check_push(self, meta):
        data = {}
        missing_keys = []
        time_limit = int(time.time()) + 10  # Allow 10s of clock drift

        def add_keys(keys, transform_func=None, required=True):
            for k in keys:
                if k in meta:
                    if transform_func:
                        data[k] = transform_func(meta[k])
                    else:
                        data[k] = meta[k]
                else:
                    if required:
                        missing_keys.append(k)

        def convert_and_check_time(source):
            converted = int(source)
            if converted > time_limit:
                raise BadRequest("Modification or rebuild time" +
                                 " seems to be in the future: %s" %
                                 source)
            return converted

        add_keys(['container_id', 'content_id', 'chunk_id'])
        add_keys(['mtime', 'rtime'], convert_and_check_time, False)
        if missing_keys:
            raise BadRequest('Missing %s' % missing_keys)
        return data

    def on_rdir_push(self, req):
        volume = self._get_volume(req)
        decoded = json.loads(req.get_data())
        data = self._check_push(decoded)

        try:
            self.backend.chunk_push(volume, **data)
        except NoSuchDb:
            if req.args.get('create'):
                self.backend.create(volume)
                self.backend.chunk_push(volume, **data)
            else:
                return NotFound('No such volume')
        return Response(status=204)

    def on_rdir_delete(self, req):
        volume = self._get_volume(req)
        decoded = json.loads(req.get_data())
        chunk_id = decoded.get('chunk_id')
        if chunk_id is None:
            return BadRequest('Missing token chunk_id')
        container_id = decoded.get('container_id')
        if container_id is None:
            return BadRequest('Missing token container_id')
        content_id = decoded.get('content_id')
        if content_id is None:
            return BadRequest('Missing token content_id')
        self.backend.chunk_delete(volume, container_id, content_id, chunk_id)
        return Response(status=204)

    def on_rdir_fetch(self, req):
        volume = self._get_volume(req)
        pretty = req.args.get('pretty')

        if req.method != 'POST':
            raise BadRequest("Expecting POST with JSON object")

        decoded = json.loads(req.get_data())
        start_after = decoded.get('start_after')
        limit = decoded.get('limit')
        if limit is not None and limit <= 0:
            return BadRequest('limit must be greater than 0')
        rebuild = decoded.get('rebuild', False)
        if not isinstance(rebuild, bool):
            return BadRequest('rebuild must be true or false')
        container_id = decoded.get('container_id')  # optional

        data = self.backend.chunk_fetch(volume, start_after=start_after,
                                        limit=limit, rebuild=rebuild,
                                        container_id=container_id)

        if pretty:
            body = json.dumps(data, indent=4)
        else:
            body = json.dumps(data)
        return Response(body, mimetype='application/json')

    def on_rdir_status(self, req):
        volume = self._get_volume(req)
        pretty = req.args.get('pretty')

        data = self.backend.chunk_status(volume)

        if pretty:
            body = json.dumps(data, indent=4)
        else:
            body = json.dumps(data)

        return Response(body, mimetype='application/json')

    def on_rdir_admin_incident(self, req):
        volume = self._get_volume(req)

        if req.method == 'POST':
            decoded = json.loads(req.get_data())
            date = decoded.get('date')
            if date is None or not isinstance(date, int):
                return BadRequest('Missing date or bad format')

            self.backend.admin_set_incident_date(volume, date)

            return Response(status=204)
        else:
            date = self.backend.admin_get_incident_date(volume)
            resp = {}
            if date:
                resp = {'date': date}
            return Response(json.dumps(resp), mimetype='application/json')

    def on_rdir_admin_clear(self, req):
        volume = self._get_volume(req)

        decoded = json.loads(req.get_data())
        clear_all = decoded.get('all', False)
        if not isinstance(clear_all, bool):
            return BadRequest('"all" must be true or false')

        lock = self.backend.admin_lock(volume, 'admin_clear')
        if lock is not None:
            return Response("Already locked by %s" % lock, 403)

        nb = self.backend.admin_clear(volume, clear_all)

        self.backend.admin_unlock(volume)

        resp = {'removed': nb}
        return Response(json.dumps(resp), mimetype='application/json')

    def dispatch_request(self, req):
        if not self.adapter:
            self.adapter = self.url_map.bind_to_environ(req.environ)
        try:
            endpoint, _values = self.adapter.match(req.path, req.method)
        except NotFound as exc:
            return BadRequest('Invalid URL')

        try:
            return getattr(self, 'on_' + endpoint)(req)
        except NoSuchDb as exc:
            return NotFound(exc)
        except HTTPException as exc:
            return exc
        except Exception:
            self.logger.exception('ERROR Unhandled exception in request')
            return InternalServerError()

    def wsgi_app(self, environ, start_response):
        req = Request(environ)
        resp = self.dispatch_request(req)
        return resp(environ, start_response)

    def __call__(self, environ, start_response):
        return self.wsgi_app(environ, start_response)


def create_app(conf, **kwargs):
    backend = RdirBackend(conf)
    app = Rdir(conf, backend)
    # default to sync worker for rdir
    if not conf.get('worker_class'):
        conf['worker_class'] = 'sync'
    # default to 1 worker (concurrency issue with leveldb)
    if not conf.get('workers'):
        conf['workers'] = 1
    return app
