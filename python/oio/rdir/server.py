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

import flask
from flask import request
from flask import current_app
from gunicorn.glogging import Logger

from oio.rdir.server_db import RdirBackend
from oio.common.utils import get_logger, json

rdir_api = flask.Blueprint('rdir_api', __name__)


def get_backend():
    return current_app.backend


@rdir_api.route('/status', methods=['GET'])
def server_status():
    status = get_backend().status()
    return flask.Response(json.dumps(status), mimetype='application/json')


@rdir_api.route('/v1/<ns>/rdir/push', methods=['POST'])
def rdir_push(ns):
    volume = request.args.get('vol')
    if not volume:
        return flask.Response('Missing volume id', 400)
    decoded = flask.request.get_json(force=True)
    chunk_id = decoded.get('chunk_id')
    if chunk_id is None:
        return flask.Response('Missing token chunk_id', 400)
    container_id = decoded.get('container_id')
    if container_id is None:
        return flask.Response('Missing token container_id', 400)
    content_id = decoded.get('content_id')
    if content_id is None:
        return flask.Response('Missing token content_id', 400)
    data = {}
    allowed_tokens_int = ['content_version', 'content_nbchunks',
                          'content_size', 'chunk_size', 'mtime', 'rtime']
    for token in allowed_tokens_int:
        if token in decoded:
            data[token] = int(decoded[token])

    allowed_tokens_str = ['content_path', 'chunk_hash', 'chunk_position']
    for token in allowed_tokens_str:
        if token in decoded:
            data[token] = decoded[token]

    get_backend().chunk_push(volume, container_id, content_id, chunk_id,
                             **data)
    return flask.Response('', 204)


@rdir_api.route('/v1/<ns>/rdir/delete', methods=['DELETE'])
def rdir_delete(ns):
    volume = request.args.get('vol')
    if not volume:
        return flask.Response('Missing volume id', 400)
    decoded = flask.request.get_json(force=True)
    chunk_id = decoded.get('chunk_id')
    if chunk_id is None:
        return flask.Response('Missing token chunk_id', 400)
    container_id = decoded.get('container_id')
    if container_id is None:
        return flask.Response('Missing token container_id', 400)
    content_id = decoded.get('content_id')
    if content_id is None:
        return flask.Response('Missing token content_id', 400)
    get_backend().chunk_delete(volume, container_id, content_id, chunk_id)
    return flask.Response('', 204)


@rdir_api.route('/v1/<ns>/rdir/fetch', methods=['POST'])
def rdir_fetch(ns):
    volume = request.args.get('vol')
    if not volume:
        return flask.Response('Missing volume id', 400)
    pretty = request.args.get('pretty')

    decoded = flask.request.get_json(force=True)
    start_after = decoded.get('start_after')
    limit = decoded.get('limit')
    if limit is not None and limit <= 0:
        return flask.Response('limit must be greate than 0', 400)
    rebuild = decoded.get('rebuild', False)
    if not isinstance(rebuild, bool):
        return flask.Response('limit must be true or false', 400)

    data = get_backend().chunk_fetch(volume, start_after=start_after,
                                     limit=limit, rebuild=rebuild)

    if pretty:
        body = json.dumps(data, indent=4)
    else:
        body = json.dumps(data)

    return flask.Response(body, mimetype='application/json')


@rdir_api.route('/v1/<ns>/rdir/status', methods=['GET'])
def rdir_status(ns):
    volume = request.args.get('vol')
    if not volume:
        return flask.Response('Missing volume id', 400)
    pretty = request.args.get('pretty')

    data = get_backend().chunk_status(volume)

    if pretty:
        body = json.dumps(data, indent=4)
    else:
        body = json.dumps(data)

    return flask.Response(body, mimetype='application/json')


@rdir_api.route('/v1/<ns>/rdir/admin/incident', methods=['POST'])
def rdir_admin_incident_set(ns):
    volume = request.args.get('vol')
    if not volume:
        return flask.Response('Missing volume id', 400)

    decoded = flask.request.get_json(force=True)
    date = decoded.get('date')
    if date is None or not isinstance(date, int):
        return flask.Response('Missing date or bad format', 400)

    get_backend().admin_set_incident_date(volume, date)

    return flask.Response('', 204)


@rdir_api.route('/v1/<ns>/rdir/admin/incident', methods=['GET'])
def rdir_admin_incident_get(ns):
    volume = request.args.get('vol')
    if not volume:
        return flask.Response('Missing volume id', 400)

    date = get_backend().admin_get_incident_date(volume)
    resp = {}
    if date:
        resp = {'date': date}
    return flask.Response(json.dumps(resp), 200,
                          mimetype='application/json')


@rdir_api.route('/v1/<ns>/rdir/admin/lock', methods=['POST'])
def rdir_admin_lock(ns):
    volume = request.args.get('vol')
    if not volume:
        return flask.Response('Missing volume id', 400)

    decoded = flask.request.get_json(force=True)
    who = decoded.get('who')
    if who is None:
        return flask.Response('Missing token who', 400)

    desc = get_backend().admin_lock(volume, who)

    if desc is not None:
        message = "Already locked by %s" % desc
        return flask.Response(message, 403,
                              mimetype='application/json')

    return flask.Response('', 204)


@rdir_api.route('/v1/<ns>/rdir/admin/unlock', methods=['POST'])
def rdir_admin_unlock(ns):
    volume = request.args.get('vol')
    if not volume:
        return flask.Response('Missing volume id', 400)

    get_backend().admin_unlock(volume)
    return flask.Response('', 204)


@rdir_api.route('/v1/<ns>/rdir/admin/show', methods=['GET'])
def rdir_admin_show(ns):
    volume = request.args.get('vol')
    if not volume:
        return flask.Response('Missing volume id', 400)

    data = get_backend().admin_show(volume)
    return flask.Response(json.dumps(data), 200, mimetype='application/json')


def create_app(conf, **kwargs):
    app = flask.Flask(__name__)
    app.register_blueprint(rdir_api)
    app.backend = RdirBackend(conf)
    # we want exceptions to be logged
    if conf.get('log_level') == 'DEBUG':
        app.config['PROPAGATE_EXCEPTIONS'] = True
    return app


class RdirServiceLogger(Logger):
    def __init__(self, cfg):
        self.cfg = cfg
        prefix = cfg.syslog_prefix if cfg.syslog_prefix else ''
        address = cfg.syslog_addr if cfg.syslog_addr else '/dev/log'

        error_conf = {
            'syslog_prefix': prefix,
            'log_facility': 'LOG_LOCAL1',
            'log_address': address
        }

        access_conf = {
            'syslog_prefix': prefix,
            'log_facility': 'LOG_LOCAL0',
            'log_address': address
        }

        self.error_log = get_logger(error_conf, 'rdir.error')
        self.access_log = get_logger(access_conf, 'rdir.access')
