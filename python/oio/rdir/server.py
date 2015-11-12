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
def status():
    status = get_backend().status()
    return flask.Response(json.dumps(status), mimetype='application/json')


@rdir_api.route('/<ns>/rdir/push', methods=['POST'])
def rdir_update(ns):
    volume = request.args.get('vol')
    if not volume:
        return flask.Response('Missing volume id', 400)
    decoded = flask.request.get_json(force=True)
    chunk = decoded.get('chunk')
    container = decoded.get('container')
    content = decoded.get('content')
    get_backend().put(volume, container, content, chunk)
    return flask.Response('', 204)


@rdir_api.route('/<ns>/rdir/dump', methods=['GET'])
def rdir_dump(ns):
    volume = request.args.get('vol')
    if not volume:
        return flask.Response('Missing volume id', 400)
    pretty = request.args.get('pretty')

    data = get_backend().dump(volume)

    if (pretty):
        body = json.dumps(data, indent=4)
    else:
        body = json.dumps(data)

    return flask.Response(body, mimetype='application/json')


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
