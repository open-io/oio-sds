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

from oio.index.server_db import IndexBackend
from oio.common.utils import get_logger, json

index_api = flask.Blueprint('index_api', __name__)


def get_backend():
    return current_app.backend


@index_api.route('/v1.0/index/update', methods=['PUT'])
def index_update():
    volume = request.args.get('volume')
    if not volume:
        return flask.Response('Missing volume id', 400)
    decoded = flask.request.get_json(force=True)
    chunk_id = decoded.get('chunk_id')
    content_cid = decoded.get('content_cid')
    content_path = decoded.get('content_path')
    get_backend().put(volume, chunk_id, content_cid, content_path)
    return flask.Response('', 204)


@index_api.route('/v1.0/index/dump', methods=['GET'])
def index_dump():
    volume = request.args.get('volume')
    if not volume:
        return flask.Response('Missing volume id', 400)
    data = get_backend().dump(volume)

    return flask.Response(json.dumps(data), mimetype='application/json')


def create_app(conf, **kwargs):
    app = flask.Flask(__name__)
    app.register_blueprint(index_api)
    app.backend = IndexBackend(conf)
    # we want exceptions to be logged
    if conf.get('log_level') == 'DEBUG':
        app.config['PROPAGATE_EXCEPTIONS'] = True
    return app


class IndexServiceLogger(Logger):
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

        self.error_log = get_logger(error_conf, 'index.error')
        self.access_log = get_logger(access_conf, 'index.access')
