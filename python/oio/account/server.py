#!/usr/bin/python

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

import json

import flask
from flask import request
from flask import current_app
from gunicorn.glogging import Logger

from oio.account.backend import AccountBackend
from oio.common.utils import get_logger


def get_backend():
    return current_app.backend

# Accounts --------------------------------------------------------------------

account_api = flask.Blueprint('account_api', __name__)


@account_api.route('/status', methods=['GET'])
def status():
    status = get_backend().status()
    return flask.Response(json.dumps(status), mimetype='text/json')


@account_api.route('/v1.0/account/create', methods=['PUT'])
def account_create():
    account_id = request.args.get('id')
    if not account_id:
        return flask.Response('Missing Account ID', 400)
    id = get_backend().create_account(account_id)
    if id:
        return flask.Response(id, 201)
    else:
        return flask.Response('', 202)


@account_api.route('/v1.0/account/update', methods=['POST'])
def account_update():
    account_id = request.args.get('id')
    if not account_id:
        return flask.Response('Missing Account ID', 400)
    decoded = flask.request.get_json(force=True)
    metadata = decoded.get('metadata')
    to_delete = decoded.get('to_delete')
    if get_backend().update_account_metadata(account_id, metadata, to_delete):
        return flask.Response('', 204)
    return 'Account not found', 404


@account_api.route('/v1.0/account/show', methods=['HEAD', 'GET'])
def account_info():
    account_id = request.args.get('id')
    if not account_id:
        return flask.Response('Missing Account ID', 400)
    raw = get_backend().info_account(account_id)
    if raw is not None:
        return flask.Response(json.dumps(raw), mimetype='text/json')
    return "Account not found", 404


@account_api.route('/v1.0/account/containers', methods=['GET'])
def account_list_containers():
    account_id = request.args.get('id')
    if not account_id:
        return flask.Response('Missing Account ID', 400)

    info = get_backend().info_account(account_id)
    if not info:
        return "Account not found", 404

    marker = request.args.get('marker', '')
    end_marker = request.args.get('end_marker', '')
    prefix = request.args.get('prefix', '')
    limit = int(request.args.get('limit', '1000'))
    delimiter = request.args.get('delimiter', '')

    user_list = get_backend().list_containers(
        account_id, limit=limit, marker=marker, end_marker=end_marker,
        prefix=prefix, delimiter=delimiter
    )

    info['listing'] = user_list
    result = json.dumps(info)
    return flask.Response(result, mimetype='text/json')


# Containers ------------------------------------------------------------------

@account_api.route('/v1.0/account/container/update', methods=['POST'])
def container_update():
    account_id = request.args.get('id')
    d = flask.request.get_json(force=True)
    name = d.get('name')
    mtime = d.get('mtime')
    dtime = d.get('dtime')
    object_count = d.get('objects')
    bytes_used = d.get('bytes')
    result = get_backend().update_container(
        account_id, name, mtime, dtime, object_count, bytes_used)
    return result


def create_app(conf, **kwargs):
    app = flask.Flask(__name__)
    app.backend = AccountBackend(conf)
    app.register_blueprint(account_api)
    # we want exceptions to be logged
    app.config['PROPAGATE_EXCEPTIONS'] = True
    return app


class AccountServiceLogger(Logger):
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

        self.error_log = get_logger(error_conf, 'account.error')
        self.access_log = get_logger(access_conf, 'account.access')
