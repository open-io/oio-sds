#!/usr/bin/python

# Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage
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
from oio.account.backend import AccountBackend
from oio.account.backend import AccountException
from oio.account.backend import CODE_ACCOUNT_NOTFOUND, CODE_SYSTEM_ERROR, CODE_USER_NOTFOUND
app = flask.Flask(__name__)

backend = AccountBackend(None)

# Accounts ---------------------------------------------------------------------

@app.route('/status', methods=['GET'])
def status():
    status = backend.status()
    return flask.Response(json.dumps(status), mimetype='text/json')


@app.route('/v1.0/account/create', methods=['PUT'])
def account_create():
    account_id = request.args.get('id')
    id = backend.create_account(account_id)
    return id



@app.route('/v1.0/account/update', methods=['POST'])
def account_update():
    account_id = request.args.get('id')
    decoded = flask.request.get_json(force=True)
    backend.update_account(account_id, decoded)
    return ""



@app.route('/v1.0/account/show', methods=['HEAD'])
def account_info():
    account_id = request.args.get('id')
    raw = backend.info_account(account_id)
    if raw is not None:
        return flask.Response(json.dumps(raw), mimetype='text/json')
    return "Account not found", 404

@app.route('/v1.0/account/containers', methods=['GET'])
def account_list_containers():
    account_id = request.args.get('id')
    user_list = backend.list_containers(account_id)
    result = json.dumps(user_list)
    return flask.Response(result, mimetype='text/json')

# Containers -------------------------------------------------------------------

@app.route('/v1.0/account/container/update', methods=['POST'])
def container_update():
    account_id = request.args.get('id')
    try:
        d = flask.request.get_json(force=True)
        container = d.get('name')
        data = {
            'mtime': d.get('mtime'),
            'object_count': d.get('object_count'),
            'bytes': d.get('bytes'),
            'storage_policy': d.get('storage_policy')
            }
        result = backend.update_container(account_id, container, data)
    except AccountException as e:
        code = 404
        if e.status_code in (CODE_ACCOUNT_NOTFOUND, CODE_USER_NOTFOUND):
            code = 403
        return repr(e.to_dict()), code
    return ""

app.run(debug=True)