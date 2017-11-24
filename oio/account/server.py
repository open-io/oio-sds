# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
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


from werkzeug.wrappers import Response
from werkzeug.routing import Map, Rule
from werkzeug.exceptions import NotFound, BadRequest, Conflict

from oio.account.backend import AccountBackend
from oio.common.json import json
from oio.common.logger import get_logger
from oio.common.wsgi import WerkzeugApp


class Account(WerkzeugApp):
    def __init__(self, conf, backend, logger=None):
        self.conf = conf
        self.backend = backend
        self.logger = logger or get_logger(conf)

        self.url_map = Map([
            Rule('/status', endpoint='status'),
            Rule('/v1.0/account/create', endpoint='account_create'),
            Rule('/v1.0/account/delete', endpoint='account_delete'),
            Rule('/v1.0/account/list', endpoint='account_list'),
            Rule('/v1.0/account/update', endpoint='account_update'),
            Rule('/v1.0/account/show', endpoint='account_show'),
            Rule('/v1.0/account/containers', endpoint='account_containers'),
            Rule('/v1.0/account/refresh', endpoint='account_refresh'),
            Rule('/v1.0/account/flush', endpoint='account_flush'),
            Rule('/v1.0/account/container/update',
                 endpoint='account_container_update'),
            Rule('/v1.0/account/container/reset',
                 endpoint='account_container_reset')
        ])
        super(Account, self).__init__(self.url_map, self.logger)

    def _get_account_id(self, req):
        account_id = req.args.get('id')
        if not account_id:
            raise BadRequest('Missing Account ID')
        return account_id

    # ACCT{{
    # GET /status
    # ~~~~~~~~~~~
    # Return a summary of the target ACCOUNT service. The body of the reply
    # will present a count of the objects in the databse, formatted as a JSON
    # object.
    #
    # .. code-block:: http
    #
    #    GET /status HTTP/1.1
    #    Host: 127.0.0.1:6021
    #    User-Agent: curl/7.55.1
    #    Accept: */*
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 200 OK
    #    Server: gunicorn/19.7.1
    #    Date: Wed, 22 Nov 2017 09:45:03 GMT
    #    Connection: keep-alive
    #    Content-Type: text/json; charset=utf-8
    #    Content-Length: 20
    #
    #    {"account_count": 0}
    #
    # }}ACCT
    def on_status(self, req):
        status = self.backend.status()
        return Response(json.dumps(status), mimetype='text/json')

    def on_account_create(self, req):
        account_id = self._get_account_id(req)
        id = self.backend.create_account(account_id)
        if id:
            return Response(id, 201)
        else:
            return Response(status=202)

    def on_account_list(self, req):
        accounts = self.backend.list_account()
        if accounts is None:
            return NotFound('No account found')
        return Response(json.dumps(accounts), mimetype='text/json')

    def on_account_delete(self, req):
        account_id = self._get_account_id(req)
        result = self.backend.delete_account(account_id)
        if result is None:
            return NotFound('No such account')
        if result is False:
            return Conflict('Account not empty')
        else:
            return Response(status=204)

    def on_account_update(self, req):
        account_id = self._get_account_id(req)
        decoded = json.loads(req.get_data())
        metadata = decoded.get('metadata')
        to_delete = decoded.get('to_delete')
        success = self.backend.update_account_metadata(
            account_id, metadata, to_delete)
        if success:
            return Response(status=204)
        return NotFound('Account not found')

    def on_account_show(self, req):
        account_id = self._get_account_id(req)
        raw = self.backend.info_account(account_id)
        if raw is not None:
            return Response(json.dumps(raw), mimetype='text/json')
        return NotFound('Account not found')

    def on_account_containers(self, req):
        account_id = self._get_account_id(req)

        info = self.backend.info_account(account_id)
        if not info:
            return NotFound('Account not found')

        marker = req.args.get('marker', '')
        end_marker = req.args.get('end_marker', '')
        prefix = req.args.get('prefix', '')
        limit = int(req.args.get('limit', '1000'))
        delimiter = req.args.get('delimiter', '')

        user_list = self.backend.list_containers(
            account_id, limit=limit, marker=marker, end_marker=end_marker,
            prefix=prefix, delimiter=delimiter)

        info['listing'] = user_list
        result = json.dumps(info)
        return Response(result, mimetype='text/json')

    def on_account_container_update(self, req):
        account_id = self._get_account_id(req)
        d = json.loads(req.get_data())
        name = d.get('name')
        mtime = d.get('mtime')
        dtime = d.get('dtime')
        object_count = d.get('objects')
        bytes_used = d.get('bytes')
        # Exceptions are catched by dispatch_request
        info = self.backend.update_container(
            account_id, name, mtime, dtime, object_count, bytes_used)
        result = json.dumps(info)
        return Response(result)

    def on_account_container_reset(self, req):
        account_id = self._get_account_id(req)
        data = json.loads(req.get_data())
        name = data.get('name')
        mtime = data.get('mtime')
        dtime = None
        object_count = 0
        bytes_used = 0
        # Exceptions are catched by dispatch_request
        self.backend.update_container(
            account_id, name, mtime, dtime, object_count, bytes_used,
            autocreate_container=False)
        return Response(status=204)

    def on_account_refresh(self, req):
        account_id = self._get_account_id(req)
        self.backend.refresh_account(account_id)
        return Response(status=204)

    def on_account_flush(self, req):
        account_id = self._get_account_id(req)
        self.backend.flush_account(account_id)
        return Response(status=204)


def create_app(conf, **kwargs):
    backend = AccountBackend(conf)
    app = Account(conf, backend)
    return app
