# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021 OVHcloud
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

from werkzeug.wrappers import Response
from werkzeug.routing import Map, Rule
from werkzeug.exceptions import NotFound, BadRequest, Conflict, HTTPException

from oio.account.backend import AccountBackend
from oio.account.iam import RedisIamDb
from oio.common.configuration import load_namespace_conf
from oio.common.constants import REQID_HEADER, STRLEN_REQID, \
    HTTP_CONTENT_TYPE_JSON
from oio.common.easy_value import int_value, true_value
from oio.common.json import json
from oio.common.logger import get_logger
from oio.common.utils import parse_conn_str
from oio.common.wsgi import WerkzeugApp


ACCOUNT_LISTING_DEFAULT_LIMIT = 1000
ACCOUNT_LISTING_MAX_LIMIT = 10000
DEFAULT_IAM_CONNECTION = 'redis://127.0.0.1:6379'


def access_log(func):

    @wraps(func)
    def _access_log_wrapper(self, req, *args, **kwargs):
        from time import time
        pre = time()
        rc = func(self, req, *args, **kwargs)
        post = time()
        reqid = req.headers.get(REQID_HEADER, '-')[:STRLEN_REQID]
        if isinstance(rc, HTTPException):
            code = str(rc.code)
        elif isinstance(rc, Response):
            code = str(rc.status_code)
        else:
            code = "-"
        # func time size user reqid
        self.logger.info("%s %s %0.6f %s %s %s",
                         func.__name__, code, post - pre, '-', '-', reqid)
        return rc

    return _access_log_wrapper


def force_master(func):

    @wraps(func)
    def _force_master_wrapper(self, req, *args, **kwargs):
        force_master = true_value(req.args.get('force_master', ''))
        return func(self, req, *args, force_master=force_master, **kwargs)

    return _force_master_wrapper


class Account(WerkzeugApp):

    # pylint: disable=no-member

    def __init__(self, conf, backend, iam_db, logger=None):
        self.conf = conf
        self.backend = backend
        self.iam = iam_db
        self.logger = logger or get_logger(conf)

        self.url_map = Map([
            Rule('/status', endpoint='status'),
            Rule('/v1.0/account/create', endpoint='account_create',
                 methods=['PUT']),
            Rule('/v1.0/account/delete', endpoint='account_delete',
                 methods=['POST']),
            Rule('/v1.0/account/list', endpoint='account_list',
                 methods=['GET']),
            Rule('/v1.0/account/update', endpoint='account_update',
                 methods=['PUT', 'POST']),  # FIXME(adu) only PUT
            Rule('/v1.0/account/update-bucket', endpoint='bucket_update',
                 methods=['PUT']),
            Rule('/v1.0/account/show', endpoint='account_show',
                 methods=['GET']),
            Rule('/v1.0/account/show-bucket', endpoint='bucket_show',
                 methods=['GET']),
            Rule('/v1.0/account/show-container',
                 endpoint='account_container_show',
                 methods=['GET']),
            Rule('/v1.0/account/buckets', endpoint='account_buckets',
                 methods=['GET']),
            Rule('/v1.0/account/containers', endpoint='account_containers',
                 methods=['GET']),
            Rule('/v1.0/account/refresh-bucket', endpoint='bucket_refresh',
                 methods=['POST']),
            Rule('/v1.0/account/refresh', endpoint='account_refresh',
                 methods=['POST']),
            Rule('/v1.0/account/flush', endpoint='account_flush',
                 methods=['POST']),
            Rule('/v1.0/account/container/reset',
                 endpoint='account_container_reset',
                 methods=['PUT', 'POST']),  # FIXME(adu) only PUT
            Rule('/v1.0/account/container/show',
                 endpoint='account_container_show',
                 methods=['GET']),
            Rule('/v1.0/account/container/update',
                 endpoint='account_container_update',
                 methods=['PUT', 'POST']),  # FIXME(adu) only PUT
            # Buckets
            Rule('/v1.0/bucket/show', endpoint='bucket_show',
                 methods=['GET']),
            Rule('/v1.0/bucket/update', endpoint='bucket_update',
                 methods=['PUT']),
            Rule('/v1.0/bucket/refresh', endpoint='bucket_refresh',
                 methods=['POST']),
            # IAM
            Rule('/v1.0/iam/delete-user-policy',
                 endpoint='iam_delete_user_policy',
                 methods=['DELETE']),
            Rule('/v1.0/iam/get-user-policy',
                 endpoint='iam_get_user_policy',
                 methods=['GET']),
            Rule('/v1.0/iam/list-users',
                 endpoint='iam_list_users',
                 methods=['GET']),
            Rule('/v1.0/iam/list-user-policies',
                 endpoint='iam_list_user_policies',
                 methods=['GET']),
            Rule('/v1.0/iam/put-user-policy',
                 endpoint='iam_put_user_policy',
                 methods=['PUT', 'POST']),
        ])
        super(Account, self).__init__(self.url_map, self.logger)

    def _get_item_id(self, req, key='id', what='account'):
        """Fetch the name of the requested item, raise an error if missing."""
        item_id = req.args.get(key)
        if not item_id:
            raise BadRequest('Missing %s ID' % what)
        return item_id

    def _get_account_id(self, req):
        """Fetch account name from request query string."""
        return self._get_item_id(req, what='account')

    # ACCT{{
    # GET /status
    # ~~~~~~~~~~~
    # Return a summary of the target account service. The body of the reply
    # will present a count of the objects in the databse, formatted as a JSON
    # object.
    #
    # Sample request:
    #
    # .. code-block:: http
    #
    #    GET /status HTTP/1.1
    #    Host: 127.0.0.1:6021
    #    User-Agent: curl/7.55.1
    #    Accept: */*
    #
    # Sample response:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 200 OK
    #    Server: gunicorn/19.7.1
    #    Date: Wed, 22 Nov 2017 09:45:03 GMT
    #    Connection: keep-alive
    #    Content-Type: application/json
    #    Content-Length: 20
    #
    #    {"account_count": 0}
    #
    # }}ACCT
    @force_master
    def on_status(self, req, **kwargs):
        status = self.backend.status(**kwargs)
        return Response(json.dumps(status), mimetype=HTTP_CONTENT_TYPE_JSON)

    # ACCT{{
    # PUT /v1.0/account/create?id=<account_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Create a new account with the specified name.
    #
    # Sample request:
    #
    # .. code-block:: http
    #
    #    PUT /v1.0/account/create?id=myaccount HTTP/1.1
    #    Host: 127.0.0.1:6013
    #    User-Agent: curl/7.47.0
    #    Accept: */*
    #
    # Sample response:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 201 CREATED
    #    Server: gunicorn/19.9.0
    #    Date: Wed, 01 Aug 2018 12:17:25 GMT
    #    Connection: keep-alive
    #    Content-Type: text/plain; charset=utf-8
    #    Content-Length: 9
    #
    #    myaccount
    #
    # }}ACCT
    @access_log
    @force_master
    def on_account_create(self, req, **kwargs):
        account_id = self._get_account_id(req)
        aid = self.backend.create_account(account_id, **kwargs)
        if aid:
            return Response(aid, 201)
        return Response(status=202)

    # ACCT{{
    # GET /v1.0/account/list
    # ~~~~~~~~~~~~~~~~~~~~~~
    # Get the list of existing accounts.
    #
    # Sample request:
    #
    # .. code-block:: http
    #
    #    GET /v1.0/account/list HTTP/1.1
    #    Host: 127.0.0.1:6013
    #    User-Agent: curl/7.47.0
    #    Accept: */*
    #
    # Sample response:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 200 OK
    #    Server: gunicorn/19.9.0
    #    Date: Wed, 01 Aug 2018 12:17:25 GMT
    #    Connection: keep-alive
    #    Content-Type: application/json
    #    Content-Length: 13
    #
    #    ["myaccount"]
    #
    # }}ACCT
    @access_log
    @force_master
    def on_account_list(self, req, **kwargs):
        accounts = self.backend.list_accounts(**kwargs)
        if accounts is None:
            return NotFound('No account found')
        return Response(json.dumps(accounts), mimetype=HTTP_CONTENT_TYPE_JSON)

    # ACCT{{
    # POST /v1.0/account/delete?id=<account_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Delete the specified account.
    #
    # Sample request:
    #
    # .. code-block:: http
    #
    #    POST /v1.0/account/delete?id=myaccount HTTP/1.1
    #    Host: 127.0.0.1:6013
    #    User-Agent: curl/7.47.0
    #    Accept: */*
    #
    # Sample response:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 204 No Content
    #    Server: gunicorn/19.9.0
    #    Date: Wed, 01 Aug 2018 12:17:25 GMT
    #    Connection: keep-alive
    #    Content-Type: text/plain; charset=utf-8
    #
    # }}ACCT
    @access_log
    @force_master
    def on_account_delete(self, req, **kwargs):
        account_id = self._get_account_id(req)
        result = self.backend.delete_account(account_id, **kwargs)
        if result is None:
            return NotFound('No such account')
        if result is False:
            return Conflict('Account not empty')
        else:
            return Response(status=204)

    # ACCT{{
    # POST /v1.0/account/update?id=<account_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    #
    # Update metadata of the specified account.
    #
    # Sample request:
    #
    # .. code-block:: http
    #
    #    PUT /v1.0/account/update?id=myaccount HTTP/1.1
    #    Host: 127.0.0.1:6013
    #    User-Agent: curl/7.47.0
    #    Accept: */*
    #    Content-Length: 41
    #    Content-Type: application/x-www-for-urlencoded
    #
    # .. code-block:: json
    #
    #    {
    #      "metadata": {"key":"value"},
    #      "to_delete": ["key"]
    #    }
    #
    # Sample response:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 204 NO CONTENT
    #    Server: gunicorn/19.9.0
    #    Date: Wed, 01 Aug 2018 12:17:25 GMT
    #    Connection: keep-alive
    #    Content-Type: text/plain; charset=utf-8
    #
    # }}ACCT
    @force_master
    def on_account_update(self, req, **kwargs):
        account_id = self._get_account_id(req)
        decoded = json.loads(req.get_data())
        metadata = decoded.get('metadata')
        to_delete = decoded.get('to_delete')
        success = self.backend.update_account_metadata(
            account_id, metadata, to_delete, **kwargs)
        if success:
            return Response(status=204)
        return NotFound('Account not found')

    # ACCT{{
    # GET /v1.0/account/show?id=<account_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Get information about the specified account.
    #
    # Sample request:
    #
    # .. code-block:: http
    #
    #    GET /v1.0/account/show?id=myaccount HTTP/1.1
    #    Host: 127.0.0.1:6013
    #    User-Agent: curl/7.47.0
    #    Accept: */*
    #
    # Sample response:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 200 OK
    #    Server: gunicorn/19.9.0
    #    Date: Wed, 01 Aug 2018 12:17:25 GMT
    #    Connection: keep-alive
    #    Content-Type: application/json
    #    Content-Length: 107
    #
    # .. code-block:: json
    #
    #    {
    #      "ctime": "1533127401.08165",
    #      "bytes": 0,
    #      "objects": 0,
    #      "id": "myaccount",
    #      "containers": 0,
    #      "metadata": {}
    #     }
    #
    # }}ACCT
    @access_log
    @force_master
    def on_account_show(self, req, **kwargs):
        account_id = self._get_account_id(req)
        raw = self.backend.info_account(account_id, **kwargs)
        if raw is not None:
            return Response(json.dumps(raw), mimetype=HTTP_CONTENT_TYPE_JSON)
        return NotFound('Account not found')

    # ACCT{{
    # GET /v1.0/account/buckets?id=<account_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    #
    # Get information about the buckets belonging to the specified account.
    #
    # Sample request:
    #
    # .. code-block:: http
    #
    #    GET /v1.0/account/buckets?id=AUTH_demo HTTP/1.1
    #    Host: 127.0.0.1:6013
    #    User-Agent: curl/7.47.0
    #    Accept: */*
    #
    # Sample response:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 200 OK
    #    Server: gunicorn/19.9.0
    #    Date: Wed, 01 Aug 2018 12:17:25 GMT
    #    Connection: keep-alive
    #    Content-Type: application/json
    #    Content-Length: 122
    #
    # .. code-block:: json
    #
    #    {
    #      "buckets": 3,
    #      "bytes": 132573,
    #      "ctime": "1582628089.30237",
    #      "objects": 3,
    #      "listing": [
    #        {
    #            "bytes": 132573,
    #            "mtime": 1582641887.75408,
    #            "name": "bucket0",
    #            "objects": 3
    #        },
    #        {
    #            "bytes": 0,
    #            "mtime": 1582641712.44969,
    #            "name": "bucket1",
    #            "objects": 0
    #        },
    #        {
    #            "bytes": 0,
    #            "mtime": 1582641715.19412,
    #            "name": "bucket2",
    #            "objects": 0
    #        }
    #      ],
    #      "id": "AUTH_demo",
    #      "containers": 5,
    #      "metadata": {}
    #    }
    #
    # }}ACCT
    @access_log
    @force_master
    def on_account_buckets(self, req, **kwargs):
        account_id = self._get_account_id(req)

        info = self.backend.info_account(account_id, **kwargs)
        if not info:
            return NotFound('Account not found')

        marker = req.args.get('marker', '')
        end_marker = req.args.get('end_marker', '')
        prefix = req.args.get('prefix', '')
        limit = int(req.args.get('limit', '1000'))

        bucket_list, next_marker = self.backend.list_buckets(
            account_id, limit=limit, marker=marker, end_marker=end_marker,
            prefix=prefix, **kwargs)

        info['listing'] = bucket_list
        info['truncated'] = next_marker is not None
        if next_marker is not None:
            info['next_marker'] = next_marker
        result = json.dumps(info)
        return Response(result, mimetype=HTTP_CONTENT_TYPE_JSON)

    # ACCT{{
    # GET /v1.0/account/containers?id=<account_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    #
    # Get information about the containers belonging to the specified account.
    #
    # Sample request:
    #
    # .. code-block:: http
    #
    #    GET /v1.0/account/containers?id=myaccount HTTP/1.1
    #    Host: 127.0.0.1:6013
    #    User-Agent: curl/7.47.0
    #    Accept: */*
    #
    # Sample response:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 200 OK
    #    Server: gunicorn/19.9.0
    #    Date: Wed, 01 Aug 2018 12:17:25 GMT
    #    Connection: keep-alive
    #    Content-Type: application/json
    #    Content-Length: 122
    #
    # .. code-block:: json
    #
    #    {
    #      "ctime": "1533127401.08165",
    #      "bytes": 0,
    #      "objects": 0,
    #      "listing": [],
    #      "id": "account",
    #      "containers": 0,
    #      "metadata": {}
    #     }
    #
    # }}ACCT
    @access_log
    @force_master
    def on_account_containers(self, req, **kwargs):
        account_id = self._get_account_id(req)

        info = self.backend.info_account(account_id, **kwargs)
        if not info:
            return NotFound('Account not found')

        marker = req.args.get('marker', '')
        end_marker = req.args.get('end_marker', '')
        prefix = req.args.get('prefix', '')
        limit = int(req.args.get('limit', '1000'))
        limit = max(0, min(ACCOUNT_LISTING_MAX_LIMIT, int_value(
            req.args.get('limit'), 0)))
        if limit <= 0:
            limit = ACCOUNT_LISTING_DEFAULT_LIMIT
        delimiter = req.args.get('delimiter', '')
        s3_buckets_only = true_value(req.args.get('s3_buckets_only', False))

        user_list = self.backend.list_containers(
            account_id, limit=limit, marker=marker, end_marker=end_marker,
            prefix=prefix, delimiter=delimiter,
            s3_buckets_only=s3_buckets_only, **kwargs)

        info['listing'] = user_list
        # TODO(FVE): add "truncated" entry telling if the listing is truncated
        result = json.dumps(info)
        return Response(result, mimetype=HTTP_CONTENT_TYPE_JSON)

    # ACCT{{
    # PUT /v1.0/account/container/update?id=<account_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    #
    # Update account with container-related metadata.
    #
    # Request example:
    #
    # .. code-block:: http
    #
    #    PUT /v1.0/account/container/update?id=myaccount HTTP/1.1
    #    Host: 127.0.0.1:6013
    #    User-Agent: curl/7.47.0
    #    Accept: */*
    #    Content-Length: 84
    #    Content-Type: application/x-www-form-urlencoded
    #
    # .. code-block:: json
    #
    #    {
    #      "mtime": "123456789",
    #      "dtime": "1223456789",
    #      "name": "user1bucket%2Ffiles",
    #      "objects": 0,
    #      "bytes": 0,
    #      "bucket": "user1bucket"
    #    }
    #
    # Response example:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 200 OK
    #    Server: gunicorn/19.9.0
    #    Date: Wed, 01 Aug 2018 12:17:25 GMT
    #    Connection: keep-alive
    #    Content-Type: application/json
    #    Content-Length: 117
    #
    # }}ACCT
    @force_master
    def on_account_container_update(self, req, **kwargs):
        account_id = self._get_account_id(req)
        data = json.loads(req.get_data())
        name = data.get('name')
        mtime = data.get('mtime')
        dtime = data.get('dtime')
        object_count = data.get('objects')
        bytes_used = data.get('bytes')
        bucket_name = data.get('bucket')  # can be None
        # Exceptions are catched by dispatch_request
        info = self.backend.update_container(
            account_id, name, mtime, dtime, object_count, bytes_used,
            bucket_name=bucket_name, **kwargs)
        result = json.dumps(info)
        return Response(result, mimetype=HTTP_CONTENT_TYPE_JSON)

    # ACCT{{
    # PUT /v1.0/account/container/reset?id=<account_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    #
    # Reset statistics of the specified container.
    # Usually followed by a "container touch" operation.
    #
    # Request example:
    #
    # .. code-block:: http
    #
    #    PUT /v1.0/account/container/reset?id=myaccount HTTP/1.1
    #    Host: 127.0.0.1:6013
    #    User-Agent: curl/7.47.0
    #    Accept: */*
    #    Content-Length: 45
    #    Content-Type: application/x-www-form-urlencoded
    #
    # .. code-block:: json
    #
    #    {
    #      "name": "container name",
    #      "mtime": 1234567891011
    #    }
    #
    # Response example:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 204 NO CONTENT
    #    Server: gunicorn/19.9.0
    #    Date: Wed, 01 Aug 2018 12:17:25 GMT
    #    Connection: keep-alive
    #    Content-Type: text/plain; charset=utf-8
    #
    # }}ACCT
    @force_master
    def on_account_container_reset(self, req, **kwargs):
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
            autocreate_container=False, **kwargs)
        return Response(status=204)

    # ACCT{{
    # POST /v1.0/account/refresh?id=<account_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Refresh counter of an account named account_name
    #
    # .. code-block:: http
    #
    #    POST /v1.0/account/refresh?id=myaccount HTTP/1.1
    #    Host: 127.0.0.1:6013
    #    User-Agent: curl/7.47.0
    #    Accept: */*
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 204 NO CONTENT
    #    Server: gunicorn/19.9.0
    #    Date: Wed, 01 Aug 2018 12:17:25 GMT
    #    Connection: keep-alive
    #    Content-Type: text/plain; charset=utf-8
    #
    # }}ACCT
    @access_log
    @force_master
    def on_account_refresh(self, req, **kwargs):
        account_id = self._get_account_id(req)
        self.backend.refresh_account(account_id, **kwargs)
        return Response(status=204)

    # ACCT{{
    # POST /v1.0/account/flush?id=<account_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Flush all container of an account named account_name
    #
    # .. code-block:: http
    #
    #    POST /v1.0/account/flush?id=myaccount HTTP/1.1
    #    Host: 127.0.0.1:6013
    #    User-Agent: curl/7.47.0
    #    Accept: */*
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 204 NO CONTENT
    #    Server: gunicorn/19.9.0
    #    Date: Wed, 01 Aug 2018 12:17:25 GMT
    #    Connection: keep-alive
    #    Content-Type: text/plain; charset=utf-8
    #
    # }}ACCT
    @access_log
    @force_master
    def on_account_flush(self, req, **kwargs):
        account_id = self._get_account_id(req)
        self.backend.flush_account(account_id, **kwargs)
        return Response(status=204)

    # ACCT{{
    # GET /v1.0/bucket/show?id=<bucket_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Get information about the specified bucket.
    #
    # Sample request:
    #
    # .. code-block:: http
    #
    #    GET /v1.0/bucket/show?id=mybucket HTTP/1.1
    #    Host: 127.0.0.1:6013
    #    User-Agent: curl/7.47.0
    #    Accept: */*
    #
    # Sample response:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 200 OK
    #    Server: gunicorn/19.9.0
    #    Date: Wed, 01 Aug 2018 12:17:25 GMT
    #    Connection: keep-alive
    #    Content-Type: application/json
    #    Content-Length: 128
    #
    # .. code-block:: json
    #
    #    {
    #      "account": "myaccount",
    #      "bytes": 11300,
    #      "mtime": "1533127401.08165",
    #      "objects": 100,
    #      "replication_enabled": false
    #    }
    #
    # }}ACCT
    @access_log
    @force_master
    def on_bucket_show(self, req, **kwargs):
        """
        Get all available information about a bucket.
        """
        bname = self._get_item_id(req, what='bucket')
        raw = self.backend.get_bucket_info(bname, **kwargs)
        if raw is not None:
            return Response(json.dumps(raw), mimetype=HTTP_CONTENT_TYPE_JSON)
        return NotFound('Bucket not found')

    # ACCT{{
    # PUT /v1.0/bucket/update?id=<bucket_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    #
    # Update metadata of the specified bucket.
    #
    # Sample request:
    #
    # .. code-block:: http
    #
    #    PUT /v1.0/bucket/update?id=mybucket HTTP/1.1
    #    Host: 127.0.0.1:6013
    #    User-Agent: curl/7.47.0
    #    Accept: */*
    #    Content-Length: 41
    #    Content-Type: application/x-www-for-urlencoded
    #
    # .. code-block:: json
    #
    #    {
    #      "metadata": {"key":"value"},
    #      "to_delete": ["oldkey"]
    #    }
    #
    # Sample response:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 200 OK
    #    Server: gunicorn/19.9.0
    #    Date: Wed, 01 Aug 2018 12:17:25 GMT
    #    Connection: keep-alive
    #    Content-Type: application/json
    #
    # .. code-block:: json
    #
    #    {
    #      "account": "myaccount",
    #      "bytes": 11300,
    #      "mtime": "1533127401.08165",
    #      "objects": 100,
    #      "replication_enabled": false
    #    }
    #
    # }}ACCT
    @force_master
    def on_bucket_update(self, req, **kwargs):
        """
        Update (or delete) bucket metadata.
        """
        bname = self._get_item_id(req, what='bucket')
        decoded = json.loads(req.get_data())
        metadata = decoded.get('metadata')
        to_delete = decoded.get('to_delete')
        info = self.backend.update_bucket_metadata(
            bname, metadata, to_delete, **kwargs)
        if info is not None:
            return Response(json.dumps(info), mimetype=HTTP_CONTENT_TYPE_JSON)
        return NotFound('Bucket not found')

    # ACCT{{
    # POST /v1.0/bucket/refresh?id=<bucket_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    #
    # Refresh the counters of a bucket named bucket_name
    #
    # Sample request:
    #
    # .. code-block:: http
    #
    #    POST /v1.0/bucket/refresh?id=mybucket HTTP/1.1
    #    Host: 127.0.0.1:6013
    #    User-Agent: curl/7.47.0
    #    Accept: */*
    #
    # Sample response:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 204 NO CONTENT
    #    Server: gunicorn/19.9.0
    #    Date: Wed, 01 Aug 2018 12:17:25 GMT
    #    Connection: keep-alive
    #    Content-Type: text/plain; charset=utf-8
    #
    # }}ACCT
    @force_master
    def on_bucket_refresh(self, req, **kwargs):
        """
        Refresh bucket counters.
        """
        bucket_name = self._get_item_id(req, what='bucket')
        self.backend.refresh_bucket(bucket_name, **kwargs)
        return Response(status=204)

    # ACCT{{
    # GET /v1.0/account/container/show?id=<account_name>&container=<container>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Get information about the specified container.
    #
    # Sample request:
    #
    # .. code-block:: http
    #
    #    GET /v1.0/account/show-container?id=AUTH_demo&container=buck0 HTTP/1.1
    #    Host: 127.0.0.1:6013
    #    User-Agent: curl/7.47.0
    #    Accept: */*
    #
    # Sample response:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 200 OK
    #    Server: gunicorn/19.9.0
    #    Date: Wed, 01 Aug 2018 12:17:25 GMT
    #    Connection: keep-alive
    #    Content-Type: application/json
    #    Content-Length: 128
    #
    # .. code-block:: json
    #
    #    {
    #      "bucket": "buck0",
    #      "bytes": 2052,
    #      "dtime": "0",
    #      "mtime": "1583772880.48631",
    #      "name": "buck0",
    #      "objects": 2,
    #      "replication_enabled": false
    #    }
    #
    # }}ACCT
    @access_log
    @force_master
    def on_account_container_show(self, req, **kwargs):
        account_id = self._get_account_id(req)
        cname = self._get_item_id(req, key='container', what='container')
        raw = self.backend.get_container_info(account_id, cname, **kwargs)
        if raw is not None:
            return Response(json.dumps(raw), mimetype=HTTP_CONTENT_TYPE_JSON)
        return NotFound('Container not found')

    @access_log
    def on_iam_delete_user_policy(self, req, **kwargs):
        account = self._get_item_id(req, key='account', what='account')
        user = self._get_item_id(req, key='user', what='user')
        policy_name = req.args.get('policy-name', '')
        self.iam.delete_user_policy(account, user, policy_name)
        return Response(status=204)

    @access_log
    def on_iam_get_user_policy(self, req, **kwargs):
        account = self._get_item_id(req, key='account', what='account')
        user = self._get_item_id(req, key='user', what='user')
        policy_name = req.args.get('policy-name', '')
        policy = self.iam.get_user_policy(account, user, policy_name)
        if not policy:
            return NotFound('User policy not found')
        return Response(policy, mimetype=HTTP_CONTENT_TYPE_JSON)

    @access_log
    def on_iam_list_users(self, req, **kwargs):
        account = self._get_item_id(req, key='account', what='account')
        users = self.iam.list_users(account)
        res = {'Users': users}
        return Response(json.dumps(res), mimetype=HTTP_CONTENT_TYPE_JSON)

    @access_log
    def on_iam_list_user_policies(self, req, **kwargs):
        account = self._get_item_id(req, key='account', what='account')
        user = self._get_item_id(req, key='user', what='user')
        policies = self.iam.list_user_policies(account, user)
        res = {'PolicyNames': policies}
        return Response(json.dumps(res), mimetype=HTTP_CONTENT_TYPE_JSON)

    @access_log
    def on_iam_put_user_policy(self, req, **kwargs):
        account = self._get_item_id(req, key='account', what='account')
        user = self._get_item_id(req, key='user', what='user')
        policy_name = req.args.get('policy-name', '')
        policy = req.get_data()
        if not policy:
            return BadRequest('Missing policy document')
        policy = policy.decode('utf-8')
        self.iam.put_user_policy(account, user, policy, policy_name)
        return Response(status=201)


def create_app(conf, **kwargs):
    logger = get_logger(conf)
    iam_conn = conf.get('iam.connection')
    if not iam_conn:
        ns_conf = load_namespace_conf(conf['namespace'], failsafe=True)
        iam_conn = ns_conf.get('iam.connection', DEFAULT_IAM_CONNECTION)
    if iam_conn == DEFAULT_IAM_CONNECTION:
        logger.warning('Using the default connection (%s) is probably '
                       'not what you want to do.', DEFAULT_IAM_CONNECTION)
    scheme, netloc, iam_kwargs = parse_conn_str(iam_conn)
    if scheme == 'redis+sentinel':
        iam_kwargs['sentinel_hosts'] = netloc
    else:
        iam_kwargs['host'] = netloc
    backend = AccountBackend(conf)
    iam_db = RedisIamDb(logger=logger, **iam_kwargs)
    app = Account(conf, backend, iam_db, logger=logger)
    return app
