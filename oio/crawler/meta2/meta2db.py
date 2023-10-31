# Copyright (C) 2021-2023 OVH SAS
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

import os
import sqlite3

import reflink

from functools import partial

from oio.common.easy_value import debinarize
from oio.common.exceptions import CorruptDb


def _meta2db_env_property(field, fetch_value_function=None):
    def getter(self):
        value = self.env.get(field, None)
        if value is None and fetch_value_function:
            value = fetch_value_function(self)
            self.env[field] = value
        return value

    def setter(self, value):
        self.env[field] = value

    return property(getter, setter)


def _fetch_file_status(meta2db):
    file_status = os.stat(meta2db.path)
    return {k: getattr(file_status, k) for k in dir(file_status) if k.startswith("st_")}


def _fetch_system(meta2db):
    meta2db_conn = None
    try:
        meta2db_conn = sqlite3.connect(f"file:{meta2db.path}?mode=ro", uri=True)
    except sqlite3.OperationalError:
        # Check if the meta2 database still exists
        try:
            os.stat(meta2db.path)
        except FileNotFoundError:
            raise
        except Exception:
            pass
        raise
    try:
        system = {}
        meta2db_cursor = meta2db_conn.cursor()
        for key, value in meta2db_cursor.execute(
            'SELECT k, v FROM admin WHERE k LIKE "sys.%"'
        ).fetchall():
            system[key] = value
        return debinarize(system)
    finally:
        meta2db_conn.close()


class Meta2DB:
    """
    Access a meta2 database file directly, through sqlite3, not through meta2 services.

    :param use_reflink: create a filesystem reflink to the database.
                        This allows to bypass sqlite's locks.
                        In case reflinks are not supported,
                        a hardlink will be created instead.
    """

    real_path = _meta2db_env_property("path")
    volume_id = _meta2db_env_property("volume_id")
    cid = _meta2db_env_property("cid")
    seq = _meta2db_env_property("seq")
    file_status = _meta2db_env_property(
        "file_status", fetch_value_function=_fetch_file_status
    )
    system = _meta2db_env_property("admin_table", fetch_value_function=_fetch_system)

    def __init__(self, app_env, env, use_reflink=False):
        self.app_env = app_env
        self.env = env
        self.api = self.app_env["api"]
        self.use_reflink = use_reflink

    def __repr__(self):
        return f"Meta2DB [{self.volume_id},{self.cid}.{self.seq}]"

    def __enter__(self):
        if self.use_reflink:
            try:
                reflink.reflink(self.real_path, self.path)
            except reflink.ReflinkImpossibleError:
                os.link(self.real_path, self.path)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.use_reflink:
            os.unlink(self.path)

    @property
    def path(self):
        if self.use_reflink:
            return self.real_path + ".link"
        return self.real_path

    def execute_sql(self, statement, params=(), open_mode="ro"):
        """
        Execute an SQL statement, return the list of all results.

        By default, the database is open in readonly mode.
        """
        meta2db_conn = sqlite3.connect(f"file:{self.path}?mode={open_mode}", uri=True)
        try:
            res = meta2db_conn.execute(statement, params)
            return res.fetchall()
        except sqlite3.DatabaseError as sqerr:
            if "database disk image is malformed" in str(sqerr):
                raise CorruptDb(str(sqerr)) from sqerr
            raise sqerr
        finally:
            meta2db_conn.close()


class Response(object):
    def __init__(self, meta2db, body=None, status=200, **kwargs):
        self.meta2db = meta2db
        self.body = body
        self.status = status
        self.env = meta2db.env

    def __call__(self, env, cb):
        if not self.body:
            self.body = ""
        cb(self.status, self.body)


class Meta2DBException(Response, Exception):
    def __init__(self, *args, **kwargs):
        Response.__init__(self, *args, **kwargs)
        Exception.__init__(self, self.status)


class StatusMap(object):
    def __getitem__(self, key):
        return partial(Meta2DBException, status=key)


status_map = StatusMap()
Meta2DBOk = status_map[200]
Meta2DBNotFound = status_map[404]
Meta2DBError = status_map[500]
