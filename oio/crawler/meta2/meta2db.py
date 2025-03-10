# Copyright (C) 2021-2025 OVH SAS
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
from functools import partial

import reflink

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


def delete_meta2_db(cid, path, suffix, volume_id, admin_client, logger):
    """Delete meta2 db specified"""
    try:
        params = {
            "service_type": "meta2",
            "cid": cid,
            "service_id": volume_id,
            "suffix": suffix,
        }
        res = admin_client.remove_base(**params)
        if res[volume_id]["status"]["status"] != 200:
            logger.warning(
                "Request to remove the meta2db copy failed, "
                "cid = %s meta2db path %s error msg %s",
                cid,
                path + "." + suffix,
                res[volume_id]["status"]["message"],
            )
            return False
    except Exception as exc:
        logger.exception(
            "Failed to remove this meta2db copy %s: %s.",
            path + "." + suffix,
            exc,
        )
        return False
    return True


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
    suffix = _meta2db_env_property("suffix")
    file_status = _meta2db_env_property(
        "file_status", fetch_value_function=_fetch_file_status
    )
    to_remove = _meta2db_env_property("to_remove", lambda _: False)

    def _fetch_system(self):
        system = {}
        for key, value in self.execute_sql(
            'SELECT k, v FROM admin WHERE k LIKE "sys.%"'
        ):
            system[key] = value
        return debinarize(system)

    system = _meta2db_env_property(
        "admin_table",
        fetch_value_function=_fetch_system,
    )

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

    @property
    def is_copy(self):
        return self.suffix is not None

    def execute_sql(self, statement, params=(), open_mode="ro"):
        """
        Execute an SQL statement, return the list of all results.

        By default, the database is open in readonly mode.
        """
        meta2db_conn = None
        try:
            meta2db_conn = sqlite3.connect(
                f"file:{self.path}?mode={open_mode}",
                uri=True,
            )
            res = meta2db_conn.execute(statement, params)
            return res.fetchall()
        except sqlite3.DatabaseError as sqerr:
            if "database disk image is malformed" in str(sqerr):
                raise CorruptDb(str(sqerr)) from sqerr
            try:
                os.stat(self.path)
            except FileNotFoundError:
                raise
            except Exception:
                pass
            raise sqerr
        finally:
            if open_mode == "rw":
                meta2db_conn.commit()
            if meta2db_conn:
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
