# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2022-2024 OVH SAS
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

from oio.common.constants import REQID_HEADER
from oio.common.easy_value import float_value
from oio.common.green import OioTimeout, Timeout
from oio.common.http_urllib3 import urllibexc
from oio.common.json import json
from oio.conscience.stats.base import BaseStat


class HttpStat(BaseStat):
    """Fetch stats using HTTP, expects one stat per line"""

    def configure(self):
        self.parser = self.stat_conf.get("parser", "lines")
        self.path = self.stat_conf["path"].lstrip("/")
        self.host = self.stat_conf["host"]
        self.port = self.stat_conf["port"]
        self.url = f"{self.host}:{self.port}/{self.path}"
        if self.parser == "json":
            # use json parser (account and rdir style)
            self._parse_func = self._parse_stats_json
        else:
            # default to lines parser (rawx style)
            self._parse_func = self._parse_stats_lines
        self.timeout = float_value(self.stat_conf.get("timeout"), 10.0)

    @staticmethod
    def _parse_stats_lines(body):
        """Converts each line to a dictionary entry"""
        if isinstance(body, bytes):
            body = body.decode("utf-8")
        data = {}
        for line in body.splitlines():
            parts = line.rsplit(None, 1)
            nparts = len(parts)
            if nparts > 1:
                # try to cast value to int or float
                try:
                    conv_v = int(parts[1])
                except ValueError:
                    try:
                        conv_v = float(parts[1])
                    except ValueError:
                        conv_v = parts[1]
                data[parts[0]] = conv_v
            else:
                data[parts[0]] = None
        return data

    @staticmethod
    def _stat_or_tag(key, value):
        """
        Prefix each entry with 'stat.' or 'tag.' depending on the value type,
        return the length if the value is a dict or a list.
        """
        if isinstance(value, (list, dict)):
            return f"stat.{key}", len(value)
        if isinstance(value, (int, float)):
            return f"stat.{key}", value
        # str, bool, NoneType
        return f"tag.{key}", value

    def _parse_stats_json(self, body):
        """
        Parse the response body as a JSON dictionary,
        add 'stat.' or 'tag.' prefix to the keys,
        convert values to the appropriate type.
        """
        if isinstance(body, bytes):
            body = body.decode("utf-8")
        body = json.loads(body)
        uuid = body.pop("uuid", None)
        res = dict((self._stat_or_tag(k, v) for k, v in body.items()))
        if uuid:
            res["tag.uuid"] = uuid
        return res

    def get_stats(self, reqid=None):
        result = {}
        resp = None
        try:
            # We have troubles identifying connections that have been closed
            # on the remote side but not on the local side, thus we
            # explicitly require the connection to be closed.
            try:
                with OioTimeout(self.timeout):
                    resp = self.agent.pool_manager.request(
                        "GET",
                        self.url,
                        headers={"Connection": "close", REQID_HEADER: reqid},
                    )
            except Timeout as toe:
                raise Exception(str(toe)) from toe
            if resp.status == 200:
                result = self._parse_func(resp.data)
            else:
                raise Exception(f"({resp.status}) {resp.data.decode('utf-8')}")
            return result
        finally:
            if resp:
                try:
                    # Probably useless since we do not disable preload_content
                    resp.drain_conn()
                    resp.close()
                except urllibexc.HTTPError:
                    pass
