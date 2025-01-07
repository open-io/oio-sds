# Copyright (C) 2023-2024 OVH SAS
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

import re

from oio.common.exceptions import CorruptDb
from oio.crawler.meta2.filters.base import Meta2Filter
from oio.crawler.meta2.meta2db import Meta2DB

RE_MISSING_FROM_INDEX = re.compile(r"row \d+ missing from index (.+)")
RE_WRONG_NUMBER_IN_INDEX = re.compile(r"wrong # of entries in index (.+)")


class Meta2IntegrityCheck(Meta2Filter):
    """
    Check Meta2 database integrity, repair if possible.
    """

    NAME = "IntegrityCheck"

    def init(self):
        super().init()
        self.broken_index = 0
        self.corrupt = 0
        self.errors = 0
        self.healthy = 0

    def _get_filter_stats(self):
        return {
            "broken_index": self.broken_index,
            "corrupt": self.corrupt,
            "errors": self.errors,
            "healthy": self.healthy,
        }

    def _reset_filter_stats(self):
        self.broken_index = 0
        self.corrupt = 0
        self.errors = 0
        self.healthy = 0

    def _process(self, env, cb):
        # 1. Make a "reflink" copy of the database (or just a hardlink?)
        # 2. Check integrity
        # TODO(FVE):
        # 3. Check if there is an election running
        # 4.a. If master, trigger a repair and then sync
        # 4.b. If slave, just warn
        with Meta2DB(self.app_env, env, use_reflink=True) as meta2db:
            self.check_integrity(meta2db)
        return self.app(env, cb)

    def analyze_integrity_results(self, results):
        """
        Analyze the results of an "integrity_check".

        :returns: the set of indices that need reindexing
        """
        errors = []
        to_reindex = set()
        for result in results:
            for line in result[0].splitlines():
                for regex in (RE_MISSING_FROM_INDEX, RE_WRONG_NUMBER_IN_INDEX):
                    match = regex.search(line)
                    if match:
                        to_reindex.add(match.group(1))
                        break
                else:
                    if line != "ok":
                        errors.append(line)
        if errors:
            raise CorruptDb("\n".join(errors))
        return to_reindex

    def check_integrity(self, meta2db):
        """
        Run some integrity checks on the provided database.
        """
        try:
            results = meta2db.execute_sql("PRAGMA integrity_check;")
            to_reindex = self.analyze_integrity_results(results)
            if to_reindex:
                self.broken_index += 1
                self.logger.warning(
                    "[%s] Database %s has corrupt indices: %s",
                    self.NAME,
                    meta2db.cid,
                    to_reindex,
                )
        except CorruptDb as exc:
            self.corrupt += 1
            self.logger.warning(
                "[%s] Database %s is corrupt: %s", self.NAME, meta2db.cid, exc
            )
        except Exception as exc:
            self.errors += 1
            self.logger.error(
                "[%s] Failed to analyze %s: %s", self.NAME, meta2db.cid, exc
            )
        else:
            self.healthy += 1


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def integrity_filter(app):
        return Meta2IntegrityCheck(app, conf)

    return integrity_filter
