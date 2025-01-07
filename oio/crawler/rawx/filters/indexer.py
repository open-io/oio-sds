# Copyright (C) 2021-2024 OVH SAS
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

import errno

from oio.common import exceptions as exc
from oio.common.green import time
from oio.common.http_urllib3 import get_pool_manager
from oio.common.utils import request_id
from oio.crawler.common.base import Filter
from oio.crawler.rawx.chunk_wrapper import ChunkWrapper, RawxCrawlerError
from oio.rdir.client import RdirClient


class Indexer(Filter):
    NAME = "Indexer"

    def init(self):
        self.successes = 0
        self.errors = 0

        self.volume_id = self.app_env["volume_id"]

        # This is indexing one volume only, no need for many connections
        pool_manager = get_pool_manager(pool_connections=5)
        self.index_client = RdirClient(
            self.conf, logger=self.logger, pool_manager=pool_manager
        )

    def error(self, chunk, container_id, msg):
        self.logger.error(
            "volume_id=%(volume_id)s "
            "container_id=%(container_id)s "
            "chunk_id=%(chunk_id)s "
            "%(error)s"
            % {
                "volume_id": chunk.volume_id,
                "container_id": container_id,
                "chunk_id": chunk.chunk_id,
                "error": msg,
            }
        )

    def update_index(self, chunk):
        self.index_client.chunk_push(
            self.volume_id,
            chunk.meta["container_id"],
            chunk.meta["content_id"],
            chunk.meta["chunk_id"],
            chunk.meta["content_path"],
            chunk.meta["content_version"],
            mtime=int(time.time()),
            reqid=request_id("blob-indexer-"),
        )

    def process(self, env, cb):
        chunk = ChunkWrapper(env)
        path = chunk.chunk_path

        body = None
        ret = 0
        try:
            self.update_index(chunk)
            self.successes += 1
            self.logger.debug("Updated %s", path)
        except (
            exc.OioNetworkException,
            exc.ChunkException,
            exc.MissingAttribute,
        ) as err:
            self.errors += 1
            ret = 1
            body = f"ERROR while updating {path}: {err}"
        except Exception as err:
            # We cannot compare errno in the 'except' line.
            # pylint: disable=no-member
            if isinstance(err, IOError) and err.errno == errno.ENOENT:
                self.logger.debug("Chunk %s disappeared before indexing", path)
                # Neither an error nor a success, do not touch counters.
            else:
                self.errors += 1
                ret = 1
                body = f"ERROR while updating {path}: {err}"

        if ret != 0:
            resp = RawxCrawlerError(chunk=chunk, body=body)
            return resp(env, cb)
        return self.app(env, cb)

    def _get_filter_stats(self):
        return {"successes": self.successes, "errors": self.errors}

    def _reset_filter_stats(self):
        self.successes = 0
        self.errors = 0


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def indexer_filter(app):
        return Indexer(app, conf)

    return indexer_filter
