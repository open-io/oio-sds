# Copyright (C) 2023 OVH SAS
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

from oio.crawler.rawx.filters.logger import Logger as RawxLogger
from oio.crawler.rawx.chunk_wrapper import ChunkWrapper


class Logger(RawxLogger):
    def process(self, env, cb):
        chunk = ChunkWrapper(env)
        self.logger.info(
            "Chunk %s identified as orphaned into volume_id=%s", chunk, self.volume_id
        )
        self.successes += 1
        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def logger_filter(app):
        return Logger(app, conf)

    return logger_filter
