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

from oio.crawler.common.crawler import Crawler
from oio.crawler.rdir.workers.rawx_worker import RdirWorkerForRawx
from oio.crawler.rdir.workers.meta2_worker import RdirWorkerForMeta2


def worker_class_for_type(conf):
    """Retrieves the right rdirworker according to volume to crawl"""
    volume_type = conf.get("volume_type", "rawx")
    if volume_type == RdirWorkerForMeta2.SERVICE_TYPE:
        return RdirWorkerForMeta2
    else:
        return RdirWorkerForRawx


class RdirCrawler(Crawler):
    """
    This crawler has a different behavior according to the type of volume.

    If the volume hosts a rawx service,
    periodically check that chunks in rdir really exist in rawx.
    In case a chunk does not exist in rawx, try to rebuild it.
    In case a chunk is not referenced in meta2, deindex it.

    If the volume hosts a meta2 service,
    periodically check that containers in rdir really exist in meta2.
    In case a container does not exist in meta2, deindex it.
    """

    CRAWLER_TYPE = "rdir"

    def __init__(self, conf, conf_file=None, **kwargs):
        worker_class = worker_class_for_type(conf)
        super().__init__(conf, conf_file=conf_file, worker_class=worker_class, **kwargs)
