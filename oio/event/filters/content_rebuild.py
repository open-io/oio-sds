# Copyright (C) 2017 OpenIO, original work as part of
# OpenIO Software Defined Storage
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
from oio.common.exceptions import ContentNotFound, NotFound, MissingData
from oio.event.filters.base import Filter
from oio.event.evob import Event
from oio.event.consumer import EventTypes
from oio.common.storage_method import STORAGE_METHODS
from oio.content.plain import PlainContent
from oio.content.ec import ECContent
from oio import ObjectStorageApi


class ContentRebuildFilter(Filter):

    def __init__(self, app, conf,  logger=None):
        super(ContentRebuildFilter, self).__init__(app, conf, logger)
        self.object_storage_api = ObjectStorageApi(conf.get('namespace'))

    def _get_content(self, container_id, meta, chunks, storage_method):
        cls = ECContent if storage_method.ec else PlainContent
        return cls(self.conf, container_id, meta, chunks, storage_method)

    def process(self, env, cb):
        event = Event(env)

        if event.event_type == EventTypes.CONTENT_BROKEN:
            url = event.env.get('url')
            container_name = url['user']
            content_name = url['path']
            account = url['account']
            meta = {}
            try:
                meta, _ = self.object_storage_api.object_analyze(
                                container=container_name, obj=content_name,
                                account=account)
            except NotFound:
                raise ContentNotFound("Content %s/%s not found" %
                                      (container_name, content_name))
            present_chunks = event.data['present_chunks']
            for chunk in present_chunks:
                chunk["url"] = chunk.pop("id")
            missing_chunks = event.data['missing_chunks']
            if len(missing_chunks) == 0:
                raise MissingData("No missing chunks found")
            chunk_method = meta['chunk_method']
            storage_method = STORAGE_METHODS.load(chunk_method)
            content = self._get_content(url['id'], meta,
                                        present_chunks,
                                        storage_method)
            for chunk_pos in missing_chunks:
                    content.rebuild_chunk(None, chunk_pos=chunk_pos)

        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def rebuild_filter(app):
        return ContentRebuildFilter(app, conf)
    return rebuild_filter
