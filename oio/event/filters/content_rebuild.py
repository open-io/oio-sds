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
import csv
import ConfigParser
from oio.common.exceptions import MissingData
from oio.content.ec import ECContent
from oio.content.plain import PlainContent
from oio.event.consumer import EventTypes
from oio.event.evob import Event
from oio.event.filters.base import Filter
from oio import ObjectStorageApi


class ContentRebuildFilter(Filter):
    rebuild_file_default_name = "content_rebuild.txt"

    def __init__(self, app, conf,  logger=None):
        super(ContentRebuildFilter, self).__init__(app, conf, logger)
        self.object_storage_api = ObjectStorageApi(conf.get('namespace'))
        config = ConfigParser.ConfigParser()
        if not self.conf.get('rebuild_file'):
            self.rebuild_file = self.rebuild_file_default_name
            self.logger.warn(("Configuration file not present falling "
                              "back to default name " + self.rebuild_file))
            return
        with open(self.conf.get('rebuild_file')) as app_key_f:
            try:
                config.readfp(app_key_f)
                self.rebuild_file = config.get('content_rebuild',
                                               'rebuild_file')
            except IOError as exc:
                self.rebuild_file = self.rebuild_file_default_name
                self.logger.warn(("Could not open Content_rebuild file falling"
                                  "back to default name %s (%s)",
                                  self.rebuild_file, exc))

    def _get_content(self, container_id, meta, chunks, storage_method):
        cls = ECContent if storage_method.ec else PlainContent
        return cls(self.conf, container_id, meta, chunks, storage_method)

    def _write_chunks(self, container_id, content_id, chunk_pos):
        self.rebuild_writer.writerow((container_id, content_id, chunk_pos))

    def process(self, env, cb):
        event = Event(env)
        self.fd = open(self.rebuild_file, "a")
        self.rebuild_writer = csv.writer(self.fd, delimiter='|')
        if event.event_type == EventTypes.CONTENT_BROKEN:
            url = event.env.get('url')
            missing_chunks = event.data['missing_chunks']
            if len(missing_chunks) == 0:
                raise MissingData("No missing chunks found")

            for chunk_pos in missing_chunks:
                self._write_chunks(url["id"], url["content"], chunk_pos)
        self.fd.flush()
        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def rebuild_filter(app):
        return ContentRebuildFilter(app, conf)
    return rebuild_filter
