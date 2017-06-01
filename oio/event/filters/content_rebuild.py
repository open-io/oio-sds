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
import json

from oio.event.beanstalk import Beanstalk, BeanstalkError
from oio.event.evob import Event, EventError
from oio.event.filters.base import Filter
from oio import ObjectStorageApi


class ContentRebuildFilter(Filter):
    rebuild_file_default_name = "content_rebuild.txt"

    def __init__(self, app, conf,  logger=None):
        super(ContentRebuildFilter, self).__init__(app, conf, logger)
        self.object_storage_api = ObjectStorageApi(conf.get('namespace'))
        queue_url = self.conf.get('queue_url', 'tcp://127.0.0.1:11300')
        self.tube = self.conf.get('tube', 'rebuild')
        self.beanstalk = Beanstalk.from_url(queue_url)
        self.beanstalk.use(self.tube)

    def process(self, env, cb):
        data = json.dumps(env)
        try:
            self.beanstalk.put(data)
        except BeanstalkError as e:
            msg = 'put failure: %s' % str(e)
            resp = EventError(event=Event(env), body=msg)
            return resp(env, cb)
        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def rebuild_filter(app):
        return ContentRebuildFilter(app, conf)
    return rebuild_filter
