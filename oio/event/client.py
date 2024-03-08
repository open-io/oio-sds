# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
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

import random

from oio.common.configuration import load_namespace_conf
from oio.event.beanstalk import Beanstalk


class EventClient(object):
    def __init__(self, conf, **kwargs):
        self.ns_conf = load_namespace_conf(conf["namespace"])
        for queue_url in (
            self.ns_conf["event-agent"],
            self.ns_conf.get("beanstalk", ""),
        ):
            if queue_url.startswith("beanstalk"):
                self.queue_url = queue_url.split(";")
                break
        else:
            raise ValueError(
                "The configured event-agent is not using beanstalkd, please "
                f"use another tool adapted to {self.ns_conf['event-agent']}"
            )
        self._beanstalk = None

    @property
    def beanstalk(self):
        if not self._beanstalk:
            self._beanstalk = Beanstalk.from_url(random.choice(self.queue_url))
        return self._beanstalk

    def exhume(self, limit=1000, tube=None):
        """Move buried or delayed jobs into the ready queue."""
        if tube:
            self.beanstalk.use(tube)
        return self.beanstalk.kick(bound=limit)

    def list_tubes(self):
        """
        Get the list of tubes known by the beanstalkd service behind
        the local event-agent.
        """
        return self.beanstalk.tubes()

    def stats(self, tube=None):
        tube = tube or "oio"
        return self.beanstalk.stats_tube(tube)
