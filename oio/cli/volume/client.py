# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2024 OVH SAS
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

from logging import getLogger

LOG = getLogger(__name__)

API_NAME = "volume"


class VolumeClientCli(object):
    def __init__(self, namespace, **kwargs):
        self.conf = {"namespace": namespace}
        self.conf.update(kwargs)
        self._rdir = None
        self._rdir_lb = None

    @property
    def volume(self):
        if not self._rdir:
            from oio.rdir.client import RdirClient

            self._rdir = RdirClient(self.conf)
        return self._rdir

    @property
    def rdir_lb(self):
        if not self._rdir_lb:
            from oio.rdir.client import RdirDispatcher

            self._rdir_lb = RdirDispatcher(self.conf)
        return self._rdir_lb

    def volume_admin_show(self, volume, **kwargs):
        return self.volume.admin_show(volume, **kwargs)

    def volume_admin_clear(self, volume, **kwargs):
        return self.volume.admin_clear(volume, **kwargs)

    def volume_show(self, volume, **kwargs):
        from oio.common.json import json

        info = self.volume.status(volume, **kwargs)
        data = {}
        containers = info.get("container")
        data["chunk"] = info.get("chunk")
        for ct in containers:
            data["container.%s" % ct] = json.dumps(containers[ct])
        return data

    def volume_admin_lock(self, volume, key, **kwargs):
        return self.volume.admin_lock(volume, key, **kwargs)

    def volume_admin_unlock(self, volume, **kwargs):
        return self.volume.admin_unlock(volume, **kwargs)

    def volume_admin_incident(self, volume, date, **kwargs):
        return self.volume.admin_incident_set(volume, date, **kwargs)


def make_client(instance):
    """
    Build a VolumeClientCli that will be added as "volume"
    field of `instance`.

    :param instance: an instance of ClientManager
    :returns: an instance of VolumeClientCli
    """
    client = VolumeClientCli(**instance.cli_conf())
    return client
