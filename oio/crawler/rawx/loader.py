# Copyright (C) 2021 OVH SAS
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

from oio.event import loader


class _Handler(loader._Handler):
    egg_protocols = ["oio.crawler.rawx.handler_factory"]
    config_prefixes = ["pipeline"]


HANDLER = _Handler()


class _Filter(loader._Filter):
    egg_protocols = ["oio.crawler.rawx.filter_factory"]


FILTER = _Filter()


class ConfigLoader(loader.ConfigLoader):
    HANDLER = HANDLER
    FILTER = FILTER


def loadpipeline(path, global_conf=None, **kwargs):
    config_loader = ConfigLoader(path)
    return loader.loadhandler(config_loader, "main", global_conf, **kwargs)
