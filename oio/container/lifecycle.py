# Copyright (C) 2017-2019 OpenIO SAS, as part of OpenIO SDS
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

import json

from oio.common.logger import get_logger


LIFECYCLE_PROPERTY_KEY = "X-Container-Sysmeta-S3Api-Lifecycle"
TAGGING_KEY = "x-object-sysmeta-swift3-tagging"


class ContainerLifecycle(object):
    def __init__(self, api, account, container, logger=None):
        self.api = api
        self.account = account
        self.container = container
        self.logger = logger or get_logger(None, name=str(self.__class__))
        self.conf_json = None

    def get_configuration(self):
        """
        Get lifecycle configuration from container property.
        """
        props = self.api.container_get_properties(self.account, self.container)
        return props["properties"].get(LIFECYCLE_PROPERTY_KEY)

    def load(self):
        """
        Load lifecycle conf from container property.

        :returns: True if a lifecycle configuration has been loaded
        """
        json_conf = self.get_configuration()
        if not json_conf:
            self.logger.info(
                "No Lifecycle configuration for %s/%s", self.account, self.container
            )
            return False
        try:
            self.load_json(json_conf)
        except ValueError as err:
            self.logger.warning("Failed to decode JSON configuration: %s", err)
            return False
        return True

    def load_json(self, json_str):
        """
        Load lifecycle json dict from LifecycleConfiguration string.

        :raises ValueError: if the string is not decodable as JSON
        """
        json_conf = json.loads(json_str)
        self.conf_json = json_conf

    def __str__(self):
        return json.dumps(self.conf_json)

    def save(self, json_str=None):
        """
        Save the lifecycle configuration in container property.

        :param json_str: the configuration to save, or None to save the
        configuration that has been loaded previously
        :type json_str: `str`
        """
        if json_str is None:
            json_str = str(self)
        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: json_str}
        )
