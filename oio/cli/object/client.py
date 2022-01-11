# Copyright (C) 2017-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2022 OVH SAS
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
from oio.api.object_storage import ObjectStorageApi

LOG = getLogger(__name__)

API_NAME = 'storage'


def make_client(instance):
    client = ObjectStorageApi(
        endpoint=instance.get_endpoint(),
        namespace=instance.namespace,
        admin_mode=instance.admin_mode,
        perfdata=instance.cli_conf().get('perfdata')
    )
    return client
