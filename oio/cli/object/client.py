# Copyright (C) 2017 OpenIO SAS, as part of OpenIO SDS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from logging import getLogger
from oio.api.object_storage import ObjectStorageApi

LOG = getLogger(__name__)

API_NAME = 'storage'


def make_client(instance):
    client = ObjectStorageApi(
        endpoint=instance.get_endpoint('storage'),
        namespace=instance.namespace,
        admin_mode=instance.admin_mode,
        perfdata=instance.cli_conf().get('perfdata')
    )
    return client
