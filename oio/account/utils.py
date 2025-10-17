# Copyright (C) 2026 OVH SAS
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

from oio.common.easy_value import boolean_value, float_value, int_value


def initialize_kms_clients(app):
    """Initialize kms client for each domain

    :param app: instance responsible for initializing the KmsApiClient.
        It should provide a configuration for each KMS domain.
    :type app: Object
    """
    kmsapi_mock_server = boolean_value(app.conf.get("kmsapi_mock_server"))
    for domain in app.kms_api.domains:
        endpoint = app.conf.get(f"kmsapi_{domain}_endpoint")
        key_id = app.conf.get(f"kmsapi_{domain}_key_id")
        cert_file = app.conf.get(f"kmsapi_{domain}_cert_file")
        key_file = app.conf.get(f"kmsapi_{domain}_key_file")
        connect_timeout = float_value(
            app.conf.get(f"kmsapi_{domain}_connect_timeout"), 1.0
        )
        read_timeout = float_value(app.conf.get(f"kmsapi_{domain}_read_timeout"), 1.0)
        pool_maxsize = int_value(app.conf.get(f"kmsapi_{domain}_pool_maxsize"), 32)
        app.kms_api.add_client(
            domain,
            endpoint,
            key_id,
            cert_file,
            key_file,
            connect_timeout,
            read_timeout,
            pool_maxsize,
            app.logger,
            app.statsd,
            kmsapi_mock_server=kmsapi_mock_server,
        )
        app.kmsapi_domains.append(domain)
