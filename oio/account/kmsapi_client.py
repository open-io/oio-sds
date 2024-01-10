# Copyright (C) 2023-2024 OVH SAS
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
import time

from oio.api.base import HttpApi
from oio.common import exceptions
from oio.common.easy_value import boolean_value
from oio.common.logger import get_logger
from oio.common.statsd import get_statsd
from oio.common.utils import get_hasher


class KmsApiClient(HttpApi):
    """Simple client for the external KMS API."""

    def __init__(self, conf, logger, **kwargs):
        self.logger = logger or get_logger(conf)
        self.key_id = conf.get("kmsapi_key_id")
        self.enabled = boolean_value(conf.get("kmsapi_enabled"))
        super(KmsApiClient, self).__init__(
            service_type="kmsapi",
            endpoint=conf.get("kmsapi_endpoint"),
            cert_reqs="CERT_REQUIRED",
            ca_certs=conf.get("kmsapi_ca_certs_file"),
            cert_file=conf.get("kmsapi_cert_file"),
            key_file=conf.get("kmsapi_key_file"),
            **kwargs,
        )
        self.statsd = get_statsd(conf=conf)

    def send_to_statsd(self, label, status, start_time):
        duration = time.monotonic() - start_time
        self.statsd.timing(
            f"openio.account.kmsapi.{label}.{status}.timing",
            duration * 1000,  # in milliseconds
        )

    def checksum(self, data=b""):
        """Get the blake3 checksum of the provided data."""
        hasher = get_hasher("blake3")
        hasher.update(data)
        return hasher.hexdigest()

    def encrypt(self, plaintext, context, **kwargs):
        """
        Encrypts data, up to 4Kb in size, using service key provided.

        :param plaintext: String to be encrypted
        :param context: Additional authenticated data
        :returns: a dictionary with details about the encrypted secret

        Return example:
            {
                "ciphertext": "string",
                "context": {
                    "key_id": "string",
                    "key_version": 0
                }
            }
        """
        start_time = time.monotonic()
        resp, body = self._request(
            "POST",
            f"v1/servicekey/{self.key_id}/encrypt",
            json={"plaintext": plaintext, "context": self.checksum(context)},
            **kwargs,
        )
        self.send_to_statsd("encrypt", resp.status, start_time)
        if resp.status != 200:
            raise exceptions.from_response(resp, body)
        return json.loads(body)

    def decrypt(self, key_id, ciphertext, context, **kwargs):
        """
        Decrypts data previously encrypted with the encrypt method.

        :param ciphertext: String to be decrypted
        :param context: Use the same context provided in encrypt operation
        :returns: a dictionnary with details about decrypted ciphertext

        Return example:
        {
            "plaintext": "string",
            "context": {
                "key_id": "string",
                "key_version": 0
            }
        }
        """
        start_time = time.monotonic()
        resp, body = self._request(
            "POST",
            f"v1/servicekey/{key_id}/decrypt",
            json={"ciphertext": ciphertext, "context": self.checksum(context)},
            **kwargs,
        )
        self.send_to_statsd("decrypt", resp.status, start_time)
        if resp.status != 200:
            raise exceptions.from_response(resp, body)
        return json.loads(body)
