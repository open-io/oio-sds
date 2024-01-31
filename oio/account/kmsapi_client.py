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

import gevent.monkey

gevent.monkey.patch_ssl()

import json  # noqa: E402
import urllib3  # noqa: E402
import time  # noqa: E402

from oio.common.easy_value import boolean_value, float_value  # noqa: E402
from oio.common.exceptions import from_response  # noqa: E402
from oio.common.logger import get_logger  # noqa: E402
from oio.common.statsd import get_statsd  # noqa: E402
from oio.common.utils import get_hasher  # noqa: E402


class KmsApiClient(object):
    """Simple client for the external KMS API."""

    def __init__(self, conf, logger, **kwargs):
        self.logger = logger or get_logger(conf)
        self.enabled = boolean_value(conf.get("kmsapi_enabled"))
        self.endpoint = conf.get("kmsapi_endpoint")
        self.key_id = conf.get("kmsapi_key_id")
        self.http = urllib3.PoolManager(
            cert_reqs="CERT_REQUIRED",
            ca_certs=conf.get("kmsapi_ca_certs_file"),
            cert_file=conf.get("kmsapi_cert_file"),
            key_file=conf.get("kmsapi_key_file"),
            timeout=urllib3.Timeout(
                connect=float_value(conf.get("kmsapi_connect_timeout"), 1.0),
                read=float_value(conf.get("kmsapi_read_timeout"), 1.0),
            ),
        )
        self.statsd = get_statsd(conf=conf)

    def checksum(self, data=b""):
        """Get the blake3 checksum of the provided data."""
        hasher = get_hasher("blake3")
        hasher.update(data)
        return hasher.hexdigest()

    def request(self, method, url, body, headers, label):
        start_time = time.monotonic()
        try:
            resp = self.http.request(
                method,
                f"{self.endpoint}/v1/{url}",
                body=body,
                headers=headers,
            )
            status = resp.status
        except Exception as exc:
            self.logger.exception(exc)
            status = type(exc).__name__
            raise exc
        finally:
            duration = time.monotonic() - start_time
            self.statsd.timing(
                f"openio.account.kmsapi.{label}.{status}.timing",
                duration * 1000,  # in milliseconds
            )
        if status != 200:
            raise from_response(resp, resp.data)
        return json.loads(resp.data)

    def encrypt(self, plaintext, context):
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
        return self.request(
            "POST",
            f"servicekey/{self.key_id}/encrypt",
            body=json.dumps(
                {
                    "plaintext": plaintext,
                    "context": self.checksum(context),
                }
            ),
            headers={"Content-Type": "application/json"},
            label="encrypt",
        )

    def decrypt(self, key_id, ciphertext, context):
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
        return self.request(
            "POST",
            f"servicekey/{key_id}/decrypt",
            body=json.dumps(
                {
                    "ciphertext": ciphertext,
                    "context": self.checksum(context),
                }
            ),
            headers={"Content-Type": "application/json"},
            label="decrypt",
        )
