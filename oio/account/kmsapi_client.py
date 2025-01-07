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
import time  # noqa: E402

import urllib3  # noqa: E402

from oio.common.easy_value import boolean_value  # noqa: E402
from oio.common.exceptions import from_response  # noqa: E402
from oio.common.logger import get_logger  # noqa: E402
from oio.common.utils import get_hasher  # noqa: E402


class HttpClient(object):
    """Http client for a given KMS domain"""

    def __init__(
        self,
        domain,
        endpoint,
        key_id,
        cert_file,
        key_file,
        connect_timeout,
        read_timeout,
        pool_maxsize,
        logger,
        statsd,
        kmsapi_mock_server=False,
    ):
        self.logger = logger
        self.domain = domain
        self.endpoint = endpoint
        self.key_id = key_id
        self.statsd = statsd
        pool_manager_kwargs = {
            "num_pools": 1,
            "maxsize": pool_maxsize,
            "retries": 0,
            "block": True,
        }
        if not kmsapi_mock_server:
            pool_manager_kwargs.update(
                {
                    "cert_reqs": "CERT_REQUIRED",
                    "cert_file": cert_file,
                    "key_file": key_file,
                    "timeout": urllib3.Timeout(
                        connect=connect_timeout,
                        read=read_timeout,
                    ),
                }
            )
        self.http = urllib3.PoolManager(**pool_manager_kwargs)

    def request(self, action, body, key_id=None):
        if key_id is None:
            key_id = self.key_id
        url = f"{self.endpoint}/v1/servicekey/{key_id}/{action}"

        start_time = time.monotonic()
        try:
            resp = self.http.request(
                "POST",
                url,
                body=body,
                headers={"Content-Type": "application/json"},
            )
            status = resp.status
        except Exception as exc:
            self.logger.exception(exc)
            status = type(exc).__name__
            raise exc
        finally:
            duration = time.monotonic() - start_time
            self.statsd.timing(
                f"openio.account.kmsapi.{self.domain}.{action}.{status}.timing",
                duration * 1000,  # in milliseconds
            )
        if status != 200:
            raise from_response(resp, resp.data)

        # Inject the key_id associated to the request into the response
        json_data = json.loads(resp.data)
        json_data["key_id"] = key_id

        return json_data


class KmsApiClient(object):
    """Simple client for the external KMS API."""

    def __init__(self, conf, logger, **kwargs):
        self.conf = conf
        self.logger = logger or get_logger(conf)
        self.enabled = boolean_value(conf.get("kmsapi_enabled"))
        if self.enabled:
            self.domains = [
                d.strip().lower()
                for d in conf.get("kmsapi_domains", "").split(",")
                if d
            ]
            if not self.domains:
                raise ValueError("No KMS domain found")
            if len(self.domains) != len(set(self.domains)):
                raise ValueError("Duplicate KMS domains")
        self.domain_to_client = {}

    def add_client(
        self,
        domain,
        endpoint,
        key_id,
        cert_file,
        key_file,
        connect_timeout,
        read_timeout,
        pool_maxsize,
        logger,
        statsd,
        kmsapi_mock_server=False,
    ):
        client = HttpClient(
            domain,
            endpoint,
            key_id,
            cert_file,
            key_file,
            connect_timeout,
            read_timeout,
            pool_maxsize,
            logger,
            statsd,
            kmsapi_mock_server=kmsapi_mock_server,
        )
        self.domain_to_client[domain] = client

    def checksum(self, data=b""):
        """Get the blake3 checksum of the provided data."""
        hasher = get_hasher("blake3")
        hasher.update(data)
        return hasher.hexdigest()

    def encrypt(self, domain, plaintext, context):
        """
        Encrypts data, up to 4Kb in size.

        :param domain: KMS domain to request
        :param plaintext: String to be encrypted
        :param context: Additional authenticated data
        :returns: a dictionary with details about the encrypted secret

        Return example:
            {
                "ciphertext": "string",
            }
        """
        try:
            client = self.domain_to_client[domain]
        except KeyError:
            raise Exception(f"No client found for domain {domain}")

        return client.request(
            action="encrypt",
            body=json.dumps(
                {
                    "plaintext": plaintext,
                    "context": self.checksum(context),
                }
            ),
        )

    def decrypt(self, domain, key_id, ciphertext, context):
        """
        Decrypts data previously encrypted with the encrypt method.

        :param key_id: KMS domain to request
        :param key_id: KMS domain key_id used to encrypt the secret
        :param ciphertext: String to be decrypted
        :param context: Use the same context provided in encrypt operation
        :returns: a dictionary with details about decrypted ciphertext

        Return example:
        {
            "plaintext": "string",
        }
        """
        try:
            client = self.domain_to_client[domain]
        except KeyError:
            raise Exception(f"No client found for domain {domain}")

        return client.request(
            action="decrypt",
            body=json.dumps(
                {
                    "ciphertext": ciphertext,
                    "context": self.checksum(context),
                }
            ),
            key_id=key_id,
        )
