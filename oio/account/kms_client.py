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

from oio.common.service_client import ServiceClient


class KmsClient(ServiceClient):
    """Simple client API for the KMS service."""

    def __init__(self, conf, **kwargs):
        super().__init__(
            "account", conf, service_name="kms", request_prefix="v1.0/kms", **kwargs
        )

    def kms_request(self, account, bucket, *args, **kwargs):
        """Send a generic request to the KMS service."""
        params = kwargs.setdefault("params", {})
        params["account"] = account
        params["bucket"] = bucket
        return self.service_request(*args, **kwargs)

    def create_secret(self, account, bucket, secret_id="1", secret_bytes=32, **kwargs):
        """
        Create and return a secret for the bucket.

        :param secret_bytes: the number of bytes of the secret to generate. Notice
                             that the output is base64-encoded, thus it is 33% longer.
        :returns: a dictionary with details about the secret, including the
                  base64-encoded secret
        """
        resp, body = self.kms_request(
            account,
            bucket,
            "PUT",
            "create-secret",
            params={"secret_id": secret_id, "secret_bytes": secret_bytes},
            **kwargs,
        )
        return (resp, body)

    def delete_secret(self, account, bucket, secret_id="1", **kwargs):
        """Delete a secret associated to the bucket."""
        resp_, body_ = self.kms_request(
            account,
            bucket,
            "DELETE",
            "delete-secret",
            params={"secret_id": secret_id},
            **kwargs,
        )

    def get_secret(self, account, bucket, secret_id="1", **kwargs):
        """
        Get a secret associated to the bucket.

        :returns: a dictionary with details about the secret, including the
                  base64-encoded secret
        """
        resp_, body = self.kms_request(
            account,
            bucket,
            "GET",
            "get-secret",
            params={"secret_id": secret_id},
            **kwargs,
        )
        return body

    def list_secrets(self, account, bucket, **kwargs):
        """List the IDs of the secrets associated to the bucket."""
        resp_, body = self.kms_request(account, bucket, "GET", "list-secrets", **kwargs)
        return body
