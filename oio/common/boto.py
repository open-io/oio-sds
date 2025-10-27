# Copyright (C) 2025 OVH SAS
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

import boto3
from botocore.config import Config


def get_boto_client(conf):
    """
    Get a boto client from a conf or a profile.
    Raises KeyError if a parameter is missing.
    """
    profile = conf.get("profile")
    if profile:
        return boto3.Session(profile_name=profile).client("s3")

    # Without profile, build the client from other parameters
    client_params = {
        "aws_access_key_id": conf["access_key"],
        "aws_secret_access_key": conf["secret_key"],
    }
    region = conf.get("region")
    if region:
        client_params["region_name"] = region
    endpoint_url = conf.get("endpoint_url")
    if endpoint_url:
        client_params["endpoint_url"] = endpoint_url

    config_kwargs = {
        "signature_version": "s3v4",
        "s3": {
            "addressing_style": "virtual",
        },
    }

    return boto3.client(
        "s3",
        **client_params,
        config=Config(**config_kwargs),
    )
