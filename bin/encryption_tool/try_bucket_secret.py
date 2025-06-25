#!/usr/bin/env python

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

import argparse
import json
import sys

from oio.common.encryption import Decrypter, decode_secret, hmac_etag

ROOT_KEY = b"Next-Gen Object Storage & Serverless Computing\n"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="try bucket_secret tool")
    parser.add_argument(
        "--metadata",
        type=str,
        default="metadata.json",
        help="path of object metadata json file",
    )
    parser.add_argument(
        "--account",
        type=str,
        required=True,
        help="name of the account in which the object is stored",
    )
    parser.add_argument(
        "--container",
        type=str,
        required=True,
        help="name of the container in which the object is stored",
    )
    parser.add_argument(
        "--obj", type=str, required=True, help="name of the object to fetch"
    )
    parser.add_argument(
        "--bucket_secret",
        type=str,
        required=True,
        help="bucket_secret can be providied",
    )
    args = parser.parse_args()

    # Read metadata
    with open(args.metadata, "r") as infile:
        metadata = json.load(infile)
        infile.close()

    # Use bucket secret to decrypt X-Object-Sysmeta-Crypto-Etag, use this ETag
    # and object_key to calculate the HMAC, the result should be the same as the
    # metadata key X-Object-Sysmeta-Crypto-Etag-Mac.
    decrypter = Decrypter(
        root_key=ROOT_KEY,
        account=args.account,
        container=args.container,
        obj=args.obj,
        metadata=metadata,
        bucket_secret=args.bucket_secret,
    )
    etag_from_metadata = decrypter.get_decrypted_etag(metadata=metadata)

    print(
        "Calculate HMAC with ETag from X-Object-Sysmeta-Crypto-Etag metadata and \
    provided key:"
    )
    object_key = decode_secret(args.bucket_secret)
    etag_from_metadata_hmac = hmac_etag(object_key, etag_from_metadata)
    print(etag_from_metadata_hmac)

    print("HMAC from X-Object-Sysmeta-Crypto-Etag-Mac metadata:")
    etag_mac_from_metadata = metadata.get("properties").get(
        "x-object-sysmeta-crypto-etag-mac"
    )
    print(etag_mac_from_metadata)

    if etag_from_metadata_hmac == etag_mac_from_metadata:
        print("The provided key is the RIGHT key!")
        sys.exit(0)
    else:
        print("The provided key is the WRONG key.")
        sys.exit(1)
