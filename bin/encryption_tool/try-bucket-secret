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
import os
import sys

from oio import ObjectStorageApi
from oio.common.configuration import load_namespace_conf
from oio.common.encryption import (
    CRYPTO_BODY_META_KEY,
    Decrypter,
    create_key,
    decode_secret,
    fetch_bucket_secret,
    hmac_etag,
    load_crypto_meta,
)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=(
            "Try to decrypt an object (root-key or SSES3 only).\n"
            "If a bucket secret is provided, it will be used.\n"
            "If the object is in SSES3 and the bucket secret is not provided, it "
            "will be fetched from the account.\n"
            "If the object is encrypted with the root-key, it should be provided.\n"
            "Object metadata can be provided with --metadata, otherwise they will be "
            "downloaded automatically."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--metadata",
        type=str,
        help=(
            "path of object metadata json file (if not provided, metadata will be "
            "downloaded from oio)"
        ),
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
    parser.add_argument("--version", type=str, help="version of the object to fetch")
    parser.add_argument(
        "--bucket_secret",  # kept with _ for compatibility with scripts
        "--bucket-secret",
        type=str,
        help="bucket secret can be provided",
    )
    parser.add_argument(
        "--root-key",
        type=str,
        help="root key (base64 encoded)",
    )
    args = parser.parse_args()

    sds_namespace = os.environ.get("OIO_NS", "OPENIO")
    conf = load_namespace_conf(sds_namespace)
    api = ObjectStorageApi(sds_namespace, endpoint=f"http://{conf['proxy']}")

    if args.metadata:
        # Read metadata if provided
        with open(args.metadata, "r") as infile:
            metadata = json.load(infile)
            infile.close()
    else:
        metadata = api.object_get_properties(
            args.account,
            args.container,
            args.obj,
            version=args.version,
        )

    # Use bucket secret to decrypt X-Object-Sysmeta-Crypto-Etag, use this ETag
    # and object_key to calculate the HMAC, the result should be the same as the
    # metadata key X-Object-Sysmeta-Crypto-Etag-Mac.
    root_key = decode_secret(args.root_key, root_secret=True) if args.root_key else None
    decrypter = Decrypter(
        root_key=root_key,
        account=args.account,
        container=args.container,
        obj=args.obj,
        metadata=metadata,
        bucket_secret=args.bucket_secret,
        api=api,
    )
    etag_from_metadata = decrypter.get_decrypted_etag(metadata=metadata)

    print(
        "Calculate HMAC with ETag from X-Object-Sysmeta-Crypto-Etag metadata and "
        "provided key:"
    )

    crypto_meta = load_crypto_meta(metadata.get("properties").get(CRYPTO_BODY_META_KEY))
    key_id = crypto_meta.get("key_id")
    if key_id.get("ssec", False) or key_id.get("sses3", False):
        if args.bucket_secret:
            object_key = decode_secret(args.bucket_secret)
            prefix_result = "The provided key"
        else:
            object_key = fetch_bucket_secret(
                api.kms, args.account, args.container, secret_id=0
            )
            prefix_result = "The key from the account"
    else:
        account_path = os.path.join(os.sep, args.account)
        path = os.path.join(account_path, args.container, args.obj)
        object_key = create_key(path, root_key)
        prefix_result = "The root_key"

    etag_from_metadata_hmac = hmac_etag(object_key, etag_from_metadata)
    print(etag_from_metadata_hmac)

    print("HMAC from X-Object-Sysmeta-Crypto-Etag-Mac metadata:")
    etag_mac_from_metadata = metadata.get("properties").get(
        "x-object-sysmeta-crypto-etag-mac"
    )
    print(etag_mac_from_metadata)

    if etag_from_metadata_hmac == etag_mac_from_metadata:
        print(f"{prefix_result} is the RIGHT key!")
        sys.exit(0)
    else:
        print(f"{prefix_result} is the WRONG key.")
        sys.exit(1)
