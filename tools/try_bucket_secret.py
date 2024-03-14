#!/usr/bin/env python

# Copyright (C) 2024 OVH SAS
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
import hashlib
import json
import sys
from encryption_tool.encryption import Decrypter

ROOT_KEY = b"Next-Gen Object Storage & Serverless Computing\n"

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
    default="AUTH_demo",
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
    "--bucket_secret", type=str, required=True, help="bucket_secret can be providied"
)
args = parser.parse_args()

# Read metadata
with open(args.metadata, "r") as infile:
    metadata = json.load(infile)
    infile.close()

# Try to decrypt with bucket_secret and check if hash of decrypted body
# corresponds to the plaintext md5 include in X-Object-Sysmeta-Crypto-Etag.

decrypter = Decrypter(
    root_key=ROOT_KEY,
    account=args.account,
    container=args.container,
    obj=args.obj,
    metadata=metadata,
    bucket_secret=args.bucket_secret,
)

etag_form_metadata = decrypter.get_decrypted_etag(metadata=metadata)
print("ETag from X-Object-Sysmeta-Crypto-Etag metadata:")
print(etag_form_metadata)

# Decrypt object and calculate md5sum
plaintext_md5 = hashlib.md5(b"")
while 1:
    chunk = sys.stdin.buffer.read()
    if not chunk:
        break
    decrypted_chunk = decrypter.decrypt(chunk)
    plaintext_md5.update(decrypted_chunk)

plaintext_etag = plaintext_md5.hexdigest()
print("md5 of object plaintext body decrypted with the provided key:")
print(plaintext_etag)
