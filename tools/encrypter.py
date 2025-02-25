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

from encryption_tool.encryption import Encrypter

ROOT_KEY = b"Next-Gen Object Storage & Serverless Computing\n"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="encryption tool")
    parser.add_argument("--rootkey", type=str, default=ROOT_KEY, help="root key")
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
        "--iv",
        type=str,
        default="iv.json",
        help="path of json file that contains IVs to reuse",
    )
    args = parser.parse_args()

    # Read metadata
    with open(args.metadata, "r") as infile:
        metadata = json.load(infile)
        infile.close()

    # Read IVs
    with open(args.iv, "r") as infile:
        iv = json.load(infile)
        infile.close()

    # Encrypter object
    encrypter = Encrypter(
        root_key=args.rootkey,
        account=args.account,
        container=args.container,
        obj=args.obj,
        iv=iv,
    )

    while 1:
        chunk = sys.stdin.buffer.read()
        if not chunk:
            break
        ciphertext = encrypter.encrypt(chunk)
        sys.stdout.buffer.write(ciphertext)

    new_metadata = encrypter.encrypt_metadata(metadata)
    encrypter.update_metadata(new_metadata)
    with open(args.metadata, "w") as outfile:
        json.dump(new_metadata, outfile)
        outfile.close()
