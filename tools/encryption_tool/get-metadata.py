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

from oio import ObjectStorageApi

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="tool that writes object metadata json"
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
    args = parser.parse_args()

    sds_namespace = os.environ.get("OIO_NS", "OPENIO")
    uri = "http://127.0.0.1:6000"
    api = ObjectStorageApi(sds_namespace, endpoint=uri)
    meta = api.object_get_properties(
        args.account,
        args.container,
        args.obj,
        version=args.version,
    )

    # Write metadata as json file to standard output
    json_object = json.dumps(meta)
    print(json_object)
