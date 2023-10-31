#!/usr/bin/env python

# Copyright (C) 2024 OVH SAS

import argparse
import json
import sys
from encryption import Encrypter

parser = argparse.ArgumentParser(description="encryption tool")
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
args = parser.parse_args()


# Read metadata
with open(args.metadata, "r") as infile:
    metadata = json.load(infile)

# Encrypter object
encrypter = Encrypter(account=args.account, container=args.container, obj=args.obj)

while 1:
    chunk = sys.stdin.buffer.read()
    if not chunk:
        break
    ciphertext = encrypter.encrypt(chunk)
    sys.stdout.buffer.write(ciphertext)

new_metadata = encrypter.encrypt_metadata(metadata)
with open("metadata.json", "w") as outfile:
    json.dump(new_metadata, outfile)
