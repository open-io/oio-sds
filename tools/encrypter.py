#!/usr/bin/env python

# Copyright (C) 2024 OVH SAS

import sys
from encryption import Encrypter

# Encrypter object
encrypter = Encrypter()

while 1:
    chunk = sys.stdin.buffer.read()
    if not chunk:
        break
    ciphertext = encrypter.encrypt(chunk)
    sys.stdout.buffer.write(ciphertext)
