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

import base64
import binascii
import hashlib
import hmac
import json
import os
import string

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from urllib import parse as urlparse

from oio import ObjectStorageApi
from oio.common.exceptions import NotFound

CRYPTO_META_KEY = "x-object-sysmeta-crypto-body-meta"


# This tool is in the oio-sds repository because it needs to be able to update
# metadata. To decrypt and re-encrypt the data, some encryption functions have
# been copied from the swift code.

# Functions copied from swift/common/swob.py


def bytes_to_wsgi(byte_str):
    return byte_str.decode("latin1")


# Functions copied from swift/common/utils.py


def strict_b64decode(value, allow_line_breaks=False):
    """
    Validate and decode Base64-encoded data.

    The stdlib base64 module silently discards bad characters, but we often
    want to treat them as an error.

    :param value: some base64-encoded data
    :param allow_line_breaks: if True, ignore carriage returns and newlines
    :returns: the decoded data
    :raises ValueError: if ``value`` is not a string, contains invalid
                        characters, or has insufficient padding
    """
    if isinstance(value, bytes):
        try:
            value = value.decode("ascii")
        except UnicodeDecodeError:
            raise ValueError
    if not isinstance(value, str):
        raise ValueError
    # b64decode will silently discard bad characters, but we want to
    # treat them as an error
    valid_chars = string.digits + string.ascii_letters + "/+"
    strip_chars = "="
    if allow_line_breaks:
        valid_chars += "\r\n"
        strip_chars += "\r\n"
    if any(c not in valid_chars for c in value.strip(strip_chars)):
        raise ValueError
    try:
        return base64.b64decode(value)
    except (TypeError, binascii.Error):  # (py2 error, py3 error)
        raise ValueError


# Used when reading config values
TRUE_VALUES = set(("true", "1", "yes", "on", "t", "y"))


def config_true_value(value):
    """
    Returns True if the value is either True or a string in TRUE_VALUES.
    Returns False otherwise.
    """
    return value is True or (isinstance(value, str) and value.lower() in TRUE_VALUES)


# Functions copied from swift/common/middleware/crypto/crypto_utils.py
# EncryptionException is replaced with Exception


def load_crypto_meta(value, b64decode=True):
    """
    Build the crypto_meta from the json object.

    Note that json.loads always produces unicode strings; to ensure the
    resultant crypto_meta matches the original object:
        * cast all keys to str (effectively a no-op on py3),
        * base64 decode 'key' and 'iv' values to bytes, and
        * encode remaining string values as UTF-8 on py2 (while leaving them
          as native unicode strings on py3).

    :param value: a string serialization of a crypto meta dict
    :param b64decode: decode the 'key' and 'iv' values to bytes, default True
    :returns: a dict containing crypto meta items
    :raises EncryptionException: if an error occurs while parsing the
                                 crypto meta
    """

    def b64_decode_meta(crypto_meta):
        return {
            str(name): (
                base64.b64decode(val)
                if name in ("iv", "key") and b64decode
                else (
                    b64_decode_meta(val)
                    if isinstance(val, dict)
                    else val.encode("utf8") if False else val
                )
            )
            for name, val in crypto_meta.items()
        }

    try:
        if not isinstance(value, str):
            raise ValueError("crypto meta not a string")
        val = json.loads(urlparse.unquote_plus(value))
        if not isinstance(val, dict):
            raise ValueError("crypto meta not a Mapping")
        return b64_decode_meta(val)
    except (KeyError, ValueError, TypeError) as err:
        msg = "Bad crypto meta %r: %s" % (value, err)
        raise Exception(msg)


def decode_secret(b64_secret):
    """Decode and check a base64 encoded secret key."""
    binary_secret = strict_b64decode(b64_secret, allow_line_breaks=True)
    if len(binary_secret) != Crypto.key_length:
        raise ValueError
    return binary_secret


# The Crypto class is copied from crypto_utils.py and modified.
# self.logger has been removed
# EncryptionException has been replaced with Exception
class Crypto(object):
    """
    Used by middleware: Calls cryptography library
    """

    cipher = "AES_CTR_256"
    # AES will accept several key sizes - we are using 256 bits i.e. 32 bytes
    key_length = 32
    iv_length = algorithms.AES.block_size // 8

    def __init__(self, conf=None):
        # memoize backend to avoid repeated iteration over entry points
        self.backend = default_backend()
        self.ciphertext_hash_algo = (
            conf.get("ciphertext_hash_algo", "md5") if conf else "md5"
        )
        self.ssec_mode = config_true_value(
            conf.get("ssec_mode", "false") if conf else False
        )

    def create_decryption_ctxt(self, key, iv, offset):
        """
        Creates a crypto context for decrypting

        :param key: 256-bit key
        :param iv: 128-bit iv or nonce used for decryption
        :param offset: offset into the message; used for range reads
        :returns: an instance of a decryptor
        """
        self.check_key(key)
        if offset < 0:
            raise ValueError("Offset must not be negative")
        if offset:
            # Adjust IV so that it is correct for decryption at offset.
            # The CTR mode offset is incremented for every AES block and taken
            # modulo 2^128.
            offset_blocks, offset_in_block = divmod(offset, self.iv_length)
            ivl = int(binascii.hexlify(iv), 16) + offset_blocks
            ivl %= 1 << algorithms.AES.block_size
            iv = bytes(bytearray.fromhex(format(ivl, "0%dx" % (2 * self.iv_length))))
        else:
            offset_in_block = 0

        engine = Cipher(algorithms.AES(key), modes.CTR(iv), backend=self.backend)
        dec = engine.decryptor()
        # Adjust decryption boundary within current AES block
        dec.update(b"*" * offset_in_block)
        return dec

    def unwrap_key(self, wrapping_key, context):
        # unwrap a key from dict of form returned by wrap_key
        # check the key length early - unwrapping won't change the length
        self.check_key(context["key"])
        decryptor = Cipher(
            algorithms.AES(wrapping_key), modes.CTR(context["iv"]), backend=self.backend
        ).decryptor()
        return decryptor.update(context["key"])

    def check_key(self, key):
        if len(key) != self.key_length:
            raise ValueError("Key must be length %s bytes" % self.key_length)


# Function copied and modified from the class BaseKeyMaster in
# swift/common/middleware/crypto/keymaster.py


def create_key(path, key):
    """
    Creates an encryption key that is unique for the given path.

    :param path: the (WSGI string) path of the resource being encrypted.
    :param key: root_key from which the key should be derived.
    :return: an encryption key.
    """
    path = path.encode("utf-8")
    return hmac.new(key, path, digestmod=hashlib.sha256).digest()


# Functions copied and modified from the class SsecKeyMasterContext in
# swift/common/middleware/crypto/ssec_keymaster.py


def fetch_bucket_secret(kms, account, bucket, secret_id=None):
    """
    Look for a bucket-specific secret.

    Load it from the bucket DB (identifying as a KMS).
    If there is no secret, do not fail, just do not encrypt.
    """
    if not bucket:
        return None
    try:
        secret_meta = kms.get_secret(account, bucket, secret_id=secret_id)
        b64_secret = secret_meta["secret"]
    except NotFound:
        b64_secret = None

    if b64_secret:
        return decode_secret(b64_secret)
    return None


class Decrypter:
    """
    Decrypt objects that has been encrypted with root key or with a key from
    kms.
    """

    def __init__(self, root_key, account=None, container=None, obj=None, metadata=None):
        self.account = account
        self.container = container
        self.obj = obj
        self.metadata = metadata
        sds_namespace = os.environ.get("OIO_NS", "OPENIO")
        self.api = ObjectStorageApi(sds_namespace)
        self.crypto = Crypto()
        self.root_key = root_key
        self.body_key = None
        self.iv = None

    def decrypt(self, chunk, metadata=None):
        """
        Decrypt chunk with root_secret and metadata

        :param chunk: data to decrypt
        :param metadata: object metadata
        """
        if self.body_key is None or self.iv is None:
            if metadata is None:
                metadata = self.metadata
            self.body_key, self.iv, _ = self.get_cipher_keys(metadata)

        offset = 0
        decrypt_ctxt = self.crypto.create_decryption_ctxt(
            self.body_key, self.iv, offset
        )
        return decrypt_ctxt.update(chunk)

    def get_cipher_keys(self, meta):
        """
        Create object_key with path and root key or fetch key from kms.
        Returns body_key and iv.

        :param meta: object metadata
        :return body_key and iv
        """
        raw_crypto_meta = meta.get("properties").get(CRYPTO_META_KEY)
        crypto_meta_json = json.loads(urlparse.unquote_plus(raw_crypto_meta))
        if crypto_meta_json is None:
            return None
        crypto_meta = load_crypto_meta(raw_crypto_meta)

        iv = crypto_meta.get("iv")
        key_id = crypto_meta.get("key_id")
        put_keys = {}
        put_keys["id"] = {}
        if key_id and not (key_id.get("ssec", False) or key_id.get("sses3", False)):
            # The object is encrypted with ROOT_KEY
            account_path = os.path.join(os.sep, self.account)
            path = os.path.join(account_path, self.container, self.obj)
            object_key = create_key(path, self.root_key)

            put_keys["id"]["sses3"] = False
        else:
            # The object is encrypted with sses3
            secret_id = 0  # TODO I am not sure about that
            object_key = fetch_bucket_secret(
                self.api.kms, self.account, self.container, secret_id=secret_id
            )
            put_keys["id"]["sses3"] = True

        put_keys["object"] = object_key

        account_path = os.path.join(os.sep, self.account)
        path = os.path.join(account_path, self.container)
        container_key = create_key(path, self.root_key)
        put_keys["container"] = container_key

        body_key = self.crypto.unwrap_key(object_key, crypto_meta["body_key"])
        return body_key, iv, put_keys
