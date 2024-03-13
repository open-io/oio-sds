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

from cgi import parse_header
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from urllib import parse as urlparse

from oio import ObjectStorageApi
from oio.common.exceptions import NotFound
from oio.common.easy_value import true_value as config_true_value

CRYPTO_BODY_META_KEY = "x-object-sysmeta-crypto-body-meta"
TRANSIENT_CRYPTO_META_KEY = "x-object-transient-sysmeta-crypto-meta"
CRYPTO_ETAG_KEY = "x-object-sysmeta-crypto-etag"
CONTAINER_UPDATE_OVERRIDE_ETAG_KEY = "x-object-sysmeta-container-update-override-etag"
CRYPTO_ETAG_MAC_KEY = "x-object-sysmeta-crypto-etag-mac"

BODY_IV = "body_iv"
BODY_KEY_IV = "body_key_iv"
USER_METADATA_IVS = "user_metadata_ivs"
ETAG_IV = "etag_iv"
OVERRIDE_ETAG_IV = "override_etag_iv"

# This tool is in the oio-sds repository because it needs to be able to update
# metadata. To decrypt and re-encrypt the data, some encryption functions have
# been copied from the swift code.


# Functions copied from swift/common/swob.py


def wsgi_to_bytes(wsgi_str):
    if wsgi_str is None:
        return None
    return wsgi_str.encode("latin1")


def bytes_to_wsgi(byte_str):
    return byte_str.decode("latin1")


# Functions copied from swift/common/request_helpers.py


OBJECT_TRANSIENT_SYSMETA_PREFIX = "x-object-transient-sysmeta-"


def is_user_meta(server_type, key):
    """
    Tests if a header key starts with and is longer than the user
    metadata prefix for given server type.

    :param server_type: type of backend server i.e. [account|container|object]
    :param key: header key
    :returns: True if the key satisfies the test, False otherwise
    """
    if len(key) <= 8 + len(server_type):
        return False
    return key.lower().startswith(get_user_meta_prefix(server_type))


def strip_user_meta_prefix(server_type, key):
    """
    Removes the user metadata prefix for a given server type from the start
    of a header key.

    :param server_type: type of backend server i.e. [account|container|object]
    :param key: header key
    :returns: stripped header key
    """
    if not is_user_meta(server_type, key):
        raise ValueError("Key is not user meta")
    return key[len(get_user_meta_prefix(server_type)) :]


def get_user_meta_prefix(server_type):
    """
    Returns the prefix for user metadata headers for given server type.

    This prefix defines the namespace for headers that will be persisted
    by backend servers.

    :param server_type: type of backend server i.e. [account|container|object]
    :returns: prefix string for server type's user metadata headers
    """
    return f"x-{server_type.lower()}-meta-"


def get_object_transient_sysmeta(key):
    """
    Returns the Object Transient System Metadata header for key.
    The Object Transient System Metadata namespace will be persisted by
    backend object servers. These headers are treated in the same way as
    object user metadata i.e. all headers in this namespace will be
    replaced on every POST request.

    :param key: metadata key
    :returns: the entire object transient system metadata header for key
    """
    return "%s%s" % (OBJECT_TRANSIENT_SYSMETA_PREFIX, key)


# Functions copied from swift/common/utils.py


MD5_OF_EMPTY_STRING = "d41d8cd98f00b204e9800998ecf8427e"


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


# Functions copied from swift/common/middleware/crypto/crypto_utils.py


def dump_crypto_meta(crypto_meta):
    """
    Serialize crypto meta to a form suitable for including in a header value.

    The crypto-meta is serialized as a json object. The iv and key values are
    random bytes and as a result need to be base64 encoded before sending over
    the wire. Base64 encoding returns a bytes object in py3, to future proof
    the code, decode this data to produce a string, which is what the
    json.dumps function expects.

    :param crypto_meta: a dict containing crypto meta items
    :returns: a string serialization of a crypto meta dict
    """

    def b64_encode_meta(crypto_meta):
        return {
            name: (
                base64.b64encode(value).decode()
                if name in ("iv", "key")
                else b64_encode_meta(value) if isinstance(value, dict) else value
            )
            for name, value in crypto_meta.items()
        }

    # use sort_keys=True to make serialized form predictable for testing
    return urlparse.quote_plus(json.dumps(b64_encode_meta(crypto_meta), sort_keys=True))


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


def append_crypto_meta(value, crypto_meta):
    """
    Serialize and append crypto metadata to an encrypted value.

    :param value: value to which serialized crypto meta will be appended.
    :param crypto_meta: a dict of crypto meta
    :return: a string of the form <value>; swift_meta=<serialized crypto meta>
    """
    if not isinstance(value, str):
        raise ValueError
    return "%s; swift_meta=%s" % (value, dump_crypto_meta(crypto_meta))


def extract_crypto_meta(value):
    """
    Extract and deserialize any crypto meta from the end of a value.

    :param value: string that may have crypto meta at end
    :return: a tuple of the form:
            (<value without crypto meta>, <deserialized crypto meta> or None)
    """
    swift_meta = None
    value, meta = parse_header(value)
    if "swift_meta" in meta:
        swift_meta = load_crypto_meta(meta["swift_meta"])
    return value, swift_meta


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

    def create_encryption_ctxt(self, key, iv):
        """
        Creates a crypto context for encrypting

        :param key: 256-bit key
        :param iv: 128-bit iv or nonce used for encryption
        :raises ValueError: on invalid key or iv
        :returns: an instance of an encryptor
        """
        self.check_key(key)
        engine = Cipher(algorithms.AES(key), modes.CTR(iv), backend=self.backend)
        return engine.encryptor()

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

    def create_iv(self):
        return os.urandom(self.iv_length)

    def create_crypto_meta(self):
        # create a set of parameters
        return {"iv": self.create_iv(), "cipher": self.cipher}

    def check_crypto_meta(self, meta):
        """
        Check that crypto meta dict has valid items.

        :param meta: a dict
        :raises EncryptionException: if an error is found in the crypto meta
        """
        try:
            if meta["cipher"] != self.cipher:
                raise Exception("Bad crypto meta: Cipher must be %s" % self.cipher)
            if len(meta["iv"]) != self.iv_length:
                raise Exception(
                    "Bad crypto meta: IV must be length %s bytes" % self.iv_length
                )
        except KeyError as err:
            raise Exception("Bad crypto meta: Missing %s" % err)

    def create_random_key(self):
        # helper method to create random key of correct length
        return os.urandom(self.key_length)

    def wrap_key(self, wrapping_key, key_to_wrap, iv=None):
        # we don't use an RFC 3394 key wrap algorithm such as cryptography's
        # aes_wrap_key because it's slower and we have iv material readily
        # available so don't need a deterministic algorithm
        if iv is None:
            iv = self.create_iv()
        encryptor = Cipher(
            algorithms.AES(wrapping_key), modes.CTR(iv), backend=self.backend
        ).encryptor()
        return {"key": encryptor.update(key_to_wrap), "iv": iv}

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


# Functions copied and modified from the class KmsWrapper in
# swift/common/middleware/crypto/ssec_keymaster.py
# self.cache has been removed


def create_bucket_secret(
    kms, bucket, account=None, secret_id=None, secret_bytes=32, reqid=None
):
    secret_meta = kms.create_secret(
        account,
        bucket,
        secret_id=secret_id,
        secret_bytes=secret_bytes,
        reqid=reqid,
    )
    return secret_meta["secret"]


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

    def __init__(
        self,
        root_key,
        account=None,
        container=None,
        obj=None,
        metadata=None,
        bucket_secret=None,
    ):
        self.account = account
        self.container = container
        self.obj = obj
        self.metadata = metadata
        sds_namespace = os.environ.get("OIO_NS", "OPENIO")
        self.api = ObjectStorageApi(sds_namespace)
        self.crypto = Crypto()
        self.root_key = root_key
        self.bucket_secret = bucket_secret
        self.body_key = None
        self.iv = {}
        self.iv[USER_METADATA_IVS] = {}

    def decrypt_metadata(self, metadata=None):
        """
        Add decrypted user metadata to the metadata dict.

        :param metadata: object metadata
        :return metadata with decrypted user metadata
        """
        if metadata is None:
            metadata = self.metadata

        crypto_meta = metadata.get("properties").get(TRANSIENT_CRYPTO_META_KEY)
        if crypto_meta is not None:
            self.body_key, _, keys = self.get_cipher_keys(crypto_meta)
            decrypted_user_metadata = self._decrypt_user_metadata(keys)

            for k, v in decrypted_user_metadata:
                metadata["properties"][k] = v

        return metadata

    def decrypt(self, chunk, metadata=None):
        """
        Decrypt chunk with root_secret and metadata

        :param chunk: data to decrypt
        :param metadata: object metadata
        """
        if self.body_key is None or self.iv.get(BODY_IV) is None:
            if metadata is None:
                metadata = self.metadata
            crypto_meta = metadata.get("properties").get(CRYPTO_BODY_META_KEY)
            self.body_key, iv, _ = self.get_cipher_keys(crypto_meta)
            self.iv[BODY_IV] = iv

        offset = 0
        decrypt_ctxt = self.crypto.create_decryption_ctxt(
            self.body_key, self.iv.get(BODY_IV), offset
        )
        return decrypt_ctxt.update(chunk)

    def get_ivs(self):
        """
        Returns dict with IVs in order to re-use them for re-encryption

        IVs are encoded to a text format so the dictionary can be saved as json
        file. User metadata IVs are contained by a dictionary nested into the
        output dictionary.
        :return iv dictionary
        """

        def get_iv(key):
            iv = None
            for name, val in self.metadata["properties"].items():
                if name.lower() == key:
                    _, meta = parse_header(val)
                    if "swift_meta" in meta:
                        swift_meta = load_crypto_meta(meta["swift_meta"])
                        iv = swift_meta.get("iv")
            return iv

        def encode_binary_dict(data):
            return {
                str(name): (
                    encode_binary_dict(val)
                    if isinstance(val, dict)
                    else base64.b64encode(val).decode("utf-8")
                )
                for name, val in data.items()
            }

        # Save IV from ETag
        etag_iv = get_iv(CRYPTO_ETAG_KEY)
        if etag_iv is not None:
            self.iv[ETAG_IV] = etag_iv

        # Save IV from container update override ETag
        override_etag_iv = get_iv(CONTAINER_UPDATE_OVERRIDE_ETAG_KEY)
        if override_etag_iv is not None:
            self.iv[OVERRIDE_ETAG_IV] = override_etag_iv

        return encode_binary_dict(self.iv)

    def get_cipher_keys(self, crypto_meta):
        """
        Create object_key with path and root key or fetch key from kms.
        Returns body_key, iv and keys.

        :param crypto_meta: crypto metadata
        :return body_key, iv and put_keys
        """
        if crypto_meta is None:
            raise ValueError("empty crypto_meta is not acceptable")
        crypto_meta = load_crypto_meta(crypto_meta)

        iv = crypto_meta.get("iv")
        key_id = crypto_meta.get("key_id")
        put_keys = {}
        put_keys["id"] = {}
        if self.bucket_secret is not None:
            # The bucket_secret was given
            object_key = decode_secret(self.bucket_secret)
            put_keys["id"]["sses3"] = True
        elif key_id and not (key_id.get("ssec", False) or key_id.get("sses3", False)):
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

        body_key = None
        wrapped_body_key = crypto_meta.get("body_key")
        if wrapped_body_key:
            self.iv[BODY_KEY_IV] = wrapped_body_key.get("iv")
            body_key = self.crypto.unwrap_key(object_key, wrapped_body_key)
        return body_key, iv, put_keys

    # Functions copied and modified from the class BaseDecrypterContext in
    # swift/common/middleware/crypto/decrypter.py

    # EncryptionException is replaced with Exception

    def _decrypt_value_with_meta(self, value, key, required, decoder):
        """
        Base64-decode and decrypt a value if crypto meta can be extracted from
        the value itself, otherwise return the value unmodified.

        A value should either be a string that does not contain the ';'
        character or should be of the form:

            <base64-encoded ciphertext>;swift_meta=<crypto meta>

        :param value: value to decrypt
        :param key: crypto key to use
        :param required: if True then the value is required to be decrypted
                         and an Exception will be raised if the header cannot
                         be decrypted due to missing crypto meta.
        :param decoder: function to turn the decrypted bytes into useful data
        :returns: decrypted value if crypto meta is found, otherwise the
                  unmodified value
        :raises Exception: if an error occurs while parsing crypto meta or if
                           the header value was required to be decrypted but
                           crypto meta was not found.
        """
        extracted_value, crypto_meta = extract_crypto_meta(value)
        if crypto_meta:
            self.crypto.check_crypto_meta(crypto_meta)
            value = self._decrypt_value(extracted_value, key, crypto_meta, decoder)
            iv = crypto_meta.get("iv")
        elif required:
            raise Exception("Missing crypto meta in value %s" % value)

        return value, iv

    def _decrypt_value(self, value, key, crypto_meta, decoder):
        """
        Base64-decode and decrypt a value using the crypto_meta provided.

        :param value: a base64-encoded value to decrypt
        :param key: crypto key to use
        :param crypto_meta: a crypto-meta dict of form returned by
            :py:func:`~swift.common.middleware.crypto.Crypto.get_crypto_meta`
        :param decoder: function to turn the decrypted bytes into useful data
        :returns: decrypted value
        """
        if not value:
            return decoder(b"")
        crypto_ctxt = self.crypto.create_decryption_ctxt(key, crypto_meta["iv"], 0)
        return decoder(crypto_ctxt.update(base64.b64decode(value)))

    # Function copied and modified from the class DecrypterObjContext
    # in swift/common/middleware/crypto/decrypter.py

    # self.server_type has been replaced with 'object'
    # self._response_header has been replaced with self.metadata['property']
    # self._decrypt_value_with_meta is called instead of self._decrypt_header

    def _decrypt_user_metadata(self, keys):
        prefix = get_object_transient_sysmeta("crypto-meta-")
        prefix_len = len(prefix)
        new_prefix = get_user_meta_prefix("object").title()
        result = []
        for name, val in self.metadata["properties"].items():
            if name.lower().startswith(prefix) and val:
                short_name = name[prefix_len:]
                decrypted_value, iv = self._decrypt_value_with_meta(
                    val, keys["object"], True, bytes_to_wsgi
                )
                self.iv[USER_METADATA_IVS][short_name] = iv
                result.append((new_prefix + short_name, decrypted_value))
        return result


class Encrypter:
    """
    Encrypt data with a random body_key and a random iv.
    """

    def __init__(self, root_key, account=None, container=None, obj=None, iv=None):
        self.account = account
        self.container = container
        self.obj = obj

        def decode_binary_dict(data):
            return {
                str(name): (
                    decode_binary_dict(val)
                    if isinstance(val, dict)
                    else base64.b64decode(val)
                )
                for name, val in data.items()
            }

        self.iv = decode_binary_dict(iv)

        sds_namespace = os.environ.get("OIO_NS", "OPENIO")
        self.api = ObjectStorageApi(sds_namespace)
        self.crypto = Crypto()
        self.root_key = root_key

        # Create bucket secret in kms
        secret_id = 0
        secret = create_bucket_secret(
            self.api.kms,
            self.container,
            account=self.account,
            secret_id=secret_id,
        )

        self.keys = {}
        # bucket secret is used as the key_object
        self.keys["object"] = decode_secret(secret)

        # key_id contains the path used to derive keys
        account_path = os.path.join(os.sep, self.account)
        path = os.path.join(account_path, self.container)
        self.keys["id"] = {"v": "1", "path": path, "sses3": True}

        self.keys["container"] = create_key(path, self.root_key)

        # Create a dict with iv and cipher keys
        self.body_crypto_meta = self.crypto.create_crypto_meta()
        # Overwrite iv with provided body_iv
        body_iv = self.iv.get(BODY_IV)
        if body_iv is not None:
            self.body_crypto_meta["iv"] = body_iv
        body_key = self.crypto.create_random_key()

        # wrap the body key with object key
        self.body_crypto_meta["body_key"] = self.crypto.wrap_key(
            self.keys["object"], body_key, self.iv.get(BODY_KEY_IV)
        )
        self.body_crypto_meta["key_id"] = self.keys["id"]
        self.body_crypto_ctxt = self.crypto.create_encryption_ctxt(
            body_key, self.body_crypto_meta.get("iv")
        )

        self.plaintext_md5 = hashlib.md5(b"")

    def encrypt(self, chunk):
        """
        Encrypt chunk.

        The body crypto context was created with a randomly chosen body key and
        a randomly chosen IV.
        Encryption of the object body is performed using this body crypto
        context:
            body_ciphertext = E(body_plaintext, body_key, body_iv)

        :param chunk: object body_plaintext
        :returns: body ciphertext
        """
        self.plaintext_md5.update(chunk)

        ciphertext = self.body_crypto_ctxt.update(chunk)
        return ciphertext

    def encrypt_metadata(self, metadata):
        """
        Add system metadata header to store crypto-metadata.

        :param metadata: object metadata
        :return metadata with crypto-body-metadata header
        """

        metadata["properties"] = self._encrypt_user_metadata(metadata["properties"])
        metadata["properties"] = self._encrypt_crypto_body_etag_metadata(
            metadata["properties"]
        )
        return metadata

    # Functions copied and modified from the class EncrypterObjContext in
    # swift/common/middleware/crypto/encrypter.py

    # self.server_type has been replaced with 'object'
    # req.headers has been replaced with metadata['property']

    def _encrypt_user_metadata(self, metadata):
        """
        Encrypt user-metadata header values. Replace each x-object-meta-<key>
        user metadata header with a corresponding
        x-object-transient-sysmeta-crypto-meta-<key> header which has the
        crypto metadata required to decrypt appended to the encrypted value.

        :param metadata: a dict of metadata properties
        :returns: metadata dict with encrypted user metadata
        """
        prefix = get_object_transient_sysmeta("crypto-meta-")
        user_meta_headers = [
            h for h in metadata.items() if is_user_meta("object", h[0]) and h[1]
        ]
        crypto_meta = None
        for name, val in user_meta_headers:
            short_name = strip_user_meta_prefix("object", name)
            new_name = prefix + short_name
            iv = self.iv[USER_METADATA_IVS][short_name]
            enc_val, crypto_meta = self._encrypt_header_val(
                self.crypto, val, self.keys["object"], iv=iv
            )
            metadata[new_name] = append_crypto_meta(enc_val, crypto_meta)
            metadata.pop(name)
        # store a single copy of the crypto meta items that are common to all
        # encrypted user metadata independently of any such meta that is stored
        # with the object body because it might change on a POST. This is done
        # for future-proofing - the meta stored here is not currently used
        # during decryption.
        if crypto_meta:
            meta = dump_crypto_meta(
                {"cipher": crypto_meta["cipher"], "key_id": self.keys["id"]}
            )
            metadata[get_object_transient_sysmeta("crypto-meta")] = meta
        return metadata

    def _encrypt_crypto_body_etag_metadata(self, metadata):
        """
        Add crypto body, Etag, override Etag and Etag mac to the metadata dict.

        Encrypt crypto body metadata and save it as
        X-Object-Sysmeta-Crypto-Body-Meta.
        Encrypt the ETag (md5 digest) of the plaintext body using the object
        key provided by the kms and save it as X-Object-Sysmeta-Crypto-Etag.
        Encrypt the ETag (md5 digest) of the plaintext body using the container
        key and save it as X-Object-Sysmeta-Container-Update-Override-Etag.
        Calculate an HMAC using the object key and the ETag and stores this
        under the metadata key X-Object-Sysmeta-Crypto-Etag-Mac.

        :param metadata: a dict of metadata properties
        :returns: metadata dict with encrypted crypto body and ETags
        """
        plaintext_etag = self.plaintext_md5.hexdigest()
        if plaintext_etag and plaintext_etag != MD5_OF_EMPTY_STRING:
            # Encrypt crypto body metadata
            metadata[CRYPTO_BODY_META_KEY] = dump_crypto_meta(self.body_crypto_meta)

            # Encrypt ETag with the object key
            iv = self.iv[ETAG_IV]
            encrypted_etag, etag_crypto_meta = self._encrypt_header_val(
                self.crypto, plaintext_etag, self.keys["object"], iv=iv
            )
            metadata[CRYPTO_ETAG_KEY] = append_crypto_meta(
                encrypted_etag, etag_crypto_meta
            )

            # Encrypt ETag with the container key
            iv = self.iv[OVERRIDE_ETAG_IV]
            val, crypto_meta = self._encrypt_header_val(
                self.crypto, plaintext_etag, self.keys["container"], iv=iv
            )
            crypto_meta["key_id"] = self.keys["id"]
            metadata[CONTAINER_UPDATE_OVERRIDE_ETAG_KEY] = append_crypto_meta(
                val, crypto_meta
            )

            # Also add an HMAC of the etag for use when evaluating
            # conditional requests
            metadata[CRYPTO_ETAG_MAC_KEY] = self._hmac_etag(
                self.keys["object"], plaintext_etag
            )

        return metadata

    def update_metadata(self, metadata):
        properties = metadata.get("properties")
        self.api.object_set_properties(
            self.account, self.container, self.obj, properties
        )

    # Functions copied from swift/common/middleware/crypto/encrypter.py

    def _encrypt_header_val(self, crypto, value, key, iv=None):
        """
        Encrypt a header value using the supplied key.

        :param crypto: a Crypto instance
        :param value: value to encrypt
        :param key: crypto key to use
        :param iv: optional iv value, if None, a randomly chosen will be use
        :returns: a tuple of (encrypted value, crypto_meta) where crypto_meta is a
            dict of form returned by
            :py:func:`~swift.common.middleware.crypto.Crypto.get_crypto_meta`
        :raises ValueError: if value is empty
        """
        if not value:
            raise ValueError("empty value is not acceptable")

        crypto_meta = crypto.create_crypto_meta()
        # Overwrite with provided iv
        if iv is not None:
            crypto_meta["iv"] = iv
        crypto_ctxt = crypto.create_encryption_ctxt(key, crypto_meta["iv"])
        enc_val = bytes_to_wsgi(
            base64.b64encode(crypto_ctxt.update(wsgi_to_bytes(value)))
        )
        return enc_val, crypto_meta

    def _hmac_etag(self, key, etag):
        """
        Compute an HMAC-SHA256 using given key and etag.

        :param key: The starting key for the hash.
        :param etag: The etag to hash.
        :returns: a Base64-encoded representation of the HMAC
        """
        if not isinstance(etag, bytes):
            etag = wsgi_to_bytes(etag)
        result = hmac.new(key, etag, digestmod=hashlib.sha256).digest()
        return base64.b64encode(result).decode()
