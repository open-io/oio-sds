#!/usr/bin/env python

import argparse
from os import getenv
import json

from oio import ObjectStorageApi
from oio.common.logger import get_logger

from encryption_tool.encryption import (
    Decrypter,
    decode_secret,
    hmac_etag,
    load_crypto_meta,
    CRYPTO_BODY_META_KEY,
)

ROOT_KEY = b"Next-Gen Object Storage & Serverless Computing\n"


def make_arg_parser():
    descr = """
        Read extracted secret file and JSON file containing all objects for a
        specific bucket sorted by version. Try to find bucket secret associated
        to each object and add it in the object dict from JSON file.
    """
    parser = argparse.ArgumentParser(description=descr)
    parser.add_argument(
        "extracted_secret",
        help="""
        Path to the file where each line is a list with time interval between 2
        commit version of fondationdb and dict with account+bucket names as key
        and its associated secret as value.
        """,
    )
    parser.add_argument(
        "version_list",
        help="""
        Path to JSON file containing a list of metadata dict for every objects
        from a specific bucket sorted by version.
        """,
    )
    parser.add_argument("bucket", help="Bucket")
    parser.add_argument(
        "--oio-ns",
        dest="ns",
        type=str,
        default=getenv("OIO_NS"),
        help="Specify a namespace instead on the OIO_NS env var.",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="More verbose output"
    )
    return parser


def is_key_the_right_key(metadata, secret):
    """
    Use bucket secret to decrypt X-Object-Sysmeta-Crypto-Etag, use this ETag to
    and object_key to calculate the HMAC, the result should be the same as the
    metadata key X-Object-Sysmeta-Crypto-Etag-Mac.
    """
    decrypter = Decrypter(
        root_key=ROOT_KEY,
        account=account,
        container=bucket,
        obj=obj,
        metadata=metadata,
        bucket_secret=secret,
    )
    etag_from_metadata = decrypter.get_decrypted_etag()

    # Calculate HMAC with ETag from X-Object-Sysmeta-Crypto-Etag meta provided key
    object_key = decode_secret(secret)
    etag_from_metadata_hamc = hmac_etag(object_key, etag_from_metadata)

    # HMAC from X-Object-Sysmeta-Crypto-Etag-Mac metadata
    etag_mac_from_metadata = metadata.get("properties").get(
        "x-object-sysmeta-crypto-etag-mac"
    )

    if etag_from_metadata_hamc == etag_mac_from_metadata:
        return True
    else:
        return False


if __name__ == "__main__":
    args = make_arg_parser().parse_args()
    extracted_secret_path = args.extracted_secret
    version_list_path = args.version_list
    bucket = args.bucket
    verbose = args.verbose

    success = True
    sizes_per_secret = {}

    nb_objects_key_not_found = 0
    nb_objects_empty = 0
    nb_objects_manifest = 0
    nb_objects_ROOT_KEY = 0
    nb_objects_key_found = 0

    file_objects_key_not_found = open(
        f"find_secret.{bucket}.objects_key_not_found.txt", "w"
    )
    file_objects_empty = open(f"find_secret.{bucket}.objects_empty.txt", "w")
    file_objects_manifest = open(f"find_secret.{bucket}.objects_manifest.txt", "w")
    file_objects_ROOT_KEY = open(f"find_secret.{bucket}.objects_ROOT_KEY.txt", "w")
    file_out_version_list_with_secrets = open(
        f"find_secret.{bucket}.objects_with_secrets.json", "w"
    )
    # File with mtime and information if secret is found or not
    file_mtime = open(f"find_secret.{bucket}.mtime.txt", "w")

    logger = get_logger({}, "version-lister", verbose=verbose)
    storage = ObjectStorageApi(args.ns, logger=logger)
    account = storage.bucket.bucket_show(bucket)["account"]

    # Read version list
    with open(version_list_path, "r") as file:
        version_list = json.load(file)

    # Read extracted secret file and deserialize each lines
    account_bucket = account + "/" + bucket
    extracted_secret = []
    with open(extracted_secret_path) as file:
        for line in file:
            extract = json.loads(line)
            # Filter the file to keep only the extracts related to the bucket
            if account_bucket in extract[1]:
                extracted_secret += extract[1].get(account_bucket)

    file_out_version_list_with_secrets.write("[\n")
    for version_metadata in version_list:
        obj = version_metadata.get("name")
        obj_size = version_metadata.get("size")

        # Skip empty objects
        if obj_size == 0:
            print(
                f"Object '{obj}' is empty: Nothing to decrypt", file=file_objects_empty
            )
            nb_objects_empty += 1
            continue
        # Skip MPU manifest
        if version_metadata.get("properties").get("x-static-large-object"):
            print(
                f"Object '{obj}' is a MPU manifest: Nothing to decrypt",
                file=file_objects_manifest,
            )
            nb_objects_manifest += 1
            continue
        # Skip objects encrypted with ROOT_KEY
        crypto_meta = version_metadata.get("properties").get(CRYPTO_BODY_META_KEY)
        crypto_meta = load_crypto_meta(crypto_meta)
        key_id = crypto_meta.get("key_id")
        if key_id and not (key_id.get("ssec", False) or key_id.get("sses3", False)):
            print(
                f"Object '{obj}' is encrypted with ROOT_KEY: don't decrypt this object",
                file=file_objects_ROOT_KEY,
            )
            nb_objects_ROOT_KEY += 1
            continue

        obj_mtime = version_metadata.get("mtime")

        # Search for right secret
        for secret in extracted_secret:
            if is_key_the_right_key(version_metadata, secret):
                # Secret found! Add secret to metadata dict
                version_metadata["secret"] = secret

                # Write output file with version metadata
                json.dump(
                    version_metadata, file_out_version_list_with_secrets, indent=2
                )
                file_out_version_list_with_secrets.write(",\n")
                nb_objects_key_found += 1

                print(
                    f"mtime: {obj_mtime} Secret FOUND     Object: {obj}",
                    file=file_mtime,
                )

                if secret in sizes_per_secret:
                    sizes_per_secret[secret] += obj_size
                else:
                    sizes_per_secret[secret] = obj_size
                continue

        if "secret" not in version_metadata:
            print(
                f"Secret not found for object: '{obj}'",
                file=file_objects_key_not_found,
            )
            print(
                f"mtime: {obj_mtime} Secret NOT FOUND Object: {obj}",
                file=file_mtime,
            )
            nb_objects_key_not_found += 1
            success = False

    # Remove last ",|n"
    file_out_version_list_with_secrets.seek(0, 2)
    end_position = file_out_version_list_with_secrets.tell()
    file_out_version_list_with_secrets.seek(end_position - 2)
    file_out_version_list_with_secrets.write("\n]\n")

    file_objects_key_not_found.close()
    file_objects_empty.close()
    file_objects_manifest.close()
    file_objects_ROOT_KEY.close()
    file_out_version_list_with_secrets.close()
    file_mtime.close()

    best_secret = max(sizes_per_secret, key=sizes_per_secret.get)
    print(f"The best secret for the bucket is '{best_secret}'")

    print(f"nb_objects_key_not_found = {nb_objects_key_not_found}")
    print(f"nb_objects_empty = {nb_objects_empty}")
    print(f"nb_objects_manifest = {nb_objects_manifest}")
    print(f"nb_objects_ROOT_KEY = {nb_objects_ROOT_KEY}")
    print(f"nb_objects_key_found = {nb_objects_key_found}")

    if not success:
        print("SCRIPT FAILED")
        exit(1)
    else:
        print("SCRIPT SUCCEED")
        exit(0)
