# Copyright (C) 2026 OVH SAS
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
import itertools
from copy import copy

from oio.account.backend_fdb import AccountBackendFdb
from oio.account.kmsapi_client import KmsApiClient
from oio.account.utils import initialize_kms_clients
from oio.common.statsd import get_statsd
from oio.common.utils import depaginate


class KmsEncryptor:
    """
    Encrypt bucket secrets with KMS.

    This binary encrypts all incomplete bucket secrets using the configured
    KMS API. It reports failures per KMS domain and exits with one of the
    following codes:

    Return codes:
        0: All bucket secrets were successfully encrypted.
        1: Encryption of some bucket secrets failed.
        2: Failed to register encrypted KMS secrets in the backend FDB.
        3: Encryption of some bucket secrets failed, and registration
           of the encrypted secrets in the backend FDB was unsuccessful.
    """

    def __init__(
        self,
        conf,
        reqid,
        logger,
        accounts=None,
        buckets=None,
        acc_marker=None,
        bkt_marker=None,
        dry_run=False,
        separator="/",
    ):
        self.conf = conf
        self.logger = logger
        # Foundation db client
        self.backend = AccountBackendFdb(conf, logger)
        self.backend.init_db()
        self.statsd = get_statsd(conf=conf)
        # External kms api client
        self.kms_api = KmsApiClient(conf, logger=logger)
        self.kmsapi_domains = []
        if not self.kms_api.enabled:
            raise ValueError("KMS API is not enabled; enable it to proceed.")
        # Initialize kms client for each kms domain
        initialize_kms_clients(self)
        self.reqid = reqid
        self.accounts = accounts
        self.account_marker = acc_marker
        self.buckets = buckets
        self.bucket_marker = bkt_marker
        self.dry_run = dry_run
        self.separator = separator

    @property
    def progress(self):
        """Format the current progression marker"""
        return f"{self.account_marker or ''}{self.separator}{self.bucket_marker or ''}"

    def get_all_buckets_secrets(self):
        """Get all secrets with their account/bucket"""
        accounts = self.accounts
        if not accounts:
            accounts = depaginate(
                self.backend.list_accounts,
                item_key=lambda x: x["id"],
                listing_key=lambda x: x[0],
                marker_key=lambda x: x[1],
                truncated_key=lambda x: x[1] is not None,
                marker=self.account_marker,
                reqid=self.reqid,
            )
        for account in accounts:
            try:
                buckets = self.buckets
                if not buckets:
                    buckets = depaginate(
                        self.backend.list_buckets,
                        listing_key=lambda x: x[1],
                        marker_key=lambda x: x[2],
                        truncated_key=lambda x: x[2] is not None,
                        account_id=account,
                        marker=self.bucket_marker,
                        reqid=self.reqid,
                    )
            except Exception as e:
                self.logger.error(
                    "Failed to list buckets for account=%s: %s", account, e
                )
                continue

            for bucket in buckets:
                try:
                    bucket_name = bucket["name"]
                    secrets = self.backend.list_bucket_secrets(account, bucket_name)
                except Exception as e:
                    self.logger.error(
                        "Failed to list secrets for account=%s bucket=%s: %s",
                        account,
                        bucket_name,
                        e,
                    )
                    continue
                for secret in secrets:
                    secret_id = secret.get("secret_id")
                    try:
                        secret, _, kms_secrets = self.backend.get_bucket_secret(
                            account, bucket_name, secret_id=secret_id
                        )
                        yield {
                            "account": account,
                            "bucket": bucket_name,
                            "secret_id": secret_id,
                            "secret": secret,
                            "kms_secrets": kms_secrets,
                        }
                    except Exception as e:
                        self.logger.error(
                            "Failed to get secret, secret_id=%s for account=%s"
                            " bucket=%s: %s",
                            secret_id,
                            account,
                            bucket_name,
                            e,
                        )

    def run(self):
        required_domains = set(self.kms_api.domains)
        secrets = self.get_all_buckets_secrets()
        # Check if we were able to list secrets
        try:
            first = next(secrets)
        except StopIteration:
            return {"status": "No bucket secrets found"}, 0
        results = {}
        counts = {
            "encrypted_on_all_kms_domains": 0,
            "missing_encryption_on_one_kms_domain": 0,
            "missing_encryption_on_multiple_kms_domains": 0,
        }
        encryptions_counters = {
            "encryption_failure": 0,
            "backend_failure": 0,
            "encryption_success": 0,
        }
        for secret_data in itertools.chain([first], secrets):
            account_id = secret_data["account"]
            bucket_name = secret_data["bucket"]
            secret_id = secret_data["secret_id"]
            secret = secret_data["secret"]
            kms_secrets = {
                domain: (v["key_id"], v["ciphertext"])
                for domain, v in secret_data["kms_secrets"].items()
            }
            actual_domains = set(kms_secrets.keys())
            missing_domains = required_domains - actual_domains
            bucket_counters = results.setdefault("bucket-analysis", copy(counts))
            encryption_per_domain = results.setdefault("result", {})
            if not missing_domains:
                bucket_counters["encrypted_on_all_kms_domains"] += 1
                continue

            missing_count = len(missing_domains)
            if missing_count == 1:
                bucket_counters["missing_encryption_on_one_kms_domain"] += 1
            elif missing_count > 1:
                bucket_counters["missing_encryption_on_multiple_kms_domains"] += 1

            self.logger.info(
                "Encrypting secret for account=%s, bucket=%s, "
                "secret_id=%s (missing domains: %s)",
                account_id,
                bucket_name,
                secret_id,
                missing_domains,
            )

            if self.dry_run:
                continue
            encryption_failure_occured = False
            try:
                for domain in missing_domains:
                    encryption_counters = encryption_per_domain.setdefault(
                        domain, copy(encryptions_counters)
                    )
                    try:
                        context = f"{account_id}_{bucket_name}".encode("utf-8")
                        b64_secret = base64.b64encode(secret)
                        checksum = self.kms_api.checksum(b64_secret)
                        utf8_secret = b64_secret.decode("utf-8")
                        data = self.kms_api.encrypt(domain, utf8_secret, context)
                        kms_secrets[domain] = (data["key_id"], data["ciphertext"])
                        self.logger.info(
                            "Successfully encrypted secret for account=%s, "
                            "bucket=%s, secret_id=%s using domain=%s",
                            account_id,
                            bucket_name,
                            secret_id,
                            domain,
                        )
                    except Exception as e:
                        encryption_counters["encryption_failure"] += 1
                        if not encryption_failure_occured:
                            encryption_failure_occured = True
                        self.logger.error(
                            "Failed to encrypt secret for account=%s, bucket=%s, "
                            "secret_id=%s using domain=%s: %s",
                            account_id,
                            bucket_name,
                            secret_id,
                            domain,
                            e,
                        )

                # Check for remaining missing domains
                new_missing_domains = required_domains - set(kms_secrets.keys())
                # Check if backend update is needed
                if missing_domains != new_missing_domains:
                    av_domains = missing_domains - new_missing_domains
                    # Only save newly encrypted domains. Existing domain entries
                    # are already correctly stored in FDB.
                    newly_encrypted_kms = {d: kms_secrets[d] for d in av_domains}
                    # Save checksum, plaintext and ciphered secrets
                    try:
                        backend_updated = False
                        incomplete = not required_domains.issubset(kms_secrets)
                        self.backend.save_bucket_secret(
                            account_id,
                            bucket_name,
                            secret,
                            checksum,
                            secret_id=secret_id,
                            kms_secrets=newly_encrypted_kms,
                            incomplete=incomplete,
                            overwrite=True,
                        )
                        backend_updated = True
                    except Exception as e:
                        for domain in av_domains:
                            encryption_per_domain[domain]["backend_failure"] += 1
                        self.logger.error(
                            "Failed to save secret in account service for "
                            "account=%s, bucket=%s, secret_id=%s, %s",
                            account_id,
                            bucket_name,
                            secret_id,
                            e,
                        )
                    if backend_updated:
                        for domain in av_domains:
                            encryption_per_domain[domain]["encryption_success"] += 1
            finally:
                self.account_marker = account_id
                self.bucket_marker = bucket_name

        # Determine overall status per domain
        status = "All buckets secrets were successfully encrypted."
        return_code = 0
        for domain, res in results["result"].items():
            new_return_code = 0
            if res["encryption_failure"] > 0:
                status = "Encryption of some buckets secrets failed."
                new_return_code = 1

            if res["backend_failure"] > 0:
                if encryption_failure_occured:
                    # earlier encryption failed and registration on
                    # succeeded encryption failed too
                    status = (
                        "Encryption of some bucket secrets failed, and the "
                        "registration of the encrypted secrets in the backend"
                        " FDB was unsuccessful."
                    )
                    new_return_code = 3
                else:
                    # Only registration failed
                    status = (
                        "Failed to register encrypted KMS secrets in the backend FDB."
                    )
                    new_return_code = 2

            if new_return_code > return_code:
                return_code = new_return_code
            res["status"] = status

        # Send metrics to statsd
        if "bucket-analysis" in results:
            bucket_analysis = results["bucket-analysis"]
            self.statsd.gauge(
                "kms_encryptor.bucket.encrypted_on_all_kms_domains",
                bucket_analysis.get("encrypted_on_all_kms_domains", 0),
            )
            self.statsd.gauge(
                "kms_encryptor.bucket.missing_encryption_on_one_kms_domain",
                bucket_analysis.get("missing_encryption_on_one_kms_domain", 0),
            )
            self.statsd.gauge(
                "kms_encryptor.bucket.missing_encryption_on_multiple_kms_domains",
                bucket_analysis.get("missing_encryption_on_multiple_kms_domains", 0),
            )

        for domain, res in results.get("result", {}).items():
            self.statsd.gauge(
                f"kms_encryptor.domain.{domain}.backend_failure",
                res.get("backend_failure", 0),
            )
            self.statsd.gauge(
                f"kms_encryptor.domain.{domain}.encryption_failure",
                res.get("encryption_failure", 0),
            )
            self.statsd.gauge(
                f"kms_encryptor.domain.{domain}.encryption_success",
                res.get("encryption_success", 0),
            )

        return results, return_code
