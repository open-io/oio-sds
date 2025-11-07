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

from oio.cli.admin.xcute import CustomerCommand, XcuteJobStartCommand
from oio.xcute.jobs.batch_replicator import (
    DEFAULT_CHECK_REPLICATION_STATUS_TIMEOUT,
    BatchReplicatorJob,
)
from oio.xcute.jobs.bucket_lister import BucketListerJob

DEFAULT_TECHNICAL_ACCOUNT = "AUTH_demo"
DEFAULT_TECHNICAL_BUCKET = "xcute-customer-technical-bucket"


class BucketLister(CustomerCommand, XcuteJobStartCommand):
    """
    List objects matching a replication rule and store them in a bucket.
    """

    JOB_CLASS = BucketListerJob

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        default_policy = self.app.client_manager.conscience.info()["options"][
            "storage_policy"
        ]
        parser.add_argument(
            dest="bucket",
            help="Customer bucket to list",
        )
        parser.add_argument(
            dest="replication_configuration",
            help="Replication configuration to use while listing all objects.",
        )
        parser.add_argument(
            "--storage-policy",
            dest="policy_manifest",
            help=f"Policy to use for the manifests (default: {default_policy})",
            default=default_policy,
        )
        parser.add_argument(
            "--technical-account",
            dest="technical_account",
            help=f"Technical account (default: {DEFAULT_TECHNICAL_ACCOUNT})",
            default=DEFAULT_TECHNICAL_ACCOUNT,
        )
        parser.add_argument(
            "--technical-bucket",
            dest="technical_bucket",
            help=f"Technical bucket (default: {DEFAULT_TECHNICAL_BUCKET})",
            default=DEFAULT_TECHNICAL_BUCKET,
        )
        return parser

    def get_job_config(self, parsed_args):
        job_params = {
            # Account comes from the common parser
            "account": self.app.client_manager.account,
            "bucket": parsed_args.bucket,
            "technical_account": parsed_args.technical_account,
            "technical_bucket": parsed_args.technical_bucket,
            "replication_configuration": parsed_args.replication_configuration,
            "policy_manifest": parsed_args.policy_manifest,
        }
        return {"params": job_params}


class BatchReplicator(CustomerCommand, XcuteJobStartCommand):
    """
    Send events and track replication status from a listing done with BucketLister.
    """

    JOB_CLASS = BatchReplicatorJob

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        parser.add_argument(
            dest="technical_manifest_prefix",
            help="Technical manifest prefix to process",
        )
        parser.add_argument(
            "--technical-account",
            dest="technical_account",
            help=f"Technical account (default: {DEFAULT_TECHNICAL_ACCOUNT})",
            default=DEFAULT_TECHNICAL_ACCOUNT,
        )
        parser.add_argument(
            "--technical-bucket",
            dest="technical_bucket",
            help=f"Technical bucket (default: {DEFAULT_TECHNICAL_BUCKET})",
            default=DEFAULT_TECHNICAL_BUCKET,
        )
        parser.add_argument(
            "--check-replication-status-timeout",
            dest="repli_status_timeout",
            help=(
                f"Timeout to wait for the object to be replicated "
                f"(default: {DEFAULT_CHECK_REPLICATION_STATUS_TIMEOUT})"
            ),
            default=DEFAULT_CHECK_REPLICATION_STATUS_TIMEOUT,
        )
        return parser

    def get_job_config(self, parsed_args):
        job_params = {
            "technical_manifest_prefix": parsed_args.technical_manifest_prefix,
            "technical_account": parsed_args.technical_account,
            "technical_bucket": parsed_args.technical_bucket,
            "check_replication_status_timeout": parsed_args.repli_status_timeout,
        }
        return {"params": job_params}
