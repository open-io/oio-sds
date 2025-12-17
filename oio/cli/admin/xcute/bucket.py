# Copyright (C) 2025-2026 OVH SAS
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
        parser.add_argument(
            "--time-limit",
            dest="time_limit",
            help="Set a time limit(Epoch timestamp in seconds) for replication. Only "
            "objects older than the limit are replicated.(-1 means no limit)",
            type=int,
            default=-1,
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
            "time_limit": parsed_args.time_limit,
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
            "--kafka-max-lags",
            dest="kafka_max_lags",
            help="Prevent to send more tasks if topic lags exceed threshold",
            type=int,
        )
        parser.add_argument(
            "--kafka-min-available-space",
            dest="kafka_min_available_space",
            help="Prevent to send more tasks if available space on kafka cluster is"
            "below threshold",
            type=float,
        )

        return parser

    def get_job_config(self, parsed_args):
        job_params = {
            "technical_manifest_prefix": parsed_args.technical_manifest_prefix,
            "technical_account": parsed_args.technical_account,
            "technical_bucket": parsed_args.technical_bucket,
        }
        if parsed_args.kafka_max_lags is not None:
            job_params["kafka_max_lags"] = parsed_args.kafka_max_lags
        if parsed_args.kafka_min_available_space is not None:
            job_params["kafka_min_available_space"] = (
                parsed_args.kafka_min_available_space
            )
        return {"params": job_params}
