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
from oio.xcute.jobs.bucket_lister import BucketListerJob


class BucketLister(CustomerCommand, XcuteJobStartCommand):
    """
    List objects matching a replication rule and store them in a bucket.
    """

    JOB_CLASS = BucketListerJob
    DEFAULT_TECHNICAL_BUCKET = "xcute-customer-technical-bucket"

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        parser.add_argument(
            dest="bucket",
            help="Customer bucket to list",
        )
        parser.add_argument(
            "--technical-bucket",
            dest="technical_bucket",
            help=f"Technical bucket (default: {self.DEFAULT_TECHNICAL_BUCKET})",
            default=self.DEFAULT_TECHNICAL_BUCKET,
        )
        return parser

    def get_job_config(self, parsed_args):
        job_params = {
            # Account comes from the common parser
            "account": self.app.client_manager.account,
            "bucket": parsed_args.bucket,
            "technical_bucket": parsed_args.technical_bucket,
        }
        return {"params": job_params}
