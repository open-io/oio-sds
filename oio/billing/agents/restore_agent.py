# Copyright (C) 2025 OVH SAS
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import uuid
from datetime import datetime, timezone

from oio.billing.agents.base import IBillingAgent
from oio.billing.helpers import RestoreBillingClient
from oio.common.configuration import load_namespace_conf
from oio.common.constants import S3StorageClasses


class RestoreAgent(IBillingAgent):
    DEFAULT_COUNTER_NAME = "storage.bucket.objects.restore"
    AGENT_NAME = "restore"

    def __init__(self, conf, logger):
        super().__init__(conf, logger)

        self.client = RestoreBillingClient(self.conf, logger=self.logger)
        self.ns = conf.get("namespace")
        self.region = load_namespace_conf(self.ns, failsafe=True).get("ns.region")
        if not self.region:
            raise ValueError("Region is missing")

        self.restore_storage_class = self.conf.get(
            "restore_storage_class", S3StorageClasses.STANDARD.name
        ).upper()

        # Ensure restore storage class is valid
        _ = S3StorageClasses(self.restore_storage_class)

    def list_buckets(self):
        for account, bucket, storage_class in self.client.list_restore():
            counters = self.client.reset_restore(account, bucket, storage_class)
            yield {
                "account": account,
                "name": bucket,
                "storage_class": storage_class,
                "bytes_used": counters.get("transfer", 0),
                "call_count": counters.get("requests", 0),
                "bytes_restored": counters.get("storage", 0),
            }

    def bucket_to_sample(self, bucket):
        tsiso8601 = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        message_id = uuid.uuid4().hex
        bucket_name = bucket["name"]
        storage_class = bucket["storage_class"]
        account = bucket.get("account")
        project_id = account[len(self.reseller_prefix) :]

        if (
            bucket["bytes_used"] == 0
            and bucket["call_count"] == 0
            and bucket["bytes_restored"] == 0
        ):
            return None
        return {
            "counter_name": self.counter_name,
            "counter_type": "gauge",
            "counter_unit": "B",
            "counter_volume": bucket["bytes_used"],
            "message_id": message_id,
            "project_id": project_id,
            "resource_id": project_id,
            "resource_metadata": {
                "storage_class": storage_class,
                "account_name": account,
                "bucket_name": bucket_name,
                "bytes_used": bucket["bytes_used"],
                "call_count": bucket["call_count"],
                "bytes_restored": bucket["bytes_restored"],
                "region_name": self.region,
                "restore_storage_class": self.restore_storage_class,
            },
            "source": self.region,
            "timestamp": tsiso8601,
        }
