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
from functools import reduce

from oio.account.backend_fdb import BYTES_FIELD, OBJECTS_FIELD, AccountBackendFdb
from oio.billing.agents.base import IBillingAgent
from oio.common.easy_value import int_value
from oio.common.exceptions import MalformedBucket
from oio.common.utils import read_storage_mappings


class AccountBillingAgent(IBillingAgent):
    """Agent to fetch buckets from account database and emit storage billing messages"""

    DEFAULT_COUNTER_NAME = "storage.bucket.objects.size"
    DEFAULT_RANKING_SIZE = 10
    AGENT_NAME = "account"

    def __init__(self, conf, logger):
        super().__init__(conf, logger=logger)

        self.backend = AccountBackendFdb(conf, self.logger)
        self.backend.init_db()

        self.ranking_size = int_value(
            self.conf.get("ranking_size"), self.DEFAULT_RANKING_SIZE
        )

        self.storage_mapping, _ = read_storage_mappings(conf)
        self.logger.debug("Storage classes/policies: %s", self.storage_mapping)

        self.per_objects_ranking = {}
        self.per_size_ranking = {}

    def list_buckets(self):
        buckets = self.backend.list_all_buckets()
        for bucket in buckets:
            yield bucket

    def pre_scan(self):
        """
        Resets ranking before pass.
        """
        super().pre_scan()
        self.per_objects_ranking = {}
        self.per_size_ranking = {}

    def _bucket_to_storage_class_stat(
        self, account: str, bucket_name: str, bucket: dict
    ) -> tuple[int, list[dict]]:
        """
        Extract bucket's storage statistics.
        """
        bucket_bytes = bucket.get("bytes")
        if bucket_bytes is None:
            raise MalformedBucket("Missing bytes count")
        if bucket_bytes < 0:
            raise MalformedBucket("Negative bytes count")

        bucket_objects = bucket.get("objects")
        if bucket_objects is None:
            raise MalformedBucket("Missing objects count")
        if bucket_objects < 0:
            raise MalformedBucket("Negative objects count")
        if not bucket_bytes or not bucket_objects:
            if bucket_bytes:
                self.logger.info(
                    'Bucket "%s" of account "%s" contains bytes (%d), '
                    "but no object, either there are only parts left, "
                    "or we should check it before sending it to billing",
                    bucket_name,
                    account,
                    bucket_bytes,
                )
            elif bucket_objects:
                self.logger.debug(
                    'Bucket "%s" of account "%s" contains only empty objects, '
                    "do not send it to billing",
                    bucket_name,
                    account,
                )
            else:
                self.logger.debug(
                    'Bucket "%s" of account "%s" contains no object, '
                    "do not send it to billing",
                    bucket_name,
                    account,
                )
            return None, None

        bytes_details = bucket.get("bytes-details", {})
        objects_details = bucket.get("objects-details", {})
        total_bytes = 0
        total_objects = 0
        storage_class_stat = {}
        storage_policies = set(bytes_details).union(objects_details)
        for policy_name in storage_policies:
            policy_bytes = bytes_details.get(policy_name, 0)
            if policy_bytes < 0:
                raise MalformedBucket(
                    f"Negative bytes for storage policy '{policy_name}'"
                )
            policy_objects = objects_details.get(policy_name, 0)
            if policy_objects < 0:
                raise MalformedBucket(
                    f"Negative objects for storage policy '{policy_name}'"
                )
            if not policy_bytes and not policy_objects:
                self.logger.debug(
                    'Empty statistics with the storage policy "%s" '
                    'for bucket "%s" of account "%s" could be deleted',
                    policy_name,
                    bucket_name,
                    account,
                )
                continue

            storage_class = self.storage_mapping.get(
                policy_name, self.default_storage_class
            )
            stat = storage_class_stat.setdefault(
                storage_class,
                {
                    "storage_class": storage_class,
                    "bytes_used": 0,
                    # 'container_count': 0,
                    "object_count": 0,
                },
            )
            stat["bytes_used"] += policy_bytes
            stat["object_count"] += policy_objects
            total_bytes += policy_bytes
            total_objects += policy_objects
        if storage_policies:
            if total_bytes != bucket_bytes:
                raise MalformedBucket(
                    f"Mismatch between total bytes ({bucket_bytes}) and detailed bytes"
                    f" ({total_bytes})"
                )
            if total_objects != bucket_objects:
                raise MalformedBucket(
                    f"Mismatch between total objects ({bucket_objects}) and detailed"
                    f" objects ({total_objects})"
                )
        else:
            self.logger.info(
                'Missing details for bucket "%s" of account "%s"', bucket_name, account
            )
            storage_class_stat[self.default_storage_class] = {
                "storage_class": self.default_storage_class,
                "bytes_used": bucket_bytes,
                # 'container_count': 0,
                "object_count": bucket_objects,
            }
        return bucket_bytes, [
            storage_class_stat[key] for key in sorted(storage_class_stat.keys())
        ]

    def _update_ranking(self, ranking, value):
        last = ranking[-1] if len(ranking) == self.ranking_size else None
        if last and value[1] <= last[1]:
            return
        insert_idx = len(ranking)
        for i, entry in enumerate(ranking):
            if entry[1] <= value[1]:
                insert_idx = i
                break
        ranking.insert(insert_idx, value)
        if len(ranking) > self.ranking_size:
            ranking.pop(-1)

    def rank_sample(self, sample):
        metadata = sample["resource_metadata"]
        region = metadata["region_name"]
        bucket_name = metadata["bucket_name"]
        stats = metadata["storage_class_stat"]
        bytes_used = sample["counter_volume"]
        object_count = reduce(lambda a, b: a + b, [e["object_count"] for e in stats])

        objects_ranking = self.per_objects_ranking.setdefault(region, [])
        size_ranking = self.per_size_ranking.setdefault(region, [])

        self._update_ranking(objects_ranking, (bucket_name, object_count))
        self._update_ranking(size_ranking, (bucket_name, bytes_used))

    def bucket_to_sample(self, bucket):
        """
        Extract bucket's information and storage statistics to create a sample.
        """
        tsiso8601 = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        bucket_name = bucket["name"]
        account = bucket.get("account")
        if not account:
            raise MalformedBucket("Missing account")
        if not account.startswith(self.reseller_prefix):
            self.logger.debug(
                'Bucket "%s" of account "%s" does not start with reseller prefix',
                bucket_name,
                account,
            )
            return None
        project_id = account[len(self.reseller_prefix) :]
        region = bucket.get("region")
        if not region:
            raise MalformedBucket("Missing region")
        bucket_size, storage_class_stat = self._bucket_to_storage_class_stat(
            account, bucket_name, bucket
        )
        if not storage_class_stat:
            return None
        message_id = uuid.uuid4().hex

        sample = {
            "counter_name": self.counter_name,
            "counter_type": "gauge",
            "counter_unit": "B",
            "counter_volume": bucket_size,
            "message_id": message_id,
            "project_id": project_id,
            "resource_id": project_id,
            "resource_metadata": {
                "account_name": account,
                "bucket_name": bucket_name,
                # 'infra_name': '',
                # 'infra_type': '',
                "storage_class_stat": storage_class_stat,
                "region_name": region,
            },
            "source": region,
            "timestamp": tsiso8601,
            # 'user_id': '',
        }

        self.rank_sample(sample)
        return sample

    def post_scan(self):
        super().post_scan
        # Publish rankings
        self.backend.update_rankings(
            {
                BYTES_FIELD: self.per_size_ranking,
                OBJECTS_FIELD: self.per_objects_ranking,
            }
        )
