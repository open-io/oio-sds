# Copyright (C) 2021-2023 OVH SAS
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

from collections import Counter
from copy import deepcopy
import fdb
from functools import wraps
import struct
import time
from werkzeug.exceptions import BadRequest, Conflict, Forbidden, NotFound

from oio.account.common_fdb import CommonFdb
from oio.common.constants import BUCKET_PROP_REPLI_ENABLED, SHARDING_ACCOUNT_PREFIX
from oio.common.easy_value import boolean_value, float_value, int_value
from oio.common.exceptions import ServiceBusy
from oio.common.timestamp import Timestamp

fdb.api_version(CommonFdb.FDB_VERSION)

LAST_UNICODE_CHAR = "\U0010fffd"

MULTIUPLOAD_SUFFIX = "+segments"
BYTES_FIELD = "bytes"
OBJECTS_FIELD = "objects"
OBJECTS_S3_FIELD = OBJECTS_FIELD + "-s3"
SHARDS_FIELD = "shards"
CONTAINERS_FIELD = "containers"
BUCKETS_FIELD = "buckets"
BUCKET_FIELD = "bucket"
ACCOUNTS_FIELD = "accounts"
REGION_FIELD = "region"
REGIONS_FIELD = "regions"
CTIME_FIELD = "ctime"
MTIME_FIELD = "mtime"
LAST_UPDATE_FIELD = "last-update"
COUNTERS_FIELDS = (
    BYTES_FIELD,
    OBJECTS_FIELD,
    SHARDS_FIELD,
    CONTAINERS_FIELD,
    BUCKETS_FIELD,
    ACCOUNTS_FIELD,
    OBJECTS_S3_FIELD,
)
TIMESTAMP_FIELDS = (CTIME_FIELD, MTIME_FIELD)
RESERVED_BUCKET_FIELDS = (
    "account",
    REGION_FIELD,
    CTIME_FIELD,
    MTIME_FIELD,
    CONTAINERS_FIELD,
    BYTES_FIELD,
    OBJECTS_FIELD,
    BYTES_FIELD + "-details",
    OBJECTS_FIELD + "-details",
    OBJECTS_S3_FIELD,
)


def catch_service_errors(func):
    """
    :raises `ServiceBusy`: in case of a fdb service error
    """

    @wraps(func)
    def catch_service_errors_wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (fdb.FDBError, ValueError) as err:
            raise ServiceBusy(message=str(err)) from err

    return catch_service_errors_wrapper


def use_snapshot_reads(func):
    """
    Use snapshot reads when read-only is required.
    """

    @wraps(func)
    def use_snapshot_reads_wrapper(self, tr, *args, readonly=False, **kwargs):
        if readonly:
            # Intentionally drop the parameter to do it only once
            tr = tr.snapshot
        return func(self, tr, *args, **kwargs)

    return use_snapshot_reads_wrapper


class AccountBackendFdb(object):
    """
    Foundationdb backend for account service.
    """

    # Default batch size, this value could be divided by 2 if time of refresh
    # by batch is too long
    BATCH_SIZE = 10000

    # Default subspaces prefixes

    ACCOUNTS_KEY_PREFIX = "accounts"
    ACCOUNT_KEY_PREFIX = "account"
    BUCKET_KEY_PREFIX = "bucket"
    BUCKET_LIST_PREFIX = "buckets"
    CONTAINERS_LIST_PREFIX = "containers"
    CONTAINER_LIST_PREFIX = "container"
    # Remaining keys for deletex containers prefix
    CTS_TO_DELETE_LIST_PREFIX = "deleted-container"
    # Metadata prefix
    METADATA_PREFIX = "metadata"
    # Prefix for bucket db
    BUCKET_RESERVE_PREFIX = "s3bucket"
    # Stats & metric prefix
    METRICS_PREFIX = "metrics"
    # Rankings prefix
    RANKINGS_PREFIX = "rankings"

    # Timeout for bucket reservation
    DEFAULT_BUCKET_RESERVATION_TIMEOUT = 30
    # Maximum number of buckets per account
    MAX_BUCKETS_PER_ACCOUNT = 100

    def init_db(self, event_model="gevent"):
        """
        This method makes connexion to fdb database. It could be called
        any time in mono process, but in case we fork processes it should be
        called after forking in gunicorn.
        This is the reason why this task is not done inside constructor.
        """
        self.fdb_file = self.conf.get("fdb_file", CommonFdb.DEFAULT_FDB)
        try:
            if self.db is None:
                self.db = fdb.open(self.fdb_file, event_model=event_model)
        except Exception as exc:
            self.logger.error(
                "can't open fdb file: %s exception %s", self.fdb_file, exc
            )
            raise
        try:
            self.namespace = fdb.directory.create_or_open(
                self.db, (self.main_namespace_name,)
            )
            self.acct_space = self.namespace.create_or_open(
                self.db, self.account_prefix
            )
            self.accts_space = self.namespace.create_or_open(
                self.db, self.accounts_prefix
            )
            self.container_space = self.namespace.create_or_open(
                self.db, self.container_list_prefix
            )
            self.containers_index_space = self.namespace.create_or_open(
                self.db, self.containers_list_prefix
            )
            self.ct_to_delete_space = self.namespace.create_or_open(
                self.db, self.ct_to_delete_prefix
            )
            self.bucket_db_space = self.namespace.create_or_open(
                self.db, self.reserve_bucket_prefix
            )
            self.bucket_space = self.namespace.create_or_open(
                self.db, self.bucket_prefix
            )
            self.buckets_index_space = self.namespace.create_or_open(
                self.db, self.buckets_list_prefix
            )
            self.metadata_space = self.namespace.create_or_open(
                self.db, self.metadata_prefix
            )
            self.metrics_space = self.namespace.create_or_open(
                self.db, self.metrics_prefix
            )
            self.rankings_space = self.namespace.create_or_open(
                self.db, self.rankings_prefix
            )
        except Exception as exc:
            self.logger.warning("Directory create exception %s", exc)
            raise

    def __init__(self, conf, logger):
        self.db = None
        self.conf = conf
        self.logger = logger
        self.fdb_file = None
        self.autocreate = boolean_value(conf.get("autocreate"), True)
        self.time_window_clear_deleted = float_value(
            self.conf.get("time_window_clear_deleted"), 60.0
        )
        self.main_namespace_name = self.conf.get(
            "main_namespace_name", CommonFdb.MAIN_NAMESPACE
        )
        self.accounts_prefix = conf.get("accounts_prefix", self.ACCOUNTS_KEY_PREFIX)
        self.account_prefix = conf.get("account_prefix", self.ACCOUNT_KEY_PREFIX)
        self.bucket_prefix = conf.get("bucket_prefix", self.BUCKET_KEY_PREFIX)
        self.buckets_list_prefix = conf.get(
            "bucket_list_prefix", self.BUCKET_LIST_PREFIX
        )
        self.container_list_prefix = conf.get(
            "container_list_prefix", self.CONTAINER_LIST_PREFIX
        )
        self.containers_list_prefix = conf.get(
            "containers_list_prefix", self.CONTAINERS_LIST_PREFIX
        )
        self.ct_to_delete_prefix = conf.get(
            "containers_to_delete_prefix", self.CTS_TO_DELETE_LIST_PREFIX
        )
        self.metadata_prefix = conf.get("metadata_prefix", self.METADATA_PREFIX)
        self.metrics_prefix = conf.get("metrics_prefix", self.METRICS_PREFIX)
        self.rankings_prefix = conf.get("rankings_prefix", self.RANKINGS_PREFIX)
        self.reserve_bucket_prefix = conf.get(
            "reserve_bucket_prefix", self.BUCKET_RESERVE_PREFIX
        )

        self.bucket_reservation_timeout = float_value(
            conf.get("bucket_reservation_timeout"),
            self.DEFAULT_BUCKET_RESERVATION_TIMEOUT,
        )
        self.max_buckets_per_account = int_value(
            conf.get("max_buckets_per_account"), self.MAX_BUCKETS_PER_ACCOUNT
        )

    # Helpers -----------------------------------------------------------------

    def _set_counter(self, tr, key, value=0):
        tr[key] = struct.pack("<q", value)

    def _increment(self, tr, key, inc=1, force=False):
        if inc or force:
            tr.add(key, struct.pack("<q", inc))

    def _counter_value_to_counter(self, counter_value):
        return struct.unpack("<q", counter_value)[0]

    def _counters_key_value_to_dict(self, counters_key_value, unpack=None):
        counters = {}
        for counter_key, counter_value in counters_key_value:
            if unpack:
                counter_key = unpack(counter_key)
            if isinstance(counter_key, tuple) and len(counter_key) == 1:
                counter_key = counter_key[0]
            counters[counter_key] = struct.unpack("<q", counter_value)[0]
        return counters

    def _get_timestamp(self, timestamp=None):
        timestamp = Timestamp(timestamp).timestamp
        # Microsecond precision
        return int(timestamp * 1000000) / 1000000

    def _set_timestamp(self, tr, key, timestamp):
        tr[key] = struct.pack("<Q", int(timestamp * 1000000))

    def _update_timestamp(self, tr, key, timestamp):
        tr.max(key, struct.pack("<Q", int(timestamp * 1000000)))

    def _timestamp_value_to_timestamp(self, timestamp_value):
        return struct.unpack("<Q", timestamp_value)[0] / 1000000

    def _unmarshal_info(self, keys_values, has_regions=False, unpack=None):
        info = {}
        for key, value in keys_values:
            if unpack:
                key = unpack(key)
            field, *details = key
            if details:
                if not has_regions and len(details) == 1:
                    policy = details[0]
                    dict_values = info.setdefault(f"{field}-details", {})
                    dict_values[policy] = self._counter_value_to_counter(value)
                elif has_regions and len(details) <= 2:
                    region = details[0]
                    dict_values = info.setdefault(REGIONS_FIELD, {}).setdefault(
                        region, {}
                    )
                    if len(details) == 2:
                        dict_values = dict_values.setdefault(f"{field}-details", {})
                        field = details[1]  # polciy
                    dict_values[field] = self._counter_value_to_counter(value)
                else:
                    self.logger.warning('Unknown key: "%s"', key)
            elif field in COUNTERS_FIELDS:
                info[field] = self._counter_value_to_counter(value)
            elif field in TIMESTAMP_FIELDS:
                info[field] = self._timestamp_value_to_timestamp(value)
            else:
                info[field] = value.decode("utf-8")
        if info:
            # Make sure all keys are still visible,
            # even if there is no associated information
            if has_regions:
                info.setdefault(REGIONS_FIELD, {})
                for region_info in info[REGIONS_FIELD].values():
                    for fields in (CONTAINERS_FIELD, BUCKETS_FIELD):
                        region_info.setdefault(fields, 0)
                    for fields in (BYTES_FIELD, OBJECTS_FIELD):
                        region_info.setdefault(f"{fields}-details", {})
            else:
                for fields in (BYTES_FIELD, OBJECTS_FIELD):
                    info.setdefault(f"{fields}-details", {})
        return info

    def _get_start_and_stop(self, space, prefix=None, marker=None, end_marker=None):
        space_range = space.range()
        start = space_range.start
        stop = space_range.stop
        if prefix:
            start = space[prefix].range().start
            stop = space[prefix + LAST_UNICODE_CHAR].range().stop
        if marker and (not prefix or marker >= prefix):
            start = space[marker].range().stop
        if end_marker and (not prefix or end_marker <= prefix + LAST_UNICODE_CHAR):
            stop = space[end_marker].range().start
        return start, stop

    @fdb.transactional
    @use_snapshot_reads
    def _list_items(
        self, tr, start, stop, limit, filters, unpack, format_item, **kwargs
    ):
        items = []

        def _append_item(name, keys_values):
            if not keys_values:
                return
            info = self._unmarshal_info(keys_values, **kwargs)
            for fltr in filters:
                if not fltr(name, info):
                    break
            else:
                items.append(format_item(tr, name, info))

        iterator = tr.get_range(start, stop)
        item_keys_values = None, None
        for key, value in iterator:
            item_name, *key = unpack(key)
            if item_name != item_keys_values[0]:
                _append_item(*item_keys_values)
                if len(items) >= limit:
                    return items
                item_keys_values = item_name, []
            item_keys_values[1].append((key, value))
        _append_item(*item_keys_values)
        return items

    @fdb.transactional
    def _update_metadata(self, tr, space, to_update, to_delete, forbidden_keys=None):
        if to_update is None:
            to_update = {}
        if to_delete is None:
            to_delete = set()
        else:
            to_delete = set(to_delete)
        if forbidden_keys is None:
            forbidden_keys = ()

        common_keys = set(to_update).intersection(to_delete)
        if common_keys:
            raise BadRequest(
                f"Keys {common_keys} cannot be updated and deleted at the same time"
            )

        for key, value in to_update.items():
            if not isinstance(key, str):
                raise BadRequest("All keys must be strings")
            if not isinstance(value, str):
                raise BadRequest("All values must be strings")
            if key in forbidden_keys:
                raise Forbidden(f"Key {key} cannot be changed")
            tr[space.pack((key,))] = value.encode("utf-8")
        for key in to_delete:
            if not isinstance(key, str):
                raise BadRequest("All keys must be strings")
            if key in forbidden_keys:
                raise Forbidden(f"Key {key} cannot be changed")
            tr.clear(space.pack((key,)))

    # Status/metrics/rankings -------------------------------------------------

    @catch_service_errors
    def status(self, **kwargs):
        return self._status(self.db, readonly=True)

    @fdb.transactional
    @use_snapshot_reads
    def _status(self, tr):
        accounts = tr[self.metrics_space.pack((ACCOUNTS_FIELD,))]
        if accounts.present():
            accounts = self._counter_value_to_counter(accounts.value)
        else:
            accounts = 0
        return {"account_count": accounts}

    @catch_service_errors
    def info_metrics(self, output_type, **kwargs):
        """
        Get all available information about global metrics.
        """
        metrics = self._info_metrics(self.db, readonly=True)
        if output_type == "prometheus":
            return self._metrics_to_prometheus_format(metrics)
        else:
            return metrics

    @fdb.transactional
    @use_snapshot_reads
    def _info_metrics(self, tr):
        """
        [transactional] Get all available information about global metrics.
        """
        metrics_range = self.metrics_space.range()
        iterator = tr.get_range(
            metrics_range.start,
            metrics_range.stop,
            streaming_mode=fdb.StreamingMode.want_all,
        )
        info = self._unmarshal_info(
            iterator, has_regions=True, unpack=self.metrics_space.unpack
        )
        info.setdefault(ACCOUNTS_FIELD, 0)
        regions = info.setdefault(REGIONS_FIELD, {})
        for _, region_info in regions.items():
            # The other counters are already added
            # in the `self._unmarshal_info` method
            region_info.setdefault(SHARDS_FIELD, 0)
        return info

    def _metrics_to_prometheus_format(self, metrics):
        prom_output = []
        prom_output.append(f"obsto_accounts {metrics[ACCOUNTS_FIELD]}")
        for region, region_details in metrics[REGIONS_FIELD].items():
            for counter, counter_value in region_details.items():
                if counter.endswith("-details"):
                    counter = counter[:-8]
                    for policy, policy_value in counter_value.items():
                        # Prometheus does not like hyphens
                        prom_output.append(
                            f"obsto_{counter.replace('-', '_')}"
                            f'{{region="{region}",policy="{policy}"}} '
                            f"{policy_value}"
                        )
                else:
                    # Prometheus does not like hyphens
                    prom_output.append(
                        f'obsto_{counter.replace("-", "_")}{{region="{region}"}} '
                        f"{counter_value}"
                    )
        return "\n".join(prom_output)

    @fdb.transactional
    def _update_metrics_stats(self, tr, region, stats_delta):
        """
        [transactional] Update metrics stats for the specified region.
        """
        if OBJECTS_S3_FIELD in stats_delta:
            self._increment(
                tr,
                self.metrics_space.pack((OBJECTS_S3_FIELD, region)),
                stats_delta.get(OBJECTS_S3_FIELD, 0),
            )

        for key in (BYTES_FIELD, OBJECTS_FIELD):
            if key not in stats_delta:
                continue
            for policy, value in stats_delta[f"{key}-details"].items():
                # Update stats by policy (by policy)
                self._increment(
                    tr, self.metrics_space.pack((key, region, policy)), value
                )

    @catch_service_errors
    def refresh_metrics(self, **kwargs):
        """
        Recompute the global metrics
        """

        self._refresh_metrics(self.db)

    @fdb.transactional
    def _refresh_metrics(self, tr):
        self._reset_metrics(tr)

        counters = {
            ACCOUNTS_FIELD: 0,
        }
        marker = None

        acc_range = self.acct_space.range()

        for key, value in tr.get_range(acc_range.start, acc_range.stop):
            account_id, field, *parts = self.acct_space.unpack(key)
            is_shard = account_id.startswith(SHARDING_ACCOUNT_PREFIX)

            if marker != account_id:
                marker = account_id

                if not is_shard:
                    counters[ACCOUNTS_FIELD] += 1

            # Only treat counters with region
            if len(parts) == 0:
                continue
            region = parts[0]
            details = parts[1] if len(parts) > 1 else None
            value = self._counter_value_to_counter(value)

            if field not in COUNTERS_FIELDS:
                continue
            if is_shard:
                if field == CONTAINERS_FIELD:
                    field = SHARDS_FIELD
            if details and field in (BYTES_FIELD, OBJECTS_FIELD):
                field_counters = counters.setdefault(field, {})
                region_counters = field_counters.setdefault(region, Counter())
                region_counters[details] += value
            else:
                counter = counters.setdefault(field, Counter())
                counter[region] += value

        # Update data with counters
        self._update_metrics(tr, counters)

    @fdb.transactional
    def _reset_metrics(self, tr):
        # Delete every keys in 'metrics' subspace
        metrics_range = self.metrics_space.range()
        tr.clear_range(metrics_range.start, metrics_range.stop)

    @fdb.transactional
    def _update_metrics(self, tr, counters):
        for key, value in counters.items():
            if key is ACCOUNTS_FIELD:
                self._set_counter(tr, self.metrics_space.pack((ACCOUNTS_FIELD,)), value)
            else:
                for counter_key, counter_value in value.items():
                    if isinstance(counter_value, Counter):
                        for detail_key, detail_value in counter_value.items():
                            entry_key = (key, counter_key, detail_key)
                            self._set_counter(
                                tr, self.metrics_space.pack(entry_key), detail_value
                            )
                    else:
                        self._set_counter(
                            tr,
                            self.metrics_space.pack((key, counter_key)),
                            counter_value,
                        )

    def _rankings_to_prometheus_format(self, rankings):
        prom_output = []
        last_update = rankings[LAST_UPDATE_FIELD]
        if last_update is None:
            return ""
        prom_output.append(f"obsto_last_update {last_update}")
        for field in (BYTES_FIELD, OBJECTS_FIELD):
            for region, region_rankings in rankings[field].items():
                for entry in region_rankings:
                    bucket_name = entry["name"]
                    # Prometheus does not like hyphens
                    prom_output.append(
                        f"obsto_{field.replace('-', '_')}"
                        f'{{region="{region}",bucket="{bucket_name}"}}'
                        f" {entry['value']}"
                    )
        return "\n".join(prom_output)

    @catch_service_errors
    def info_rankings(self, output_type, **kwargs):
        """
        Get all available information about buckets rankings.
        """
        rankings = self._info_rankings(self.db, readonly=True)
        if output_type == "prometheus":
            return self._rankings_to_prometheus_format(rankings)
        else:
            return rankings

    @fdb.transactional
    @use_snapshot_reads
    def _info_rankings(self, tr):
        """
        [transactional] Get all available information about rankings.
        """
        rankings_range = self.rankings_space.range()
        iterator = tr.get_range(
            rankings_range.start,
            rankings_range.stop,
            streaming_mode=fdb.StreamingMode.want_all,
        )
        rankings = {LAST_UPDATE_FIELD: None, OBJECTS_FIELD: {}, BYTES_FIELD: {}}
        for key, value in iterator:
            field, *key = self.rankings_space.unpack(key)
            if field == LAST_UPDATE_FIELD:
                rankings[field] = self._timestamp_value_to_timestamp(value)
                continue
            if field not in (BYTES_FIELD, OBJECTS_FIELD):
                self.logger.warning(f"Field '{field}' is not supported")
                continue
            region, bucket = key
            region_rankings = rankings[field].setdefault(region, [])
            region_rankings.append(
                {"name": bucket, "value": self._counter_value_to_counter(value)}
            )
        return rankings

    def update_rankings(self, rankings):
        """
        Update rankings
        """
        self._update_rankings(self.db, rankings)

    @fdb.transactional
    def _update_rankings(self, tr, global_rankings):

        # Reset rankings
        rankings_range = self.rankings_space.range()
        tr.clear_range(rankings_range.start, rankings_range.stop)

        for field in (BYTES_FIELD, OBJECTS_FIELD):
            if field not in global_rankings:
                self.logger.warning(f"Field '{field}' is missing")
                continue

            region_rankings = global_rankings[field]
            for region, rankings in region_rankings.items():
                for bucket, value in rankings:
                    key = (field, region, bucket)
                    self._set_counter(tr, self.rankings_space.pack(key), value)

        now = self._get_timestamp()
        self._set_timestamp(tr, self.rankings_space.pack((LAST_UPDATE_FIELD,)), now)

    # Account -----------------------------------------------------------------

    @catch_service_errors
    def create_account(self, account_id, **kwargs):
        """
        Create the account if it doesn't already exist.
        """
        # get ctime is only used for migration
        ctime = kwargs.get(CTIME_FIELD)
        status = self._create_account(self.db, account_id, ctime=ctime)
        if not status:
            return None
        return account_id

    @fdb.transactional
    def _create_account(self, tr, account_id, ctime=None):
        """
        [transactional] Create the account if it doesn't already exist.
        """
        account_space = self.acct_space[account_id]

        if tr[account_space.pack((CTIME_FIELD,))].present():
            # Account already exists
            return False
        self._real_create_account(tr, account_id, ctime=ctime)
        return True

    @fdb.transactional
    def _real_create_account(self, tr, account_id, ctime=None):
        """
        [transactional] Create the account.
        This method assumes that the account does not exist.
        """
        account_space = self.acct_space[account_id]
        if ctime is None:
            ctime = self._get_timestamp()

        # Add basic info
        tr[account_space.pack(("id",))] = account_id.encode("utf-8")
        self._set_counter(tr, account_space.pack((BYTES_FIELD,)))
        self._set_counter(tr, account_space.pack((OBJECTS_FIELD,)))
        self._set_counter(tr, account_space.pack((CONTAINERS_FIELD,)))
        self._set_counter(tr, account_space.pack((BUCKETS_FIELD,)))
        # Set account ctime and mtime
        self._set_timestamp(tr, account_space.pack((CTIME_FIELD,)), ctime)
        self._set_timestamp(tr, account_space.pack((MTIME_FIELD,)), ctime)
        # Add account in index
        tr[self.accts_space.pack((account_id,))] = b"1"
        # Increase accounts counter in metrics
        if not account_id.startswith(SHARDING_ACCOUNT_PREFIX):
            self._increment(tr, self.metrics_space.pack((ACCOUNTS_FIELD,)))
        # else:
        #     Do not count sharding accounts in metrics

    @catch_service_errors
    def delete_account(self, account_id, **kwargs):
        """
        Delete the account if it already exists.
        """
        self._delete_account(self.db, account_id)
        return True

    @fdb.transactional
    def _delete_account(self, tr, account_id):
        """
        [transactional] Delete the account if it already exists.
        """
        if not account_id.startswith(SHARDING_ACCOUNT_PREFIX):
            # Delete sharding account
            try:
                self._delete_account(tr, SHARDING_ACCOUNT_PREFIX + account_id)
            except NotFound:
                pass

        account_space = self.acct_space[account_id]

        account_ctime = tr[account_space.pack((CTIME_FIELD,))]
        if not account_ctime.present():
            raise NotFound("Account does'nt exist")

        containers = tr[account_space.pack((CONTAINERS_FIELD,))]
        if containers.present():
            containers = self._counter_value_to_counter(containers.value)
        else:
            containers = 0
        if containers > 0:
            raise Conflict("Account not empty")

        self._real_delete_account(tr, account_id)

    @fdb.transactional
    def _real_delete_account(self, tr, account_id):
        """
        [transactional] Delete the account.
        This method assumes that the account exists.
        """
        # Delete containers
        containers_range = self.containers_index_space[account_id].range()
        tr.clear_range(containers_range.start, containers_range.stop)
        # Delete containers index
        container_range = self.container_space[account_id].range()
        tr.clear_range(container_range.start, container_range.stop)
        # Delete deleted containers
        deleted_containers_range = self.ct_to_delete_space[account_id].range()
        tr.clear_range(deleted_containers_range.start, deleted_containers_range.stop)
        # Delete buckets
        buckets_range = self.buckets_index_space[account_id].range()
        tr.clear_range(buckets_range.start, buckets_range.stop)
        # Delete buckets index
        bucket_range = self.bucket_space[account_id].range()
        tr.clear_range(bucket_range.start, bucket_range.stop)
        # TODO(adu): Delete buckets index by region
        # Delete metadata
        metadata_space = self.metadata_space[account_id].range()
        tr.clear_range(metadata_space.start, metadata_space.stop)
        # Delete account info
        account_range = self.acct_space[account_id].range()
        tr.clear_range(account_range.start, account_range.stop)
        # Delete account in index
        tr.clear(self.accts_space.pack((account_id,)))

        # Decrease accounts counter in metrics
        if not account_id.startswith(SHARDING_ACCOUNT_PREFIX):
            self._increment(tr, self.metrics_space.pack((ACCOUNTS_FIELD,)), -1)
        # else:
        #     Do not count sharding accounts in metrics

    @catch_service_errors
    def info_account(self, account_id, **kwargs):
        """
        Get all available information about an account.
        """
        return self._account_info(self.db, account_id, full=True, readonly=True)

    @fdb.transactional
    @use_snapshot_reads
    def _account_info(self, tr, account_id, full=False):
        """
        [transactional] Get all available information about an account.
        """
        account_space = self.acct_space[account_id]
        account_range = account_space.range()
        iterator = tr.get_range(
            account_range.start,
            account_range.stop,
            streaming_mode=fdb.StreamingMode.want_all,
        )
        info = self._unmarshal_info(
            iterator, has_regions=True, unpack=account_space.unpack
        )
        if not info:
            return None

        if full:
            info["metadata"] = self._get_account_metadata(tr, account_id)

        if not account_id.startswith(SHARDING_ACCOUNT_PREFIX):
            self._merge_sharding_account_info(tr, account_id, info)

        return info

    @fdb.transactional
    @use_snapshot_reads
    def _get_account_metadata(self, tr, account_id):
        metadata = {}
        metadata_space = self.metadata_space[account_id]
        metadata_range = metadata_space.range()
        iterator = tr.get_range(
            metadata_range.start,
            metadata_range.stop,
            streaming_mode=fdb.StreamingMode.want_all,
        )
        for key, value in iterator:
            key = metadata_space.unpack(key)
            if len(key) == 1:
                metadata[key[0]] = value.decode("utf-8")
            else:
                self.logger.warning('Unknown key: "%s"', key)
        return metadata

    @fdb.transactional
    @use_snapshot_reads
    def _merge_sharding_account_info(self, tr, account_id, info):
        info[SHARDS_FIELD] = 0
        regions_info = info[REGIONS_FIELD]
        for region_info in regions_info.values():
            region_info[SHARDS_FIELD] = 0
        # Fetch sharding account
        sharding_info = self._account_info(
            tr, SHARDING_ACCOUNT_PREFIX + account_id, full=False
        )
        if not sharding_info:
            return
        # Update global stats of sharding account
        for key in (BYTES_FIELD, OBJECTS_FIELD):
            value = sharding_info.get(key)
            if not value:
                continue
            info[key] = info.get(key, 0) + value
        info[SHARDS_FIELD] = sharding_info.get(CONTAINERS_FIELD, 0)
        info[MTIME_FIELD] = max(
            info.get(MTIME_FIELD, 0), sharding_info.get(MTIME_FIELD, 0)
        )
        # Update detailed stats of sharding account
        for region, shards_region_info in sharding_info.get(REGIONS_FIELD, {}).items():
            region_info = regions_info.setdefault(region, {})
            for key in (BYTES_FIELD, OBJECTS_FIELD):
                shards_region_details = shards_region_info.get(f"{key}-details")
                if shards_region_details is None:
                    continue
                region_details = region_info.setdefault(f"{key}-details", {})
                for policy, value in shards_region_details.items():
                    region_details[policy] = region_details.get(policy, 0) + value
            region_info[SHARDS_FIELD] = shards_region_info.get(CONTAINERS_FIELD, 0)

    @catch_service_errors
    def list_accounts(
        self,
        limit=1000,
        marker=None,
        end_marker=None,
        prefix=None,
        stats=False,
        sharding_accounts=False,
        **kwargs,
    ):
        """
        Get the list of accounts (except if requested, the sharding accounts
        are excluded).

        :keyword limit: maximum number of results to return
        :type limit: `int`
        :keyword marker: ID of the account from where to start the listing
            (excluded)
        :type marker: `str`
        :keyword end_marker: ID of the account where to stop the listing
            (excluded)
        :type end_marker: `str`
        :keyword prefix: list only the accounts starting with the prefix
        :type prefix: `str`
        :keyword stats: Fetch all stats and metadata for each account
        :type stats: `bool`
        :keyword sharding_accounts: Add sharding accounts in the listing
        :type sharding_accounts: `bool`
        :returns: the list of accounts (with account metadata if requested),
            and the next marker (in case the list is truncated).
        """
        accounts_space = self.acct_space

        if stats:
            format_account = self._format_account_for_listing2
        else:
            format_account = self._format_account_for_listing

        remaining = limit + 1
        accounts = []
        while remaining > 0:
            start, stop = self._get_start_and_stop(
                accounts_space, prefix=prefix, marker=marker, end_marker=end_marker
            )
            accounts_sublist = self._list_accounts(
                self.db,
                start,
                stop,
                remaining,
                [],
                accounts_space.unpack,
                format_account,
                readonly=True,
            )
            new_accounts = 0
            for account in accounts_sublist:
                if not sharding_accounts and account["id"].startswith(
                    SHARDING_ACCOUNT_PREFIX
                ):
                    continue
                accounts.append(account)
                new_accounts += 1
            if not accounts_sublist or len(accounts_sublist) < remaining:
                break
            remaining -= new_accounts
            last_account_id = accounts_sublist[-1]["id"]
            if not sharding_accounts and last_account_id.startswith(
                SHARDING_ACCOUNT_PREFIX
            ):
                marker = SHARDING_ACCOUNT_PREFIX + LAST_UNICODE_CHAR
            else:
                marker = last_account_id

        next_marker = None
        if len(accounts) > limit:
            accounts.pop()
            next_marker = accounts[-1]["id"]
        return accounts, next_marker

    @fdb.transactional
    @use_snapshot_reads
    def _list_accounts(self, tr, start, stop, limit, filters, unpack, format_account):
        if limit > 0:
            accounts = self._list_items(
                tr,
                start,
                stop,
                limit,
                filters,
                unpack,
                format_account,
                has_regions=True,
            )
        else:
            accounts = []
        return accounts

    @fdb.transactional
    @use_snapshot_reads
    def _format_account_for_listing(self, tr, account_id, account_info):
        formatted = {}
        formatted["id"] = account_id
        return formatted

    @fdb.transactional
    @use_snapshot_reads
    def _format_account_for_listing2(self, tr, account_id, account_info):
        account_info = deepcopy(account_info)
        if not account_id.startswith(SHARDING_ACCOUNT_PREFIX):
            self._merge_sharding_account_info(tr, account_id, account_info)
        formatted = {}
        kept_keys = TIMESTAMP_FIELDS + COUNTERS_FIELDS
        for key, value in account_info.items():
            if key in kept_keys:
                formatted[key] = value
        formatted["metadata"] = self._get_account_metadata(tr, account_id)
        formatted["id"] = account_id
        return formatted

    @fdb.transactional
    def _update_account_stats(self, tr, account_id, region, stats_delta, mtime):
        """
        [transactional] Update account stats for the specified region.
        This method assumes that the account exists.
        """
        account_space = self.acct_space[account_id]

        if OBJECTS_S3_FIELD in stats_delta:
            self._increment(
                tr,
                account_space.pack((OBJECTS_S3_FIELD, region)),
                stats_delta.get(OBJECTS_S3_FIELD, 0),
            )
        # Update account stats
        for key in (BYTES_FIELD, OBJECTS_FIELD):
            if key not in stats_delta:
                continue
            # Update global stats
            value = stats_delta[key]
            self._increment(tr, account_space.pack((key,)), value)
            # Update stats by policy (by region)
            for policy, value in stats_delta[f"{key}-details"].items():
                self._increment(tr, account_space.pack((key, region, policy)), value)

        # Update account mtime
        self._update_timestamp(tr, account_space.pack((MTIME_FIELD,)), mtime)

        # Update metrics stats with the delta
        self._update_metrics_stats(tr, region, stats_delta)

    @catch_service_errors
    def update_account_metadata(self, account_id, to_update, to_delete=None, **kwargs):
        """
        Update (or delete) account metadata.

        :param to_update: dict of entries to set (or update)
        :param to_delete: iterable of keys to delete
        """
        return self._update_account_metadata(self.db, account_id, to_update, to_delete)

    @fdb.transactional
    def _update_account_metadata(self, tr, account_id, to_update, to_delete):
        """
        [transactional] Update (or delete) account metadata.
        """
        account_space = self.acct_space[account_id]
        account_metadata_space = self.metadata_space[account_id]

        if not tr[account_space.pack((CTIME_FIELD,))].present():
            # Account doesn't exist
            if self.autocreate:
                self._create_account(tr, account_id)
            else:
                return False

        self._update_metadata(tr, account_metadata_space, to_update, to_delete)
        return True

    @catch_service_errors
    def refresh_account(self, account_id, **kwargs):
        if not account_id:
            raise BadRequest("Missing account")
        self._refresh_account(self.db, account_id)

        shards_account_id = SHARDING_ACCOUNT_PREFIX + account_id
        if self._is_element(self.db, self.accts_space, shards_account_id):
            self._refresh_account(self.db, shards_account_id)

    @fdb.transactional
    def _refresh_account(self, tr, account_id):
        if not self._is_element(tr, self.accts_space, account_id):
            raise NotFound(account_id)

        is_sharding = account_id.startswith(SHARDING_ACCOUNT_PREFIX)

        # Reset statistics
        for field in (
            BYTES_FIELD,
            CONTAINERS_FIELD,
            OBJECTS_FIELD,
            BUCKETS_FIELD,
            OBJECTS_S3_FIELD,
        ):
            stats_range = self.acct_space[account_id][field].range()
            # Propagate to metrics
            for key, value in tr[stats_range.start : stats_range.stop]:
                region, *details = self.acct_space[account_id][field].unpack(key)
                value = self._counter_value_to_counter(value)
                metric_key = (region,)
                if len(details) > 0:
                    metric_key += (details[0],)
                self._increment(tr, self.metrics_space[field].pack(metric_key), -value)

            del tr[stats_range.start : stats_range.stop]

        ct_space = self.container_space[account_id]
        s_range = ct_space.range()

        def _add_to_global_counters(region, local_counters):
            if region is None:
                return
            # Increment containers counters
            counters[CONTAINERS_FIELD][region] += 1
            counters[CONTAINERS_FIELD][""] += 1

            for field in (BYTES_FIELD, OBJECTS_FIELD):
                for policy, value in local_counters[field].items():
                    if not policy:
                        global_counter = counters[field].setdefault("", Counter())
                        global_counter[""] += value
                    counter = counters[field].setdefault(region, Counter())
                    counter[policy] += value

        # Meta counters for containers
        counters = {
            BYTES_FIELD: {},
            BUCKETS_FIELD: Counter(),
            CONTAINERS_FIELD: Counter(),
            OBJECTS_FIELD: {},
            OBJECTS_S3_FIELD: Counter(),
        }

        # Counters for one container
        local_counters = {
            BYTES_FIELD: Counter(),
            OBJECTS_FIELD: Counter(),
        }

        marker = None
        region = None
        iterator = tr.get_range(s_range.start, s_range.stop, reverse=False)
        for key, value in iterator:
            container, field, *details = ct_space.unpack(key)
            if field not in (BYTES_FIELD, OBJECTS_FIELD, REGION_FIELD):
                continue

            policy = ""
            if len(details) == 1:
                policy = details[0]

            if container != marker:
                _add_to_global_counters(region, local_counters)

                # Reset local info
                region = None
                local_counters = {
                    BYTES_FIELD: Counter(),
                    OBJECTS_FIELD: Counter(),
                }
                # Next container
                marker = container

            if field in (BYTES_FIELD, OBJECTS_FIELD):
                local_counters[field][policy] += self._counter_value_to_counter(value)
            elif field == REGION_FIELD:
                region = value.decode("utf-8")

        # Add eventual last container
        _add_to_global_counters(region, local_counters)

        if not is_sharding:
            # List buckets
            account_buckets = self.bucket_space[account_id]
            buckets_range = account_buckets.range()

            region = None
            objects = None

            iterator = tr.get_range(buckets_range.start, buckets_range.stop)
            for key, value in iterator:
                _, *details = account_buckets.unpack(key)

                if details[0] == REGION_FIELD:
                    region = value.decode("utf-8")

                if len(details) == 1 and details[0] == OBJECTS_FIELD:
                    objects = self._counter_value_to_counter(value)

                if region is not None and objects is not None:
                    counters[BUCKETS_FIELD][region] += 1
                    counters[BUCKETS_FIELD][""] += 1
                    counters[OBJECTS_S3_FIELD][region] += objects

                    region = objects = None

        # Persist counters
        for field, counter in counters.items():
            field_key = (
                account_id,
                field,
            )

            if field in (BUCKETS_FIELD, CONTAINERS_FIELD, OBJECTS_S3_FIELD):
                for region, value in counter.items():
                    key = field_key
                    if region:
                        key += (region,)
                        metric_key = (
                            field,
                            region,
                        )
                        self._increment(tr, self.metrics_space.pack(metric_key), value)
                    self._set_counter(tr, self.acct_space.pack(key), value)
            else:
                for region, policy_counter in counter.items():
                    key = field_key
                    if region:
                        key += (region,)
                    for policy, value in policy_counter.items():
                        if (region and not policy) or (
                            region and policy and value == 0
                        ):
                            continue
                        p_key = key
                        if policy:
                            p_key += (policy,)
                            if region:
                                metric_key = (
                                    field,
                                    region,
                                    policy,
                                )
                                self._increment(
                                    tr, self.metrics_space.pack(metric_key), value
                                )
                        self._set_counter(tr, self.acct_space.pack(p_key), value)

    @catch_service_errors
    def flush_account(self, account_id, **kwargs):
        if not account_id:
            raise BadRequest("Missing account")

        mtime = time.time()
        self._flush_account(self.db, account_id, mtime)

    @fdb.transactional
    def _flush_account(self, tr, account_id, mtime):
        # Reset stats
        account_space = self.acct_space[account_id]
        current_mtime = tr[account_space.pack((MTIME_FIELD,))]
        if current_mtime.present():
            current_mtime = self._timestamp_value_to_timestamp(current_mtime.value)
            if mtime == current_mtime:
                self.logger.info(
                    "flush account %s: transaction replay                              "
                    "    skipped",
                    account_id,
                )
                return
        else:
            raise NotFound("Account doesn't exist")
        for field in (BYTES_FIELD, OBJECTS_FIELD, CONTAINERS_FIELD, BUCKETS_FIELD):
            self._set_counter(tr, account_space.pack((field,)))
            details_space = account_space[field]
            details_range = details_space.range()
            # Update metrics
            iterator = tr.get_range(details_range.start, details_range.stop)
            for key, value in iterator:
                key = account_space.unpack(key)
                value = self._counter_value_to_counter(value)
                if field == CONTAINERS_FIELD and account_id.startswith(
                    SHARDING_ACCOUNT_PREFIX
                ):
                    # Replace 'containers' with 'shards' for sharding account
                    key = (SHARDS_FIELD,) + key[1:]
                self._increment(tr, self.metrics_space.pack(key), -value)
            # Remove details by region
            tr.clear_range(details_range.start, details_range.stop)
        # Delete containers
        containers_range = self.containers_index_space[account_id].range()
        tr.clear_range(containers_range.start, containers_range.stop)
        # Delete containers index
        container_range = self.container_space[account_id].range()
        tr.clear_range(container_range.start, container_range.stop)
        # Delete deleted containers
        deleted_containers_range = self.ct_to_delete_space[account_id].range()
        tr.clear_range(deleted_containers_range.start, deleted_containers_range.stop)
        # Delete buckets
        bucket_range = self.bucket_space[account_id].range()
        tr.clear_range(bucket_range.start, bucket_range.stop)
        # Delete buckets index
        buckets_range = self.buckets_index_space[account_id].range()
        tr.clear_range(buckets_range.start, buckets_range.stop)
        # TODO(adu): Delete buckets index by region
        # Delete metadata
        metadata_space = self.metadata_space[account_id].range()
        tr.clear_range(metadata_space.start, metadata_space.stop)
        self._update_timestamp(tr, account_space.pack((MTIME_FIELD,)), mtime)

        if not account_id.startswith(SHARDING_ACCOUNT_PREFIX):
            # Flush sharding account
            try:
                self._flush_account(tr, SHARDING_ACCOUNT_PREFIX + account_id, mtime)
            except NotFound:
                pass

    @fdb.transactional
    @use_snapshot_reads
    def _check_max_buckets(self, tr, account):
        account_space = self.acct_space[account]
        metadata_space = self.metadata_space[account]

        buckets = tr[account_space.pack((BUCKETS_FIELD,))]
        if buckets.present():
            buckets = self._counter_value_to_counter(buckets.value)
        else:  # Account does not yet exist
            buckets = 0
        max_buckets = tr[metadata_space.pack(("max-buckets",))]
        if not max_buckets.present():
            # Stay compatible with old (swift) property
            max_buckets = tr[metadata_space.pack(("X-Account-Meta-Max-Buckets",))]
        if max_buckets.present():
            try:
                max_buckets = int(max_buckets.decode("utf-8"))
            except ValueError:
                self.logger.warning(
                    'Property "max-buckets" should be a number (account=%s)', account
                )
                max_buckets = self.max_buckets_per_account
        else:
            max_buckets = self.max_buckets_per_account
        if buckets >= max_buckets:
            raise BadRequest("Too many buckets")

    # Container ---------------------------------------------------------------

    @fdb.transactional
    def _real_create_container(self, tr, account_id, cname, region, ctime):
        """
        [transactional] Create the container.
        This method assumes that the account exists.
        This method assumes that the container does not exist.
        """
        container_space = self.container_space[account_id][cname]
        deleted_container_space = self.ct_to_delete_space[account_id][cname]

        if not region:
            raise BadRequest("Missing region")

        # Add basic info
        tr[container_space.pack(("name",))] = cname.encode("utf-8")
        tr[container_space.pack((REGION_FIELD,))] = region.encode("utf-8")
        self._set_counter(tr, container_space.pack((BYTES_FIELD,)))
        self._set_counter(tr, container_space.pack((OBJECTS_FIELD,)))
        # Set container mtime
        self._set_timestamp(tr, container_space.pack((MTIME_FIELD,)), ctime)
        # Add container in index
        tr[self.containers_index_space.pack((account_id, cname))] = b"1"
        # Delete the old dtime
        tr.clear(deleted_container_space.key())
        # Increase containers counter in account
        self._increment(tr, self.acct_space[account_id].pack((CONTAINERS_FIELD,)))
        self._increment(
            tr, self.acct_space[account_id].pack((CONTAINERS_FIELD, region))
        )
        # Increase containers counter in metrics
        metrics_field = CONTAINERS_FIELD
        if account_id.startswith(SHARDING_ACCOUNT_PREFIX):
            metrics_field = SHARDS_FIELD
        self._increment(tr, self.metrics_space.pack((metrics_field, region)))

    @fdb.transactional
    def _real_delete_container(self, tr, account_id, cname, region, dtime):
        """
        [transactional] Delete the container.
        This method assumes that the account exists.
        This method assumes that the container exists.
        """
        container_space = self.container_space[account_id][cname]
        deleted_container_space = self.ct_to_delete_space[account_id][cname]

        # Fetch the current stats to compute the others stats
        stats_delta = {}
        for key in (BYTES_FIELD, OBJECTS_FIELD):
            # Fetch the global stats
            current_value = tr[container_space.pack((key,))]
            if current_value.present():
                current_value = -self._counter_value_to_counter(current_value.value)
            else:
                current_value = 0
            stats_delta[key] = current_value

            # Fetch the stats by policy
            details_space = container_space[key]
            details_range = details_space.range()
            current_value_by_policy = self._counters_key_value_to_dict(
                tr.get_range(
                    details_range.start,
                    details_range.stop,
                    streaming_mode=fdb.StreamingMode.want_all,
                ),
                unpack=details_space.unpack,
            )
            delta_by_policy = {}
            for policy, value in current_value_by_policy.items():
                delta_by_policy[policy] = -value
            stats_delta[f"{key}-details"] = delta_by_policy

        # Delete container info
        container_range = container_space.range()
        tr.clear_range(container_range.start, container_range.stop)
        # Delete container in index
        tr.clear(self.containers_index_space.pack((account_id, cname)))
        # Keep the dtime in case an event is late
        self._update_timestamp(tr, deleted_container_space.key(), dtime)
        # Decrease containers counter in account
        self._increment(tr, self.acct_space[account_id].pack((CONTAINERS_FIELD,)), -1)
        self._increment(
            tr, self.acct_space[account_id].pack((CONTAINERS_FIELD, region)), -1
        )
        # Decrease containers counter in metrics
        metrics_field = CONTAINERS_FIELD
        if account_id.startswith(SHARDING_ACCOUNT_PREFIX):
            metrics_field = SHARDS_FIELD
        self._increment(tr, self.metrics_space.pack((metrics_field, region)), -1)

        # Forget the old deleted containers
        self._clear_deleted_containers(tr, account_id)

        # Update account stats with the delta
        self._update_account_stats(tr, account_id, region, stats_delta, dtime)

        return stats_delta

    @catch_service_errors
    def get_container_info(self, account_id, cname, **kwargs):
        """
        Get all available information about a container, including some
        information coming from the bucket it belongs to.
        """
        return self._container_info(
            self.db, account_id, cname, full=True, readonly=True
        )

    @fdb.transactional
    @use_snapshot_reads
    def _container_info(self, tr, account_id, cname, full=False):
        """
        [transactional] Get all available information about a container,
        including some information coming from the bucket it belongs to.
        """
        container_space = self.container_space[account_id][cname]
        container_range = container_space.range()
        iterator = tr.get_range(
            container_range.start,
            container_range.stop,
            streaming_mode=fdb.StreamingMode.want_all,
        )
        info = self._unmarshal_info(iterator, unpack=container_space.unpack)
        if not info:
            return None

        if full:
            repli_enabled = None
            bname = info.get(BUCKET_FIELD)
            if bname:
                if account_id.startswith(SHARDING_ACCOUNT_PREFIX):
                    account_id = account_id[len(SHARDING_ACCOUNT_PREFIX) :]
                buckat_space = self.bucket_space[account_id][bname]
                repli_enabled = tr[buckat_space.pack((BUCKET_PROP_REPLI_ENABLED,))]
                if repli_enabled.present():
                    repli_enabled = repli_enabled.decode("utf-8")
                else:
                    repli_enabled = None
            info[BUCKET_PROP_REPLI_ENABLED] = boolean_value(repli_enabled)

        return info

    @catch_service_errors
    def list_containers(
        self,
        account_id,
        limit=1000,
        prefix=None,
        marker=None,
        end_marker=None,
        region=None,
        bucket=None,
        **kwargs,
    ):
        """
        Get the list of containers of the specified account.

        :param account_id: account from which to get the container list
        :type account: `str`
        :keyword limit: maximum number of results to return
        :type limit: `int`
        :keyword marker: name of the container from where to start the listing
        :type marker: `str`
        :keyword end_marker: name of the container where to stop the listing
            (excluded)
        :type end_marker: `str`
        :keyword prefix: list only the containers starting with the prefix
        :type prefix: `str`
        :keyword region: list only the containers belonging to the region
        :type region: `str`
        :keyword bucket: list only the containers belonging to the bucket
        :type bucket: `str`
        :returns: account information, the list of containers (with account
            metadata), and the next marker (in case the list is truncated).
        """
        containers_space = self.container_space[account_id]

        filters = []
        if region:
            region = region.upper()
            filters.append(lambda name, info: info[REGION_FIELD] == region)
        if bucket:
            filters.append(lambda name, info: info[BUCKET_FIELD] == bucket)

        start, stop = self._get_start_and_stop(
            containers_space, prefix=prefix, marker=marker, end_marker=end_marker
        )
        account_info, containers = self._list_containers(
            self.db,
            account_id,
            start,
            stop,
            limit + 1,
            filters,
            containers_space.unpack,
            self._format_container_for_listing,
            readonly=True,
        )
        if not account_info:
            return None, None, None

        next_marker = None
        if len(containers) > limit:
            containers.pop()
            next_marker = containers[-1][0]
        return account_info, containers, next_marker

    @fdb.transactional
    @use_snapshot_reads
    def _list_containers(
        self, tr, account, start, stop, limit, filters, unpack, format_container
    ):
        account_info = self._account_info(tr, account, full=True)
        if not account_info:
            return None, None
        if limit > 0:
            containers = self._list_items(
                tr, start, stop, limit, filters, unpack, format_container
            )
        else:
            containers = []
        return account_info, containers

    @fdb.transactional
    @use_snapshot_reads
    def _format_container_for_listing(self, tr, cname, container_info):
        return [
            cname,
            container_info.get(OBJECTS_FIELD, 0),
            container_info.get(BYTES_FIELD, 0),
            0,
            container_info.get(MTIME_FIELD, 0.0),
        ]

    @catch_service_errors
    def update_container(
        self,
        account_id,
        cname,
        mtime,
        dtime,
        object_count,
        bytes_used,
        bucket_name=None,
        region=None,
        objects_details=None,
        bytes_details=None,
        autocreate_account=None,
        autocreate_container=True,
        **kwargs,
    ):
        """
        Update container info and stats.
        Create the account if it does not exist and autocreation is enabled.
        Create the container if it does not exist and autocreation is enabled.
        """
        if autocreate_account is None:
            autocreate_account = self.autocreate

        if mtime is None:
            mtime = 0.0
        else:
            mtime = self._get_timestamp(mtime)
        if dtime is None:
            dtime = 0.0
        else:
            dtime = self._get_timestamp(dtime)

        if object_count is None:
            object_count = 0
        if objects_details is None:
            objects_details = {}
        total = 0
        for _, count in objects_details.items():
            total += count
        if total != object_count:
            raise BadRequest(
                f"Mismatch between total objects ({object_count}) "
                f"and detailed objects ({total})"
            )
        if bytes_used is None:
            bytes_used = 0
        if bytes_details is None:
            bytes_details = {}
        total = 0
        for _, count in bytes_details.items():
            total += count
        if total != bytes_used:
            raise BadRequest(
                f"Mismatch between total bytes ({bytes_used}) "
                f"and detailed bytes ({total})"
            )
        new_stats = {
            OBJECTS_FIELD: object_count,
            f"{OBJECTS_FIELD}-details": objects_details,
            BYTES_FIELD: bytes_used,
            f"{BYTES_FIELD}-details": bytes_details,
        }

        if region:
            region = region.upper()

        self._update_container(
            self.db,
            account_id,
            cname,
            bucket_name,
            region,
            new_stats,
            mtime,
            dtime,
            autocreate_account,
            autocreate_container,
        )

    @fdb.transactional
    def _update_container(
        self,
        tr,
        account_id,
        cname,
        bname,
        region,
        new_stats,
        new_mtime,
        new_dtime,
        autocreate_account,
        autocreate_container,
    ):
        """
        [transactional] Update container info and stats.
        Create the account if it does not exist and autocreation is enabled.
        Create the container if it does not exist and autocreation is enabled.
        """
        account_space = self.acct_space[account_id]
        container_space = self.container_space[account_id][cname]
        deleted_container_space = self.ct_to_delete_space[account_id][cname]

        # Check that the account exists and create it if necessary
        account_ctime = tr[account_space.pack((CTIME_FIELD,))]
        if not account_ctime.present():
            # It's a new account
            if not autocreate_account:
                raise NotFound("Account does'nt exist")
            self._real_create_account(tr, account_id)

        container_is_deleted = new_dtime >= new_mtime

        # Check that the container exists and create it if necessary
        current_mtime = tr[container_space.pack((MTIME_FIELD,))]
        if not current_mtime.present():
            # Container doesn't exist
            # Check that the container has not been recently deleted
            current_dtime = tr[deleted_container_space.key()]
            if current_dtime.present():
                current_dtime = self._timestamp_value_to_timestamp(current_dtime.value)
                if container_is_deleted:
                    if current_dtime >= new_dtime:
                        raise Conflict(
                            "No update needed, event older than last container update"
                        )
                elif current_dtime >= new_mtime:
                    # Container no longer exists
                    raise Conflict(
                        "No update needed, event older than last container update"
                    )
            if container_is_deleted:
                # Container is already deleted, keep the most recent dtime
                self._update_timestamp(tr, deleted_container_space.key(), new_dtime)
                return
            # It's a new container
            if not autocreate_container:
                raise NotFound("Container does'nt exist")
            self._real_create_container(tr, account_id, cname, region, new_mtime)
            current_mtime = new_mtime
        else:
            # Container exists
            current_mtime = self._timestamp_value_to_timestamp(current_mtime.value)
            if container_is_deleted:
                # If the deletion timestamp equals the last modification,
                # allow the deletion.
                if current_mtime > new_dtime:
                    raise Conflict(
                        "No update needed, event older than last container update"
                    )
            elif current_mtime >= new_mtime:
                raise Conflict(
                    "No update needed, event older than last container update"
                )

        current_region = tr[container_space.pack((REGION_FIELD,))]
        if current_region.present():
            # Container is already associated with a region
            current_region = current_region.decode("utf-8")
            if region:
                # Check that the region has not changed
                if region != current_region:
                    self.logger.warning(
                        "The region has changed for the container %s "
                        "in account %s (before: %s, after: %s)",
                        cname,
                        account_id,
                        current_region,
                        region,
                    )
                    # If the container was associated with a bucket,
                    # that bucket should have already changed region.
                    # With this change, the bucket is no longer associated
                    # with those old containers, so there is no need
                    # to decrement the number of containers in the bucket.
                    # Only delete the container from the old region...
                    self._real_delete_container(
                        tr, account_id, cname, current_region, current_mtime
                    )
                    # ...and recreate the container in the new region.
                    self._real_create_container(
                        tr, account_id, cname, region, current_mtime
                    )
                    # Bucket name will be associated when updating the bucket
                    # and container stats will be updated right after.
                    current_region = region
            else:
                region = current_region
        if not region:
            raise BadRequest("Missing region")

        container_has_new_bucket = False
        current_bname = tr[container_space.pack((BUCKET_FIELD,))]
        if current_bname.present():
            # Container is already associated with a bucket
            current_bname = current_bname.decode("utf-8")
            if bname:
                # Check that the bucket has not changed
                if bname != current_bname:
                    self.logger.warning(
                        "The bucket has changed for the container %s "
                        "in account %s (before: %s, after: %s)",
                        cname,
                        account_id,
                        current_bname,
                        bname,
                    )
                    # TODO(adu): Decrease the current container stats
                    #            in current bucket
                    container_has_new_bucket = True
            else:
                bname = current_bname
        elif bname:
            container_has_new_bucket = True

        # Update container info/stats
        if container_is_deleted:
            stats_delta = self._real_delete_container(
                tr, account_id, cname, region, new_dtime
            )
        else:
            stats_delta = self._update_container_stats(
                tr, account_id, cname, region, new_stats, new_mtime
            )

        # Update bucket stats
        if bname:
            if container_has_new_bucket:
                # Update bucket stats with the container stats
                stats_delta = new_stats
            bucket_mtime = max(new_mtime, new_dtime)
            self._update_bucket_stats(
                tr,
                account_id,
                cname,
                bname,
                region,
                stats_delta,
                bucket_mtime,
                container_is_deleted,
                container_has_new_bucket,
            )

    @fdb.transactional
    def _update_container_stats(self, tr, account_id, cname, region, new_stats, mtime):
        """
        [transactional] Update container stats.
        This method assumes that the account exists.
        This method assumes that the container exists.
        """
        container_space = self.container_space[account_id][cname]

        # Update container stats
        stats_delta = {}
        for key in (BYTES_FIELD, OBJECTS_FIELD):
            # Fetch the global stats
            new_value = new_stats[key]
            current_value = tr[container_space.pack((key,))]
            if current_value.present():
                current_value = self._counter_value_to_counter(current_value.value)
            else:
                current_value = 0
            # Compute the delta and set new value for global stats
            stats_delta[key] = new_value - current_value
            self._set_counter(tr, container_space.pack((key,)), new_value)

            # Fetch the stats by policy
            new_value_by_policy = new_stats[f"{key}-details"]
            details_space = container_space[key]
            details_range = details_space.range()
            current_value_by_policy = self._counters_key_value_to_dict(
                tr.get_range(
                    details_range.start,
                    details_range.stop,
                    streaming_mode=fdb.StreamingMode.want_all,
                ),
                unpack=details_space.unpack,
            )
            delta_by_policy = {}
            all_policies = set(current_value_by_policy).union(new_value_by_policy)
            for policy in all_policies:
                # Compute the delta and set new value for stats by policy
                policy_key = details_space.pack((policy,))
                new_value = new_value_by_policy.get(policy, 0)
                current_value = current_value_by_policy.get(policy, 0)
                delta_by_policy[policy] = new_value - current_value
                if policy in new_value_by_policy:
                    self._set_counter(tr, policy_key, new_value)
                else:
                    tr.clear(policy_key)
            stats_delta[f"{key}-details"] = delta_by_policy

        # Update container mtime
        self._update_timestamp(tr, container_space.pack((MTIME_FIELD,)), mtime)

        # Update account stats with the delta
        self._update_account_stats(tr, account_id, region, stats_delta, mtime)

        return stats_delta

    @fdb.transactional
    def _clear_deleted_containers(self, tr, account_id):
        deleted_containers_range = self.ct_to_delete_space[account_id].range()
        iterator = tr.get_range(
            deleted_containers_range.start,
            deleted_containers_range.stop,
            streaming_mode=fdb.StreamingMode.want_all,
        )
        now = self._get_timestamp()
        for key, dtime in iterator:
            dtime = self._timestamp_value_to_timestamp(dtime)
            if dtime + self.time_window_clear_deleted < now:
                tr.clear(key)

    # Bucket ------------------------------------------------------------------

    @catch_service_errors
    def create_bucket(
        self, bname, account_id, region, ctime=None, autocreate_account=None, **kwargs
    ):
        """
        Create the bucket if it doesn't already exist.
        """
        region = region.upper()
        if ctime is None:
            ctime = self._get_timestamp()
        if autocreate_account is None:
            autocreate_account = self.autocreate
        return self._create_bucket(
            self.db, bname, account_id, region, ctime, autocreate_account
        )

    @fdb.transactional
    def _create_bucket(self, tr, bname, account, region, ctime, autocreate_account):
        """
        [transactional] Create the bucket if it doesn't already exist.
        """
        self._check_max_buckets(tr, account)

        account_space = self.acct_space[account]
        bucket_space = self.bucket_space[account][bname]

        # Check that the account exists and create it if necessary
        account_ctime = tr[account_space.pack((CTIME_FIELD,))]
        if not account_ctime.present():
            # It's a new account
            if not autocreate_account:
                raise NotFound("Account does'nt exist")
            self._real_create_account(tr, account)

        self._set_bucket_owner(tr, bname, account)

        # Do not use the ctime, it is not present for old buckets
        current_region = tr[bucket_space.pack((REGION_FIELD,))]
        if current_region.present():
            # Bucket already exists
            current_region = current_region.decode("utf-8")
            if region != current_region:
                raise Conflict("Created in another region")
            return False
        self._real_create_bucket(tr, bname, account, region, ctime)
        return True

    @fdb.transactional
    def _real_create_bucket(self, tr, bname, account, region, ctime):
        """
        [transactional] Create the bucket.
        This method assumes that the account exists.
        This method assumes that the bucket does not exist.
        """
        bucket_space = self.bucket_space[account][bname]

        # Add basic info
        tr[bucket_space.pack(("account",))] = account.encode("utf-8")
        tr[bucket_space.pack((REGION_FIELD,))] = region.encode("utf-8")
        self._set_counter(tr, bucket_space.pack((CONTAINERS_FIELD,)))
        self._set_counter(tr, bucket_space.pack((BYTES_FIELD,)))
        self._set_counter(tr, bucket_space.pack((OBJECTS_FIELD,)))
        # Set bucket ctime and mtime
        self._set_timestamp(tr, bucket_space.pack((CTIME_FIELD,)), ctime)
        self._set_timestamp(tr, bucket_space.pack((MTIME_FIELD,)), ctime)
        # Add bucket in index
        tr[self.buckets_index_space.pack((account, bname))] = b"1"
        tr[self.buckets_index_space.pack((region, account, bname))] = b"1"
        # Increase buckets counter in account
        self._increment(tr, self.acct_space[account].pack((BUCKETS_FIELD,)))
        self._increment(tr, self.acct_space[account].pack((BUCKETS_FIELD, region)))
        # Set bucket objects counters
        self._increment(
            tr, self.acct_space[account].pack((OBJECTS_S3_FIELD, region)), 0, True
        )
        self._increment(
            tr, self.metrics_space.pack((OBJECTS_S3_FIELD, region)), 0, True
        )
        # Increase buckets counter in metrics
        self._increment(tr, self.metrics_space.pack((BUCKETS_FIELD, region)))

    @catch_service_errors
    def delete_bucket(self, bname, account, region, force=False, **kwargs):
        """
        Delete the account if it already exists.
        """
        if region:
            region = region.upper()
        self._delete_bucket(self.db, bname, account, region, force)
        return True

    @fdb.transactional
    def _delete_bucket(self, tr, bucket, account, region, force):
        """
        [transactional] Delete the account if it already exists.
        """
        bucket_space = self.bucket_space[account][bucket]
        try:
            # Do not use the ctime, it is not present for old buckets
            current_region = tr[bucket_space.pack((REGION_FIELD,))]
            if not current_region.present():
                raise NotFound("Bucket does not exist")
            current_region = current_region.decode("utf-8")
            if current_region != region:
                raise Forbidden(
                    "Deletion is not allowed in any region other than the bucket region"
                )

            if not force:
                containers = tr[bucket_space.pack((CONTAINERS_FIELD,))]
                if containers.present():
                    containers = self._counter_value_to_counter(containers.value)
                else:
                    containers = 0
                if containers > 0:
                    raise Conflict("Bucket not empty")
            # else:
            #     Since the bucket is deleted synchronously,
            #     there is no need to check for asynchronously updated counters
        except NotFound:
            # The bucket might not exist, but the account owns it
            try:
                self._release_bucket(tr, bucket, account, check_reservation=False)
                return
            except Forbidden:
                pass
            raise

        try:
            self._release_bucket(tr, bucket, account, check_reservation=False)
        except Forbidden:
            # It may happen that a bucket is still present,
            # but that there is no longer an owner or that it has changed
            pass

        self._real_delete_bucket(tr, bucket, account, region)

    @fdb.transactional
    def _real_delete_bucket(self, tr, bucket, account, region):
        """
        [transactional] Delete the bucket.
        This method assumes that the account exists.
        This method assumes that the bucket exists.
        """
        bucket_space = self.bucket_space[account][bucket]

        objects = tr[bucket_space.pack((OBJECTS_FIELD,))]
        objects = self._counter_value_to_counter(objects.value)
        # Delete bucket info
        bucket_range = bucket_space.range()
        tr.clear_range(bucket_range.start, bucket_range.stop)
        # Delete bucket in index
        tr.clear(
            self.buckets_index_space.pack(
                (
                    account,
                    bucket,
                )
            )
        )
        tr.clear(
            self.buckets_index_space.pack(
                (
                    region,
                    account,
                    bucket,
                )
            )
        )
        # Decrease buckets counter in account
        self._increment(tr, self.acct_space[account].pack((BUCKETS_FIELD,)), -1)
        self._increment(tr, self.acct_space[account].pack((BUCKETS_FIELD, region)), -1)
        self._increment(
            tr, self.acct_space[account].pack((OBJECTS_S3_FIELD, region)), -objects
        )
        # Decrease buckets counter in metrics
        self._increment(tr, self.metrics_space.pack((BUCKETS_FIELD, region)), -1)
        self._increment(
            tr, self.metrics_space.pack((OBJECTS_S3_FIELD, region)), -objects
        )

    @catch_service_errors
    def get_bucket_info(self, bname, **kwargs):
        """
        Get all available information about a bucket.
        """
        return self._bucket_info(self.db, bname, readonly=True, **kwargs)

    @fdb.transactional
    @use_snapshot_reads
    def _bucket_info(self, tr, bname, raw_metadata=False, **kwargs):
        """
        [transactional] Get all available information about a bucket.
        """
        account_id = self._get_bucket_account(tr, bname, **kwargs)

        bucket_space = self.bucket_space[account_id][bname]
        bucket_range = bucket_space.range()
        iterator = tr.get_range(
            bucket_range.start,
            bucket_range.stop,
            streaming_mode=fdb.StreamingMode.want_all,
        )
        info = self._unmarshal_info(iterator, unpack=bucket_space.unpack)
        if not info:
            return None
        if not raw_metadata:
            repli_enabled = info.get(BUCKET_PROP_REPLI_ENABLED)
            info[BUCKET_PROP_REPLI_ENABLED] = boolean_value(repli_enabled)
        return info

    @catch_service_errors
    def list_buckets(
        self,
        account_id,
        limit=1000,
        marker=None,
        end_marker=None,
        prefix=None,
        region=None,
        **kwargs,
    ):
        """
        Get the list of buckets of the specified account.

        :param account_id: account from which to get the bucket list
        :keyword limit: maximum number of results to return
        :type limit: `int`
        :keyword marker: name of the bucket from where to start the listing
            (excluded)
        :type marker: `str`
        :keyword end_marker: name of the bucket where to stop the listing
            (excluded)
        :type end_marker: `str`
        :keyword prefix: list only the buckets starting with the prefix
        :type prefix: `str`
        :keyword region: list only the buckets belonging to the region
        :type region: `str`
        :returns: account information, the list of accounts (with account
            metadata), and the next marker (in case the list is truncated).
        """
        buckets_space = self.bucket_space[account_id]

        filters = []
        if region:
            region = region.upper()
            filters.append(lambda name, info: info[REGION_FIELD] == region)

        start, stop = self._get_start_and_stop(
            buckets_space, prefix=prefix, marker=marker, end_marker=end_marker
        )
        account_info, buckets = self._list_buckets(
            self.db,
            account_id,
            start,
            stop,
            limit + 1,
            filters,
            buckets_space.unpack,
            self._format_bucket_for_listing,
            readonly=True,
        )
        if not account_info:
            return None, None, None

        next_marker = None
        if len(buckets) > limit:
            buckets.pop()
            next_marker = buckets[-1]["name"]
        return account_info, buckets, next_marker

    @fdb.transactional
    @use_snapshot_reads
    def _list_buckets(
        self, tr, account, start, stop, limit, filters, unpack, format_bucket
    ):
        account_info = self._account_info(tr, account, full=True)
        if not account_info:
            return None, None
        if limit > 0:
            buckets = self._list_items(
                tr, start, stop, limit, filters, unpack, format_bucket
            )
        else:
            buckets = []
        return account_info, buckets

    @fdb.transactional
    @use_snapshot_reads
    def _format_bucket_for_listing(self, tr, bname, bucket_info):
        formatted = {}
        kept_keys = TIMESTAMP_FIELDS + COUNTERS_FIELDS + (REGION_FIELD,)
        for key, value in bucket_info.items():
            if key in kept_keys:
                formatted[key] = value
        formatted["name"] = bname
        return formatted

    @catch_service_errors
    def list_all_buckets(self):
        """
        Get all buckets

        :returns: the list of all buckets (with metadata).
        """
        b_space_range = self.bucket_space.range()
        transaction = self.db.create_transaction()
        try:
            entries = transaction.snapshot.get_range(
                b_space_range.start,
                b_space_range.stop,
                streaming_mode=fdb.StreamingMode.want_all,
            )
            bucket_keys_values = None, None, None
            for key, value in entries:
                account, bucket, *key = self.bucket_space.unpack(key)
                if (account, bucket) != bucket_keys_values[:2]:
                    if bucket_keys_values[2]:
                        bucket_info = self._unmarshal_info(bucket_keys_values[2])
                        bucket_info["account"] = bucket_keys_values[0]
                        bucket_info["name"] = bucket_keys_values[1]
                        yield bucket_info
                    bucket_keys_values = account, bucket, []
                bucket_keys_values[2].append((key, value))
            if bucket_keys_values[2]:
                bucket_info = self._unmarshal_info(bucket_keys_values[2])
                bucket_info["account"] = bucket_keys_values[0]
                bucket_info["name"] = bucket_keys_values[1]
                yield bucket_info
        finally:
            transaction.commit()

    @fdb.transactional
    def _update_bucket_stats(
        self,
        tr,
        account_id,
        cname,
        bname,
        region,
        stats_delta,
        mtime,
        container_is_deleted,
        container_has_new_bucket,
    ):
        """
        [transactional] Update bucket stats.
        Create the bucket if it doesn't exist
        and if the container is not deleted.
        Delete the bucket if the root container is deleted.
        This method assumes that the account exists.
        """
        container_space = self.container_space[account_id][cname]

        # Filter the special accounts hosting bucket shards.
        root_container = cname
        if account_id.startswith(SHARDING_ACCOUNT_PREFIX):
            account_id = account_id[len(SHARDING_ACCOUNT_PREFIX) :]
            root_container = cname.rsplit("-", 3)[0]

        bucket_space = self.bucket_space[account_id][bname]

        bucket_stats = {}

        current_region = tr[bucket_space.pack((REGION_FIELD,))]
        if not current_region.present():  # Bucket doesn't exist
            if container_is_deleted:
                # Bucket is already deleted
                return
            self.logger.warning(
                "Bucket %s/%s must be created explicitly, "
                "it is no longer automatically created asynchronously",
                account_id,
                bname,
            )
            if not container_has_new_bucket:
                # If the bucket is recreated, all of the container statistics
                # will be added to the bucket, not just the delta
                tr.clear(container_space.pack((BUCKET_FIELD,)))
            return
        else:  # Bucket exists
            # Check that the region has not changed
            current_region = current_region.decode("utf-8")
            if current_region != region:
                raise Conflict(
                    "The container must be in the same region as the bucket "
                    f"it belongs to. Bucket {bname} in {current_region}, "
                    f"container {cname} in {region}"
                )

            # Update containers counter
            if container_is_deleted:
                if not container_has_new_bucket:
                    # If the container already belonged to the bucket,
                    # decrease the containers counter
                    self._increment(tr, bucket_space.pack((CONTAINERS_FIELD,)), -1)
            elif container_has_new_bucket:
                # Next time, only the delta will be added
                tr[container_space.pack((BUCKET_FIELD,))] = bname.encode("utf-8")
                self._increment(tr, bucket_space.pack((CONTAINERS_FIELD,)))

        # Update bucket stats
        is_segment = root_container.endswith(MULTIUPLOAD_SUFFIX)
        for key in (BYTES_FIELD, OBJECTS_FIELD):
            if is_segment and key == OBJECTS_FIELD:
                continue
            # Update global stats
            value = stats_delta[key]
            if key == OBJECTS_FIELD:
                bucket_stats[OBJECTS_S3_FIELD] = value
            self._increment(tr, bucket_space.pack((key,)), value)
            for policy, value in stats_delta[f"{key}-details"].items():
                # Update stats by policy
                self._increment(tr, bucket_space.pack((key, policy)), value)

        # Update bucket mtime
        self._update_timestamp(tr, bucket_space.pack((MTIME_FIELD,)), mtime)

        self._update_account_stats(tr, account_id, region, bucket_stats, mtime)

    @catch_service_errors
    def update_bucket_metadata(self, bname, metadata, to_delete=None, **kwargs):
        """
        Update (or delete) bucket metadata.

        :param to_update: dict of entries to set (or update)
        :param to_delete: iterable of keys to delete
        """
        return self._update_bucket_metadata(
            self.db, bname, metadata, to_delete, **kwargs
        )

    @fdb.transactional
    def _update_bucket_metadata(self, tr, bname, to_update, to_delete, **kwargs):
        """
        [transactional] Update (or delete) bucket metadata.
        """
        account_id = self._get_bucket_account(tr, bname, **kwargs)
        bucket_space = self.bucket_space[account_id][bname]

        # Do not use the ctime, it is not present for old buckets
        current_region = tr[bucket_space.pack((REGION_FIELD,))]
        if current_region.present():
            current_region = current_region.decode("utf-8")
        else:
            # Bucket doesn't exist
            return False

        if to_update is None:
            to_update = {}
        # Allow to change the bucket region
        new_region = to_update.pop(REGION_FIELD, None)

        self._update_metadata(
            tr,
            bucket_space,
            to_update,
            to_delete,
            forbidden_keys=RESERVED_BUCKET_FIELDS,
        )

        if new_region is None:
            return True
        if new_region == "":
            raise BadRequest("Region cannot be empty")
        new_region = new_region.upper()
        if new_region == current_region:
            # Nothing to do
            return True

        # Change the bucket region
        ctime = tr[bucket_space.pack((CTIME_FIELD,))]
        if ctime.present():
            ctime = self._timestamp_value_to_timestamp(ctime.value)
        else:
            ctime = None
        # Fetch the bucket metadata
        metadata = self._bucket_info(tr, bname, account=account_id, raw_metadata=True)
        for field in RESERVED_BUCKET_FIELDS:
            metadata.pop(field, None)
        # Delete the bucket in the old region...
        self._real_delete_bucket(tr, bname, account_id, current_region)
        # ...and recreate the bucket in the new region without stats
        self._real_create_bucket(
            tr, bname, account_id, new_region, ctime or self._get_timestamp()
        )
        # Update the timestamp
        if ctime is None:
            del tr[bucket_space.pack((CTIME_FIELD,))]
        else:
            self._set_timestamp(
                tr, bucket_space.pack((MTIME_FIELD,)), self._get_timestamp()
            )
        # Re-add the bucket metadata
        self._update_metadata(tr, bucket_space, metadata, None)
        return True

    @catch_service_errors
    def refresh_bucket(self, bucket_name, **kwargs):
        """
        Refresh the counters of a bucket. Recompute them from the counters
        of all shards (containers).
        """
        batch_size = kwargs.get("batch_size", self.BATCH_SIZE)
        marker = None
        tr = self.db.create_transaction()
        # Loop to replay transaction in case of failure
        while True:
            account_id = self._get_bucket_account(tr, bucket_name, **kwargs)
            try:
                self._reset_bucket_counters(tr, account_id, bucket_name)
                for sharded in [False, True]:
                    marker = None
                    while True:
                        marker = self._refresh_bucket(
                            tr, account_id, bucket_name, sharded, marker, batch_size
                        )

                        if marker is None:
                            break
                tr.commit().wait()
                break
            except fdb.FDBError as e:
                tr.on_error(e).wait()

    @fdb.transactional
    def _reset_bucket_counters(self, tr, account_id, bucket_name):
        account_bucket = self.bucket_space[account_id][bucket_name]

        keys_to_remove = []
        found = False
        for key, _ in tr[account_bucket.range()]:
            found = True
            field, *policy = account_bucket.unpack(key)

            if field not in (BYTES_FIELD, OBJECTS_FIELD):
                continue
            if len(policy) > 0:
                keys_to_remove.append(key)

        # Ensure bucket exists
        if not found:
            raise NotFound("Bucket %s not found" % bucket_name)

        # Reset the containers counter
        self._set_counter(tr, account_bucket[CONTAINERS_FIELD])

        # Reset global counters
        self._set_counter(tr, account_bucket[BYTES_FIELD])
        self._set_counter(tr, account_bucket[OBJECTS_FIELD])

        # Remove policy counters
        for key in keys_to_remove:
            del tr[key]

    @fdb.transactional
    def _refresh_bucket(
        self, tr, bucket_account_id, bucket_name, sharded, marker, batch_size
    ):
        new_marker = None
        counters = {
            CONTAINERS_FIELD: 0,
            BYTES_FIELD: Counter(),
            OBJECTS_FIELD: Counter(),
        }

        container_account_id = bucket_account_id

        if sharded:
            container_account_id = SHARDING_ACCOUNT_PREFIX + bucket_account_id

        # Ensure container account exists
        account_exists = self._is_element(tr, self.accts_space, container_account_id)
        if not account_exists:
            return None

        # Compute request range
        account_containers = self.container_space[container_account_id]
        start, stop = self._get_start_and_stop(account_containers, marker=marker)
        count = 0
        containers = tr.get_range(start, stop)
        data = {}

        # Propagate container counters to bucket if container belongs to bucket
        def _process_data_to_counters():
            if BUCKET_FIELD in data and data[BUCKET_FIELD] == bucket_name:
                counters[CONTAINERS_FIELD] += 1
                for field in (BYTES_FIELD, OBJECTS_FIELD):
                    counters[field] += data.get(field, {})

        # Iterate over containers
        for key, value in containers:
            container, field, *_policy = account_containers.unpack(key)
            root_container = container
            if sharded:
                root_container = container.rsplit("-", 3)[0]

            # Check if we start to process a new container
            if new_marker != container:
                count += 1
                if count > batch_size:
                    break
                new_marker = container
                # Process data if container belongs to bucket
                _process_data_to_counters()
                # Reset data for next container
                data = {}

            if field == BUCKET_FIELD:
                data[BUCKET_FIELD] = value.decode("utf-8")
                continue
            # Skip not counter values
            if field not in (BYTES_FIELD, OBJECTS_FIELD):
                continue
            # Ignore '+segments' objects counter
            if field == OBJECTS_FIELD and root_container.endswith(MULTIUPLOAD_SUFFIX):
                continue

            policy = "_" if len(_policy) == 0 else _policy[0]
            values = data.setdefault(field, {})
            values[policy] = self._counter_value_to_counter(value)

        # Process last data
        _process_data_to_counters()

        # Update counters
        bucket = self.bucket_space[bucket_account_id][bucket_name]
        self._increment(
            tr, bucket.pack((CONTAINERS_FIELD,)), counters[CONTAINERS_FIELD]
        )
        for field in (BYTES_FIELD, OBJECTS_FIELD):
            for policy, counter in counters.get(field, {}).items():
                key = bucket[field]
                if policy != "_":
                    # Not a global counter, add policy
                    key = key[policy]
                self._increment(tr, key, counter)

        return new_marker if count > batch_size else None

    @catch_service_errors
    def reserve_bucket(self, bucket, account_id, **kwargs):
        self._reserve_bucket(self.db, bucket, account_id)

    @fdb.transactional
    def _reserve_bucket(self, tr, bucket, account):
        self._check_max_buckets(tr, account)

        reserved_bucket_space = self.bucket_db_space[bucket]

        rtime = tr[reserved_bucket_space.pack(("rtime",))]
        now = self._get_timestamp()
        if rtime.present():
            # Check if the reservation is ongoing
            rtime = self._timestamp_value_to_timestamp(rtime.value)
            if rtime + self.bucket_reservation_timeout > now:
                raise Forbidden("Already reserved")
        else:
            current_account = tr[reserved_bucket_space.pack(("account",))]
            if current_account.present():
                raise Forbidden("Already associated with an owner")

        self._set_timestamp(tr, reserved_bucket_space.pack(("rtime",)), now)
        tr[reserved_bucket_space.pack(("account",))] = account.encode("utf-8")

    @catch_service_errors
    def release_bucket(self, bucket, account_id, **kwargs):
        self._release_bucket(self.db, bucket, account_id)

    @fdb.transactional
    def _release_bucket(self, tr, bucket, account, check_reservation=True):
        reserved_bucket_space = self.bucket_db_space[bucket]

        current_account = tr[reserved_bucket_space.pack(("account",))]
        if not current_account.present():
            return  # Already release
        current_account = current_account.decode("utf-8")
        if account != current_account:
            raise Forbidden("Bucket reserved by another owner")

        rtime = tr[reserved_bucket_space.pack(("rtime",))]
        if check_reservation and not rtime.present():
            raise Forbidden(
                "The owner has already arrived, "
                "the reservation can no longer be cancelled"
            )

        reserved_bucket_range = reserved_bucket_space.range()
        tr.clear_range(reserved_bucket_range.start, reserved_bucket_range.stop)

    @fdb.transactional
    def _set_bucket_owner(self, tr, bucket, account):
        reserved_bucket_space = self.bucket_db_space[bucket]

        current_account = tr[reserved_bucket_space.pack(("account",))]
        if current_account.present():
            current_account = current_account.decode("utf-8")
        else:
            # Last minute reservations are accepted
            # if the bucket is not already reserved
            self._reserve_bucket(tr, bucket, account)
            current_account = account
        rtime = tr[reserved_bucket_space.pack(("rtime",))]
        if not rtime.present():
            if account == current_account:
                return
            raise Forbidden("Already associated with an owner")
        rtime = self._timestamp_value_to_timestamp(rtime.value)
        if account != current_account:
            raise Forbidden("Bucket reserved by another owner")

        delay = time.time() - (rtime + self.bucket_reservation_timeout)
        if delay > 0:
            self.logger.info(
                "Reservation has expired (delay: %f seconds), "
                "but since no one else has reserved the bucket %s, "
                "the request is accepted",
                delay,
                bucket,
            )
        tr.clear(reserved_bucket_space.pack(("rtime",)))

    @catch_service_errors
    def get_bucket_owner(self, bucket, **kwargs):
        return self._get_bucket_owner(self.db, bucket, readonly=True)

    @fdb.transactional
    @use_snapshot_reads
    def _get_bucket_owner(self, tr, bucket):
        reserved_bucket_space = self.bucket_db_space[bucket]

        rtime = tr[reserved_bucket_space.pack(("rtime",))]
        if rtime.present():
            raise NotFound("Bucket is reserved, but the owner has not arrived yet")
        current_account = tr[reserved_bucket_space.pack(("account",))]
        if not current_account.present():
            raise NotFound("No owner")

        return current_account.decode("utf-8")

    @fdb.transactional
    @use_snapshot_reads
    def _get_bucket_account(
        self, tr, bucket, account=None, check_owner=False, **kwargs
    ):
        if not check_owner and account:
            return account
        try:
            owner = self._get_bucket_owner(tr, bucket)
        except NotFound as exc:
            if check_owner:
                raise Forbidden(f"No owner found: {exc}") from exc
            raise BadRequest(f"Missing account param or an owner: {exc}") from exc
        if account and account != owner:
            raise Forbidden("Bucket reserved by another owner")
        return owner

    @fdb.transactional
    def _is_element(self, tr, space, key):
        return tr[space.pack((key,))].present()
