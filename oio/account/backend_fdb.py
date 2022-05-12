# Copyright (C) 2021-2022 OVH SAS
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
import fdb
from functools import wraps
import struct
import time
from werkzeug.exceptions import BadRequest, Conflict, Forbidden, NotFound

from oio.account.common_fdb import CommonFdb
from oio.common.constants import BUCKET_PROP_REPLI_ENABLED
from oio.common.easy_value import boolean_value, float_value, debinarize
from oio.common.exceptions import ServiceBusy
from oio.common.timestamp import Timestamp

fdb.api_version(CommonFdb.FDB_VERSION)


MULTIUPLOAD_SUFFIX = '+segments'
SHARDING_ACCOUNT_PREFIX = '.shards_'
BYTES_FIELD = 'bytes'
OBJECTS_FIELD = 'objects'
SHARDS_FIELD = 'shards'
CONTAINERS_FIELD = 'containers'
BUCKETS_FIELD = 'buckets'
ACCOUNTS_FIELD = 'accounts'
REGIONS_FIELD = 'regions'
CTIME_FIELD = 'ctime'
MTIME_FIELD = 'mtime'
COUNTERS_FIELDS = (BYTES_FIELD, OBJECTS_FIELD, SHARDS_FIELD, CONTAINERS_FIELD,
                   BUCKETS_FIELD, ACCOUNTS_FIELD)
TIMESTAMP_FIELDS = (CTIME_FIELD, MTIME_FIELD)


def catch_service_errors(func):
    """
    :raises `ServiceBusy`: in case of a fdb service error
    """

    @wraps(func)
    def catch_service_errors_wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (fdb.FDBError, ValueError) as err:
            raise ServiceBusy(message=str(err))

    return catch_service_errors_wrapper


class AccountBackendFdb(object):
    """
    Foundationdb backend for account service.
    """

    # Default batch size, this value could be divided by 2 if time of refresh
    # by batch is too long
    BATCH_SIZE = 10000

    # Default subspaces prefixes

    ACCOUNTS_KEY_PREFIX = 'accounts'
    ACCOUNT_KEY_PREFIX = 'account'
    BUCKET_KEY_PREFIX = 'bucket'
    BUCKET_LIST_PREFIX = 'buckets'
    CONTAINERS_LIST_PREFIX = 'containers'
    CONTAINER_LIST_PREFIX = 'container'
    # Remaining keys for deletex containers prefix
    CTS_TO_DELETE_LIST_PREFIX = 'deleted-container'
    # Metadata prefix
    METADATA_PREFIX = 'metadata'
    # Prefix for bucket db
    BUCKET_RESERVE_PREFIX = 's3bucket'
    # Stats & metric prefix
    METRICS_PREFIX = 'metrics'

    # Timeout for bucket reservation
    DEFAULT_BUCKET_RESERVATION_TIMEOUT = 30

    def init_db(self, event_model='gevent'):
        """
        This method makes connexion to fdb database. It could be called
        any time in mono process, but in case we fork processes it should be
        called after forking in gunicorn.
        This is the reason why this task is not done inside constructor.
        """
        self.fdb_file = self.conf.get('fdb_file',
                                      CommonFdb.DEFAULT_FDB)
        try:
            if self.db is None:
                self.db = fdb.open(self.fdb_file, event_model=event_model)
        except Exception as exc:
            self.logger.error("can't open fdb file: %s exception %s",
                              self.fdb_file, exc)
            raise
        try:
            self.namespace = fdb.directory.create_or_open(
                self.db, (self.main_namespace_name,))
            self.acct_space = self.namespace.create_or_open(
                self.db, self.account_prefix)
            self.accts_space = self.namespace.create_or_open(
                self.db, self.accounts_prefix)
            self.container_space = self.namespace.create_or_open(
                self.db, self.container_list_prefix)
            self.containers_index_space = self.namespace.create_or_open(
                self.db, self.containers_list_prefix)
            self.ct_to_delete_space = self.namespace.create_or_open(
                self.db, self.ct_to_delete_prefix)
            self.bucket_db_space = self.namespace.create_or_open(
                self.db, self.reserve_bucket_prefix)
            self.bucket_space = self.namespace.create_or_open(
                self.db, self.bucket_prefix)
            self.buckets_index_space = self.namespace.create_or_open(
                self.db, self.buckets_list_prefix)
            self.metadata_space = self.namespace.create_or_open(
                self.db, self.metadata_prefix)
            self.metrics_space = self.namespace.create_or_open(
                self.db, self.metrics_prefix)
        except Exception as exc:
            self.logger.warning("Directory create exception %s", exc)
            raise

    def __init__(self, conf, logger):
        self.db = None
        self.conf = conf
        self.logger = logger
        self.fdb_file = None
        self.autocreate = boolean_value(conf.get('autocreate'), True)
        self.time_window_clear_deleted = \
            float_value(self.conf.get('time_window_clear_deleted'), 60.0)
        self.main_namespace_name = self.conf.get('main_namespace_name',
                                                 CommonFdb.MAIN_NAMESPACE)
        self.accounts_prefix = conf.get('accounts_prefix',
                                        self.ACCOUNTS_KEY_PREFIX)
        self.account_prefix = conf.get('account_prefix',
                                       self.ACCOUNT_KEY_PREFIX)
        self.bucket_prefix = conf.get('bucket_prefix',
                                      self.BUCKET_KEY_PREFIX)
        self.buckets_list_prefix = conf.get('bucket_list_prefix',
                                            self.BUCKET_LIST_PREFIX)
        self.container_list_prefix = conf.get('container_list_prefix',
                                              self.CONTAINER_LIST_PREFIX)
        self.containers_list_prefix = conf.get('containers_list_prefix',
                                               self.CONTAINERS_LIST_PREFIX)
        self.ct_to_delete_prefix = conf.get('containers_to_delete_prefix',
                                            self.CTS_TO_DELETE_LIST_PREFIX)
        self.metadata_prefix = conf.get('metadata_prefix',
                                        self.METADATA_PREFIX)
        self.metrics_prefix = conf.get('metrics_prefix',
                                       self.METRICS_PREFIX)
        self.reserve_bucket_prefix = conf.get('reserve_bucket_prefix',
                                              self.BUCKET_RESERVE_PREFIX)

        self.bucket_reservation_timeout = float_value(
            conf.get('bucket_reservation_timeout'),
            self.DEFAULT_BUCKET_RESERVATION_TIMEOUT)

    # Helpers -----------------------------------------------------------------

    def _set_counter(self, tr, key, value=0):
        tr[key] = struct.pack('<q', value)

    def _increment(self, tr, key, inc=1):
        if inc:
            tr.add(key, struct.pack('<q', inc))

    def _counter_value_to_counter(self, counter_value):
        return struct.unpack('<q', counter_value)[0]

    def _counters_key_value_to_dict(self, counters_key_value, unpack=None):
        counters = {}
        for counter_key, counter_value in counters_key_value:
            if unpack:
                counter_key = unpack(counter_key)
            if isinstance(counter_key, tuple) and len(counter_key) == 1:
                counter_key = counter_key[0]
            counters[counter_key] = struct.unpack('<q', counter_value)[0]
        return counters

    def _get_timestamp(self, timestamp=None):
        timestamp = Timestamp(timestamp).timestamp
        # Microsecond precision
        return int(timestamp * 1000000) / 1000000

    def _set_timestamp(self, tr, key, timestamp):
        tr[key] = struct.pack('<Q', int(timestamp * 1000000))

    def _update_timestamp(self, tr, key, timestamp):
        tr.max(key, struct.pack('<Q', int(timestamp * 1000000)))

    def _timestamp_value_to_timestamp(self, timestamp_value):
        return struct.unpack('<Q', timestamp_value)[0] / 1000000

    def _unmarshal_info(self, keys_values, has_region=False, unpack=None):
        info = {}
        for key, value in keys_values:
            if unpack:
                key = unpack(key)
            field, *details = key
            if details:
                if not has_region and len(details) == 1:
                    policy = details[0]
                    dict_values = info.setdefault(f"{field}-details", {})
                    dict_values[policy] = self._counter_value_to_counter(value)
                elif has_region and len(details) <= 2:
                    region = details[0]
                    dict_values = info.setdefault(
                        REGIONS_FIELD, {}).setdefault(region, {})
                    if len(details) == 2:
                        dict_values = dict_values.setdefault(
                            f"{field}-details", {})
                        field = details[1]  # polciy
                    dict_values[field] = self._counter_value_to_counter(value)
                else:
                    self.logger.warning('Unknown key: "%s"', key)
            elif field in COUNTERS_FIELDS:
                info[field] = self._counter_value_to_counter(value)
            elif field in TIMESTAMP_FIELDS:
                info[field] = self._timestamp_value_to_timestamp(value)
            else:
                info[field] = value.decode('utf-8')
        return info

    # Status/metrics ----------------------------------------------------------

    @catch_service_errors
    def status(self, **kwargs):
        return self._status(self.db)

    @fdb.transactional
    def _status(self, tr):
        accounts = tr.snapshot[self.metrics_space.pack((ACCOUNTS_FIELD,))]
        if accounts.present():
            accounts = self._counter_value_to_counter(accounts.value)
        else:
            accounts = 0
        return {'account_count': accounts}

    @catch_service_errors
    def info_metrics(self, output_type, **kwargs):
        """
        Get all available information about global metrics.
        """
        metrics = self._info_metrics(self.db)
        if output_type == 'prometheus':
            return self._metrics_to_prometheus_format(metrics)
        else:
            return metrics

    @fdb.transactional
    def _info_metrics(self, tr):
        """
        [transactional] Get all available information about global metrics.
        """
        metrics_range = self.metrics_space.range()
        iterator = tr.snapshot.get_range(
            metrics_range.start, metrics_range.stop,
            streaming_mode=fdb.StreamingMode.want_all)
        info = self._unmarshal_info(
            iterator, has_region=True, unpack=self.metrics_space.unpack)
        info.setdefault(ACCOUNTS_FIELD, 0)
        info.setdefault(REGIONS_FIELD, {})
        return info

    def _metrics_to_prometheus_format(self, metrics):
        prom_output = []
        prom_output.append(f"obsto_accounts {metrics[ACCOUNTS_FIELD]}")
        for region, region_details in metrics[REGIONS_FIELD].items():
            for counter, counter_value in region_details.items():
                if counter.endswith('-details'):
                    counter = counter[:-8]
                    for policy, policy_value in counter_value.items():
                        prom_output.append(
                            f"obsto_{counter}{{region=\"{region}\","
                            f"policy=\"{policy}\"}} {policy_value}")
                else:
                    prom_output.append(
                        f"obsto_{counter}{{region=\"{region}\"}} "
                        f"{counter_value}")
        return '\n'.join(prom_output)

    @fdb.transactional
    def _update_metrics_stats(self, tr, region, stats_delta):
        """
        [transactional] Update metrics stats for the specified region.
        """
        for key in (BYTES_FIELD, OBJECTS_FIELD):
            for policy, value in stats_delta[f"{key}-details"].items():
                # Update stats by policy (by policy)
                self._increment(
                    tr, self.metrics_space.pack((key, region, policy)), value)

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
        tr[account_space.pack(('id',))] = account_id.encode('utf-8')
        self._set_counter(tr, account_space.pack((BYTES_FIELD,)))
        self._set_counter(tr, account_space.pack((OBJECTS_FIELD,)))
        self._set_counter(tr, account_space.pack((CONTAINERS_FIELD,)))
        self._set_counter(tr, account_space.pack((BUCKETS_FIELD,)))
        # Set account ctime and mtime
        self._set_timestamp(tr, account_space.pack((CTIME_FIELD,)), ctime)
        self._set_timestamp(tr, account_space.pack((MTIME_FIELD,)), ctime)
        # Add account in index
        tr[self.accts_space.pack((account_id,))] = b'1'
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
            raise NotFound('Account does\'nt exist')

        containers = tr[account_space.pack((CONTAINERS_FIELD,))]
        if containers.present():
            containers = self._counter_value_to_counter(containers.value)
        else:
            containers = 0
        if containers:
            raise Conflict('Account not empty')

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
        tr.clear_range(deleted_containers_range.start,
                       deleted_containers_range.stop)
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
        Get all available information about a account.
        """
        return self._account_info(self.db, account_id, full=True)

    @fdb.transactional
    def _account_info(self, tr, account_id, full=False):
        """
        [transactional] Get all available information about a account.
        """
        account_space = self.acct_space[account_id]
        account_range = account_space.range()
        iterator = tr.snapshot.get_range(
            account_range.start, account_range.stop,
            streaming_mode=fdb.StreamingMode.want_all)
        info = self._unmarshal_info(
            iterator, has_region=True, unpack=account_space.unpack)
        if not info:
            return None

        if full:
            metadata = {}
            metadata_space = self.metadata_space[account_id]
            metadata_range = metadata_space.range()
            iterator = tr.snapshot.get_range(
                metadata_range.start, metadata_range.stop,
                streaming_mode=fdb.StreamingMode.want_all)
            for key, value in iterator:
                key = metadata_space.unpack(key)
                if len(key) == 1:
                    metadata[key[0]] = value.decode('utf-8')
                else:
                    self.logger.warning('Unknown key: "%s"', key)
            info['metadata'] = metadata

        if not account_id.startswith(SHARDING_ACCOUNT_PREFIX):
            self._merge_sharding_account_info(tr, account_id, info)

        return info

    @fdb.transactional
    def _merge_sharding_account_info(self, tr, account_id, info):
        # Fetch sharding account
        sharding_info = self._account_info(
            tr, SHARDING_ACCOUNT_PREFIX + account_id, full=False)
        if not sharding_info:
            return
        # Update global stats of sharding account
        for key in (BYTES_FIELD, OBJECTS_FIELD):
            value = sharding_info.get(key)
            if not value:
                continue
            info[key] = info.get(key, 0) + value
        info[SHARDS_FIELD] = sharding_info.get(CONTAINERS_FIELD, 0)
        info[MTIME_FIELD] = max(info.get(MTIME_FIELD, 0),
                                sharding_info.get(MTIME_FIELD, 0))
        # Update detailed stats of sharding account
        regions_info = info.setdefault(REGIONS_FIELD, {})
        for region, shards_region_info in sharding_info.get(
                REGIONS_FIELD, {}).items():
            region_info = regions_info.setdefault(region, {})
            for key in (BYTES_FIELD, OBJECTS_FIELD):
                shards_region_details = shards_region_info.get(
                    f'{key}-details')
                if shards_region_details is None:
                    continue
                region_details = region_info.setdefault(f'{key}-details', {})
                for policy, value in shards_region_details.items():
                    region_details[policy] = region_details.get(
                        policy, 0) + value
            region_info[SHARDS_FIELD] = shards_region_info.get(
                CONTAINERS_FIELD, 0)

    @catch_service_errors
    def list_accounts(self, **kwargs):
        """
        Get the list of all accounts.
        """
        accounts = self._list_accounts(self.db)
        return debinarize(accounts)

    @fdb.transactional
    def _list_accounts(self, tr):
        # iterate over the whole 'accounts:' subspace
        iterator = tr.get_range_startswith(self.accts_space)
        res = list()
        for key, _ in iterator:
            account_id = self.accts_space.unpack(key)[0]
            res.append(account_id)
        return res

    @fdb.transactional
    def _update_account_stats(self, tr, account_id, region, stats_delta,
                              mtime):
        """
        [transactional] Update account stats for the specified region.
        This method assumes that the account exists.
        """
        account_space = self.acct_space[account_id]

        # Update account stats
        for key in (BYTES_FIELD, OBJECTS_FIELD):
            # Update global stats
            value = stats_delta[key]
            self._increment(tr, account_space.pack((key,)), value)
            # Update stats by policy (by region)
            for policy, value in stats_delta[f"{key}-details"].items():
                self._increment(
                    tr, account_space.pack((key, region, policy)), value)

        # Update account mtime
        self._update_timestamp(tr, account_space.pack((MTIME_FIELD,)), mtime)

        # Update metrics stats with the delta
        self._update_metrics_stats(tr, region, stats_delta)

    @catch_service_errors
    def get_account_metadata(self, req_account_id, **kwargs):
        if not req_account_id:
            return None
        account_id = self._val_element(self.db, self.acct_space,
                                       req_account_id, 'id')
        if account_id is None:
            self.logger.info('metadata account %s not found', account_id)
            return None

        account_id = account_id.decode('utf-8')
        meta = self._get_metada(self.db, account_id)
        return debinarize(meta)

    @catch_service_errors
    def update_account_metadata(self, account_id, metadata, to_delete=None,
                                **kwargs):
        if not account_id:
            return None

        _acct_id = self._val_element(self.db, self.acct_space,
                                     account_id, 'id')

        if _acct_id is None:
            if self.autocreate:
                self.create_account(account_id)
            else:
                return None

        if not metadata and not to_delete:
            return account_id
        self._manage_metadata(self.db, self.metadata_space, account_id,
                              metadata, to_delete)

        return account_id

    def cast_fields(self, info):
        """
        Cast dict entries to the type they are supposed to be.
        """
        for what in (b'bytes', b'objects'):
            try:
                info[what] = self._counter_value_to_counter(info.get(what))
            except (TypeError, ValueError):
                pass
        for what in (b'ctime', b'mtime'):
            try:
                info[what] = self._timestamp_value_to_timestamp(info.get(what))
            except (TypeError, ValueError):
                pass
        for what in (BUCKET_PROP_REPLI_ENABLED.encode('utf-8'), ):
            try:
                val = info.get(what)
                decoded = val.decode('utf-8') if val is not None else None
                info[what] = boolean_value(decoded)
            except (TypeError, ValueError):
                pass

    @catch_service_errors
    def refresh_account(self, account_id, **kwargs):
        if not account_id:
            raise BadRequest("Missing account")
        self._refresh_account(self.db, account_id)

    @fdb.transactional
    def _refresh_account(self, tr, account_id):
        if not self._is_element(tr, self.accts_space, account_id):
            raise NotFound(account_id)

        ct_space = self.container_space[account_id]
        s_range = ct_space.range()

        iterator = tr.get_range(s_range.start, s_range.stop, reverse=False)
        sum_bytes = 0
        sum_objects = 0
        for key, val in iterator:
            _, field, *policy_region = ct_space.unpack(key)
            if policy_region:
                continue
            if field == BYTES_FIELD:
                sum_bytes += self._counter_value_to_counter(val)
            if field == OBJECTS_FIELD:
                sum_objects += self._counter_value_to_counter(val)

        self._set_counter(
            tr, self.acct_space.pack((account_id, BYTES_FIELD)), sum_bytes)
        self._set_counter(
            tr, self.acct_space.pack((account_id, OBJECTS_FIELD)), sum_objects)

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
            current_mtime = self._timestamp_value_to_timestamp(
                current_mtime.value)
            if mtime == current_mtime:
                self.logger.info('flush account %s: transaction replay \
                                 skipped', account_id)
                return
        else:
            raise NotFound('Account does\'nt exist')
        for field in (BYTES_FIELD, OBJECTS_FIELD, CONTAINERS_FIELD,
                      BUCKETS_FIELD):
            self._set_counter(tr, account_space.pack((field,)))
            details_space = account_space[field]
            details_range = details_space.range()
            # Update metrics
            iterator = tr.get_range(details_range.start, details_range.stop)
            for key, value in iterator:
                key = account_space.unpack(key)
                value = self._counter_value_to_counter(value)
                if field == CONTAINERS_FIELD and account_id.startswith(
                        SHARDING_ACCOUNT_PREFIX):
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
        tr.clear_range(deleted_containers_range.start,
                       deleted_containers_range.stop)
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
                self._flush_account(
                    tr, SHARDING_ACCOUNT_PREFIX + account_id, mtime)
            except NotFound:
                pass

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
            raise BadRequest('Missing region')

        # Add basic info
        tr[container_space.pack(('name',))] = cname.encode('utf-8')
        tr[container_space.pack(('region',))] = region.encode('utf-8')
        self._set_counter(tr, container_space.pack((BYTES_FIELD,)))
        self._set_counter(tr, container_space.pack((OBJECTS_FIELD,)))
        # Set container mtime
        self._set_timestamp(tr, container_space.pack((MTIME_FIELD,)), ctime)
        # Add container in index
        tr[self.containers_index_space.pack((account_id, cname))] = b'1'
        # Delete the old dtime
        tr.clear(deleted_container_space.key())
        # Increase containers counter in account
        self._increment(tr, self.acct_space[account_id].pack(
            (CONTAINERS_FIELD,)))
        self._increment(tr, self.acct_space[account_id].pack(
            (CONTAINERS_FIELD, region)))
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
                current_value = - self._counter_value_to_counter(
                    current_value.value)
            else:
                current_value = 0
            stats_delta[key] = current_value

            # Fetch the stats by policy
            details_space = container_space[key]
            details_range = details_space.range()
            current_value_by_policy = self._counters_key_value_to_dict(
                tr.get_range(details_range.start, details_range.stop,
                             streaming_mode=fdb.StreamingMode.want_all),
                unpack=details_space.unpack)
            delta_by_policy = {}
            for policy, value in current_value_by_policy.items():
                delta_by_policy[policy] = - value
            stats_delta[f"{key}-details"] = delta_by_policy

        # Delete container info
        container_range = container_space.range()
        tr.clear_range(container_range.start, container_range.stop)
        # Delete container in index
        tr.clear(self.containers_index_space.pack((account_id, cname)))
        # Keep the dtime in case an event is late
        self._update_timestamp(tr, deleted_container_space.key(), dtime)
        # Decrease containers counter in account
        self._increment(tr, self.acct_space[account_id].pack(
            (CONTAINERS_FIELD,)), -1)
        self._increment(tr, self.acct_space[account_id].pack(
            (CONTAINERS_FIELD, region)), -1)
        # Decrease containers counter in metrics
        metrics_field = CONTAINERS_FIELD
        if account_id.startswith(SHARDING_ACCOUNT_PREFIX):
            metrics_field = SHARDS_FIELD
        self._increment(tr, self.metrics_space.pack(
            (metrics_field, region)), -1)

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
        return self._container_info(self.db, account_id, cname, full=True)

    @fdb.transactional
    def _container_info(self, tr, account_id, cname, full=False):
        """
        [transactional] Get all available information about a container,
        including some information coming from the bucket it belongs to.
        """
        container_space = self.container_space[account_id][cname]
        container_range = container_space.range()
        iterator = tr.snapshot.get_range(
            container_range.start, container_range.stop,
            streaming_mode=fdb.StreamingMode.want_all)
        info = self._unmarshal_info(iterator, unpack=container_space.unpack)
        if not info:
            return None

        if full:
            repli_enabled = None
            bname = info.get('bucket')
            if bname:
                if account_id.startswith(SHARDING_ACCOUNT_PREFIX):
                    account_id = account_id[8:]
                buckat_space = self.bucket_space[account_id][bname]
                repli_enabled = tr.snapshot[
                    buckat_space.pack((BUCKET_PROP_REPLI_ENABLED,))]
                if repli_enabled.present():
                    repli_enabled = repli_enabled.decode('utf-8')
                else:
                    repli_enabled = None
            info[BUCKET_PROP_REPLI_ENABLED] = boolean_value(repli_enabled)

        return info

    @catch_service_errors
    def list_containers(self, account_id, limit=1000, marker=None,
                        end_marker=None, prefix=None, **kwargs):
        if prefix is None:
            prefix = ''
        ct_index_space = self.containers_index_space[account_id]
        ct_space = self.container_space[account_id]
        raw_list, _ = self._raw_listing(
            self.db, ct_index_space, ct_space, limit, prefix,
            marker, end_marker)

        return raw_list

    @fdb.transactional
    def _raw_listing(self, tr, index_space, main_space, limit, prefix,
                     marker, end_marker):
        start = index_space.range().start
        stop = index_space.range().stop

        min_k = None
        max_k = stop

        orig_marker = marker
        results = list()
        beyond_prefix = False
        if prefix is None:
            prefix = ''

        if marker:
            marker = fdb.KeySelector.first_greater_or_equal(
                index_space.pack((marker,)))

        while len(results) < limit and not beyond_prefix:
            min_k = start
            max_k = stop
            local_limit = (limit - len(results) + 1)

            if prefix:
                max_k = stop
                min_k = fdb.KeySelector.first_greater_or_equal(
                    index_space.pack((prefix,)))

            if marker and (not prefix or
                           tr.get_key(marker) >= tr.get_key(min_k)):
                min_k = marker

            if end_marker and (not prefix
                               or end_marker <= prefix + b'\xff'):
                max_k = fdb.KeySelector.last_less_or_equal(
                    index_space.pack((end_marker,)))

            iterator = tr.snapshot.get_range(min_k, max_k, limit=local_limit,
                                             reverse=False)

            empty = True
            for key, _ in iterator:
                ctr = index_space.unpack(key)[0]
                if len(results) >= limit:
                    break
                if prefix and not ctr.startswith(prefix):
                    beyond_prefix = True
                    # No more items
                    marker = None
                    break
                if end_marker:
                    marker = fdb.KeySelector.first_greater_or_equal(
                        index_space.pack((end_marker,)))
                else:
                    marker = fdb.KeySelector.first_greater_than(
                        index_space.pack((ctr,)))

                # don't include marker
                if orig_marker == ctr:
                    continue

                nb_objects = 0
                nb_bytes = 0
                mtime = 0
                ct_space = main_space[ctr]
                ct_range = ct_space.range()
                ct_it = tr.get_range(ct_range.start,
                                     ct_range.stop, reverse=False)
                for ct_key, a_value in ct_it:
                    a_key, *pol = ct_space.unpack(ct_key)
                    if pol:
                        continue
                    if a_key == OBJECTS_FIELD:
                        nb_objects = self._counter_value_to_counter(a_value)
                    if a_key == BYTES_FIELD:
                        nb_bytes = self._counter_value_to_counter(a_value)
                    if a_key == MTIME_FIELD:
                        mtime = self._timestamp_value_to_timestamp(a_value)
                results.append([ctr, nb_objects, nb_bytes, 0, mtime])

                empty = False
            if empty:
                break
        return results, orig_marker

    @catch_service_errors
    def update_container(self, account_id, cname, mtime, dtime,
                         object_count, bytes_used,
                         bucket_name=None, region=None,
                         objects_details=None, bytes_details=None,
                         autocreate_account=None, autocreate_container=True,
                         **kwargs):
        """
        Update container info and stats.
        Create the account if it does not exist and autocreation is enabled.
        Create the container if it does not exist and autocreation is enabled.
        """
        if autocreate_account is None:
            autocreate_account = self.autocreate

        if mtime is None:
            mtime = 0.
        else:
            mtime = self._get_timestamp(mtime)
        if dtime is None:
            dtime = 0.
        else:
            dtime = self._get_timestamp(dtime)

        if object_count is None:
            object_count = 0
        if objects_details is None:
            objects_details = {}
        if bytes_used is None:
            bytes_used = 0
        if bytes_details is None:
            bytes_details = {}
        new_stats = {
            OBJECTS_FIELD: object_count,
            f'{OBJECTS_FIELD}-details': objects_details,
            BYTES_FIELD: bytes_used,
            f'{BYTES_FIELD}-details': bytes_details
        }

        if region:
            region = region.upper()

        self._update_container(
            self.db, account_id, cname, bucket_name, region, new_stats,
            mtime, dtime, autocreate_account, autocreate_container)

    @fdb.transactional
    def _update_container(self, tr, account_id, cname, bname, region,
                          new_stats, new_mtime, new_dtime, autocreate_account,
                          autocreate_container):
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
                raise NotFound('Account does\'nt exist')
            self._real_create_account(tr, account_id)

        container_is_deleted = new_dtime >= new_mtime

        # Check that the container exists and create it if necessary
        current_mtime = tr[container_space.pack((MTIME_FIELD,))]
        if not current_mtime.present():
            # Container doesn't exist
            # Check that the container has not been recently deleted
            current_dtime = tr[deleted_container_space.key()]
            if current_dtime.present():
                current_dtime = self._timestamp_value_to_timestamp(
                    current_dtime.value)
                if container_is_deleted:
                    if current_dtime >= new_dtime:
                        raise Conflict(
                            'No update needed, '
                            'event older than last container update')
                elif current_dtime >= new_mtime:
                    # Container no longer exists
                    raise Conflict(
                        'No update needed, '
                        'event older than last container update')
            if container_is_deleted:
                # Container is already deleted, keep the most recent dtime
                self._update_timestamp(
                    tr, deleted_container_space.key(), new_dtime)
                return
            # It's a new container
            if not autocreate_container:
                raise NotFound('Container does\'nt exist')
            self._real_create_container(tr, account_id, cname, region,
                                        new_mtime)
            current_mtime = new_mtime
        else:
            # Container exists
            current_mtime = self._timestamp_value_to_timestamp(
                current_mtime.value)
            if container_is_deleted:
                # If the deletion timestamp equals the last modification,
                # allow the deletion.
                if current_mtime > new_dtime:
                    raise Conflict(
                        'No update needed, '
                        'event older than last container update')
            elif current_mtime >= new_mtime:
                raise Conflict(
                    'No update needed, '
                    'event older than last container update')

        current_region = tr[container_space.pack(('region',))]
        if current_region.present():
            # Container is already associated with a region
            current_region = current_region.decode('utf-8')
            if region:
                # Check that the region has not changed
                if region != current_region:
                    self.logger.warning(
                        'The region has changed for the container %s '
                        'in account %s (before: %s, after: %s)',
                        cname, account_id, current_region, region)
                    # Fetch the bucket associated with this container
                    current_bname = tr[container_space.pack(('bucket',))]
                    if current_bname.present():
                        current_bname = current_bname.value
                    else:
                        current_bname = None
                    # Delete the container from the old region
                    self._real_delete_container(
                        tr, account_id, cname, current_region, current_mtime)
                    # Recreate the container in the new region
                    # His stats will be updated later
                    self._real_create_container(
                        tr, account_id, cname, region, current_mtime)
                    # Reattach the bucket to the container.
                    if current_bname:
                        tr[container_space.pack(('bucket',))] = current_bname
                    current_region = region
            else:
                region = current_region
        if not region:
            raise BadRequest('Missing region')

        container_has_new_bucket = False
        current_bname = tr[container_space.pack(('bucket',))]
        if current_bname.present():
            # Container is already associated with a bucket
            current_bname = current_bname.decode('utf-8')
            if bname:
                # Check that the bucket has not changed
                if bname != current_bname:
                    self.logger.warning(
                        'The bucket has changed for the container %s '
                        'in account %s (before: %s, after: %s)',
                        cname, account_id, current_bname, bname)
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
                tr, account_id, cname, region, new_dtime)
        else:
            stats_delta = self._update_container_stats(
                tr, account_id, cname, region, new_stats, new_mtime)

        # Update bucket stats
        if bname:
            if container_has_new_bucket:
                # Update bucket stats with the container stats
                stats_delta = new_stats
            bucket_mtime = max(new_mtime, new_dtime)
            self._update_bucket_stats(
                tr, account_id, cname, bname, region, stats_delta,
                bucket_mtime, container_is_deleted, container_has_new_bucket)

    @fdb.transactional
    def _update_container_stats(self, tr, account_id, cname, region,
                                new_stats, mtime):
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
                current_value = self._counter_value_to_counter(
                    current_value.value)
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
                tr.get_range(details_range.start, details_range.stop,
                             streaming_mode=fdb.StreamingMode.want_all),
                unpack=details_space.unpack)
            delta_by_policy = {}
            all_policies = set(current_value_by_policy).union(
                new_value_by_policy)
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
            deleted_containers_range.start, deleted_containers_range.stop,
            streaming_mode=fdb.StreamingMode.want_all)
        now = self._get_timestamp()
        for key, dtime in iterator:
            dtime = self._timestamp_value_to_timestamp(dtime)
            if dtime + self.time_window_clear_deleted < now:
                tr.clear(key)

    # Bucket ------------------------------------------------------------------

    @catch_service_errors
    def create_bucket(self, bname, account_id, region, ctime=None,
                      autocreate_account=None, **kwargs):
        """
        Create the bucket if it doesn't already exist.
        """
        region = region.upper()
        if ctime is None:
            ctime = self._get_timestamp()
        if autocreate_account is None:
            autocreate_account = self.autocreate
        return self._create_bucket(self.db, bname, account_id, region,
                                   ctime, autocreate_account)

    @fdb.transactional
    def _create_bucket(self, tr, bname, account, region, ctime,
                       autocreate_account):
        """
        [transactional] Create the bucket if it doesn't already exist.
        """
        account_space = self.acct_space[account]
        bucket_space = self.bucket_space[account][bname]

        # Check that the account exists and create it if necessary
        account_ctime = tr[account_space.pack((CTIME_FIELD,))]
        if not account_ctime.present():
            # It's a new account
            if not autocreate_account:
                raise NotFound('Account does\'nt exist')
            self._real_create_account(tr, account)

        self._set_bucket_owner(tr, bname, account)

        # Do not use the ctime, it is not present for old buckets
        current_region = tr[bucket_space.pack(('region',))]
        if current_region.present():
            # Bucket already exists
            current_region = current_region.decode('utf-8')
            if region != current_region:
                raise Conflict('Created in another region')
            return False
        self._real_create_bucket(tr, bname, account, region, ctime=ctime)
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
        tr[bucket_space.pack(('account',))] = account.encode('utf-8')
        tr[bucket_space.pack(('region',))] = region.encode('utf-8')
        self._set_counter(tr, bucket_space.pack((CONTAINERS_FIELD,)))
        self._set_counter(tr, bucket_space.pack((BYTES_FIELD,)))
        self._set_counter(tr, bucket_space.pack((OBJECTS_FIELD,)))
        # Set bucket ctime and mtime
        self._set_timestamp(tr, bucket_space.pack((CTIME_FIELD,)), ctime)
        self._set_timestamp(tr, bucket_space.pack((MTIME_FIELD,)), ctime)
        # Add bucket in index
        tr[self.buckets_index_space.pack((account, bname))] = b'1'
        tr[self.buckets_index_space.pack((region, account, bname))] = b'1'
        # Increase buckets counter in account
        self._increment(tr, self.acct_space[account].pack((BUCKETS_FIELD,)))
        self._increment(tr, self.acct_space[account].pack(
            (BUCKETS_FIELD, region)))
        # Increase buckets counter in metrics
        self._increment(tr, self.metrics_space.pack((BUCKETS_FIELD, region)))

    @catch_service_errors
    def delete_bucket(self, bname, account, region, **kwargs):
        """
        Delete the account if it already exists.
        """
        if region:
            region = region.upper()
        self._delete_bucket(self.db, bname, account, region)
        return True

    @fdb.transactional
    def _delete_bucket(self, tr, bucket, account, region):
        """
        [transactional] Delete the account if it already exists.
        """
        bucket_space = self.bucket_space[account][bucket]
        try:
            # Do not use the ctime, it is not present for old buckets
            current_region = tr[bucket_space.pack(('region',))]
            if not current_region.present():
                raise NotFound('Bucket does not exist')
            current_region = current_region.decode('utf-8')
            if current_region != region:
                raise Forbidden(
                    'Deletion is not allowed in any region other '
                    'than the bucket region')

            # Since the bucket is deleted synchronously,
            # there is no need to check for asynchronously updated counters
        except NotFound:
            # The bucket might not exist, but the account owns it
            try:
                self._release_bucket(tr, bucket, account,
                                     check_reservation=False)
                return
            except Forbidden:
                pass
            raise

        try:
            self._release_bucket(tr, bucket, account,
                                 check_reservation=False)
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

        # Delete bucket info
        bucket_range = bucket_space.range()
        tr.clear_range(bucket_range.start, bucket_range.stop)
        # Delete bucket in index
        tr.clear(self.buckets_index_space.pack((account, bucket,)))
        tr.clear(self.buckets_index_space.pack((region, account, bucket,)))
        # Decrease buckets counter in account
        self._increment(tr, self.acct_space[account].pack(
            (BUCKETS_FIELD,)), -1)
        self._increment(tr, self.acct_space[account].pack(
            (BUCKETS_FIELD, region)), -1)
        # Decrease buckets counter in metrics
        self._increment(tr, self.metrics_space.pack(
            (BUCKETS_FIELD, region)), -1)

    @catch_service_errors
    def get_bucket_info(self, bname, **kwargs):
        """
        Get all available information about a bucket.
        """
        return self._bucket_info(self.db, bname, **kwargs)

    @fdb.transactional
    def _bucket_info(self, tr, bname, **kwargs):
        """
        [transactional] Get all available information about a bucket.
        """
        tr = tr.snapshot
        account_id = self._get_bucket_account(tr, bname, **kwargs)

        bucket_space = self.bucket_space[account_id][bname]
        bucket_range = bucket_space.range()
        iterator = tr.get_range(
            bucket_range.start, bucket_range.stop,
            streaming_mode=fdb.StreamingMode.want_all)
        info = self._unmarshal_info(iterator, unpack=bucket_space.unpack)
        if not info:
            return None
        repli_enabled = info.get(BUCKET_PROP_REPLI_ENABLED)
        info[BUCKET_PROP_REPLI_ENABLED] = boolean_value(repli_enabled)
        return info

    @catch_service_errors
    def list_buckets(self, account_id, limit=1000, marker=None,
                     end_marker=None, prefix=None, **kwargs):
        """
        Get the list of buckets of the specified account.

        :returns: the list of buckets (with metadata), and the next
            marker (in case the list is truncated).
        """
        if prefix is None:
            prefix = ''

        bs_space = self.buckets_index_space[account_id]

        raw_list, next_marker = self._raw_listing_m1(
            self.db, account_id, bs_space, limit, prefix,
            marker, end_marker)

        output = list()
        for bucket in raw_list:
            bdict = {
                'name': bucket[0],
                OBJECTS_FIELD: bucket[1],
                BYTES_FIELD: bucket[2],
                MTIME_FIELD: bucket[3]
            }
            output.append(bdict)
        return output, next_marker

    @fdb.transactional
    def _raw_listing_m1(self, tr, account_id, key_space, limit,
                        prefix, marker, end_marker):

        start = key_space.range().start
        stop = key_space.range().stop

        min_k = None
        max_k = stop

        orig_marker = next_marker = marker
        results = list()
        beyond_prefix = False
        if prefix is None:
            prefix = ''

        if marker:
            marker = fdb.KeySelector.first_greater_or_equal(
                key_space.pack((marker,)))

        while len(results) < limit and not beyond_prefix:
            min_k = start
            max_k = stop
            local_limit = (limit - len(results) + 1)

            if prefix:
                max_k = stop
                min_k = fdb.KeySelector.first_greater_or_equal(
                    key_space.pack((prefix,)))

            if marker and (not prefix or
                           tr.get_key(marker) >= tr.get_key(min_k)):
                min_k = marker

            if end_marker and (not prefix
                               or end_marker <= prefix + b'\xff'):
                max_k = fdb.KeySelector.last_less_or_equal(
                    key_space.pack((end_marker,)))

            iterator = tr.snapshot.get_range(min_k, max_k, limit=local_limit,
                                             reverse=False)

            empty = True
            for key, _ in iterator:
                ctr = key_space.unpack(key)[0]
                if len(results) >= limit:
                    break
                if prefix and not ctr.startswith(prefix):
                    beyond_prefix = True
                    # No more items
                    marker = None
                    break
                if end_marker:
                    marker = fdb.KeySelector.first_greater_or_equal(
                        key_space.pack((end_marker,)))
                else:
                    marker = fdb.KeySelector.first_greater_than(
                        key_space.pack((ctr,)))

                # don't include marker
                if orig_marker == ctr:
                    continue

                nb_objects = 0
                nb_bytes = 0
                mtime = 0
                next_marker = ctr
                bucket_space = self.bucket_space[account_id][ctr]
                bucket_range = bucket_space.range()
                bucket_it = tr.get_range(bucket_range.start,
                                         bucket_range.stop, reverse=False)
                for bucket_key, a_value in bucket_it:
                    key = bucket_space.unpack(bucket_key)
                    if len(key) > 1:
                        # This is a per policy metric, skip it
                        continue
                    a_key = key[0]
                    if a_key == OBJECTS_FIELD:
                        nb_objects = self._counter_value_to_counter(a_value)
                    if a_key == BYTES_FIELD:
                        nb_bytes = self._counter_value_to_counter(a_value)
                    if a_key == MTIME_FIELD:
                        mtime = self._timestamp_value_to_timestamp(a_value)
                results.append([ctr, nb_objects, nb_bytes, mtime])

                empty = False
            if empty:
                break
        return results, next_marker

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
                b_space_range.start, b_space_range.stop,
                streaming_mode=fdb.StreamingMode.want_all)
            bucket_keys_values = None, None, None
            for key, value in entries:
                account, bucket, *key = self.bucket_space.unpack(key)
                if (account, bucket) != bucket_keys_values[:2]:
                    if bucket_keys_values[2]:
                        bucket_info = self._unmarshal_info(
                            bucket_keys_values[2])
                        bucket_info['account'] = bucket_keys_values[0]
                        bucket_info['name'] = bucket_keys_values[1]
                        yield bucket_info
                    bucket_keys_values = account, bucket, []
                bucket_keys_values[2].append((key, value))
            if bucket_keys_values[2]:
                bucket_info = self._unmarshal_info(bucket_keys_values[2])
                bucket_info['account'] = bucket_keys_values[0]
                bucket_info['name'] = bucket_keys_values[1]
                yield bucket_info
        finally:
            transaction.commit()

    @fdb.transactional
    def _update_bucket_stats(self, tr, account_id, cname, bname, region,
                             stats_delta, mtime, container_is_deleted,
                             container_has_new_bucket):
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
            account_id = account_id[8:]
            root_container = cname.rsplit('-', 3)[0]

        bucket_space = self.bucket_space[account_id][bname]

        current_region = tr[bucket_space.pack(('region',))]
        if not current_region.present():  # Bucket doesn't exist
            if container_is_deleted:
                # Bucket is already deleted
                return
            self.logger.warning(
                'Bucket %s/%s must be created explicitly, '
                'it is no longer automatically created asynchronously',
                account_id, bname)
            if not container_has_new_bucket:
                # If the bucket is recreated, all of the container statistics
                # will be added to the bucket, not just the delta
                tr.clear(container_space.pack(('bucket',)))
            return
        else:  # Bucket exists
            # Check that the region has not changed
            current_region = current_region.decode('utf-8')
            if current_region != region:
                raise Conflict(
                    'The container must be in the same region as the bucket '
                    'to belong to it')

            # Update containers counter
            if container_is_deleted:
                if not container_has_new_bucket:
                    # If the container already belonged to the bucket,
                    # decrease the containers counter
                    self._increment(
                        tr, bucket_space.pack((CONTAINERS_FIELD,)), -1)
            elif container_has_new_bucket:
                # Next time, only the delta will be added
                tr[container_space.pack(('bucket',))] = bname.encode('utf-8')
                self._increment(tr, bucket_space.pack((CONTAINERS_FIELD,)))

        # Update bucket stats
        is_segment = root_container.endswith(MULTIUPLOAD_SUFFIX)
        for key in (BYTES_FIELD, OBJECTS_FIELD):
            if is_segment and key == OBJECTS_FIELD:
                continue
            # Update global stats
            value = stats_delta[key]
            self._increment(tr, bucket_space.pack((key,)), value)
            for policy, value in stats_delta[f"{key}-details"].items():
                # Update stats by policy
                self._increment(tr, bucket_space.pack((key, policy)), value)

        # Update bucket mtime
        self._update_timestamp(tr, bucket_space.pack((MTIME_FIELD,)), mtime)

    @catch_service_errors
    def update_bucket_metadata(self, bname, metadata, to_delete=None,
                               **kwargs):
        """
        Update (or delete) bucket metadata.

        :param metadata: dict of entries to set (or update)
        :param to_delete: iterable of keys to delete
        """
        account_id = self._get_bucket_account(self.db, bname, **kwargs)

        self._manage_metadata(self.db, self.bucket_space[account_id], bname,
                              metadata, to_delete)

        info = self._multi_get(self.db, self.bucket_space[account_id], bname)
        if not info:
            return None

        self.cast_fields(info)
        return info

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
                        marker = self._refresh_bucket(tr, account_id,
                                                      bucket_name, sharded,
                                                      marker, batch_size)

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
    def _refresh_bucket(self, tr, bucket_account_id, bucket_name,
                        sharded, marker, batch_size):
        new_marker = None
        counters = {
            CONTAINERS_FIELD: 0,
            BYTES_FIELD: Counter(),
            OBJECTS_FIELD: Counter()
        }

        container_account_id = bucket_account_id

        if sharded:
            container_account_id = SHARDING_ACCOUNT_PREFIX + bucket_account_id

        # Ensure container account exists
        account_exists = \
            self._is_element(tr, self.accts_space, container_account_id)
        if not account_exists:
            return None

        # Compute request range
        account_containers = self.container_space[container_account_id]
        containers_begin = account_containers.range().start
        containers_end = account_containers.range().stop
        if marker:
            containers_begin = fdb.KeySelector.first_greater_or_equal(
                account_containers.pack((marker,)))
        count = 0
        new_marker = None
        containers = tr.get_range(containers_begin, containers_end)
        data = {}

        # Propagate container counters to bucket if container belongs to bucket
        def _process_data_to_counters():
            if 'bucket' in data and data['bucket'] == bucket_name:
                counters[CONTAINERS_FIELD] += 1
                for field in (BYTES_FIELD, OBJECTS_FIELD):
                    counters[field] += data.get(field, {})

        # Iterate over containers
        for key, value in containers:
            container, field, *_policy = account_containers.unpack(key)
            root_container = container
            if sharded:
                root_container = container.rsplit('-', 3)[0]

            # Check if we start to process a new container
            if new_marker != container:
                new_marker = container
                count += 1
                if count > batch_size:
                    break
                # Process data if container belongs to bucket
                _process_data_to_counters()
                # Reset data for next container
                data = {}

            if field == 'bucket':
                data['bucket'] = value.decode('utf-8')
                continue
            # Skip not counter values
            if field not in (BYTES_FIELD, OBJECTS_FIELD):
                continue
            # Ignore '+segments' objects counter
            if field == OBJECTS_FIELD \
                    and root_container.endswith(MULTIUPLOAD_SUFFIX):
                continue

            policy = '_' if len(_policy) == 0 else _policy[0]
            values = data.setdefault(field, {})
            values[policy] = self._counter_value_to_counter(value)

        # Process last data
        _process_data_to_counters()

        # Update counters
        bucket = self.bucket_space[bucket_account_id][bucket_name]
        self._increment(tr, bucket.pack((CONTAINERS_FIELD,)),
                        counters[CONTAINERS_FIELD])
        for field in (BYTES_FIELD, OBJECTS_FIELD):
            for policy, counter in counters.get(field, {}).items():
                key = bucket[field]
                if policy != '_':
                    # Not a global counter, add policy
                    key = key[policy]
                self._increment(tr, key, counter)

        return new_marker if count > batch_size else None

    @catch_service_errors
    def reserve_bucket(self, bucket, account_id, **kwargs):
        self._reserve_bucket(self.db, bucket, account_id)

    @fdb.transactional
    def _reserve_bucket(self, tr, bucket, account):
        reserved_bucket_space = self.bucket_db_space[bucket]

        rtime = tr[reserved_bucket_space.pack(('rtime',))]
        now = self._get_timestamp()
        if rtime.present():
            # Check if the reservation is ongoing
            rtime = self._timestamp_value_to_timestamp(rtime.value)
            if rtime + self.bucket_reservation_timeout > now:
                raise Forbidden('Already reserved')
        else:
            current_account = tr[reserved_bucket_space.pack(('account',))]
            if current_account.present():
                raise Forbidden('Already associated with an owner')

        self._set_timestamp(tr, reserved_bucket_space.pack(('rtime',)), now)
        tr[reserved_bucket_space.pack(('account',))] = account.encode('utf-8')

    @catch_service_errors
    def release_bucket(self, bucket, account_id, **kwargs):
        self._release_bucket(self.db, bucket, account_id)

    @fdb.transactional
    def _release_bucket(self, tr, bucket, account, check_reservation=True):
        reserved_bucket_space = self.bucket_db_space[bucket]

        current_account = tr[reserved_bucket_space.pack(('account',))]
        if not current_account.present():
            return  # Already release
        current_account = current_account.decode('utf-8')
        if account != current_account:
            raise Forbidden('Bucket reserved by another owner')

        rtime = tr[reserved_bucket_space.pack(('rtime',))]
        if check_reservation and not rtime.present():
            raise Forbidden(
                'The owner has already arrived, '
                'the reservation can no longer be cancelled')

        reserved_bucket_range = reserved_bucket_space.range()
        tr.clear_range(reserved_bucket_range.start, reserved_bucket_range.stop)

    @fdb.transactional
    def _set_bucket_owner(self, tr, bucket, account):
        reserved_bucket_space = self.bucket_db_space[bucket]

        current_account = tr[reserved_bucket_space.pack(('account',))]
        if current_account.present():
            current_account = current_account.decode('utf-8')
        else:
            # Last minute reservations are accepted
            # if the bucket is not already reserved
            self._reserve_bucket(tr, bucket, account)
            current_account = account
        rtime = tr[reserved_bucket_space.pack(('rtime',))]
        if not rtime.present():
            if account == current_account:
                return
            raise Forbidden('Already associated with an owner')
        rtime = self._timestamp_value_to_timestamp(rtime.value)
        if account != current_account:
            raise Forbidden('Bucket reserved by another owner')

        delay = time.time() - (rtime + self.bucket_reservation_timeout)
        if delay > 0:
            self.logger.info(
                'Reservation has expired (delay: %f secondes), '
                'but since no one else has reserved the bucket %s, '
                'the request is accepted', delay, bucket)
        tr.clear(reserved_bucket_space.pack(('rtime',)))

    @catch_service_errors
    def get_bucket_owner(self, bucket, **kwargs):
        return self._get_bucket_owner(self.db, bucket)

    @fdb.transactional
    def _get_bucket_owner(self, tr, bucket):
        reserved_bucket_space = self.bucket_db_space[bucket]

        rtime = tr[reserved_bucket_space.pack(('rtime',))]
        if rtime.present():
            raise NotFound(
                'Bucket is reserved, but the owner has not arrived yet')
        current_account = tr[reserved_bucket_space.pack(('account',))]
        if not current_account.present():
            raise NotFound('No owner')

        return current_account.decode('utf-8')

    @fdb.transactional
    def _get_bucket_account(self, tr, bucket, account=None, check_owner=False,
                            **kwargs):
        if not check_owner and account:
            return account
        try:
            owner = self._get_bucket_owner(tr, bucket)
        except NotFound as exc:
            if check_owner:
                raise Forbidden(f'No owner found: {exc}') from exc
            raise BadRequest(
                f'Missing account param or an owner: {exc}') from exc
        if account and account != owner:
            raise Forbidden('Bucket reserved by another owner')
        return owner

    @fdb.transactional
    def _is_element(self, tr, space, key):
        return tr[space.pack((key,))].present()

    @fdb.transactional
    def _val_element(self, tr, space, id_x, key):
        val = tr[space.pack((id_x, key))]
        if val.present():
            return val
        return None

    @fdb.transactional
    def _multi_get(self, tr, multi_space, index):
        pairs = tr[multi_space.range((index,))]
        info = {}
        for key, val in pairs:
            unpacked_key = (multi_space.unpack(key)[-1])
            info[bytes(unpacked_key, 'utf-8')] = val
        return info

    @fdb.transactional
    def _get_metada(self, tr, req_account_id):
        account_id = self._val_element(tr, self.acct_space,
                                       req_account_id, 'id')
        if account_id is None:
            return None
        meta = self._multi_get(tr, self.metadata_space,
                               account_id.decode('utf-8'))
        return meta

    @fdb.transactional
    def _manage_metadata(self, tr, space, id_x, metadata, to_delete):
        if to_delete:
            for element in to_delete:
                tr.clear(space.pack((id_x, element)))

        if metadata:
            for key, value in metadata.items():
                tr[space.pack((id_x, key))] = \
                    bytes(str(value), 'utf-8')
