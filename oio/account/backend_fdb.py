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

import re
import struct
from functools import wraps
import fdb

from six import text_type

from werkzeug.exceptions import NotFound, Conflict, BadRequest
from oio.common.exceptions import OioException
from oio.common.constants import BUCKET_PROP_REPLI_ENABLED
from oio.common.timestamp import Timestamp
from oio.common.easy_value import int_value, boolean_value, float_value, \
    debinarize
from oio.common.exceptions import ServiceBusy
from oio.account.common_fdb import CommonFdb

fdb.api_version(CommonFdb.FDB_VERSION)


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


class Metric(object):
    """
    Constants for prometheus metrics.
    """
    METRIC_ACCOUNTS = "obsto_accounts"
    METRIC_CONTAINERS = "obsto_containers"
    METRIC_BUCKETS = "obsto_buckets"
    METRIC_OBJECTS = "obsto_objects"
    METRIC_BYTES = "obsto_bytes"

    REGION_LABEL = "region"
    STORAGE_LABEL = "storage_class"


class AccountBackendFdb():
    """
    Foundationdb backend for account service.
    """

    # This regex comes from https://stackoverflow.com/a/50484916
    #
    # The first group looks ahead to ensure that the match
    # is between 3 and 63 characters long.
    #
    # The next group (?!^(\d+\.)+\d+$) looks ahead to forbid matching
    # bucket names that look like IP addresses.
    #
    # <The last group matches zero or more labels followed by a dot *
    buckets_pattern = re.compile(
        r"""(?=^.{3,63}$)   # first group
        (?!^(\d+\.)+\d+$) # second
        (^(([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\.)* #third
        ([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])$)""", re.X)

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
                                self.db,
                                self.account_prefix)
            self.accts_space = self.namespace.create_or_open(
                                self.db,
                                self.accounts_prefix)
            self.container_space = self.namespace.create_or_open(
                                    self.db,
                                    self.container_list_prefix)
            self.containers_index_space = self.namespace.create_or_open(
                                            self.db,
                                            self.containers_list_prefix)
            self.ct_to_delete_space = self.namespace.create_or_open(
                                        self.db,
                                        self.ct_to_delete_prefix)
            self.bucket_db_space = self.namespace.create_or_open(
                                    self.db,
                                    self.reserve_bucket_prefix)
            self.bucket_space = self.namespace.create_or_open(
                                    self.db,
                                    self.bucket_prefix)
            self.buckets_index_space = self.namespace.create_or_open(
                                    self.db,
                                    self.buckets_list_prefix)
            self.metadata_space = self.namespace.create_or_open(
                                    self.db,
                                    self.metadata_prefix)
            self.metrics_space = self.namespace.create_or_open(
                                    self.db,
                                    self.metrics_prefix)
        except Exception as exc:
            self.logger.warning("Directory create exception %s", exc)
            raise

    def __init__(self, conf, logger):
        self.db = None
        self.conf = conf
        self.logger = logger
        self.fdb_file = None
        self.autocreate = boolean_value(conf.get('autocreate'), True)
        self.default_location = self.conf.get('default_location', '')
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

    @catch_service_errors
    def create_account(self, account_id, **kwargs):
        """
        Create account account_id
        """
        if not account_id:
            return None
        # get ctime is only used for migration
        now = kwargs.get('ctime') or Timestamp().normal

        status = self._create_account(self.db, self.accts_space,
                                      self.acct_space, account_id, now)
        if not status:
            return None

        return account_id

    @catch_service_errors
    def delete_account(self, req_account_id, **kwargs):
        if not req_account_id:
            return None

        status = self._delete_account(self.db, req_account_id)
        if status is None:
            self.logger.info('account to delete %s not found', req_account_id)
        elif not status:
            self.logger.info('account to delete %s not empty', req_account_id)
        else:
            self.logger.info('account deleted %s', req_account_id)
        return status

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

    def cast_fields(self, info):
        """
        Cast dict entries to the type they are supposed to be.
        """
        for what in (b'bytes', b'objects'):
            try:
                info[what] = int_value(struct.unpack('<q', info.get(what))[0],
                                       0)
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
    def get_bucket_info(self, bname, **kwargs):
        """
        Get all available information about a bucket.
        """
        if not bname:
            return None
        info = self._bucket_info(self.db, bname)
        if not info:
            return None
        self.cast_fields(info)
        self.logger.debug('get_bucket_info %s ', info)
        return info

    @fdb.transactional
    def _bucket_info(self, tr, bname):
        info = {}
        b_space = self.bucket_space[bname]
        b_range = b_space.range()
        iterator = tr.get_range(b_range.start, b_range.stop)
        for key, value in iterator:
            field, *policy = b_space.unpack(key)
            if policy:
                info['.'.join([field, policy[0]])] = \
                    struct.unpack('<q', value)[0]
            elif field in ('bytes', 'objects'):
                info[field] = struct.unpack('<q', value)[0]
            elif field in (BUCKET_PROP_REPLI_ENABLED):
                info[bytes(field, 'utf-8')] = value
            else:
                info[field] = value
        return info

    @catch_service_errors
    def get_container_info(self, account_id, cname, **kwargs):
        """
        Get all available information about a container, including some
        information coming from the bucket it belongs to.
        """
        if not cname:
            return None
        ct_space = self.container_space[account_id]
        info = self._multi_get(self.db, ct_space, cname)

        replication_enabled = b'False'
        bname = self._val_element(self.db, ct_space, cname, 'bucket')

        if bname is not None:
            bname = bname.decode("utf-8")
            self.logger.info('bname: %s', bname)
            rep_enabled = self._val_element(self.db, self.bucket_space, bname,
                                            BUCKET_PROP_REPLI_ENABLED)

            if rep_enabled is not None:
                replication_enabled = rep_enabled

        info[bytes(BUCKET_PROP_REPLI_ENABLED, 'utf-8')] = replication_enabled
        self.cast_fields(info)
        return info

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

    @catch_service_errors
    def update_bucket_metadata(self, bname, metadata, to_delete=None,
                               **kwargs):
        """
        Update (or delete) bucket metadata.

        :param metadata: dict of entries to set (or update)
        :param to_delete: iterable of keys to delete
        """
        self._manage_metadata(self.db, self.bucket_space, bname, metadata,
                              to_delete)

        info = self._multi_get(self.db, self.bucket_space, bname)

        if not info:
            return None

        self.logger.debug('get_bucket_info %s ', info)
        self.cast_fields(info)
        return info

    @catch_service_errors
    def info_account(self, req_account_id, **kwargs):
        """
        get account infos: containers, metadata and buckets
        """
        if not req_account_id:
            self.logger.info('No account id')
            return None

        if not self._is_element(self.db, self.accts_space, req_account_id):
            self.logger.info('Account %s doesn\'t exist', req_account_id)
            return None
        info = self._multi_get(self.db, self.acct_space, req_account_id)

        # reformat to integers
        info[b'bytes'] = struct.unpack('<q', info[b'bytes'])[0]
        info[b'objects'] = struct.unpack('<q', info[b'objects'])[0]

        if not info:
            self.logger.warning('Account  %s infos not found', req_account_id)
            return None

        containers = self._multi_get(self.db, self.containers_index_space,
                                     req_account_id)
        metadata = self._multi_get(self.db, self.metadata_space,
                                   req_account_id)
        buckets = self._multi_get(self.db, self.buckets_index_space,
                                  req_account_id)
        self.cast_fields(info)
        info[b'buckets'] = len(buckets)
        info[b'containers'] = len(containers)
        info[b'metadata'] = metadata
        return debinarize(info)

    @catch_service_errors
    def list_accounts(self, **kwargs):
        """
        Get the list of all accounts.
        """
        accounts = self._list_accounts(self.db)
        return debinarize(accounts)

    @catch_service_errors
    def update_container(self, account_id, cname, mtime, dtime,
                         object_count, bytes_used,
                         bucket_name=None, autocreate_account=None,
                         autocreate_container=True, **kwargs):
        if not account_id or not cname:
            raise BadRequest("Missing account or container")

        if autocreate_account is None:
            autocreate_account = self.autocreate

        if mtime is None:
            mtime = '0'
        else:
            mtime = Timestamp(mtime).normal
        if dtime is None:
            dtime = '0'
        else:
            dtime = Timestamp(dtime).normal
        if object_count is None:
            object_count = 0
        if bytes_used is None:
            bytes_used = 0

        # ctime = kwargs.get('ctime') or None
        # If no bucket name is provided, set it to ''
        bucket_name = bucket_name or ''
        now = Timestamp().normal
        # bucket location
        bucket_location = kwargs.get('bucket_location', self.default_location)
        # dict object details per storage class
        objects_details = kwargs.get('objects-details') or {}
        bytes_details = kwargs.get('bytes-details') or {}

        # read mtime & dtime
        ct_space = self.container_space[account_id]
        cts_space = self.containers_index_space[account_id]

        new_mtime = bytes(mtime, 'utf-8')
        new_dtime = bytes(dtime, 'utf-8')
        status = self._update_container(self.db, cts_space, ct_space,
                                        account_id, cname, bucket_name,
                                        new_mtime, new_dtime, now,
                                        autocreate_account,
                                        autocreate_container, object_count,
                                        bytes_used, bucket_location,
                                        objects_details, bytes_details)

        return status

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
            self.db, bs_space, limit, prefix,
            marker, end_marker)

        output = list()
        for bucket in raw_list:
            bdict = {
                'name': bucket[0],
                'objects': int_value(bucket[1], 0),
                'bytes': int_value(bucket[2], 0),
                'mtime': float_value(bucket[3], 0.0),
            }
            output.append(bdict)
        return output, next_marker

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

    @catch_service_errors
    def status(self, **kwargs):
        status = {'account_count': 0}
        if self.db is not None:
            s_range = self.accts_space.range()
            iterator = self.db.get_range(s_range.start, s_range.stop,
                                         reverse=False)
            count = 0
            for _, _ in iterator:
                count += 1
            status['account_count'] = count
            self.logger.debug('status: %s', status)
        else:
            self.logger.error('Failed to check connect to fdb server')
            raise OioException('Connection failed to db')
        return status

    @catch_service_errors
    def refresh_bucket(self, bucket_name, **kwargs):
        """
        Refresh the counters of a bucket. Recompute them from the counters
        of all shards (containers).
        """
        batch_size = kwargs.get("batch_size", self.BATCH_SIZE)
        marker = None
        # refresh sharded containers
        bucket_space = self.bucket_space[bucket_name]
        account_id = self.db[bucket_space.pack(('account',))]
        if account_id is None:
            return
        account_id = account_id.decode('utf-8')
        containers = self._list_containers(self.db, account_id, bucket_name)

        sharded_marker = None
        if containers is not None:
            for el in containers:
                while True:
                    next_marker = self._refresh_sharded_ct(
                        self.db, account_id, el, sharded_marker, batch_size)
                    if next_marker is None or next_marker == sharded_marker:
                        break

                    sharded_marker = next_marker

        marker = None
        # refresh based on non sharded or root containers
        while True:
            marker = self._refresh_bucket(self.db, bucket_space, bucket_name,
                                          batch_size, marker)
            if marker in (None, 'no_bucket'):
                break

        if text_type(marker).endswith("no_account"):
            raise NotFound("Account not found for bucket" % bucket_name)
        if text_type(marker).endswith("no_bucket"):
            raise NotFound("Bucket %s not found" % bucket_name)

    @catch_service_errors
    def refresh_account(self, account_id, **kwargs):
        if not account_id:
            raise BadRequest("Missing account")
        batch_size = kwargs.get("batch_size", self.BATCH_SIZE)
        containers = self._list_containers(self.db, account_id, None)

        sharded_marker = None
        if containers is not None:
            for elem in containers:
                while True:
                    next_marker = self._refresh_sharded_ct(
                        self.db, account_id, elem, sharded_marker, batch_size)
                    if next_marker is None or next_marker == sharded_marker:
                        break
                    sharded_marker = next_marker
        # Loop over all top level containers in account
        self._refresh_account(self.db, account_id)

    @catch_service_errors
    def flush_account(self, account_id, **kwargs):
        if not account_id:
            raise BadRequest("Missing account")

        if not self._is_element(self.db, self.accts_space, account_id):
            raise NotFound(account_id)

        self._flush_account(self.db, account_id)

    @catch_service_errors
    def reserve_bucket(self, account_id, bucket_name, **kwargs):
        if account_id is None:
            return False
        reserved_space = self.bucket_db_space[bucket_name]
        reserved = self._reserve_bucket(self.db, reserved_space, account_id)
        return {'reserved': reserved}

    @fdb.transactional
    def _reserve_bucket(self, tr, space_, account_id):
        if tr[space_.pack(('account',))].present():
            return 0
        now = Timestamp().normal
        tr[space_.pack(('account',))] = bytes(str(now), 'utf-8')
        return 1

    @catch_service_errors
    def release_bucket(self, bucket_name, **kwargs):
        reserved_space = self.bucket_db_space[bucket_name]
        self._release_bucket(self.db, reserved_space)
        return True

    @fdb.transactional
    def _release_bucket(self, tr, space):
        tr.clear_range_startswith(space)

    @catch_service_errors
    def set_bucket_owner(self, account_id, bucket_name, **kwargs):
        reserved_space = self.bucket_db_space[bucket_name]
        self.db[reserved_space.pack(('account',))] = bytes(account_id, 'utf-8')

    @catch_service_errors
    def get_bucket_owner(self, bucket_name, **kwargs):
        account = self._val_element(self.db, self.bucket_db_space,
                                    bucket_name, 'account')
        if account is None:
            return {'account': None}
        else:
            account_ = account.decode('utf-8')
            return {'account': account_}

    @catch_service_errors
    def info_metrics(self, output_type, **kwargs):
        metrics = dict()
        # generic metrics:
        # number of accounts
        # number of buckets per region
        # number of containers per region
        # number of objects per region /storage policy
        metrics = self._read_all_metrics(self.db)
        if output_type == 'json':
            return debinarize(metrics)
        else:
            return self._format_metrics(metrics)

    def _format_metrics(self, metrics):
        prom_output = ""
        for key, value in metrics.items():
            if key == Metric.METRIC_ACCOUNTS:
                prom_output = prom_output + key + " " + str(value) + "\n"
            if key in (Metric.METRIC_BUCKETS, Metric.METRIC_CONTAINERS):
                if value and isinstance(value, dict):
                    for reg, val in value.items():
                        prom_output = prom_output + key + "{" + \
                            Metric.REGION_LABEL
                        prom_output = prom_output + "=\"" + reg + "\"}" + " "
                        prom_output = prom_output + str(val) + "\n"
            if key in (Metric.METRIC_OBJECTS, Metric.METRIC_BYTES):
                if value and isinstance(value, dict):
                    for reg, val in value.items():
                        if val and isinstance(val, dict):
                            for storage_classe, v in val.items():
                                prom_output = prom_output + key + \
                                    "{" + Metric.REGION_LABEL + "=\"" + \
                                    reg + "\""
                                prom_output = prom_output + "," + \
                                    Metric.STORAGE_LABEL + "=\"" + \
                                    storage_classe + "\"}"
                                prom_output = prom_output + " " + str(v) + "\n"
        return prom_output

    @fdb.transactional
    def _read_all_metrics(self, tr):
        metrics = dict()
        metrics[Metric.METRIC_ACCOUNTS] = self._read_account_metrics(tr)
        metrics[Metric.METRIC_BUCKETS] = self._read_buckets_metrics(tr)
        metrics[Metric.METRIC_CONTAINERS] = self._read_containers_metrics(tr)
        metrics[Metric.METRIC_OBJECTS] = self._read_field_metrics(
                                                tr,
                                                'objects')
        metrics[Metric.METRIC_BYTES] = self._read_field_metrics(tr, 'bytes')
        return metrics

    @fdb.transactional
    def _read_account_metrics(self, tr):
        accts_field = tr[self.metrics_space.pack(('accounts',))]
        nb_accts = 0
        if accts_field.present():
            nb_accts = struct.unpack('<q', accts_field.value)[0]
        return nb_accts

    @fdb.transactional
    def _read_buckets_metrics(self, tr):
        metrics_buckets = dict()
        bucket_metrics_space = self.metrics_space['buckets']
        b_metrics_range = bucket_metrics_space.range()
        iterator = tr.get_range(b_metrics_range.start, b_metrics_range.stop,
                                reverse=False)
        for key, value in iterator:
            region = bucket_metrics_space.unpack(key)[0]
            metrics_buckets[region] = struct.unpack('<q', value)[0]
        return metrics_buckets

    @fdb.transactional
    def _read_containers_metrics(self, tr):
        metrics_containers = dict()
        ct_metrics_space = self.metrics_space['containers']
        ct_metrics_range = ct_metrics_space.range()

        iterator = tr.get_range(ct_metrics_range.start, ct_metrics_range.stop,
                                reverse=False)
        for key, value in iterator:
            region = ct_metrics_space.unpack(key)[0]
            metrics_containers[region] = struct.unpack('<q', value)[0]

        return metrics_containers

    @fdb.transactional
    def _read_field_metrics(self, tr, field):
        metrics_field = dict()
        ct_metrics_space = self.metrics_space[field]
        ct_metrics_range = ct_metrics_space.range()

        iterator = tr.get_range(ct_metrics_range.start, ct_metrics_range.stop,
                                reverse=False)
        for key, value in iterator:
            region, storage_class = ct_metrics_space.unpack(key)
            if region not in metrics_field:
                metrics_field[region] = {}
            metrics_field[region][storage_class] = \
                struct.unpack('<q', value)[0]
        return metrics_field

    @fdb.transactional
    def _increment(self, tr, counter, incr_by=1):
        tr.add(counter, struct.pack('<q', incr_by))

    @fdb.transactional
    def _decrement(self, tr, counter, decr_by=-1):
        tr.add(counter, struct.pack('<q', decr_by))
        tr.compare_and_clear(counter, struct.pack('<q', 0))

    @fdb.transactional
    def _flush_account(self, tr, account_id):
        tr[self.acct_space.pack((account_id, 'objects'))] = \
           struct.pack('<q', 0)
        tr[self.acct_space.pack((account_id, 'bytes'))] = struct.pack('<q', 0)
        tr.clear_range_startswith(self.containers_index_space[account_id])
        tr.clear_range_startswith(self.container_space[account_id])

    @fdb.transactional
    def _create_account(self, tr, accts_space, acct_space, account_id, now):

        if self._is_element(tr, accts_space, account_id):
            return False
        tr[accts_space.pack((account_id,))] = b'1'
        tr[acct_space.pack((account_id, 'id'))] = \
            bytes(account_id, 'utf-8')
        tr[acct_space.pack((account_id, 'objects'))] = struct.pack('<q', 0)
        tr[acct_space.pack((account_id, 'bytes'))] = struct.pack('<q', 0)
        tr[acct_space.pack((account_id, 'ctime'))] = bytes(str(now), 'utf-8')

        # metrics
        self._increment(tr, self.metrics_space.pack(('accounts',)))
        return True

    @fdb.transactional
    def _delete_account(self, tr, req_account_id):

        account_id = self._val_element(self.db, self.acct_space,
                                       req_account_id, 'id')
        if account_id is None:
            return None
        account_id = account_id.decode('utf-8')

        ct_account_space = self.container_space[account_id]
        s_range = ct_account_space.range()
        iterator = self.db.get_range(s_range.start, s_range.stop,
                                     reverse=False)
        for _, _ in iterator:
            return False

        tr.clear_range_startswith(self.acct_space[account_id])
        tr.clear_range_startswith(self.accts_space[account_id])
        tr.clear_range_startswith(self.ct_to_delete_space[account_id])
        tr.clear_range_startswith(self.metadata_space[account_id])
        tr.clear_range_startswith(self.containers_index_space[account_id])
        self._decrement(tr, self.metrics_space.pack(('accounts',)))
        return True

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
    def _refresh_account(self, tr, account_id):
        if not self._is_element(self.db, self.accts_space, account_id):
            raise NotFound(account_id)

        ct_space = self.container_space[account_id]
        s_range = ct_space.range()

        iterator = tr.snapshot.get_range(s_range.start, s_range.stop,
                                         reverse=False)
        sum_bytes = 0
        sum_objects = 0
        for key, val in iterator:
            _, field = ct_space.unpack(key)
            if field == 'bytes':
                sum_bytes += struct.unpack('<q', val)[0]
            if field == 'objects':
                sum_objects += struct.unpack('<q', val)[0]

        tr[self.acct_space.pack((account_id, 'bytes'))] = \
            struct.pack('<q', sum_bytes)
        tr[self.acct_space.pack((account_id, 'objects'))] = \
            struct.pack('<q', sum_objects)

    @fdb.transactional
    def _update_container(self, tr, cts_space, ct_space, account_id, cname,
                          bucket_name, new_mtime, new_dtime, now,
                          autocreate_account, autocreate_container,
                          new_total_objects, new_total_bytes, bucket_location,
                          objects_details, bytes_details):
        creation = False
        to_delete_space = self.ct_to_delete_space[account_id]

        account_exists = self._is_element(self.db, self.accts_space,
                                          account_id)
        if not account_exists:
            if autocreate_account:
                self._create_account(tr, self.accts_space, self.acct_space,
                                     account_id, now)
            else:
                raise NotFound("Account %s not found" % account_id)
        if not autocreate_container:
            container_exists = tr[ct_space.pack((cname, 'name'))].present()
            if not container_exists:
                raise NotFound("Container %s not found" % cname)
        deleted_time = b'0'

        delete_cname_time = tr[to_delete_space.pack((cname,))]
        if delete_cname_time.present():
            deleted_time = delete_cname_time.value
        # real update
        if tr[ct_space.pack((cname, 'name'))].present():
            dtime = tr[ct_space.pack((cname, 'dtime'))].value
            mtime = tr[ct_space.pack((cname, 'mtime'))].value
            nb_objects_field = tr[ct_space.pack((cname, 'objects'))]
            nb_bytes_field = tr[ct_space.pack((cname, 'bytes'))]
            nb_objects = 0
            nb_bytes = 0
            if nb_objects_field.present():
                nb_objects = struct.unpack('<q', nb_objects_field.value)[0]
            if nb_bytes_field.present():
                nb_bytes = struct.unpack('<q', nb_bytes_field.value)[0]
        # event update interleaved with container delete
        elif float(new_mtime) < float(deleted_time):
            raise NotFound("Deleted container %s" % cname)
        else:  # real creation
            dtime = b'0'
            mtime = b'0'
            nb_objects = 0
            nb_bytes = 0
            creation = True

        if not autocreate_container and dtime >= mtime:
            raise NotFound("Container %s not found" % cname)

        region = self._get_region(tr, bucket_location, bucket_name, cname)

        old_mtime = mtime
        inc_objects = 0
        inc_bytes = 0
        deleted = False

        if float(new_mtime) <= float(mtime) and \
           float(new_dtime) <= float(dtime):
            raise Conflict("No update needed, "
                           "event older than last container update")

        if float(new_mtime) > float(mtime):
            mtime = new_mtime
        if float(new_dtime) > float(dtime):
            dtime = new_dtime

        if float(dtime) >= float(mtime):
            mtime = dtime
            # Protect against "minus zero".
            if nb_objects != 0:
                inc_objects -= nb_objects

            if nb_bytes != 0:
                inc_bytes -= nb_bytes

            # remove container cname from container:account
            # and from containers:account
            tr.clear_range_startswith(ct_space.pack((cname,)))
            tr.clear_range_startswith(cts_space.pack((cname,)))
            tr[to_delete_space.pack((cname,))] = dtime

            # metrics
            self._decrement(tr, self.metrics_space.pack(
                        ('containers', region)))
            # clean ct_to_delete_space
            self._clear_deleted_containers(tr, account_id, now)

            deleted = True

        elif float(mtime) > float(old_mtime):
            inc_objects = new_total_objects - int(nb_objects)
            inc_bytes = new_total_bytes - int(nb_bytes)
            tr[ct_space.pack((cname, 'objects'))] = \
                struct.pack('<q', new_total_objects)
            tr[ct_space.pack((cname, 'bytes'))] = \
                struct.pack('<q', new_total_bytes)
            tr[cts_space.pack((cname,))] = b'1'
            tr[ct_space.pack((cname, 'name'))] = bytes(str(cname), 'utf-8')
            tr[ct_space.pack((cname, 'mtime'))] = mtime
            tr[ct_space.pack((cname, 'dtime'))] = dtime

            # metrics
            if creation:
                self._increment(tr, self.metrics_space.pack(
                                ('containers', region)))

        else:
            raise Conflict("No update needed, "
                           "event older than last container update")

        # increase account stats
        if inc_objects != 0:
            self._increment(tr,
                            self.acct_space.pack((account_id, 'objects')),
                            inc_objects)

        if inc_bytes != 0:
            self._increment(tr,
                            self.acct_space.pack((account_id, 'bytes')),
                            inc_bytes)

        deltas = self._update_ct_stats_policy(tr, account_id, cname, region,
                                              objects_details,
                                              bytes_details)

        # incr / decr relative values
        for policy, dict_field in deltas.items():
            for field, value in dict_field.items():
                if value > 0:
                    self._increment(tr, self.metrics_space.pack(
                                    (field, region, policy)),
                                    value)
                else:
                    self._decrement(tr, self.metrics_space.pack(
                                    (field, region, policy)),
                                    value)

        # define bname here
        current_bucket_name = self._val_element(self.db, ct_space, cname,
                                                'bucket')

        if bucket_name == '' and current_bucket_name is not None:
            # Use the bucket name already registered when it is not given
            bucket_name = current_bucket_name.decode('utf-8')
        if bucket_name != '':
            # FIXME(FVE): this may no be needed anymore
            # This container is not yet associated with this bucket.
            # We must add all the totals in case the container
            # already existed but didn't know its parent bucket.
            if not deleted and current_bucket_name is None:
                inc_objects = new_total_objects
                inc_bytes = new_total_bytes

            container_name = cname
            if deleted:
                if tr[ct_space.pack((container_name, 'bucket'))].present():
                    tr.clear_range_startswith(
                        ct_space.pack((container_name, 'bucket')))

                #  Update the buckets list if it's the root container
                if bucket_name == container_name:
                    tr.clear_range_startswith(self.buckets_index_space.pack(
                        (account_id, bucket_name)))
                    tr.clear_range_startswith(
                        self.buckets_index_space.pack((region, bucket_name)))
                    # Also delete the bucket
                    tr.clear_range_startswith(
                        self.bucket_space.pack((bucket_name,)))

                    # decrements metrics
                    self._decrement(tr, self.metrics_space.pack(
                                ('buckets', region)))
                    return

                # We used to return here. But since we delete shard before
                # cleaning them, we need to fix counters first.

            # For container holding MPU segments, we do not want to count
            # each segment as an object. But we still want to consider
            # their size.
            is_segment = False
            if '+segments' in container_name:
                inc_objects = 0
                is_segment = True

            # Check if a refresh bucket is in progress
            # No lock is needed as add operation is atomic
            # local marker = redis.call("HGET", bucket_lock, "marker")

            # Increment the counters if needed.
            # if marker == false or container_name <= marker then
            if tr[self.bucket_space.pack((bucket_name, 'objects'))].present():
                tr.add(self.bucket_space.pack((bucket_name, 'objects')),
                       struct.pack('<q', inc_objects))
            else:
                tr[self.bucket_space.pack((bucket_name, 'objects'))] = \
                    struct.pack('<q', inc_objects)

            if tr[self.bucket_space.pack((bucket_name, 'bytes'))].present():
                tr.add(self.bucket_space.pack((bucket_name, 'bytes')),
                       struct.pack('<q', inc_bytes))
            else:
                tr[self.bucket_space.pack((bucket_name, 'bytes'))] = \
                    struct.pack('<q', inc_bytes)

            tr[self.bucket_space.pack((bucket_name, 'region'))] = \
                bytes(str(region), 'utf-8')

            # Update the modification time.
            if mtime != b'0':
                tr[self.bucket_space.pack((bucket_name, 'mtime'))] = mtime

            self._update_bucket_per_policy(tr, bucket_name, is_segment, deltas)

            if deleted:
                return 'deleted'
            # Set the bucket owner.
            # Filter the special accounts hosting bucket shards.
            if not account_id.startswith('.shards_'):
                tr[self.bucket_space.pack((bucket_name, 'account'))] = \
                    bytes(str(account_id), 'utf-8')

            # Update container info
            tr[ct_space.pack((cname, 'bucket'))] = \
                bytes(str(bucket_name), 'utf-8')

            # Update the buckets list if it's the root container
            if bucket_name == cname:
                tr[self.buckets_index_space.pack((account_id, bucket_name))] =\
                      b'1'
                tr[self.buckets_index_space.pack((region, bucket_name))] = \
                    b'1'
                # increments metrics
                if creation:
                    self._increment(tr, self.metrics_space.pack(
                                    ('buckets', region)))
        return 'updated'

    @fdb.transactional
    def _get_region(self, tr, bucket_location, bucket_name, ct_name):
        if bucket_location is not None:
            return bucket_location
        if bucket_name != '':
            region = self._val_element(tr, self.bucket_space, bucket_name,
                                       'region')
            if region is not None:
                return region.decode('utf-8')
        return self.default_location

    @fdb.transactional
    def _update_ct_stats_policy(self, tr, account_id, cname, region,
                                objs_per_policy, bytes_per_policy):
        """
        Read current values for given container and per region/policy
        Compute deltas, update values then return deltas
        """
        current_values = dict()
        deltas = dict()
        c_space = self.container_space[account_id][cname][region]
        for policy, value in objs_per_policy.items():
            if policy not in current_values.keys():
                current_values[policy] = {}
            if policy not in deltas:
                deltas[policy] = {}
            if self._is_element(tr, c_space, policy) is not None:
                nb_obj_ct = self._val_element(tr, c_space, policy,
                                              'objects')
                current_values[policy]['objects'] = 0 if nb_obj_ct is None \
                    else struct.unpack('<q', nb_obj_ct.value)[0]

            else:
                current_values[policy]['objects'] = 0
            delta = value - current_values[policy]['objects']
            if value > 0 and delta != 0:
                deltas[policy]['objects'] = delta
                tr[c_space.pack((policy, 'objects'))] = \
                    struct.pack('<q', value)

        for policy, value in bytes_per_policy.items():
            if policy not in current_values.keys():
                current_values[policy] = {}
            if policy not in deltas:
                deltas[policy] = {}
            if self._is_element(tr, c_space, policy) is not None:
                nb_bytes_ct = self._val_element(tr, c_space, policy,
                                                'bytes')
                current_values[policy]['bytes'] = 0 if nb_bytes_ct is None \
                    else struct.unpack('<q', nb_bytes_ct.value)[0]

            delta = value - current_values[policy]['bytes']
            # update values only when needed
            if value > 0 and delta != 0:
                deltas[policy]['bytes'] = delta
                tr[c_space.pack((policy, 'bytes'))] = \
                    struct.pack('<q', value)

        # empty policies that are not present in objs_per_policy
        reg_range = c_space.range()
        res = tr.get_range(reg_range.start, reg_range.stop)

        # gather data to deduce from metrics
        for key, val in res:
            pol, field = c_space.unpack(key)
            if pol not in objs_per_policy:
                if pol not in deltas:
                    deltas[pol] = {}
                deltas[pol][field] = - struct.unpack('<q', val)[0]
        # clear not present policies for given container
        policies_to_clear = list()
        for key, val in res:
            pol, field = c_space.unpack(key)
            if pol not in objs_per_policy and pol not in policies_to_clear:
                policies_to_clear.append(pol)
        for pol in policies_to_clear:
            tr.clear_range_startswith(c_space.pack((pol,)))

        return deltas

    @fdb.transactional
    def _update_bucket_per_policy(self, tr, bucket_name, is_segment, deltas):
        """
        Update objects/bytes per policy for given bucket
        """
        bucket_obj_space = self.bucket_space[bucket_name]
        # incr / decr relative values
        for policy, dict_field in deltas.items():
            for field, value in dict_field.items():
                if is_segment and field == 'objects':
                    continue
                if value > 0:
                    self._increment(tr, bucket_obj_space.pack(
                                    (field, policy)), value)
                else:
                    self._decrement(tr, bucket_obj_space.pack(
                                    (field, policy)), value)

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
                    a_key = ct_space.unpack(ct_key)[0]
                    if a_key == 'objects':
                        nb_objects = struct.unpack('<q', a_value)[0]
                    if a_key == 'bytes':
                        nb_bytes = struct.unpack('<q', a_value)[0]
                    if a_key == 'mtime':
                        mtime = float(a_value)
                results.append([ctr, nb_objects, nb_bytes, 0, mtime])

                empty = False
            if empty:
                break
        return results, orig_marker

    @fdb.transactional
    def _raw_listing_m1(self, tr, key_space, limit,
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

                if self.buckets_pattern.match(ctr):
                    nb_objects = 0
                    nb_bytes = 0
                    mtime = 0
                    next_marker = ctr
                    bucket_space = self.bucket_space[ctr]
                    bucket_range = bucket_space.range()
                    bucket_it = tr.get_range(bucket_range.start,
                                             bucket_range.stop, reverse=False)
                    for bucket_key, a_value in bucket_it:
                        a_key = bucket_space.unpack(bucket_key)[0]
                        if a_key == 'objects':
                            nb_objects = struct.unpack('<q', a_value)[0]
                        if a_key == 'bytes':
                            nb_bytes = struct.unpack('<q', a_value)[0]
                        if a_key == 'mtime':
                            mtime = float(a_value)
                    results.append([ctr, nb_objects, nb_bytes, mtime])

                empty = False
            if empty:
                break
        return results, next_marker

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
                tr.clear_range_startswith(
                    space.pack((id_x, element)))

        if metadata:
            for key, value in metadata.items():
                tr[space.pack((id_x, key))] = \
                    bytes(str(value), 'utf-8')

    @fdb.transactional
    def _refresh_bucket(self, tr, bucket_key, bucket_name, batch_size, marker):
        new_marker = None
        sum_bytes = 0
        sum_objects = 0
        count = 0
        if tr[bucket_key.pack(('account',))].present() is None:
            return 'no_bucket'

        account_id = tr[bucket_key.pack(('account',))].decode('utf-8')
        ckey_prefix = self.container_space[account_id]

        # get_range is fetching data in batchs, the default mode for
        # streaming_mode is iterator which is efficient.
        # fdb.StreamingMode.want_all could be used
        start = ckey_prefix.range().start
        if marker is not None:
            start = fdb.KeySelector.first_greater_or_equal(
                    ckey_prefix.pack((marker,)))

        stop = ckey_prefix.range().stop
        iterator = tr.snapshot.get_range(start, stop, reverse=False)

        if marker is None:
            tr[self.bucket_space.pack((bucket_name, 'objects'))] = \
                struct.pack('<q', 0)
            tr[self.bucket_space.pack((bucket_name, 'bytes'))] = \
                struct.pack('<q', 0)

        for key, val in iterator:
            container, unpacked_key = ckey_prefix.unpack(key)

            if marker == container:
                continue

            if unpacked_key not in ('bytes', 'objects'):
                continue

            # check if bucket exists
            check_bucket = tr[ckey_prefix.pack((container, 'bucket'))]
            if check_bucket.present() and \
               check_bucket.decode('utf-8') \
               == bucket_name:

                if unpacked_key == 'bytes':
                    sum_bytes += struct.unpack('<q', val)[0]
                if unpacked_key == 'objects' and \
                   container.find('+segments') == -1:
                    sum_objects += struct.unpack('<q', val)[0]
                    count += 1
            new_marker = container

            if count == 2 * batch_size:
                break

        tr.add(bucket_key.pack(('objects',)), struct.pack('<q', sum_objects))
        tr.add(bucket_key.pack(('bytes',)), struct.pack('<q', sum_bytes))
        return new_marker

    @fdb.transactional
    def _refresh_sharded_ct(self, tr, account_id, cname, marker, batch_size):
        # detect if container is sharded without requesting state
        account_exists = self._is_element(tr, self.accts_space, account_id)
        if not account_exists:
            return None
        sharded_account_id = '.shards_' + account_id
        sharded_account_exists = self._is_element(tr, self.accts_space,
                                                  sharded_account_id)
        if not sharded_account_exists:
            return None

        ct_space = self.container_space[account_id]
        ckey_prefix = self.container_space[sharded_account_id]

        orig_marker = marker
        new_marker = None
        count = 0
        stop = ckey_prefix.range().stop

        start_marker = cname if marker is None else marker
        start_ct = fdb.KeySelector.first_greater_than(
                ckey_prefix.pack((start_marker,)))

        iterator = tr.snapshot.get_range(start_ct, stop, reverse=False)
        sum_bytes = 0
        sum_objects = 0

        ended = True
        found = False

        for key, val in iterator:
            container, unpacked_key = ckey_prefix.unpack(key)
            if unpacked_key not in ('bytes', 'objects'):
                continue
            composed_cname = container.split('-')
            # remove last digits
            composed_cname.pop()

            timestamp = composed_cname.pop()
            if len(timestamp) != 16:
                self.logger.warning('malformed cname: %s %s', container,
                                    timestamp)
            hash_id = composed_cname.pop()
            if len(timestamp) != 64:
                self.logger.warning('malformed cname: %s hash_id %s',
                                    container, hash_id)
            truncated_cname = '-'.join(composed_cname)
            if cname != truncated_cname:
                continue

            new_marker = container
            if count >= 2 * batch_size:
                ended = False
                break

            found = True

            if unpacked_key == 'bytes':
                sum_bytes += struct.unpack('<q', val)[0]
            if unpacked_key == 'objects' and \
               container.find('+segments') == -1:
                sum_objects += struct.unpack('<q', val)[0]

            count += 1

        if found:
            if orig_marker is None:
                tr[ct_space.pack((cname, 'objects'))] = struct.pack('<q', 0)
                tr[ct_space.pack((cname, 'bytes'))] = struct.pack('<q', 0)

            tr.add(ct_space.pack((cname, 'objects')),
                   struct.pack('<q', sum_objects))
            tr.add(ct_space.pack((cname, 'bytes')),
                   struct.pack('<q', sum_bytes))
        else:
            new_marker = None
        if ended:
            new_marker = None

        return new_marker

    @fdb.transactional
    def _list_containers(self, tr, account_id, bucket_name):
        # detect if container is sharded without requesting state
        containers = list()

        sharded_account_id = '.shards_' + account_id
        sharded_account_exist = self._is_element(tr, self.accts_space,
                                                 sharded_account_id)
        if not sharded_account_exist:
            return containers

        ct_space = self.container_space[account_id]
        start = ct_space.range().start
        stop = ct_space.range().stop

        iterator = tr.snapshot.get_range(start, stop, reverse=False)
        for key, _ in iterator:
            container = ct_space.unpack(key)[0]
            if bucket_name is None:
                if container not in containers:
                    containers.append(container)
            else:
                read_bucket_name = tr[ct_space.pack((container, 'bucket'))]
                if read_bucket_name.present() and \
                   read_bucket_name.decode('utf-8') == bucket_name:
                    if container not in containers:
                        containers.append(container)
        return containers

    @fdb.transactional
    def _clear_deleted_containers(self, tr, account_id, now):
        to_delete_space = self.ct_to_delete_space[account_id]
        start = to_delete_space.range().start
        stop = to_delete_space.range().stop
        iterator = tr.get_range(start, stop)
        for key, value in iterator:
            if float(value) + self.time_window_clear_deleted < float(now):
                ct_name = to_delete_space.unpack(key)[0]
                del tr[to_delete_space.pack((ct_name,))]
