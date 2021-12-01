# Copyright (C) 2021 OVH SAS
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

from six import text_type

import fdb
from fdb.tuple import unpack

from werkzeug.exceptions import NotFound, Conflict, BadRequest
from oio.common.exceptions import OioException
from oio.common.constants import BUCKET_PROP_REPLI_ENABLED
from oio.common.timestamp import Timestamp
from oio.common.easy_value import int_value, boolean_value, float_value, \
    debinarize
from oio.common.exceptions import ServiceBusy

fdb.api_version(630)

ACCOUNTS_KEY_PREFIX = 'accounts:'
ACCOUNT_KEY_PREFIX = 'account:'

BUCKET_KEY_PREFIX = 'bucket:'
BUCKET_LIST_PREFIX = 'buckets:'

CONTAINERS_LIST_PREFIX = 'containers:'
CONTAINER_LIST_PREFIX = 'container:'
CTS_TO_DELETE_LIST_PREFIX = 'ct-to-delete:'

METADATA_PREFIX = 'metadata:'

BUCKET_RESERVE_PREFIX = 's3bucket:'

METRICS_PREFIX = 'metrics:'


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
    METRIC_ACCOUNTS = "obsto_accounts"
    METRIC_CONTAINERS = "obsto_containers"
    METRIC_BUCKETS = "obsto_buckets"
    METRIC_OBJECTS = "obsto_objects"
    METRIC_BYTES = "obsto_bytes"

    REGION_LABEL = "region"
    STORAGE_LABEL = "storage_class"


class AccountBackendFdb():

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

    DEFAULT_FDB = '/etc/foundationdb/fdb.cluster'

    # Default batch size, this value could be divided by 2 if time of refresh
    # by batch is too long
    BATCH_SIZE = 10000

    def init_db(self):
        """
        This method makes connexion to fdb database. It could be called
        any time in mono process, but in case we fork processes it should be
        called after forking in gunicorn.
        This is the reason why this task is not done inside constructor.
        """
        self.fdb_file = self.conf.get('fdb_file',
                                      AccountBackendFdb.DEFAULT_FDB)
        self.logger.info('fdb backend using %s file', self.fdb_file)

        try:
            if self.db is None:
                self.db = fdb.open(self.fdb_file, event_model='gevent')
        except Exception as exc:
            self.logger.error("can't open fdb file: %s exception %s",
                              self.fdb_file, exc)
            raise

    def __init__(self, conf, logger):
        self.db = None
        self.conf = conf
        self.logger = logger
        self.logger.info('fdb backend')
        self.fdb_file = None
        self.autocreate = boolean_value(conf.get('autocreate'), True)
        self._accounts_prefix = conf.get('accounts_prefix',
                                         ACCOUNTS_KEY_PREFIX)
        self._account_prefix = conf.get('account_prefix', ACCOUNT_KEY_PREFIX)

        self._bucket_prefix = conf.get('bucket_prefix', BUCKET_KEY_PREFIX)
        self._buckets_list_prefix = conf.get('bucket_list_prefix',
                                             BUCKET_LIST_PREFIX)
        self._containers_list_prefix = conf.get('containers_list_prefix',
                                                CONTAINERS_LIST_PREFIX)
        self._container_list_prefix = conf.get('container_list_prefix',
                                               CONTAINER_LIST_PREFIX)

        self.ct_to_delete_prefix = conf.get('containers_to_delete_prefix',
                                            CTS_TO_DELETE_LIST_PREFIX)

        self._reserve_bucket_prefix = conf.get('reserve_bucket_prefix',
                                               BUCKET_RESERVE_PREFIX)
        self._bucket_db_space = fdb.Subspace((self._reserve_bucket_prefix,))

        self.accts_space = fdb.Subspace((self._accounts_prefix,))
        self.acct_space = fdb.Subspace((self._account_prefix,))

        self.cts_space = fdb.Subspace((self._containers_list_prefix,))
        self.ct_space = fdb.Subspace((self._container_list_prefix,))

        self.ct_to_delete_space = fdb.Subspace((self.ct_to_delete_prefix,))

        self.bs_space = fdb.Subspace((self._buckets_list_prefix,))
        self.b_space = fdb.Subspace((self._bucket_prefix,))

        self.metadata_subspace = fdb.Subspace((METADATA_PREFIX,))

        self.default_location = self.conf.get('default_location', '')

        self.metrics_space = fdb.Subspace((METRICS_PREFIX,))

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
        info = self._multi_get(self.db, self.b_space, bname)
        if not info:
            return None

        self.cast_fields(info)
        self.logger.debug('get_bucket_info %s ', info)
        return info

    @catch_service_errors
    def get_container_info(self, account_id, cname, **kwargs):
        """
        Get all available information about a container, including some
        information coming from the bucket it belongs to.
        """
        if not cname:
            return None
        ct_space = fdb.Subspace((self._container_list_prefix, account_id))
        info = self._multi_get(self.db, ct_space, cname)

        replication_enabled = b'False'
        bname = self._val_element(self.db, ct_space, cname, 'bucket')

        if bname is not None:
            bname = bname.decode("utf-8")
            self.logger.info('bname: %s', bname)
            rep_enabled = self._val_element(self.db, self.b_space, bname,
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
                self.create_account(_acct_id)
            else:
                return None
        _acct_id = _acct_id.decode('utf-8')

        if not metadata and not to_delete:
            return account_id
        self._manage_metadata(self.db, self.metadata_subspace, _acct_id,
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
        self._manage_metadata(self.db, self.b_space, bname, metadata,
                              to_delete)

        info = self._multi_get(self.db, self.b_space, bname)

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

        containers = self._multi_get(self.db, self.cts_space, req_account_id)
        metadata = self._multi_get(self.db, self.metadata_subspace,
                                   req_account_id)
        buckets = self._multi_get(self.db, self.bs_space, req_account_id)
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
        objects_details = kwargs.get('objects-details', {})
        bytes_details = kwargs.get('bytes-details', {})

        # read mtime & dtime
        ct_space = fdb.Subspace((self._container_list_prefix, account_id))
        cts_space = fdb.Subspace((self._containers_list_prefix, account_id))

        new_mtime = bytes(mtime, 'utf-8')
        new_dtime = bytes(dtime, 'utf-8')
        status = self._update_container(self.db, cts_space, ct_space,
                                        account_id, cname, bucket_name,
                                        new_mtime, new_dtime, now,
                                        autocreate_account,
                                        autocreate_container, object_count,
                                        bytes_used, bucket_location,
                                        objects_details, bytes_details)

        if text_type(status).endswith("no_account"):
            raise NotFound("Account %s not found" % account_id)
        if text_type(status).endswith("no_container"):
            raise NotFound("Container %s not found" % cname)
        elif text_type(status).endswith("no_update_needed"):
            raise Conflict("No update needed, "
                           "event older than last container update")

        return cname

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

        bs_space = fdb.Subspace((self._buckets_list_prefix, account_id))

        raw_list, next_marker = self._raw_listing_m1(
            self.db, bs_space, limit, prefix,
            marker, end_marker, delimiter=None, **kwargs)

        output = list()
        i = 0
        for bucket in raw_list:
            if not bucket[3]:
                bdict = {
                    'name': bucket[0],
                    'objects': int_value(raw_list[i][1], 0),
                    'bytes': int_value(raw_list[i][2], 0),
                    'mtime': float_value(raw_list[i][4], 0.0),
                }
                i += 1
            else:
                bdict = {'prefix': bucket}
            output.append(bdict)
        return output, next_marker

    @catch_service_errors
    def list_containers(self, account_id, limit=1000, marker=None,
                        end_marker=None, prefix=None, delimiter=None,
                        s3_buckets_only=False, **kwargs):
        if prefix is None:
            prefix = ''
        ct_space = fdb.Subspace((self._container_list_prefix, account_id))
        raw_list, next_marker = self._raw_listing(
            self.db, ct_space, limit=limit, marker=marker,
            end_marker=end_marker, prefix=prefix,
            delimiter=delimiter,
            s3_buckets_only=s3_buckets_only, **kwargs)

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
        bucket_space = fdb.Subspace((self._bucket_prefix, bucket_name))
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
            for el in containers:
                while True:
                    next_marker = self._refresh_sharded_ct(
                        self.db, account_id, el, sharded_marker, batch_size)
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
        reserved_space = self._bucket_db_space[bucket_name]
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
        reserved_space = self._bucket_db_space[bucket_name]
        self._release_bucket(self.db, reserved_space)
        return True

    @fdb.transactional
    def _release_bucket(self, tr, space):
        tr.clear_range_startswith(space)

    @catch_service_errors
    def set_bucket_owner(self, account_id, bucket_name, **kwargs):
        reserved_space = self._bucket_db_space[bucket_name]
        self.db[reserved_space.pack(('account',))] = bytes(account_id, 'utf-8')

    @catch_service_errors
    def get_bucket_owner(self, bucket_name, **kwargs):
        account = self._val_element(self.db, self._bucket_db_space,
                                    bucket_name, 'account')
        if account is None:
            return {'account': None}
        else:
            account_ = account.decode('utf-8')
            # TODO check if account is timestamp, (shouldn't happen)
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
                                                'nb-objects')
        metrics[Metric.METRIC_BYTES] = self._read_field_metrics(tr, 'nb-bytes')
        return metrics

    @fdb.transactional
    def _read_account_metrics(self, tr):
        if tr[self.metrics_space.pack(('nb-accounts',))].present():
            nb_accts = tr[self.metrics_space.pack(('nb-accounts',))]
            nb_accts = int.from_bytes(nb_accts, byteorder='little')
        else:
            nb_accts = 0
        return nb_accts

    @fdb.transactional
    def _read_buckets_metrics(self, tr):
        metrics_buckets = dict()
        bucket_metrics_space = self.metrics_space['nb-buckets']
        b_metrics_range = bucket_metrics_space.range()
        iterator = tr.get_range(b_metrics_range.start, b_metrics_range.stop,
                                reverse=False)
        for key, value in iterator:
            _, _, region = unpack(key)
            metrics_buckets[region] = struct.unpack('<q', value)[0]
        return metrics_buckets

    @fdb.transactional
    def _read_containers_metrics(self, tr):
        metrics_containers = dict()
        ct_metrics_space = self.metrics_space['nb-containers']
        ct_metrics_range = ct_metrics_space.range()

        iterator = tr.get_range(ct_metrics_range.start, ct_metrics_range.stop,
                                reverse=False)
        for key, value in iterator:
            _, _, region = unpack(key)
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
            _, _, region, storage_class = unpack(key)
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
        tr.clear_range_startswith(fdb.Subspace((self._containers_list_prefix,
                                                account_id)))
        tr.clear_range_startswith(fdb.Subspace((self._container_list_prefix,
                                                account_id)))

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
        self._increment(tr, self.metrics_space.pack(('nb-accounts',)))
        return True

    @fdb.transactional
    def _delete_account(self, tr, req_account_id):

        account_id = self._val_element(self.db, self.acct_space,
                                       req_account_id, 'id')
        if account_id is None:
            return None
        account_id = account_id.decode('utf-8')

        ct_account_space = self.ct_space[account_id]
        s_range = ct_account_space.range()
        iterator = self.db.get_range(s_range.start, s_range.stop,
                                     reverse=False)
        for _, _ in iterator:
            return False

        tr.clear_range_startswith(self.acct_space[account_id])
        tr.clear_range_startswith(self.accts_space[account_id])
        tr.clear_range_startswith(self.metadata_subspace[account_id])
        # tr.clear_range_startswith(self.ct_space[account_id])
        tr.clear_range_startswith(self.cts_space[account_id])
        self._decrement(tr, self.metrics_space.pack(('nb-accounts',)))
        return True

    @fdb.transactional
    def _list_accounts(self, tr):
        # iterate over the whole 'accounts:' namespace
        iterator = tr.get_range_startswith(self.accts_space)
        res = list()
        for key, _ in iterator:
            _, account_id = unpack(key)
            res.append(account_id)
        return res

    @fdb.transactional
    def _refresh_account(self, tr, account_id):
        if not self._is_element(self.db, self.accts_space, account_id):
            raise NotFound(account_id)

        ct_space = fdb.Subspace((self._container_list_prefix, account_id))
        s_range = ct_space.range()

        iterator = tr.snapshot.get_range(s_range.start, s_range.stop,
                                         reverse=False)
        sum_bytes = 0
        sum_objects = 0
        for key, v in iterator:
            space, account, ct, k = fdb.tuple.unpack(key)
            if k == 'bytes':
                sum_bytes += struct.unpack('<q', v)[0]
            if k == 'objects':
                sum_objects += struct.unpack('<q', v)[0]

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
        to_delete_space = fdb.Subspace((self.ct_to_delete_prefix, account_id))

        account_exists = self._is_element(self.db, self.accts_space,
                                          account_id)
        if not account_exists:
            if autocreate_account:
                self._create_account(tr, self.accts_space, self.acct_space,
                                     account_id, now)
            else:
                return 'no_account'
        if not autocreate_container:
            container_exists = tr[ct_space.pack((cname, 'name'))].present()
            if not container_exists:
                return 'no_container'
        deleted_time = b'0'
        if tr[to_delete_space.pack((cname, 'deleted'))].present():
            deleted_time = tr[to_delete_space.pack((cname, 'deleted'))]
        # real update
        if tr[ct_space.pack((cname, 'name'))].present():
            dtime = tr[ct_space.pack((cname, 'dtime'))]
            mtime = tr[ct_space.pack((cname, 'mtime'))]
            nb_objects = tr[ct_space.pack((cname, 'objects'))]
            nb_bytes = tr[ct_space.pack((cname, 'bytes'))]
            nb_objects = int.from_bytes(nb_objects, byteorder='little')
            nb_bytes = int.from_bytes(nb_bytes, byteorder='little')
        # event update interleaved with container delete
        elif new_mtime < deleted_time:
            # TODO clear following keys in a method like status or in
            # separate crawler:
            # ct-to-delete:accountid,containerid,deleted

            return 'no_container'
        else:  # real creation
            dtime = b'0'
            mtime = b'0'
            nb_objects = 0
            nb_bytes = 0
            creation = True

        if not autocreate_container and dtime >= mtime:
            return 'no_container'

        region = self._get_region(tr, bucket_location, bucket_name, cname)

        old_mtime = mtime
        inc_objects = 0
        inc_bytes = 0
        deleted = False

        if new_mtime > mtime or new_dtime > dtime:
            if new_mtime > mtime:
                mtime = new_mtime
            if new_dtime > dtime:
                dtime = new_dtime

            if dtime >= mtime:
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
                tr[to_delete_space.pack((cname, 'deleted'))] = dtime

                # metrics
                self._decrement(tr, self.metrics_space.pack(
                            ('nb-containers', region)))
                deleted = True

            elif mtime > old_mtime:
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
                                    ('nb-containers', region)))
            else:
                return 'no_update_needed'

            # increase account stats
            if inc_objects != 0:
                self._increment(tr,
                                self.acct_space.pack((account_id, 'objects')),
                                inc_objects)

            if inc_bytes != 0:
                self._increment(tr,
                                self.acct_space.pack((account_id, 'bytes')),
                                inc_bytes)

            deltas = self._update_ct_stats_policy(tr, cname, region,
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
                        tr.clear_range_startswith(self.bs_space.pack(
                            (account_id, bucket_name)))
                        tr.clear_range_startswith(
                            self.bs_space.pack((region, bucket_name)))
                        # Also delete the bucket
                        tr.clear_range_startswith(
                            self.b_space.pack((bucket_name,)))

                        # decrements metrics
                        self._decrement(tr, self.metrics_space.pack(
                                    ('nb-buckets', region)))
                        return

                    # We used to return here. But since we delete shard before
                    # cleaning them, we need to fix counters first.

                # For container holding MPU segments, we do not want to count
                # each segment as an object. But we still want to consider
                # their size.
                if '+segments' in container_name:
                    inc_objects = 0

                # Check if a refresh bucket is in progress
                # No lock is needed as add operation is atomic
                # local marker = redis.call("HGET", bucket_lock, "marker")

                # Increment the counters if needed.
                # if marker == false or container_name <= marker then
                if tr[self.b_space.pack((bucket_name, 'objects'))].present():
                    tr.add(self.b_space.pack((bucket_name, 'objects')),
                           struct.pack('<q', inc_objects))
                else:
                    tr[self.b_space.pack((bucket_name, 'objects'))] = \
                                         struct.pack('<q', inc_objects)

                if tr[self.b_space.pack((bucket_name, 'bytes'))].present():
                    tr.add(self.b_space.pack((bucket_name, 'bytes')),
                           struct.pack('<q', inc_bytes))
                else:
                    tr[self.b_space.pack((bucket_name, 'bytes'))] = \
                                        struct.pack('<q', inc_bytes)

                tr[self.b_space.pack((bucket_name, 'region'))] = \
                    bytes(str(region), 'utf-8')

                # Update the modification time.
                if mtime != b'0':
                    tr[self.b_space.pack((bucket_name, 'mtime'))] = mtime

                if deleted:
                    return 'deleted'
                # Set the bucket owner.
                # Filter the special accounts hosting bucket shards.
                if not account_id.startswith('.shards_'):
                    tr[self.b_space.pack((bucket_name, 'account'))] = \
                       bytes(str(account_id), 'utf-8')

                # Update container info
                tr[ct_space.pack((cname, 'bucket'))] = \
                    bytes(str(bucket_name), 'utf-8')

                # Update the buckets list if it's the root container
                if bucket_name == cname:
                    tr[self.bs_space.pack((account_id, bucket_name))] = b'0'
                    tr[self.bs_space.pack((region, bucket_name))] = \
                        b'0'
                    # increments metrics
                    if creation:
                        self._increment(tr, self.metrics_space.pack(
                                        ('nb-buckets', region)))
        else:
            return 'no_update_needed'
        return 'updated'

    @fdb.transactional
    def _get_region(self, tr, bucket_location, bucket_name, ct_name):
        if bucket_location is not None:
            return bucket_location
        if bucket_name != '':
            region = self._val_element(tr, self.b_space, bucket_name, 'region')
            if region is not None:
                return region.decode('utf-8')
        return self.default_location

    @fdb.transactional
    def _update_ct_stats_policy(self, tr, cname, region, objs_per_policy,
                                bytes_per_policy):
        """
        Read current values for given container and per region/policy
        Compute deltas, update values then return deltas
        """
        current_values = dict()
        deltas = dict()

        c_space = fdb.Subspace((METRICS_PREFIX, cname, region))
        for policy, value in objs_per_policy.items():
            if policy not in current_values.keys():
                current_values[policy] = {}
            if policy not in deltas:
                deltas[policy] = {}
            if self._is_element(tr, c_space, policy) is not None:
                nb_obj_ct = self._val_element(tr, c_space, policy,
                                              'nb-objects')
                current_values[policy]['nb-objects'] = int.from_bytes(
                                                        nb_obj_ct,
                                                        byteorder='little') \
                    if nb_obj_ct else 0
            else:
                current_values[policy]['nb-objects'] = 0
            delta = value - current_values[policy]['nb-objects']
            if value > 0 and delta != 0:
                deltas[policy]['nb-objects'] = delta
                tr[c_space.pack((policy, 'nb-objects'))] = \
                    struct.pack('<q', value)

        for policy, value in bytes_per_policy.items():
            if policy not in current_values.keys():
                current_values[policy] = {}
            if policy not in deltas:
                deltas[policy] = {}
            if self._is_element(tr, c_space, policy) is not None:
                nb_bytes_ct = self._val_element(tr, c_space, policy,
                                                'nb-bytes')
                current_values[policy]['nb-bytes'] = \
                    int.from_bytes(nb_bytes_ct,
                                   byteorder='little') \
                    if nb_bytes_ct else 0
            else:
                current_values[policy]['nb-bytes'] = 0
            delta = value - current_values[policy]['nb-bytes']
            # update values only when needed
            if value > 0 and delta != 0:
                deltas[policy]['nb-bytes'] = delta
                tr[c_space.pack((policy, 'nb-bytes'))] = \
                    struct.pack('<q', value)

        # empty policies that are not present in objs_per_policy
        reg_space = fdb.Subspace((METRICS_PREFIX, cname, region))
        reg_range = reg_space.range()
        res = tr.get_range(reg_range.start, reg_range.stop)

        # gather data to deduce from metrics
        for key, val in res:
            _, _, reg, pol, field = unpack(key)
            if pol not in objs_per_policy:
                deltas[pol] = {}
                deltas[pol][field] = - struct.unpack('<q', val)[0]
        # clear not present policies for given container
        for key, val in res:
            _, _, reg, pol, field = unpack(key)
            if pol not in objs_per_policy:
                tr.clear(reg_space.pack((pol, )))

        return deltas

    @fdb.transactional
    def _raw_listing(self, tr, ct_space, limit, prefix, marker, end_marker,
                     delimiter=None, s3_buckets_only=False,  **kwargs):

        s_range = ct_space.range()
        start = s_range.start
        stop = s_range.stop

        NB_ELEMNTS = 4

        min_k = None
        max_k = stop
        xx = start[:-1]

        orig_marker = marker
        results = list()
        beyond_prefix = False
        if prefix is None:
            prefix = ''

        current_ct = None

        while len(results) < limit and not beyond_prefix:
            min_k = start
            max_k = stop
            local_limit = (limit - len(results) + 1) * 5

            if prefix:
                min_k = xx + b'\x02' + bytes(prefix, 'utf-8')
                max_k = stop

            if marker and (not prefix or marker >= prefix):
                min_k = xx + b'\x02' + bytes(marker, 'utf-8')

            if end_marker and (not prefix
                               or end_marker <= prefix + b'\xff'):
                yy = stop[:-1]
                max_k = yy + b'\x02' + bytes(end_marker, 'utf-8')

            iterator = tr.snapshot.get_range(min_k, max_k, limit=local_limit,
                                             reverse=False)

            current_values = [None, 0, 0, 0, 0]
            count = 0
            empty = True
            for key, val in iterator:
                _, _, ctr, k = fdb.tuple.unpack(key)
                if len(results) >= limit:
                    break
                if prefix and not ctr.startswith(prefix):
                    beyond_prefix = True
                    # No more items
                    marker = None
                    break
                if end_marker:
                    marker = end_marker
                else:
                    marker = ctr + str(b'\xff')

                # don't include marker
                if orig_marker == ctr:
                    continue

                if current_ct is None:
                    current_ct = ctr
                    changed = False
                elif current_ct != ctr:
                    changed = True
                    current_ct = ctr
                else:
                    changed = False

                if changed:
                    NB_ELEMNTS = 4

                if delimiter:
                    end = ctr.find(delimiter, len(prefix))
                    if end > 0:
                        # Delimiter found after the prefix.
                        # Build a new marker, and continue listing from there.
                        # TODO(FVE): we can avoid another request to Redis by
                        # analyzing the rest of the list ourselves.
                        dir_name = ctr[:end + 1]
                        marker = dir_name + str(b'\xff')
                        if dir_name != orig_marker:
                            results.append([dir_name, 0, 0, 1, 0])

                        empty = False
                        break
                current_values[0] = ctr
                if k == 'objects':
                    current_values[1] = struct.unpack('<q', val)[0]
                if k == 'bytes':
                    current_values[2] = struct.unpack('<q', val)[0]
                if k == 'mtime':
                    current_values[4] = float(val)
                if k == 'bucket':
                    NB_ELEMNTS = 5
                if count == NB_ELEMNTS:
                    if not s3_buckets_only or self.buckets_pattern.match(ctr):
                        results.append(current_values)
                    count = 0
                    current_values = [None, 0, 0, 0, 0]
                else:
                    count += 1

                empty = False

            if empty:
                break

        return results, marker

    @fdb.transactional
    def _raw_listing_m1(self, tr, key_space, limit, prefix, marker,
                        end_marker, delimiter=None, s3_buckets_only=False,
                        **kwargs):

        start = key_space.range().start
        stop = key_space.range().stop

        min_k = None
        max_k = stop
        xx = start[:-1]

        orig_marker = marker
        results = list()
        beyond_prefix = False
        if prefix is None:
            prefix = ''

        while len(results) < limit and not beyond_prefix:
            min_k = start
            max_k = stop
            local_limit = (limit - len(results) + 1)

            if prefix:
                min_k = xx + b'\x02' + bytes(prefix, 'utf-8')
                max_k = stop

            if marker and (not prefix or marker >= prefix):
                min_k = xx + b'\x02' + bytes(marker, 'utf-8')

            if end_marker and (not prefix
                               or end_marker <= prefix + b'\xff'):
                yy = stop[:-1]
                max_k = yy + b'\x02' + bytes(end_marker, 'utf-8')

            iterator = tr.snapshot.get_range(min_k, max_k, limit=local_limit,
                                             reverse=False)

            empty = True
            for key, val in iterator:
                _, _, ctr = fdb.tuple.unpack(key)
                if len(results) >= limit:
                    break
                if prefix and not ctr.startswith(prefix):
                    beyond_prefix = True
                    # No more items
                    marker = None
                    break
                if end_marker:
                    marker = end_marker
                else:
                    marker = ctr + str(b'\xff')

                # don't include marker
                if orig_marker == ctr:
                    continue

                if delimiter:
                    end = ctr.find(delimiter, len(prefix))
                    if end > 0:
                        # Delimiter found after the prefix.
                        # Build a new marker, and continue listing from there.
                        # TODO(FVE): we can avoid another request to Redis by
                        # analyzing the rest of the list ourselves.
                        dir_name = ctr[:end + 1]
                        marker = dir_name + str(b'\xff')
                        if dir_name != orig_marker:
                            results.append([dir_name, 0, 0, 1, 0])

                        empty = False
                        break

                if not s3_buckets_only or self.buckets_pattern.match(ctr):
                    nb_objects = 0
                    nb_bytes = 0
                    mtime = 0
                    bucket_space = fdb.Subspace((self._bucket_prefix, ctr))
                    bucket_range = bucket_space.range()
                    bucket_it = tr.get_range(bucket_range.start,
                                             bucket_range.stop, reverse=False)
                    for bucket_key, a_value in bucket_it:
                        bucket_space, _, a_key = unpack(bucket_key)

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
        return results, marker

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
        meta = self._multi_get(tr, self.metadata_subspace,
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
        if tr[bucket_key.pack(('account',))].present() is None:
            return 'no_bucket'

        account_id = tr[bucket_key.pack(('account',))].decode('utf-8')
        ckey_prefix = fdb.Subspace((self._container_list_prefix, account_id))

        # get_range is fetching data in batchs, the default mode for
        # streaming_mode is iterator which is efficient.
        # fdb.StreamingMode.want_all could be used
        new_marker = None
        start = ckey_prefix.range().start
        if marker is not None:
            trim_start = start[:-1]
            start = trim_start + b'\x02' + bytes(marker, 'utf-8')

        stop = ckey_prefix.range().stop
        iterator = tr.snapshot.get_range(start, stop, reverse=False)
        sum_bytes = 0
        sum_objects = 0
        count = 0

        if marker is None:
            tr[self.b_space.pack((bucket_name, 'objects'))] = \
                struct.pack('<q', 0)
            tr[self.b_space.pack((bucket_name, 'bytes'))] = \
                struct.pack('<q', 0)

        for key, val in iterator:
            _, _, container, unpacked_key = fdb.tuple.unpack(key)

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
            return
        sharded_account_id = '.shards_' + account_id
        sharded_account_exists = self._is_element(tr, self.accts_space,
                                                  sharded_account_id)
        if not sharded_account_exists:
            return

        ct_space = fdb.Subspace((self._container_list_prefix, account_id))
        ckey_prefix = fdb.Subspace((self._container_list_prefix,
                                    sharded_account_id))

        orig_marker = marker
        new_marker = None
        count = 0
        start = ckey_prefix.range().start
        stop = ckey_prefix.range().stop

        trim_start = start[:-1]

        if marker is None:
            start_ct = trim_start + b'\x02' + bytes(cname, 'utf-8')
        else:
            start_ct = trim_start + b'\x02' + bytes(marker, 'utf-8')

        iterator = tr.snapshot.get_range(start_ct, stop, reverse=False)
        sum_bytes = 0
        sum_objects = 0

        ended = True
        found = False

        for key, val in iterator:
            _, _, container, unpacked_key = fdb.tuple.unpack(key)

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
        sharded_account_id = '.shards_' + account_id
        sharded_account_exist = self._is_element(tr, self.accts_space,
                                                 sharded_account_id)
        if not sharded_account_exist:
            return

        ct_space = fdb.Subspace((self._container_list_prefix, account_id))

        containers = list()
        start = ct_space.range().start
        stop = ct_space.range().stop

        iterator = tr.snapshot.get_range(start, stop, reverse=False)
        for key, val in iterator:
            _, _, ct, unpacked_key = fdb.tuple.unpack(key)

            if bucket_name is None:
                if ct not in containers:
                    containers.append(ct)
            else:
                read_bucket_name = tr[ct_space.pack((ct, 'bucket'))]
                if read_bucket_name.present() and \
                   read_bucket_name.decode('utf-8') == bucket_name:
                    if ct not in containers:
                        containers.append(ct)

        return containers
