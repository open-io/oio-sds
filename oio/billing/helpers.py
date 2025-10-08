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


from oio.common.logger import get_logger
from oio.common.redis_conn import RedisConnection, catch_service_errors


class _BillingClient:
    PREFIX = None

    _INCR_FIELDS = """
    local function getIncrements(array)
        local i = 0;
        return function()
            i = i + 1;
            if i > #array / 2 then return; end;
            return i, array[i*2-1], array[i*2]
        end;
    end;

    local retValues = {}
    for i, f, v in getIncrements(ARGV) do
        retValues[i] = redis.call('HINCRBYFLOAT', KEYS[1], f, v);
    end;
    return retValues;
    """

    _GETDEL_FIELDS = """
    local retValues = {}
    for i, field in ipairs(ARGV) do
        retValues[i] =  redis.call('HGET', KEYS[1], field)
        redis.call('HDEL',  KEYS[1], field)
    end;
    return retValues;
    """

    def __init__(self, conf, logger=None):
        self._conf = conf
        self._logger = logger or get_logger(self._conf)

        redis_conf = {k[6:]: v for k, v in self._conf.items() if k.startswith("redis_")}
        self._redis_client = RedisConnection(**redis_conf)

        self.__increments_values = self._redis_client.register_script(self._INCR_FIELDS)
        self.__get_and_delete_fields = self._redis_client.register_script(
            self._GETDEL_FIELDS
        )

    def _key(self, *fields, separator="/"):
        return separator.join((f for f in (self.PREFIX, *fields) if f))

    def _unkey(self, key, separator="/"):
        if self.PREFIX and key.startswith(self.PREFIX):
            key = key[len(self.PREFIX) :]
        key = key.lstrip(separator)
        return key.split(separator)

    @catch_service_errors
    def _list_keys(self, pattern="*"):
        if self.PREFIX:
            pattern = f"{self.PREFIX}{pattern}"
        for key in self._redis_client.conn.scan_iter(match=pattern, count=100):
            yield self._unkey(key.decode("utf-8"))

    @catch_service_errors
    def _reset_value(self, *fields, counters=None):
        if not counters:
            return
        values = self.__get_and_delete_fields(
            keys=[self._key(*fields)],
            args=counters,
            client=self._redis_client.conn,
        )
        return [float(v) if v else 0 for v in values]

    @catch_service_errors
    def _increment_counters(self, *fields, counters=None):
        if not counters:
            return
        self.__increments_values(
            keys=[self._key(*fields)],
            args=[str(e) for i in counters.items() for e in i],
            client=self._redis_client.conn,
        )


class BillingAdjustmentClient(_BillingClient):
    PREFIX = "BillingAdjustment"

    @catch_service_errors
    def add_adjustment(self, account, bucket, storage_class, volume, objects=1):
        """Add volume to bucket early deletion total

        Args:
            account (str): account
            bucket (str): bucket
            storage_class (str): storage class
            volume (float): Volume of storage to add (bytes.hour)
            objects (int): Number of objects deleted
        """

        self._increment_counters(
            account,
            bucket,
            storage_class,
            counters={"objects": objects, "volume": volume},
        )

    @catch_service_errors
    def list_adjustments(self):
        """List buckets with anticipated deletion

        Yields:
            tuple(str,str,str): account, bucket and storage class
        """
        for k in self._list_keys():
            account, bucket, storage_class = k
            yield (account, bucket, storage_class)

    @catch_service_errors
    def reset_adjustment(self, account, bucket, storage_class):
        """Get and reset the volume of data due for specified storage class
        for the bucket and the number of objects

        Args:
            account (str): account
            bucket (str): bucket
            storage_class (str): storage class

        Returns:
            dict: the volume of storage(bytes.hour) due for bucket and the number
            of objects
        """
        fields = ["objects", "volume"]
        values = self._reset_value(account, bucket, storage_class, counters=fields)
        return {k: v or 0 for k, v in zip(fields, values)}


class RestoreBillingClient(_BillingClient):
    PREFIX = "ArchiveRestore"

    @catch_service_errors
    def list_restore(self):
        """List accounts and buckets which have restore awaiting for billing

        Yields:
            tuple(str, str, str): account, bucket, storage_class
        """
        for account, bucket, storage_class in self._list_keys():
            yield account, bucket, storage_class

    @catch_service_errors
    def add_restore(
        self, account, bucket, storage_class, requests=0, transfer=0, storage=0
    ):
        """
        Increment restoration counters for bucket.
        Args:
            account (str): account name
            bucket (str): bucket name
            requests (int): Number of restore requests
            transfer (int): Volume of restored data (in bytes)
            storage (float): Volume of storage (in bytes.h)
        """
        if requests == 0 and transfer == 0 and storage == 0:
            return

        self._increment_counters(
            account,
            bucket,
            storage_class,
            counters={
                "resquests": requests,
                "transfer": transfer,
                "storage": storage,
            },
        )

    @catch_service_errors
    def reset_restore(self, account, bucket, storage_class):
        """
        Get and reset the volume of data due for specified storage class
        for the bucket and the number of objects

        Args:
            account (str): account
            bucket (str): bucket
            storage_class (str): storage_class

        Returns:
            dict: the volume of storage (bytes.hour), the number of requests and the
            restored volume (bytes).
        """
        fields = ["requests", "storage", "transfer"]
        values = self._reset_value(account, bucket, storage_class, counters=fields)
        return {k: v or 0 for k, v in zip(fields, values)}
