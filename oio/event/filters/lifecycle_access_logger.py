# Copyright (C) 2024 OVH SAS
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

from datetime import datetime, timezone
from enum import Enum
from urllib.parse import quote

from oio.common.logger import get_logger, LogStringFormatter
from oio.event.evob import Event
from oio.event.filters.base import Filter


class LifecycleOperationLog(str, Enum):
    """
    S3 Lifecycle actions. Ref:
    https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-and-other-bucket-config.html
    """

    EXPIRE_OBJECT = "S3.EXPIRE.OBJECT"
    CREATE_DELETEMARKER = "S3.CREATE.DELETEMARKER"
    TRANSITION_SIA = "S3.TRANSITION_SIA.OBJECT"  # Standard IA
    TRANSITION_ZIA = "S3.TRANSITION_ZIA.OBJECT"  # One zone IA
    TRANSITION_INT = "S3.TRANSITION_INT.OBJECT"  # Intelligent Tiering
    TRANSITION_GIR = "S3.TRANSITION_GIR.OBJECT"  # Glacier Instant
    TRANSITION_OBJECT = "S3.TRANSITION.OBJECT"  # Glacier Flexible Retrival
    TRANSITION_GDA = "S3.TRANSITION_GDA.OBJECT"  # Glacier Deep Archive
    DELETE_UPLOAD = "S3.DELETE.UPLOAD"


def event_to_s3_operation(event):
    """
    Mapping from an event to a S3 Lifecycle action
    """
    action = event.data.get("action")
    if action in ("Transition", "NoncurrentVersionTransition"):
        # TODO: storage class mapping
        # storage_class = event.data.get("storage_class")
        return LifecycleOperationLog.TRANSITION_OBJECT
    if action in ("Expiration", "NoncurrentVersionExpiration"):
        add_delete_marker = event.data.get("add_delete_marker")
        if add_delete_marker:
            return LifecycleOperationLog.CREATE_DELETEMARKER
        return LifecycleOperationLog.EXPIRE_OBJECT
    if action in ("AbortIncompleteMultipartUpload",):
        return LifecycleOperationLog.DELETE_UPLOAD
    raise ValueError("No mapping to S3 Operation found")


class LifecycleAccessLoggerFilter(Filter):
    """ "
    Log lifecycle event
    """

    DEFAULT_LOG_FORMAT = (
        "{program}: {bucket_owner} {bucket} [{time}] "
        "{remote_ip} {requester} {request_id} {operation} {key} "
        '"{request_uri}" {http_status} {error_code} {bytes_sent} '
        '{object_size} {total_time} {turn_around_time} "{referer}" '
        '"{user_agent}" {version_id} {host_id} {signature_version} '
        "{cipher_suite} {authentication_type} {host_header} {tls_version} "
        "{access_point_arn}"
    )

    def __init__(self, *args, **kwargs):
        self._access_logger = None
        self._log_prefix = None
        self._log_format = None
        self._formatter = None
        super().__init__(*args, **kwargs)

    def init(self):
        self._log_format = self.conf.get("log_format", self.DEFAULT_LOG_FORMAT)
        log_name = self.conf.get("log_name", "access_logger_filter")
        self._log_prefix = self.conf.get("log_prefix", "s3access-")
        self._formatter = LogStringFormatter(default="-")
        self._validate_format()
        self._access_logger = get_logger(self.conf, name=log_name, fmt=None)

    def _validate_format(self):
        dummy_env = {
            "program": None,
            "bucket_owner": None,
            "bucket": None,
            "time": None,
            "remote_ip": None,
            "requester": None,
            "request_id": None,
            "operation": None,
            "key": None,
            "request_uri": None,
            "http_status": None,
            "error_code": None,
            "bytes_sent": None,
            "object_size": None,
            "total_time": None,
            "turn_around_time": None,
            "referer": None,
            "user_agent": None,
            "version_id": None,
            "host_id": None,
            "signature_version": None,
            "cipher_suite": None,
            "authentication_type": None,
            "host_header": None,
            "tls_version": None,
            "access_point_arn": None,
        }
        try:
            self._formatter.format(self._log_format, **dummy_env)
        except Exception as e:
            raise ValueError(f"Cannot interpolate log template, reason: {e}") from e

    def _should_log(self, event):
        if not event.data:
            return False
        return event.data.get("has_bucket_logging", False) and event.data.get("bucket")

    def _log_event(self, event):
        current_time = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S %z")
        key = event.data.get("object")
        if key:
            key = quote(quote(key))

        log_env = {
            "program": self._log_prefix + event.data.get("bucket", ""),
            "bucket_owner": event.data.get("account"),
            "bucket": event.url.get("bucket"),
            "time": current_time,
            "remote_ip": None,  # ignored
            "requester": None,  # ignored
            "request_id": event.reqid,
            "operation": event_to_s3_operation(event),
            "key": key,
            "request_uri": None,  # ignored
            "http_status": None,  # ignored
            "error_code": None,  # ignored
            "bytes_sent": None,  # ignored
            "object_size": event.data.get("size"),
            "total_time": None,  # ignored
            "turn_around_time": None,  # ignored
            "referer": None,  # ignored
            "user_agent": None,  # ignored
            "version_id": event.data.get("version_id"),
            "host_id": None,  # ignored
            "signature_version": None,  # ignored
            "cipher_suite": None,  # ignored
            "authentication_type": None,  # ignored
            "host_header": None,  # ignored
            "tls_version": None,  # ignored
            "access_point_arn": None,  # ignored
        }
        self._access_logger.info(self._formatter.format(self._log_format, **log_env))

    def process(self, env, cb):
        event = Event(env)
        if self._should_log(event):
            self._log_event(event)
        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def access_log_filter(app):
        return LifecycleAccessLoggerFilter(app, conf)

    return access_log_filter
