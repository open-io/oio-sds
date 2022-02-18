# Copyright (C) 2022 OVH SAS
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

import random
import re
import signal
import ssl
import sys
import time
import uuid
from datetime import datetime

import pika
from pika.exchange_type import ExchangeType

from oio.account.backend_fdb import AccountBackendFdb
from oio.common.easy_value import boolean_value, int_value
from oio.common.exceptions import MalformedBucket
from oio.common.json import json
from oio.common.logger import get_logger, redirect_stdio
from oio.common.utils import drop_privileges


class BillingAgent():
    """
    Daemon responsible who will scan all buckets to fetch storage statistics
    and send billing messages to a RabbitMQ.
    """

    DEFAULT_RESELLER_PREFIX = 'AUTH_'
    DEFAULT_STORAGE_CLASS = 'STANDARD'
    DEFAULT_EVENT_TYPE = 'telemetry.polling'
    DEFAULT_PUBLISHER_ID = 'ceilometer.polling'
    DEFAULT_COUNTER_NAME = 'storage.bucket.objects.size'
    DEFAULT_BATCH_SIZE = 50

    DEFAULT_AMQP_URL = 'amqp://guest:guest@localhost:5672/'
    DEFAULT_AMQP_EXCHANGE = 'swift'
    DEFAULT_AMQP_QUEUE = 'notifications.info'
    DEFAULT_AMQP_DURABLE = True
    DEFAULT_AMQP_AUTO_DELETE = False

    def __init__(self, conf, logger=None):
        self.conf = conf
        self.logger = logger or get_logger(conf)

        self.wait_random_time_before_starting = boolean_value(
            self.conf.get('wait_random_time_before_starting'), False)
        self.scans_interval = int_value(self.conf.get('interval'), 1800)
        self.report_interval = int_value(self.conf.get('report_interval'), 300)

        self.backend = AccountBackendFdb(conf, logger=self.logger)
        self.backend.init_db()

        self.reseller_prefix = self.conf.get(
            'reseller_prefix', self.DEFAULT_RESELLER_PREFIX)
        self.default_storage_class = self.conf.get(
            'default_storage_class', self.DEFAULT_STORAGE_CLASS)
        self.event_type = self.conf.get(
            'event_type', self.DEFAULT_EVENT_TYPE)
        self.publisher_id = self.conf.get(
            'publisher_id', self.DEFAULT_PUBLISHER_ID)
        self.counter_name = self.conf.get(
            'counter_name', self.DEFAULT_COUNTER_NAME)
        self.batch_size = int_value(
            self.conf.get('batch_size'), self.DEFAULT_BATCH_SIZE)

        self.amqp_url = self.conf.get(
            'amqp_url', self.DEFAULT_AMQP_URL)
        self.amqp_exchange = self.conf.get(
            'amqp_exchange', self.DEFAULT_AMQP_EXCHANGE)
        self.amqp_queue = self.conf.get(
            'amqp_queue', self.DEFAULT_AMQP_QUEUE)
        self.amqp_durable = boolean_value(
            self.conf.get('amqp_durable'), self.DEFAULT_AMQP_DURABLE)
        self.amqp_auto_delete = boolean_value(
            self.conf.get('amqp_auto_delete'), self.DEFAULT_AMQP_AUTO_DELETE)

        storage_re = re.compile('[A-Z0-9_]+')
        self.storage_mapping = {}
        for key, value in conf.items():
            if not key.startswith('storage_class.'):
                continue
            storage_class = key[14:].upper()
            if not storage_re.match(storage_class):
                self.logger.warning(
                    'Storage class "%s" does not respect the format',
                    storage_class)
                continue
            for storage_policy in value.split(','):
                storage_policy = storage_policy.strip()
                if not storage_re.match(storage_class):
                    self.logger.warning(
                        'Storage policy "%s"\'s storage class "%s" does not '
                        'respect the format', storage_policy, storage_class)
                    continue
                storage_class_ = self.storage_mapping.get(storage_policy)
                if not storage_class_:
                    self.storage_mapping[storage_policy] = storage_class
                    continue
                if storage_class_ != storage_class:
                    self.logger.warning(
                        'Storage policy "%s"\'s storage class "%s" already '
                        'associated with the storage class "%s"',
                        storage_policy, storage_class, storage_class_)
                    continue
        self.logger.debug('Storage classes/policies: %s', self.storage_mapping)

        self.running = True
        self.passes = 0
        self.errors = 0
        self.missing_info = 0
        self.ignored = 0
        self.buckets = 0
        self.messages = 0
        self.start_time = 0
        self.last_report_time = 0
        self.scanned_since_last_report = 0

    def _wait_next_pass(self, start):
        """
        Wait for the remaining time before the next pass.

        :param tag: The start timestamp of the current pass.
        """
        duration = time.time() - start
        waiting_time_to_start = self.scans_interval - duration
        if waiting_time_to_start > 0:
            for _ in range(int(waiting_time_to_start)):
                if not self.running:
                    return
                time.sleep(1)
        else:
            self.logger.warning(
                'duration=%d is higher than interval=%d',
                duration, self.scans_interval)

    def _reset_stats(self):
        """
        Resets all accumulated statistics except the number of passes.
        """
        self.errors = 0
        self.missing_info = 0
        self.ignored = 0
        self.buckets = 0
        self.messages = 0

    def _report(self, tag, now):
        """
        Log a report containing all statistics.

        :param tag: One of three: starting, running, ended.
        :param now: The current timestamp to use in the report.
        """
        elapsed = (now - self.start_time) or 0.00001
        total = self.missing_info + self.ignored + self.buckets
        since_last_rprt = (now - self.last_report_time) or 0.00001
        since_last_rprt = (now - self.last_report_time) or 0.00001
        self.logger.info(
            '%(tag)s '
            'elapsed=%(elapsed).02f '
            'pass=%(pass)d '
            'missing_info=%(missing_info)d '
            'ignored=%(ignored)d '
            'buckets=%(buckets)d '
            'messages=%(messages)d '
            'total_scanned=%(total_scanned)d '
            'rate=%(scan_rate).2f/s',
            {
                'tag': tag,
                'elapsed': elapsed,
                'pass': self.passes,
                'missing_info': self.missing_info,
                'ignored': self.ignored,
                'buckets': self.buckets,
                'messages': self.messages,
                'total_scanned': total,
                'scan_rate': self.scanned_since_last_report / since_last_rprt,
            })

    def _bucket_to_storage_class_stat(self, account, bucket_name, bucket):
        """
        Extract bucket's storage statistics.
        """
        bucket_bytes = bucket.get('bytes')
        if bucket_bytes is None:
            self.logger.warning(
                'Missing bytes for bucket "%s"\'s account "%s"',
                bucket_name, account)
            raise MalformedBucket
        if bucket_bytes < 0:
            self.logger.warning(
                'Negative bytes for bucket "%s"\'s account "%s"',
                bucket_name, account)
            raise MalformedBucket
        bucket_objects = bucket.get('objects')
        if bucket_objects is None:
            self.logger.warning(
                'Missing objects for bucket "%s"\'s account "%s"',
                bucket_name, account)
            raise MalformedBucket
        if bucket_objects < 0:
            self.logger.warning(
                'Negative objects for bucket "%s"\'s account "%s"',
                bucket_name, account)
            raise MalformedBucket
        if not bucket_bytes or not bucket_objects:
            if bucket_bytes:
                self.logger.warning(
                    'Bucket "%s"\'s account "%s" contains bytes (%d), '
                    'but no objects, '
                    'we should check it before sending it to billing',
                    bucket_name, account, bucket_bytes)
                raise MalformedBucket
            self.logger.debug(
                'Bucket "%s"\'s account "%s" contains no objects, '
                'do not send it to billing',
                bucket_name, account)
            return None, None

        bytes_details = bucket.get('bytes-details', {})
        objects_details = bucket.get('objects-details', {})
        total_bytes = 0
        total_objects = 0
        storage_class_stat = {}
        storage_policies = set(bytes_details).union(objects_details)
        for policy_name in storage_policies:
            policy_bytes = bytes_details.get(policy_name, 0)
            if policy_bytes < 0:
                self.logger.warning(
                    'Negative bytes (%d) with the storage policy "%s" '
                    'for bucket "%s"\'s account "%s"',
                    policy_bytes, policy_name, bucket_name, account)
                raise MalformedBucket
            policy_objects = objects_details.get(policy_name, 0)
            if policy_objects < 0:
                self.logger.warning(
                    'Negative objects (%d) with the policy "%s" '
                    'for bucket "%s"\'s account "%s"',
                    policy_objects, policy_name, bucket_name, account)
                raise MalformedBucket
            if not policy_bytes and not policy_objects:
                self.logger.warning(
                    'Empty statistics with the storage policy "%s" '
                    'for bucket "%s"\'s account "%s" should be deleted',
                    policy_name, bucket_name, account)
                continue

            storage_class = self.storage_mapping.get(
                policy_name, self.default_storage_class)
            stat = storage_class_stat.setdefault(storage_class, {
                'storage_class': storage_class,
                'bytes_used': 0,
                # 'container_count': 0,
                'object_count': 0
            })
            stat['bytes_used'] += policy_bytes
            stat['object_count'] += policy_objects
            total_bytes += policy_bytes
            total_objects += policy_objects
        if storage_policies:
            if total_bytes != bucket_bytes:
                self.logger.warning(
                    'Mismatch between total bytes (%d) '
                    'and detailed bytes (%d) '
                    'for bucket "%s"\'s account "%s"',
                    bucket_bytes, total_bytes, bucket_name, account)
                raise MalformedBucket
            if total_objects != bucket_objects:
                self.logger.warning(
                    'Mismatch between total objects (%d) '
                    'and detailed objects (%d) '
                    'for bucket "%s"\'s account "%s"',
                    bucket_objects, total_objects, bucket_name, account)
                raise MalformedBucket
        else:
            self.logger.info(
                'Missing details for bucket "%s"\'s account "%s"',
                bucket_name, account)
            storage_class_stat[self.default_storage_class] = {
                'storage_class': self.default_storage_class,
                'bytes_used': bucket_bytes,
                # 'container_count': 0,
                'object_count': bucket_objects
            }
        return bucket_bytes, [storage_class_stat[key]
                              for key in sorted(storage_class_stat.keys())]

    def bucket_to_sample(self, bucket):
        """
        Extract bucket's information and storage statistics to create a sample.
        """
        tsiso8601 = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        bucket_name = bucket['name']
        account = bucket.get('account')
        if not account:
            self.logger.warning(
                'Missing account for bucket "%s", '
                'we should check it before sending it to billing',
                bucket_name)
            raise MalformedBucket
        if not account.startswith(self.reseller_prefix):
            self.logger.debug(
                'Bucket "%s"\'s account "%s" does not start '
                'with reseller prefix', bucket_name, account)
            return None
        project_id = account[len(self.reseller_prefix):]
        region = bucket.get('region')
        if not region:
            self.logger.warning(
                'Missing region for bucket "%s"\'s account "%s", '
                'we should check it before sending it to billing',
                bucket_name, account)
            raise MalformedBucket
        bucket_size, storage_class_stat = self._bucket_to_storage_class_stat(
            account, bucket_name, bucket)
        if not storage_class_stat:
            return None
        message_id = uuid.uuid4().hex

        return {
            'counter_name': self.counter_name,
            'counter_type': 'gauge',
            'counter_unit': 'B',
            'counter_volume': bucket_size,
            'message_id': message_id,
            'project_id': project_id,
            'resource_id': project_id,
            'resource_metadata': {
                'account_name': account,
                'bucket_name': bucket_name,
                # 'infra_name': '',
                # 'infra_type': '',
                'storage_class_stat': storage_class_stat,
                'region_name': region
            },
            'source': region,
            'timestamp': tsiso8601,
            # 'user_id': '',
        }

    def _amqp_connect(self):
        """
        Returns an AMQP BlockingConnection and a channel for the provided URL.
        """
        url_param = pika.URLParameters(self.amqp_url)
        if url_param.ssl_options:
            # Force TLSv1 to support production rabbit
            url_param.ssl_options.context = ssl.SSLContext(
                protocol=ssl.PROTOCOL_TLSv1_1)
        self.logger.debug('Connecting to %s', url_param)
        connection = pika.BlockingConnection(url_param)
        try:
            channel = connection.channel()
            try:
                channel.exchange_declare(
                    exchange=self.amqp_exchange,
                    exchange_type=ExchangeType.topic,
                    durable=self.amqp_durable,
                    auto_delete=self.amqp_auto_delete)
                channel.queue_declare(
                    queue=self.amqp_queue,
                    durable=self.amqp_durable,
                    auto_delete=self.amqp_auto_delete)
                channel.queue_bind(
                    exchange=self.amqp_exchange,
                    queue=self.amqp_queue)
            except Exception:
                if channel.is_open:
                    channel.cancel()
                raise
        except Exception:
            if connection.is_open:
                connection.close()
            raise
        return connection, channel

    def send_message(self, channel, samples):
        """
        Create billing message with the samples and send it to the RabbitMQ.
        """
        if not samples:
            return

        tsiso8601 = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")
        message_id = uuid.uuid4().hex
        unique_id = uuid.uuid4().hex

        payload = {
            # '_context_auth_token': '',
            # '_context_domain': '',
            # '_context_is_admin': '',
            # '_context_is_admin_project': '',
            # '_context_project_domain': '',
            # '_context_read_only': '',
            # '_context_request_id': '',
            # '_context_resource_uuid': '',
            # '_context_roles': '',
            # '_context_show_deleted': '',
            # '_context_tenant': '',
            # '_context_user': '',
            # '_context_user_domain': '',
            # '_context_user_identity': '',
            'event_type': self.event_type,
            'message_id': message_id,
            'priority': 'SAMPLE',
            'publisher_id': self.publisher_id,
            'timestamp': tsiso8601,
            '_unique_id': unique_id,
            'payload': {
                'samples': samples
            }
        }
        marshalled_payload = json.dumps(
            payload, separators=(',', ':'), sort_keys=True)
        message = json.dumps({
            'oslo.message': marshalled_payload,
            'oslo.version': '2.0',
        }, separators=(',', ':'), sort_keys=True)

        channel.basic_publish(exchange=self.amqp_exchange,
                              routing_key=self.amqp_queue,
                              body=message)
        self.messages += 1

    def report(self, tag, force=False):
        """
        Log the status.

        :param tag: One of three: starting, running, ended.
        :param force: Forces the report to be displayed even if the interval
            between reports has not been reached.
        """
        now = time.time()
        if not force and now - self.last_report_time < self.report_interval:
            return
        self._report(tag, now)
        self.last_report_time = now
        self.scanned_since_last_report = 0

    def scan(self):
        """
        List all buckets and send billing messages to the RabbitMQ.
        """
        self.passes += 1
        self._reset_stats()

        self.report('starting', force=True)
        self.start_time = time.time()

        connection, channel = self._amqp_connect()
        samples = []
        try:
            buckets = self.backend.list_all_buckets()
            for bucket in buckets:
                if not self.running:
                    self.logger.info('Stop asked')
                    break
                try:
                    sample = self.bucket_to_sample(bucket)
                    if sample:
                        self.buckets += 1
                        samples.append(sample)
                        if len(samples) >= self.batch_size:
                            try:
                                self.send_message(channel, samples)
                            finally:
                                samples.clear()
                    else:
                        self.ignored += 1
                except MalformedBucket:
                    self.missing_info += 1
                except Exception:
                    self.errors += 1
                    self.logger.exception('Failed to process bucket')
                self.scanned_since_last_report += 1
                self.report('running')
            else:
                try:
                    self.send_message(channel, samples)
                except Exception:
                    self.errors += 1
                    self.logger.exception('Failed to send the last message')
                self.report('ended', force=True)
        finally:
            if channel.is_open:
                channel.cancel()
            if connection.is_open:
                connection.close()

    def run(self):
        """
        Run passes successfully until agent is stopped.
        """
        if self.wait_random_time_before_starting:
            waiting_time_to_start = random.randint(0, self.scans_interval)
            self.logger.info('Wait %d secondes before starting',
                             waiting_time_to_start)
            for _ in range(waiting_time_to_start):
                if not self.running:
                    return
                time.sleep(1)
        while self.running:
            try:
                start = time.time()
                self.scan()
            except Exception:
                self.logger.exception('Failed to scan')
            finally:
                self._wait_next_pass(start)

    def stop(self):
        """
        Needed for gracefully stopping.
        """
        self.running = False

    def start(self):
        drop_privileges(self.conf.get('user', 'openio'))
        redirect_stdio(self.logger)

        def _on_sigquit(*_args):
            self.stop()
            sys.exit()

        def _on_sigint(*_args):
            self.stop()
            sys.exit()

        def _on_sigterm(*_args):
            self.stop()
            sys.exit()

        signal.signal(signal.SIGINT, _on_sigint)
        signal.signal(signal.SIGQUIT, _on_sigquit)
        signal.signal(signal.SIGTERM, _on_sigterm)

        self.run()
