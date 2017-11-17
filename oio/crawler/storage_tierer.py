# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
#
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

import time

from oio.account.client import AccountClient
from oio.common import exceptions as exc
from oio.common.daemon import Daemon
from oio.common.exceptions import NotFound
from oio.common.utils import cid_from_name
from oio.common.easy_value import int_value
from oio.common.logger import get_logger
from oio.common.green import ratelimit
from oio.container.client import ContainerClient
from oio.content.factory import ContentFactory

SLEEP_TIME = 30

CONF_ACCOUNT = 'account'
CONF_OUTDATED_THRESHOLD = 'outdated_threshold'
CONF_NEW_POLICY = 'new_policy'


class StorageTiererWorker(object):

    def __init__(self, conf, logger):
        self.conf = conf
        self.logger = logger
        self.account = conf[CONF_ACCOUNT]
        self.container_client = ContainerClient(self.conf, logger=self.logger)
        self.account_client = AccountClient(self.conf, logger=self.logger)
        self.content_factory = ContentFactory(self.conf)
        self.passes = 0
        self.errors = 0
        self.last_reported = 0
        self.contents_run_time = 0
        self.total_contents_processed = 0
        self.report_interval = int_value(
            conf.get('report_interval'), 3600)
        self.max_contents_per_second = int_value(
            conf.get('contents_per_second'), 30)
        self.container_fetch_limit = int_value(
            conf.get('container_fetch_limit'), 100)
        self.content_fetch_limit = int_value(
            conf.get('content_fetch_limit'), 100)
        self.outdated_threshold = int_value(
            conf.get(CONF_OUTDATED_THRESHOLD), 9999999999)
        self.new_policy = conf.get(CONF_NEW_POLICY)

    def _list_containers(self):
        container = None
        while True:
            resp = self.account_client.container_list(
                self.account, marker=container,
                limit=self.container_fetch_limit)
            if len(resp["listing"]) == 0:
                break
            for container, _, _, _ in resp["listing"]:
                yield container

    def _list_contents(self):
        for container in self._list_containers():
            marker = None
            while True:
                try:
                    _, listing = self.container_client.content_list(
                        account=self.account, reference=container,
                        limit=self.content_fetch_limit, marker=marker)
                except NotFound:
                    self.logger.warn(
                        "Container %s appears in account but doesn't exist",
                        container)
                    break
                if len(listing["objects"]) == 0:
                    break
                for obj in listing["objects"]:
                    marker = obj["name"]
                    if obj["mtime"] > time.time() - self.outdated_threshold:
                        continue
                    if obj["policy"] == self.new_policy:
                        continue
                    container_id = cid_from_name(self.account, container)
                    yield (container_id, obj["content"])

    def run(self):
        start_time = report_time = time.time()

        total_errors = 0

        for (container_id, content_id) in self._list_contents():
            self.safe_change_policy(container_id, content_id)

            self.contents_run_time = ratelimit(
                self.contents_run_time,
                self.max_contents_per_second
            )
            self.total_contents_processed += 1
            now = time.time()

            if now - self.last_reported >= self.report_interval:
                self.logger.info(
                    '%(start_time)s '
                    '%(passes)d '
                    '%(errors)d '
                    '%(c_rate).2f '
                    '%(total).2f ' % {
                        'start_time': time.ctime(report_time),
                        'passes': self.passes,
                        'errors': self.errors,
                        'c_rate': self.passes / (now - report_time),
                        'total': (now - start_time)
                    }
                )
                report_time = now
                total_errors += self.errors
                self.passes = 0
                self.errors = 0
                self.last_reported = now
        elapsed = (time.time() - start_time) or 0.000001
        self.logger.info(
            '%(elapsed).02f '
            '%(errors)d '
            '%(content_rate).2f ' % {
                'elapsed': elapsed,
                'errors': total_errors + self.errors,
                'content_rate': self.total_contents_processed / elapsed
            }
        )

    def safe_change_policy(self, container_id, content_id):
        try:
            self.change_policy(container_id, content_id)
        except Exception:
            self.errors += 1
            self.logger.exception("ERROR while changing policy for content "
                                  "%s/%s", container_id, content_id)
        self.passes += 1

    def change_policy(self, container_id, content_id):
        self.logger.info("Changing policy for content %s/%s",
                         container_id, content_id)
        self.content_factory.change_policy(
            container_id, content_id, self.new_policy)


class StorageTierer(Daemon):
    def __init__(self, conf, **kwargs):
        super(StorageTierer, self).__init__(conf)
        self.logger = get_logger(conf)
        if not conf.get(CONF_ACCOUNT):
            raise exc.ConfigurationException(
                "No account specified for storage tiering "
                "(token '%s'" % CONF_ACCOUNT)
        if not conf.get(CONF_OUTDATED_THRESHOLD):
            raise exc.ConfigurationException(
                "No threshold specified for storage tiering "
                "(token '%s'" % CONF_OUTDATED_THRESHOLD)
        if not conf.get(CONF_NEW_POLICY):
            raise exc.ConfigurationException(
                "No new policy specified for storage tiering "
                "(token '%s'" % CONF_NEW_POLICY)
        if conf.get('syslog_prefix'):
            print("Logging to syslog, with prefix '%(syslog_prefix)s'" % conf)

    def run(self, *args, **kwargs):
        while True:
            try:
                worker = StorageTiererWorker(self.conf, self.logger)
                worker.run()
            except Exception as e:
                self.logger.exception('ERROR during storage tiering: %s', e)
            self._sleep()

    def _sleep(self):
        time.sleep(SLEEP_TIME)
