# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
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


from oio.common.green import GreenPool, sleep

import re
import os
import glob

from six import iteritems
import pkg_resources

from oio.common.daemon import Daemon
from oio.common.http_urllib3 import get_pool_manager
from oio.common.easy_value import float_value, int_value, true_value
from oio.common.configuration import parse_config, validate_service_conf
from oio.common.logger import get_logger
from oio.common.client import ProxyClient
from oio.conscience.client import ConscienceClient
from oio.common.exceptions import OioException


def load_modules(group_name):
    modules = {}
    for entry_point in pkg_resources.iter_entry_points(group_name):
        cls = entry_point.load(require=False)
        modules[entry_point.name] = cls
    return modules


class ServiceWatcher(object):
    def __init__(self, conf, service, **kwargs):
        self.conf = conf
        self.running = False

        for k in ['host', 'port', 'type']:
            if k not in service:
                raise Exception(
                    'Missing field "%s" in service configuration' % k)
        self.name = '%s|%s|%s' % \
            (service['type'], service['host'], service['port'])

        self.service = service

        self.rise = int_value(self._load_item_config('rise'), 1)
        self.fall = int_value(self._load_item_config('fall'), 1)
        self.check_interval = float_value(
                self._load_item_config('check_interval'), 1)
        self.deregister_on_exit = true_value(
                self._load_item_config('deregister_on_exit', False))

        self.logger = get_logger(self.conf)
        self.pool_manager = get_pool_manager()
        self.cs = ConscienceClient(self.conf, pool_manager=self.pool_manager,
                                   logger=self.logger)
        # FIXME: explain that
        self.client = ProxyClient(self.conf, pool_manager=self.pool_manager,
                                  no_ns_in_url=True, logger=self.logger)
        self.last_status = False
        self.status = False
        self.failed = False
        self.service_definition = {
            'ns': self.conf['namespace'],
            'type': self.service['type'],
            'addr': '%s:%s' % (self.service['host'], self.service['port']),
            'score': 0,
            'tags': {}}
        if self.service.get('slots', None):
            self.service_definition['tags']['tag.slots'] = \
                    ','.join(self.service['slots'])
        for name, tag in (('location', 'tag.loc'),
                          ('service_id', 'tag.service_id'),
                          ('tls', 'tag.tls')):
            if self.service.get(name):
                self.service_definition['tags'][tag] = \
                    self.service[name]

        self.service_checks = list()
        self.service_stats = list()
        self.init_checkers(service)
        self.init_stats(service)

    def _load_item_config(self, item, default=None):
        return self.service.get(item, self.conf.get(item)) or default

    def start(self):
        self.logger.info('watcher "%s" starting', self.name)
        self.running = True
        self.watch()
        self.running = False

    def stop(self):
        self.logger.info('watcher "%s" stopping', self.name)
        if self.deregister_on_exit:
            self.logger.info('watcher "%s" deregister service', self.name)
            try:
                self.status = False
                self.last_status = False
                self.register()
            except Exception as e:
                self.logger.warn('Failed to register service: %s', e)
        self.running = False

    def check(self):
        """Perform the registered checks on the service until any of
        them fails of the end of the list is reached."""
        self.status = True
        for service_check in (x for x in self.service_checks if self.running):
            if not service_check.service_status():
                self.status = False
                return

    def get_stats(self):
        """Update service definition with all configured stats"""
        if not self.status:
            return
        collectors = (x for x in self.service_stats if self.running)
        try:
            for stat in collectors:
                stats = stat.get_stats()
                self.service_definition['tags'].update(stats)
        except Exception as ex:
            self.logger.debug("get_stats error: %s, skipping %s", ex,
                              [type(col).__name__ for col in collectors]
                              or "<nothing>")
            self.status = False

    def register(self):
        # only accept a final zero/down-registration when exiting
        if not self.running and self.status:
            return

        # Alert when the status changes
        if self.status != self.last_status:
            if self.status:
                self.logger.info('service "%s" is now up', self.name)
            else:
                self.logger.warn('service "%s" is now down', self.name)
            self.last_status = self.status

        # Use a boolean so we can easily convert it to a number in conscience
        self.service_definition['tags']['tag.up'] = self.status
        try:
            self.cs.register(self.service_definition, retries=False)
        except OioException as rqe:
            self.logger.warn("Failed to register service %s: %s",
                             self.service_definition["addr"], rqe)

    def watch(self):
        try:
            while self.running:
                self.check()
                self.get_stats()
                self.register()
                sleep(self.check_interval)
        except Exception as e:
            self.logger.warn('ERROR in watcher "%s"', e)
            self.failed = True
            raise e
        finally:
            self.logger.info('watcher "%s" stopped', self.name)

    def init_checkers(self, service):
        for check in service['checks']:
            check['host'] = check.get('host') or service['host']
            check['port'] = check.get('port') or service['port']
            check['name'] = check.get('name') or "%s|%s|%s" % \
                (check['type'], check['host'], check['port'])
            check['rise'] = check.get('rise') or self.rise
            check['fall'] = check.get('fall') or self.fall

            check['type'] = check.get('type') or 'unknown'
            service_check_class = CHECKERS_MODULES.get(check['type'])
            if not service_check_class:
                raise Exception(
                    'Invalid check type "%s", valid types: %s' %
                    (check['type'], ', '.join(CHECKERS_MODULES.keys())))
            service_check = service_check_class(self, check, self.logger)
            self.service_checks.append(service_check)

    def init_stats(self, service):
        """Initialize service stat fetchers"""
        self.service_stats[:] = []
        for stat in service['stats']:
            stat.setdefault('host', service['host'])
            stat.setdefault('port', service['port'])
            stat.setdefault('path', "")
            service_stat_class = STATS_MODULES.get(stat['type'], None)
            if not service_stat_class:
                raise Exception(
                    'Invalid stat type "%s", valid types: %s' %
                    (stat['type'], ', '.join(STATS_MODULES.keys())))
            service_stat = service_stat_class(self, stat, self.logger)
            self.service_stats.append(service_stat)


class ConscienceAgent(Daemon):
    def __init__(self, conf):
        validate_service_conf(conf)
        self.running = True
        self.conf = conf
        self.logger = get_logger(conf)
        self.load_services()
        self.check_for_conflicts()
        self.init_watchers(self.conf['services'])

    def stop(self):
        self.running = False

    def run(self, *args, **kwargs):
        try:
            self.logger.info('conscience agent: starting')

            pool = GreenPool(len(self.watchers))
            for watcher in self.watchers:
                pool.spawn(watcher.start)

            self.running = True
            while self.running:
                sleep(1)
                for w in self.watchers:
                    if w.failed:
                        self.watchers.remove(w)
                        self.logger.warn('restart watcher "%s"', w.name)
                        new_w = ServiceWatcher(self.conf, w.service)
                        self.watchers.append(new_w)
                        pool.spawn(new_w.start)

        except Exception as e:
            self.logger.error('ERROR in main loop %s', e)
            raise e
        finally:
            self.logger.warn('conscience agent: stopping')
            self.running = False
            self.stop_watchers()

    def init_watchers(self, services):
        watchers = []
        for _name, conf in iteritems(services):
            try:
                watchers.append(ServiceWatcher(self.conf, conf))
            except Exception:
                self.logger.exception("Failed to load configuration from %s",
                                      conf.get('cfgfile', 'main config file'))
        self.watchers = watchers

    def stop_watchers(self):
        for watcher in self.watchers:
            watcher.stop()

    def load_services(self):
        include_dir = self.conf.get('include_dir')
        self.conf['services'] = self.conf.get('services') or {}
        if include_dir:
            include_dir = os.path.expanduser(include_dir)

            cfgfiles = [f for d in include_dir.split(':')
                        for f in glob.glob(d + "/*")
                        if re.match(r'.+\.(json|yml|yaml)$', f)]
            for cfgfile in cfgfiles:
                name = os.path.basename(cfgfile)
                name = os.path.splitext(name)[0]
                config = parse_config(cfgfile)
                if not config:
                    self.logger.warning('Ignoring empty config file %s',
                                        cfgfile)
                    continue
                if not isinstance(config, dict):
                    raise TypeError(
                        'Expecting YAML dictionary for the config file %s',
                        cfgfile)
                self.conf['services'][name] = config
                self.conf['services'][name]['cfgfile'] = cfgfile

    def check_for_conflicts(self):
        per_sock = dict()
        for name, desc in self.conf['services'].items():
            hostport = ':'.join((desc['host'], str(desc.get('port', 80))))
            per_sock.setdefault(hostport, list()).append((name, desc))

        for hostport, services in per_sock.items():
            if len(services) > 1:
                conflicting = ['%s (%s)' % (name, desc['type'])
                               for name, desc in services]
                self.logger.error(
                    ("The following services are configured with the same "
                     "endpoint (%s): %s. Please fix the configuration. "
                     "Until then, they won't be updated."),
                    hostport, ', '.join(conflicting))
                for name, _ in services:
                    del self.conf['services'][name]


CHECKERS_MODULES = load_modules('oio.conscience.checker')
STATS_MODULES = load_modules('oio.conscience.stats')
