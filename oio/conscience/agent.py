import re
import os

import pkg_resources
from eventlet import GreenPool, sleep

from oio.common.daemon import Daemon
from oio.common.http import requests
from oio.common.utils import get_logger, float_value, validate_service_conf, \
    int_value, parse_config, true_value
from oio.common.client import Client
from oio.conscience.client import ConscienceClient


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
        self.session = requests.Session()
        self.cs = ConscienceClient(self.conf, session=self.session)
        self.client = Client(self.conf, session=self.session)
        self.last_status = False
        self.failed = False
        self.service_definition = {
            'ns': self.conf['namespace'],
            'type': self.service['type'],
            'addr': '%s:%s' % (self.service['host'], self.service['port']),
            'score': 0,
            'tags': {}}
        if self.service.get('location', None):
            self.service_definition['tags']['tag.loc'] = \
                    self.service['location']
        if self.service.get('slots', None):
            self.service_definition['tags']['tag.slots'] = \
                    ','.join(self.service['slots'])
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

    def stop(self):
        self.logger.info('watcher "%s" stopping', self.name)
        if self.deregister_on_exit:
            self.logger.info('watcher "%s" deregister service', self.name)
            try:
                self.last_status = False
                self.register()
            except Exception as e:
                self.logger.warn('Failed to register service: %s', e)
        self.running = False

    def check(self):
        status = True
        for service_check in self.service_checks:
            if not service_check.service_status():
                status = False

        if status != self.last_status:
            if status:
                self.logger.info('service "%s" is now up', self.name)
            else:
                self.logger.warn('service "%s" is now down', self.name)
            self.last_status = status

    def get_stats(self):
        """Update service definition with all configured stats"""
        if not self.last_status:
            return
        for stat in self.service_stats:
            stats = stat.get_stats()
            self.service_definition['tags'].update(stats)

    def register(self):
        # Use a boolean so we can easily convert it to a number in conscience
        self.service_definition['tags']['tag.up'] = self.last_status
        try:
            self.cs.register(self.service['type'], self.service_definition)
        except requests.RequestException as rqe:
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
        self.conf = conf
        self.logger = get_logger(conf)
        self.load_services()
        self.init_watchers(self.conf['services'])

    def run(self, *args, **kwargs):
        try:
            self.logger.info('conscience agent: starting')

            pool = GreenPool(len(self.watchers))
            for watcher in self.watchers:
                pool.spawn(watcher.start)

            while True:
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
            self.stop_watchers()

    def init_watchers(self, services):
        watchers = []
        for _name, conf in services.iteritems():
            watchers.append(ServiceWatcher(self.conf, conf))
        self.watchers = watchers

    def stop_watchers(self):
        for watcher in self.watchers:
            watcher.stop()

    def load_services(self):
        include_dir = self.conf.get('include_dir')
        self.conf['services'] = self.conf.get('services') or {}
        if include_dir:
            include_dir = os.path.expanduser(include_dir)

            cfgfiles = [os.path.join(include_dir, f)
                        for f in os.listdir(include_dir)
                        if re.match(r'.+\.(json|yml|yaml)$', f)]
            for cfgfile in cfgfiles:
                name = os.path.basename(cfgfile)
                name = os.path.splitext(name)[0]
                self.conf['services'][name] = parse_config(cfgfile)

CHECKERS_MODULES = load_modules('oio.conscience.checker')
STATS_MODULES = load_modules('oio.conscience.stats')
