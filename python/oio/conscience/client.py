import json
import socket

from eventlet import sleep
from eventlet import connect
from eventlet import spawn_n

from oio.common.http import requests
from oio.common.utils import get_logger
from oio.common.utils import validate_service_conf
from oio.common.utils import load_namespace_conf


class RegisterThread(object):
    def __init__(self, conf, ns_conf, instance_info):
        self.conf = conf
        self.logger = get_logger(conf)
        self.instance_info = instance_info
        self.proxy_addr = ns_conf.get('proxy')
        self.ns = conf.get('namespace')
        self.register_interval = 5
        self.register_uri = None

    def run(self):
        while True:
            try:
                self._health_check()
                self._register()
            except Exception:
                self.logger.warn('Failed to register instance')
            sleep(self.register_interval)

    def _register(self):
        if not self.register_uri:
            self.register_uri = 'http://%s/v1.0/cs/%s/%s' % (
                self.proxy_addr,
                self.ns,
                self.instance_info['type']
            )
        resp = requests.put(self.register_uri,
                            data=json.dumps(self.instance_info))
        if resp.status_code is not 200:
            raise Exception(resp.text)

    def _health_check(self):
        up = False
        try:
            connect((self.instance_info['bind_addr'],
                     self.instance_info['bind_port']))
            up = True
        except (socket.error, Exception):
            self.logger.warn('Failed health check, setting instance'
                             'status to down')
        self._change_status(up)

    def _change_status(self, status):
        self.instance_info['up'] = status


class ConscienceClient(object):
    def __init__(self, conf, register=False):
        validate_service_conf(conf)
        self.ns = conf.get('namespace')
        ns_conf = load_namespace_conf(self.ns)
        self.conf = conf
        self.logger = get_logger(conf)
        self.proxy_addr = ns_conf.get('proxy')
        if register:
            instance_info = {
                'ns': conf.get('namespace'),
                'score': 0,
                'type': conf.get('type'),
                'addr': '%s:%s' % (conf.get('bind_addr'),
                                   conf.get('bind_port')),
                'tags': conf.get('tags')
            }
            register_thread = RegisterThread(conf, ns_conf, instance_info)
            spawn_n(register_thread.run)

    def next_instance(self, pool):
        uri = 'http://%s/v1.0/lb/%s/%s' % (self.proxy_addr, self.ns, pool)
        resp = requests.get(uri)
        if resp.status_code == 200:
            return resp.json()[0]
        else:
            raise Exception('Error while getting next instance')



