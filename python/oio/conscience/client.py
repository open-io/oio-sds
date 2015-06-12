import json
import socket

from eventlet import sleep
from eventlet import connect
from eventlet import spawn_n

from oio.common.http import requests
from oio.common.utils import get_logger


class RegisterThread(object):
    def __init__(self, conf, instance_info):
        self.conf = conf
        self.logger = get_logger(conf)
        self.instance_info = instance_info
        self.proxyd_uri = self.conf.get('proxyd_uri')
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
            self.register_uri = '%s/v1.0/cs/%s/%s' % (
                self.proxyd_uri,
                self.instance_info['ns'],
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
        self.instance_info['up'] = up


class ConscienceClient(object):
    def __init__(self, conf, register=False):
        self.conf = conf
        self.logger = get_logger(conf)
        self.proxyd_uri = self.conf.get('proxyd_uri')
        self.instance_info = {
            'ns': conf.get('namespace'),
            'score': 0,
            'type': conf.get('type'),
            'addr': '%s:%s' % (self.instance_info['bind_addr'],
                               self.instance_info['bind_port']),
            'tags': conf.get('tags')
        }

        if register:
            register_thread = RegisterThread(conf)
            spawn_n(register_thread.run)

    def next_instance(self, pool):
        uri = '%s/v1.0/lb/%s/%s' % (self.proxyd_uri, self.instance_info['ns'],
                                    pool)
        resp = requests.get(uri)
        if resp.status_code is 200:
            return resp.json()
        else:
            raise Exception('Error while getting next instance')



