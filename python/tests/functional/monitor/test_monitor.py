import os
import subprocess
import unittest
import json

import requests


class TestMonitorFunctional(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestMonitorFunctional, self).__init__(*args, **kwargs)
        self._load_config()

    def _load_config(self):
        self.test_dir = os.path.expanduser('~/.oio/sds/')
        with open(self.test_dir + 'conf/test.conf') as f:
            self.conf = json.load(f)

        with open(self.test_dir + 'run/NS-rawx-httpd-1.pid') as f:
            self.rawx_pid = f.read().split("\n")[0]
            get_rawx_pids = os.popen(
                "ps -eo pid,ppid | grep " + self.rawx_pid).read()
            self.rawx_pid = str(
                max([int(s) for s in get_rawx_pids.split() if s.isdigit()]))

        get_srv_pid = os.popen("ps -eo pid,comm | grep meta0").read()
        self.srv_pid = str(
            [int(s) for s in get_srv_pid.split() if s.isdigit()][0])

        self.namespace = self.conf['namespace']
        self.proxyd = self.conf['proxyd_uri'] + "/v2.0/cs/"
        self.session = requests.session()

        self.rawx_test = self.conf["namespace"] + '|rawx|' + self.conf["rawx"][
            0]
        self.srv_test = (self.conf["namespace"] + '|meta0|' +
                         self.conf["meta0"][0])
        self.account_test = (self.conf["namespace"] + '|account|' +
                             self.conf["account_addr"][0])
        self.file_path = os.path.abspath("..") + '/'

    def setUp(self):
        super(TestMonitorFunctional, self).setUp()

    def tearDown(self):
        try:
            self.kill_slow_server()
        except Exception:
            pass
        for pid in [self.rawx_pid, self.srv_pid]:
            try:
                os.system("kill -CONT " + self.rawx_pid)
            except Exception:
                pass
        super(TestMonitorFunctional, self).tearDown()

    def set_slow_server(self):
        self.server_test = self.conf["namespace"] + '|external|127.0.0.1:9999'
        os.system("python .slow_server.py 9999 &")
        get_server_pid = os.popen("ps -eo pid,args | grep slow_server").read()
        self.server_pid = str(
            [int(s) for s in get_server_pid.split() if s.isdigit()][0])

    def kill_slow_server(self):
        os.system("kill " + self.server_pid)

    def call_shell(self, tested_file, aim):
        s = subprocess.Popen([self.file_path + tested_file, aim],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = s.communicate()
        return out, err

    def test_rawx_on(self):
        out, err = self.call_shell('rawx-monitor.py', self.rawx_test)
        self.assertTrue('stat.total_reqpersec' in out)
        self.assertEqual(err, '')

    def test_rawx_slow(self):
        self.set_slow_server()
        out, err = self.call_shell('rawx-monitor.py', self.server_test)
        self.assertEqual(out, '')
        self.assertTrue('socket.timeout' in err)

    def test_rawx_off(self):
        os.system("kill -STOP " + self.rawx_pid)
        out, err = self.call_shell('rawx-monitor.py', self.rawx_test)
        self.assertEqual(out, '')
        self.assertTrue('socket.timeout' in err)

    def test_rainx_on(self):
        out, err = self.call_shell('rainx-monitor.py', self.rawx_test)
        self.assertEqual(out, '')
        self.assertEqual(err, '')

    def test_rainx_slow(self):
        self.set_slow_server()
        out, err = self.call_shell('rainx-monitor.py', self.server_test)
        self.assertEqual(out, '')
        self.assertTrue('socket.timeout' in err)

    def test_rainx_off(self):
        os.system("kill -STOP " + self.rawx_pid)
        out, err = self.call_shell('rainx-monitor.py', self.rawx_test)
        self.assertEqual(out, '')
        self.assertTrue('socket.timeout' in err)

    def test_proxy_on(self):
        out, err = self.call_shell('proxy-monitor.py', self.srv_test)
        self.assertEqual(out, '')
        self.assertFalse(
            'timed out' in err)

    def test_proxy_slow(self):
        self.set_slow_server()
        out, err = self.call_shell('proxy-monitor.py', self.server_test)
        self.assertEqual(out, '')
        self.assertTrue('timed out' in err)

    def test_proxy_off(self):
        os.system("kill -STOP " + self.srv_pid)
        out, err = self.call_shell('proxy-monitor.py', self.srv_test)
        self.assertEqual(out, '')
        self.assertTrue('timed out' in err)
        os.system("kill -CONT " + self.srv_pid)

    def test_account_on(self):
        out, err = self.call_shell('account-monitor.py', self.srv_test)
        self.assertEqual(out, '')
        self.assertFalse(err, '')

    def test_account_slow(self):
        self.set_slow_server()
        out, err = self.call_shell('account-monitor.py', self.server_test)
        self.assertEqual(out, '')
        self.assertTrue('timed out' in err)

    def test_account_off(self):
        os.system("kill -STOP " + self.srv_pid)
        out, err = self.call_shell('account-monitor.py', self.srv_test)
        self.assertEqual(out, '')
        self.assertTrue('timed out' in err)
