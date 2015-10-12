from __future__ import print_function
import sys
import os
import fixtures
import json
import testtools


def get_config(defaults=None):
    conf = {}
    if defaults is not None:
        conf.update(defaults)

    default_conf_path = os.path.expanduser('~/.oio/sds/conf/test.conf')
    conf_file = os.environ.get('SDS_TEST_CONFIG_FILE', default_conf_path)

    try:
        with open(conf_file, 'r') as f:
            conf = json.load(f)
    except SystemExit:
        if not os.path.exists(conf_file):
            reason = 'file not found'
        elif not os.access(conf_file, os.R_OK):
            reason = 'permission denied'
        else:
            reason = 'n/a'
            print('Unable to read test config %s (%s)' % (conf_file, reason),
                  file=sys.stderr)
    return conf


class BaseTestCase(testtools.TestCase):
    def setUp(self):
        super(BaseTestCase, self).setUp()
        self.useFixture(fixtures.TempHomeDir())
        self.conf = get_config()
