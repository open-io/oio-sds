import os
from ConfigParser import SafeConfigParser


def load_functest_config():
    default_conf_path = os.path.expanduser('~/.oio/sds/conf/test.conf')
    config_file = os.environ.get('SDS_TEST_CONFIG_FILE', default_conf_path)
    config = SafeConfigParser()
    config.read(config_file)
    return config
