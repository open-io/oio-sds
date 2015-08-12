import os
from ConfigParser import SafeConfigParser


def load_functest_config():
    default_conf_path = os.path.abspath('../../../etc/blob-auditor.conf-sample')
    config_file = os.environ.get('SDS_TEST_CONFIG_FILE', default_conf_path)
    config = SafeConfigParser()
    config.read(config_file)
    conf = config._sections['blob-auditor']
    return conf
