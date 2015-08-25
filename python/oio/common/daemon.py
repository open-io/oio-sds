import sys
import signal

import os
from re import sub

from oio.common.utils import read_conf
from oio.common.utils import drop_privileges
from oio.common.utils import redirect_stdio
from oio.common.utils import get_logger


class Daemon(object):
    def __init__(self, conf):
        self.conf = conf
        self.logger = get_logger(conf)

    def run(self, *args, **kwargs):
        raise NotImplementedError('run not implemented')

    def start(self, **kwargs):
        drop_privileges(self.conf.get('user', 'openio'))
        redirect_stdio(self.logger)

        def kill_children(*args):
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            os.killpg(0, signal.SIGTERM)
            sys.exit()

        signal.signal(signal.SIGTERM, kill_children)

        self.run(**kwargs)


def run_daemon(klass, conf_file, section_name=None, **kwargs):
    if section_name is None:
        section_name = sub(r'([a-z])([A-Z])', r'\1-\2', klass.__name__).lower()
    conf = read_conf(
        conf_file, section_name, use_yaml=kwargs.pop('use_yaml', False))
    logger = get_logger(
        conf, section_name, verbose=kwargs.pop('verbose', False))
    try:
        klass(conf).start(**kwargs)
    except KeyboardInterrupt:
        logger.info('User interrupt')
    logger.info('Daemon exited')
