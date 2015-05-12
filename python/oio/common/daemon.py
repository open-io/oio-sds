import os
import sys
import logging
import signal

from oio.common.utils import read_conf


class Daemon(object):

    def run(self, *args, **kwargs):
        raise NotImplementedError('run not implemented')

    def start(self, **kwargs):

        def kill_children(*args):
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            os.killpg(0, signal.SIGTERM)
            sys.exit()

        signal.signal(signal.SIGTERM, kill_children)

        self.run(**kwargs)


def run_daemon(klass, conf_file, section_name=None, **kwargs):
    if section_name is None:
        section_name = klass.__name__.lower()
    conf = read_conf(conf_file, section_name)
    logger = logging.getLogger(__name__)
    try:
        klass(conf).start(**kwargs)
    except KeyboardInterrupt:
        logger.info('User interrupt')
    logger.info('Daemon exited')
