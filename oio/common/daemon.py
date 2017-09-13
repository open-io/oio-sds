# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
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


import sys
import signal

import os
from re import sub

import eventlet.hubs
from oio.common.utils import drop_privileges
from oio.common.configuration import read_conf
from oio.common.logger import redirect_stdio, get_logger
from oio.common.green import get_hub


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
    eventlet.hubs.use_hub(get_hub())
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
