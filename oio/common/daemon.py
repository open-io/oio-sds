# Copyright (C) 2015-2018 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2024 OVH SAS
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


import os
import signal
import sys
from re import sub

from oio.common.configuration import read_conf
from oio.common.green import eventlet_hubs, get_hub
from oio.common.logger import get_logger, redirect_stdio
from oio.common.utils import drop_privileges


class Daemon(object):
    def __init__(self, conf):
        self.conf = conf
        self.logger = get_logger(conf)

    def run(self, *args, **kwargs):
        raise NotImplementedError("run not implemented")

    def stop(self):
        """
        Default stop handler: exit the process.

        We suggest to override this method, there is probably a cleanup to do
        before actually exiting the process.
        """
        os.killpg(0, signal.SIGTERM)
        sys.exit()

    def start(self, **kwargs):
        drop_privileges(self.conf.get("user", "openio"))
        redirect_stdio(self.logger)

        def kill_children():
            self.stop()

        def _on_SIGTERM(*args):
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            kill_children()

        def _on_SIGQUIT(*args):
            signal.signal(signal.SIGQUIT, signal.SIG_IGN)
            kill_children()

        def _on_SIGINT(*args):
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            kill_children()

        signal.signal(signal.SIGINT, _on_SIGINT)
        signal.signal(signal.SIGQUIT, _on_SIGQUIT)
        signal.signal(signal.SIGTERM, _on_SIGTERM)

        self.run(**kwargs)


def run_daemon(klass, conf_file, section_name=None, **kwargs):
    eventlet_hubs.use_hub(get_hub())
    if section_name is None:
        section_name = sub(r"([a-z])([A-Z])", r"\1-\2", klass.__name__).lower()
    conf = read_conf(conf_file, section_name, use_yaml=kwargs.pop("use_yaml", False))
    logger = get_logger(conf, section_name, verbose=kwargs.pop("verbose", False))
    try:
        klass(conf, conf_file=conf_file).start(**kwargs)
    except KeyboardInterrupt:
        logger.info("User interrupt")
    logger.info("Daemon exited")
