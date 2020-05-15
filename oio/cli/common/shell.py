# Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""Command-line interface to the OpenIO APIs"""

import sys
import logging
from cliff.app import App

from oio import __version__ as oio_version
from oio.cli import add_common_parser_options
from oio.cli.common.commandmanager import CommandManager
from oio.cli.common.clientmanager import ClientManager, get_plugin_module
from oio.common.json import json

json.encoder.FLOAT_REPR = lambda o: format(o, '.6f')
LOG = logging.getLogger(__name__)

GROUP_LIST = ["account", "container", "object", "reference", "volume",
              "directory", "events", "cluster", "election", "lifecycle",
              "rdir", "zk"]


class CommonShell(App):

    def __init__(self, namespace):
        super(CommonShell, self).__init__(
            description=__doc__.strip() if __doc__ else None,
            version=oio_version,
            command_manager=CommandManager(namespace),
            deferred_help=True)
        self.client_manager = None
        self.profiler = None

    def configure_logging(self):
        super(CommonShell, self).configure_logging()

        root_logger = logging.getLogger('')

        if self.options.verbose_level == 0:
            root_logger.setLevel(logging.ERROR)
        elif self.options.verbose_level == 1:
            root_logger.setLevel(logging.WARNING)
        elif self.options.verbose_level == 2:
            root_logger.setLevel(logging.INFO)
        elif self.options.verbose_level >= 3:
            root_logger.setLevel(logging.DEBUG)

        requests_log = logging.getLogger('requests')

        if self.options.debug:
            requests_log.setLevel(logging.DEBUG)
        else:
            requests_log.setLevel(logging.ERROR)

        urllib3_log = logging.getLogger('urllib3')

        if self.options.debug:
            urllib3_log.setLevel(logging.DEBUG)
        else:
            urllib3_log.setLevel(logging.WARNING)

        cliff_log = logging.getLogger('cliff')
        cliff_log.setLevel(logging.ERROR)

        stevedore_log = logging.getLogger('stevedore')
        stevedore_log.setLevel(logging.ERROR)

    def start_profiling(self):
        import importlib
        if self.options.profiler in ('cProfile', 'profile'):
            prof_mod = importlib.import_module(self.options.profiler)
            self.profiler = prof_mod.Profile()
            self.profiler.enable()
        elif self.options.profiler == 'GreenletProfiler':
            prof_mod = importlib.import_module(self.options.profiler)
            self.profiler = prof_mod
            LOG.debug("Using %s, clock type: %s",
                      self.profiler, self.profiler.get_clock_type())
            self.profiler.start(builtins=True)
        else:
            raise ValueError('Unknown profiler: %s' % self.options.profiler)

    def stop_profiling(self):
        import os
        fname = self.options.profile % {'pid': os.getpid()}
        if self.options.profiler in ('cProfile', 'profile'):
            self.profiler.disable()
            self.profiler.dump_stats(fname)
            LOG.info('Profiling data saved in %s', fname)
        elif self.options.profiler == 'GreenletProfiler':
            stats = self.profiler.get_func_stats()
            stats.save(fname, type='callgrind')
            LOG.info('Profiling data saved in %s', fname)
        else:
            LOG.error('Something bad happened with profiling data!')

    def build_option_parser(self, description, version):
        parser = super(CommonShell, self).build_option_parser(
            description, version)
        add_common_parser_options(parser)
        return parser

    def initialize_app(self, argv):
        super(CommonShell, self).initialize_app(argv)
        if self.options.profile and self.options.profile_early:
            self.start_profiling()

    def prepare_to_run_command(self, cmd):
        LOG.debug(
            'command: %s -> %s.%s',
            getattr(cmd, 'cmd_name', '<none>'),
            cmd.__class__.__module__,
            cmd.__class__.__name__)
        if self.options.profile and not self.options.profile_early:
            self.start_profiling()

    def clean_up(self, cmd, result, err):
        LOG.debug('clean up %s: %s', cmd.__class__.__name__, err or '')
        if self.profiler:
            self.stop_profiling()


class OpenIOShell(CommonShell):

    def __init__(self):
        super(OpenIOShell, self).__init__('oiopy.cli')

    def run(self, argv):
        try:
            res = super(OpenIOShell, self).run(argv)
            perfdata = self.client_manager.cli_conf().get('perfdata')
            if perfdata:
                LOG.debug("Performance data: x %s",
                          json.dumps(perfdata, sort_keys=True, indent=4))
            return res
        except Exception as e:
            LOG.error('Exception raised: %s', e)
            return 1

    def build_option_parser(self, description, version):
        parser = super(OpenIOShell, self).build_option_parser(
            description, version)

        # This is specific to download/upload operation, thus should not
        # be needed in the "admin" CLI.
        parser.add_argument(
            "--dump-perfdata",
            action='store_true',
            help="Force the API to dump performance data")
        return parser

    def initialize_app(self, argv):
        super(OpenIOShell, self).initialize_app(argv)

        try:
            api = argv[0]
            module_name = 'oio.cli.%s.client' % api
            get_plugin_module(module_name)
            cmd_group = 'openio.%s' % api
            self.command_manager.add_command_group(cmd_group)
            LOG.debug('%s API: cmd group %s', api, cmd_group)
        except ImportError:
            for api in GROUP_LIST:
                cmd_group = 'openio.%s' % api
                self.command_manager.add_command_group(cmd_group)
                LOG.debug('%s API: cmd group %s', api, cmd_group)
        except IndexError:
            for api in GROUP_LIST:
                module_name = 'oio.cli.%s.client' % api
                get_plugin_module(module_name)
                cmd_group = 'openio.%s' % api
                self.command_manager.add_command_group(cmd_group)
                LOG.debug('%s API: cmd group %s', api, cmd_group)

        self.print_help_if_requested()

        options = {
            'namespace': self.options.ns,
            'account_name': self.options.account,
            'proxyd_url': self.options.proxyd_url,
            'admin_mode': self.options.admin_mode,
            'log_level': logging.getLevelName(
                logging.getLogger('').getEffectiveLevel()),
            'is_cli': True,
        }
        if self.options.dump_perfdata:
            options['perfdata'] = dict()
        self.client_manager = ClientManager(options)


def main(argv=sys.argv[1:]):
    return OpenIOShell().run(argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
