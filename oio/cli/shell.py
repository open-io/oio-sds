# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
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
from oio.common.utils import env
from oio.cli.commandmanager import CommandManager
from oio.cli import clientmanager


class OpenIOShell(App):
    log = logging.getLogger(__name__)

    def __init__(self):
        super(OpenIOShell, self).__init__(
            description=__doc__.strip() if __doc__ else None,
            version=oio_version,
            command_manager=CommandManager('oiopy.cli'),
            deferred_help=True)
        self.api_version = {}
        self.client_manager = None

    def configure_logging(self):
        super(OpenIOShell, self).configure_logging()
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

    def run(self, argv):
        try:
            return super(OpenIOShell, self).run(argv)
        except Exception as e:
            self.log.error('Exception raised: ' + str(e))
            return 1

    def build_option_parser(self, description, version):
        parser = super(OpenIOShell, self).build_option_parser(
            description,
            version)

        parser.add_argument(
            '--oio-ns',
            metavar='<namespace>',
            dest='ns',
            default=env('OIO_NS'),
            help='Namespace name (Env: OIO_NS)',
        )
        parser.add_argument(
            '--oio-account',
            metavar='<account>',
            dest='account_name',
            default=env('OIO_ACCOUNT'),
            help='Account name (Env: OIO_ACCOUNT)'
        )
        parser.add_argument(
            '--oio-proxyd-url',
            metavar='<proxyd url>',
            dest='proxyd_url',
            default=env('OIO_PROXYD_URL'),
            help='Proxyd URL (Env: OIO_PROXYD_URL)'
        )
        parser.add_argument(
            "--admin",
            dest='admin_mode',
            action='store_true',
            help="Add 'admin mode' flag to all proxy requests")

        return clientmanager.build_plugin_option_parser(parser)

    def initialize_app(self, argv):
        super(OpenIOShell, self).initialize_app(argv)

        for module in clientmanager.PLUGIN_MODULES:
            api = module.API_NAME
            cmd_group = 'openio.' + api.replace('-', '_')
            self.command_manager.add_command_group(cmd_group)
            self.log.debug('%s API: cmd group %s', api, cmd_group)
        self.command_manager.add_command_group('openio.common')
        self.command_manager.add_command_group('openio.ext')

        options = {
            'namespace': self.options.ns,
            'account_name': self.options.account_name,
            'proxyd_url': self.options.proxyd_url,
            'admin_mode': self.options.admin_mode,
            'log_level': logging.getLevelName(
                logging.getLogger('').getEffectiveLevel()),
            'is_cli': True,
        }

        self.print_help_if_requested()
        self.client_manager = clientmanager.ClientManager(options)

    def prepare_to_run_command(self, cmd):
        self.log.debug(
            'command: %s -> %s.%s',
            getattr(cmd, 'cmd_name', '<none>'),
            cmd.__class__.__module__,
            cmd.__class__.__name__,
        )

    def clean_up(self, cmd, result, err):
        self.log.debug('clean up %s: %s', cmd.__class__.__name__, err or '')


def main(argv=sys.argv[1:]):
    return OpenIOShell().run(argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
