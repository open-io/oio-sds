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

import sys

from logging import getLogger, getLevelName
from pkg_resources import iter_entry_points
from oio.common.exceptions import CommandError, ConfigurationException
from oio.common.utils import load_namespace_conf
from oio.common.autocontainer import HashedContainerBuilder


LOG = getLogger(__name__)
PLUGIN_MODULES = []


def validate_options(options):
    msg = ''
    if not options.get('proxyd_url', None):
        msg = 'Set a proxyd URL with --oio-proxyd-url, OIO_PROXYD_URL\n'
        raise CommandError('Missing parameter(s): \n%s' % msg)


class ClientCache(object):
    def __init__(self, factory):
        self.factory = factory
        self._handle = None

    def __get__(self, instance, owner):
        instance.setup()
        if self._handle is None:
            # FIXME: not thread safe
            self._handle = self.factory(instance)
        return self._handle


class ClientManager(object):
    def __init__(self, options):
        self._options = options
        self.namespace = None
        self.setup_done = False
        self._admin_mode = False
        self._flatns_manager = None
        self._meta1_digits = None
        self._nsinfo = None
        root_logger = getLogger('')
        LOG.setLevel(root_logger.getEffectiveLevel())

    def setup(self):
        if not self.setup_done:
            if not self._options.get('namespace', None):
                msg = 'Set a namespace with --oio-ns, OIO_NS\n'
                raise CommandError('Missing parameter: \n%s' % msg)
            self.namespace = self._options['namespace']
            sds_conf = load_namespace_conf(self.namespace) or {}
            if not self._options.get('proxyd_url') and 'proxy' in sds_conf:
                proxyd_url = 'http://%s' % sds_conf.get('proxy')
                self._options['proxyd_url'] = proxyd_url
            validate_options(self._options)
            LOG.debug('Using parameters %s' % self._options)
            self.setup_done = True
            self._admin_mode = self._options.get('admin_mode')
            if 'meta1_digits' in sds_conf:
                self._meta1_digits = int(sds_conf["meta1_digits"])
            self._options['log_level'] = \
                getLevelName(LOG.getEffectiveLevel())

    def get_process_configuration(self):
        return dict(self._options)

    def info(self):
        self.setup()
        if self._nsinfo:
            return
        from oio.conscience.client import ConscienceClient
        client = ConscienceClient({"namespace": self.namespace})
        self._nsinfo = client.info()

    def get_meta1_digits(self):
        self.setup()
        return self._meta1_digits

    def get_admin_mode(self):
        self.setup()
        return self._admin_mode

    def get_endpoint(self, service_type):
        self.setup()
        # TODO: for the moment always return the proxyd URL
        endpoint = self._options['proxyd_url']
        return endpoint

    def get_account(self):
        account_name = self._options.get('account_name', None)
        if not account_name:
            msg = 'Set an account name with --oio-account, OIO_ACCOUNT\n'
            raise CommandError('Missing parameter: \n%s' % msg)
        return account_name

    def get_flatns_manager(self):
        if self._flatns_manager:
            return self._flatns_manager
        self.info()
        options = self._nsinfo['options']
        bitlength, offset, size = None, 0, 0
        try:
            bitlength = int(options['flat_bitlength'])
        except Exception:
            raise ConfigurationException(
                    "Namespace not configured for autocontainers")
        try:
            if 'flat_hash_offset' in options:
                offset = int(options['flat_hash_offset'])
            if 'flat_hash_size' in options:
                size = int(options['flat_hash_size'])
        except Exception:
            raise Exception("Invalid autocontainer config: offset/size")
        self._flatns_manager = HashedContainerBuilder(
            offset=offset, size=size, bits=bitlength)
        return self._flatns_manager


def get_plugin_modules(group):
    modules_list = []
    for entry_point in iter_entry_points(group):
        LOG.debug('Found plugin %r', entry_point.name)

        __import__(entry_point.module_name)
        module = sys.modules[entry_point.module_name]
        modules_list.append(module)

        client_cache = ClientCache(
            getattr(module, 'make_client', None)
        )

        setattr(
            ClientManager,
            module.API_NAME,
            client_cache
        )
    return modules_list


def build_plugin_option_parser(parser):
    for module in PLUGIN_MODULES:
        parser = module.build_option_parser(parser)
    return parser


PLUGIN_MODULES.extend(get_plugin_modules(
    'openio.cli.base'
))

PLUGIN_MODULES.extend(get_plugin_modules(
    'openio.cli.ext'
))
