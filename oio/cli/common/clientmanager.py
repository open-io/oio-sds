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

import sys

from logging import getLogger, getLevelName


LOG = getLogger(__name__)


class ClientManager(object):
    """
    OpenIO SDS command line god object.
    """

    def __init__(self, options):
        self._options = options
        self._client_conf = None
        self._sds_conf = None
        self._namespace = None
        self._admin_mode = None
        self._flatns_bits = None
        self._flatns_manager = None
        self._meta1_digits = None
        self._nsinfo = None
        self._account = None

        # Various API client classes
        self._account_client = None
        self._admin_client = None
        self._conscience_client = None
        self._rdir_client = None
        self._rdir_dispatcher = None
        self._storage = None

        self._logger = None
        self._pool_manager = None

        LOG.setLevel(getLogger('').getEffectiveLevel())
        LOG.debug('Using parameters %s', self._options)
        self._options['log_level'] = getLevelName(LOG.getEffectiveLevel())

    @property
    def client_conf(self):
        """Dict to be passed as first parameter to all *Client classes."""
        if not self._client_conf:
            self._client_conf = {'namespace': self.namespace,
                                 'proxyd_url': self.get_endpoint()}
        return self._client_conf

    @property
    def sds_conf(self):
        """Dict holding what's in local configuration files."""
        if not self._sds_conf:
            from oio.common.configuration import load_namespace_conf
            self._sds_conf = load_namespace_conf(self.namespace, failsafe=True)
        return self._sds_conf

    @property
    def namespace(self):
        """Name of the namespace set on the CLI or environment."""
        if not self._namespace:
            ns = self._options.get('namespace', None)
            if not ns:
                from oio.common.exceptions import CommandError
                msg = 'Set a namespace with --ns, OIO_NS\n'
                raise CommandError('Missing parameter: \n%s' % msg)
            self._namespace = ns
        return self._namespace

    @property
    def admin_mode(self):
        if not self._admin_mode:
            self._admin_mode = self._options.get('admin_mode')
        return self._admin_mode

    @property
    def account_client(self):
        if self._account_client is None:
            from oio.account.client import AccountClient
            self._account_client = AccountClient(
                self.client_conf, pool_manager=self.pool_manager)
        return self._account_client

    @property
    def xcute_client(self):
        if self._account_client is None:
            from oio.xcute.client import XcuteClient
            self._account_client = XcuteClient(
                self.client_conf, pool_manager=self.pool_manager)
        return self._account_client

    @property
    def admin(self):
        if self._admin_client is None:
            from oio.directory.admin import AdminClient
            self._admin_client = AdminClient(self.client_conf,
                                             pool_manager=self.pool_manager)
        return self._admin_client

    @property
    def conscience(self):
        if self._conscience_client is None:
            from oio.conscience.client import ConscienceClient
            self._conscience_client = ConscienceClient(
                self.client_conf, pool_manager=self.pool_manager)
        return self._conscience_client

    @property
    def logger(self):
        if self._logger is None:
            from oio.common.logger import get_logger
            self._logger = get_logger(self._options, __name__)
        return self._logger

    @property
    def rdir(self):
        if self._rdir_client is None:
            from oio.rdir.client import RdirClient
            self._rdir_client = RdirClient(self.client_conf,
                                           pool_manager=self.pool_manager)
        return self._rdir_client

    @property
    def rdir_dispatcher(self):
        if self._rdir_dispatcher is None:
            from oio.rdir.client import RdirDispatcher
            self._rdir_dispatcher = RdirDispatcher(
                self.client_conf, rdir_client=self.rdir,
                pool_manager=self.pool_manager)
        return self._rdir_dispatcher

    @property
    def storage(self):
        """
        Get an instance of ObjectStorageApi.
        """
        if self._storage is None:
            from oio.api.object_storage import ObjectStorageApi
            self._storage = ObjectStorageApi(
                self.namespace,
                endpoint=self.get_endpoint(),
                pool_manager=self.pool_manager)
        return self._storage

    def flatns_set_bits(self, bits):
        self._flatns_bits = bits

    @property
    def flatns_manager(self):
        if self._flatns_manager is not None:
            return self._flatns_manager
        from oio.common.autocontainer import HashedContainerBuilder
        options = self.nsinfo['options']
        bitlength, offset, size = None, 0, None
        try:
            bitlength = int(self._flatns_bits or options['flat_bitlength'])
        except Exception:
            from oio.common.exceptions import ConfigurationException
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

    @property
    def pool_manager(self):
        if self._pool_manager is None:
            from oio.common.http_urllib3 import get_pool_manager
            # TODO(FVE): load parameters from self._options or self.ns_conf
            self._pool_manager = get_pool_manager()
        return self._pool_manager

    @property
    def meta1_digits(self):
        if self._meta1_digits is None:
            m1d = (self.sds_conf.get("ns.meta1_digits") or
                   self.sds_conf.get("meta1_digits"))
            if m1d:
                self._meta1_digits = int(m1d)
            else:
                LOG.warn("ns.meta1_digits not set or invalid, default is 4")
                self._meta1_digits = 4
        return self._meta1_digits

    @property
    def nsinfo(self):
        if self._nsinfo is None:
            self._nsinfo = self.conscience.info()
        return self._nsinfo

    @property
    def account(self):
        if not self._account:
            account_name = self._options.get('account_name', None)
            if not account_name:
                from oio.common.exceptions import CommandError
                msg = 'Set an account name with --account, OIO_ACCOUNT\n'
                raise CommandError('Missing parameter: \n%s' % msg)
            self._account = account_name
        return self._account

    def get_endpoint(self, service_type=None):
        if 'proxyd_url' not in self._options:
            proxy_netloc = self.sds_conf.get('proxy', None)
            if proxy_netloc:
                self._options['proxyd_url'] = 'http://%s' % proxy_netloc
            else:
                from oio.common.exceptions import CommandError
                msg = """ Set a proxyd URL with --oio-proxy,
                          OIO_PROXY_URL\n """
                raise CommandError('Missing parameter(s): \n%s' % msg)
        # TODO: for the moment always return the proxyd URL
        return self._options['proxyd_url']

    def cli_conf(self):
        """Get a copy of the CLI configuration options."""
        return dict(self._options)


class ClientCache(object):
    def __init__(self, factory):
        self.factory = factory
        self._handle = None

    def __get__(self, instance, owner):
        if self._handle is None:
            self._handle = self.factory(instance)
        return self._handle


def get_plugin_module(module_name):
    __import__(module_name)
    module = sys.modules[module_name]

    client_cache = ClientCache(
        getattr(module, 'make_client', None)
    )

    setattr(
        ClientManager,
        module.API_NAME,
        client_cache
    )

    return module
