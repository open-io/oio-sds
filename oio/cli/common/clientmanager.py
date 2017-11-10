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


LOG = getLogger(__name__)


class ClientManager(object):
    def __init__(self, options):
        self._options = options
        self._sds_conf = None
        self._namespace = None
        self._admin_mode = None
        self._flatns_manager = None
        self._meta1_digits = None
        self._nsinfo = None
        self._account = None

        LOG.setLevel(getLogger('').getEffectiveLevel())
        LOG.debug('Using parameters %s' % self._options)
        self._options['log_level'] = getLevelName(LOG.getEffectiveLevel())

    @property
    def sds_conf(self):
        if not self._sds_conf:
            from oio.common.configuration import load_namespace_conf
            self._sds_conf = load_namespace_conf(self.namespace) or {}
        return self._sds_conf

    @property
    def namespace(self):
        if not self._namespace:
            ns = self._options.get('namespace', None)
            if not ns:
                from oio.common.exceptions import CommandError
                msg = 'Set a namespace with --oio-ns, OIO_NS\n'
                raise CommandError('Missing parameter: \n%s' % msg)
            self._namespace = ns
        return self._namespace

    @property
    def admin_mode(self):
        if not self._admin_mode:
            self._admin_mode = self._options.get('admin_mode')
        return self._admin_mode

    @property
    def flatns_manager(self):
        if self._flatns_manager:
            return self._flatns_manager
        from oio.common.autocontainer import HashedContainerBuilder
        options = self.nsinfo['options']
        bitlength, offset, size = None, 0, None
        try:
            bitlength = int(options['flat_bitlength'])
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
    def meta1_digits(self):
        if not self._meta1_digits:
            m1d = self.sds_conf.get("meta1_digits", None)
            if m1d:
                self._meta1_digits = int(m1d)
        return self._meta1_digits

    @property
    def nsinfo(self):
        if not self._nsinfo:
            from oio.conscience.client import ConscienceClient
            client = ConscienceClient({"namespace": self.namespace})
            self._nsinfo = client.info()
        return self._nsinfo

    @property
    def account(self):
        if not self._account:
            account_name = self._options.get('account_name', None)
            if not account_name:
                from oio.common.exceptions import CommandError
                msg = 'Set an account name with --oio-account, OIO_ACCOUNT\n'
                raise CommandError('Missing parameter: \n%s' % msg)
            self._account = account_name
        return self._account

    def get_endpoint(self, service_type):
        endpoint = self._options.get('proxyd_url', None)
        if not endpoint:
            endpoint = self.sds_conf.get('proxy', None)
            if endpoint:
                self._options['proxyd_url'] = 'http://%s' % endpoint
                endpoint = self._options['proxyd_url']
            else:
                from oio.common.exceptions import CommandError
                msg = """ Set a proxyd URL with --oio-proxyd-url,
                          OIO_PROXYD_URL\n """
                raise CommandError('Missing parameter(s): \n%s' % msg)
        # TODO: for the moment always return the proxyd URL
        return endpoint

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
