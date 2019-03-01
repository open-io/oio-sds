# Copyright (C) 2017-2019 OpenIO SAS, as part of OpenIO SDS
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

from __future__ import print_function

import sys
from os import path
from yaml import load
from optparse import OptionParser
from glob import glob
from ConfigParser import SafeConfigParser


def parse_options(parser=None):
    if parser is None:
        parser = OptionParser(usage='%prog CONFIGURATION_FILE [options]')
    parser.add_option('-v', '--verbose', default=False,
                      action='store_true', help='verbose output')

    options, args = parser.parse_args(args=None)

    if not args:
        parser.print_usage()
        print("Error: missing configuration file path")
        sys.exit(1)
    config = path.abspath(args.pop(0))
    if not path.exists(config):
        parser.print_usage()
        print("Error: unable to locate %s" % config)
        sys.exit(1)

    options = vars(options)

    return config, options


class InvalidServiceConfigError(ValueError):
    def __str__(self):
        return "namespace missing from service conf"


def read_conf(conf_path, section_name=None, defaults=None, use_yaml=False):
    if use_yaml:
        return parse_config(conf_path)
    if defaults is None:
        defaults = {}
    parser = SafeConfigParser(defaults)
    success = parser.read(conf_path)
    if not success:
        print("Unable to read config from %s" % conf_path)
        sys.exit(1)
    if section_name:
        if parser.has_section(section_name):
            conf = dict(parser.items(section_name))
        else:
            print('Unable to find section %s in config %s' % (section_name,
                                                              conf_path))
            exit(1)
    else:
        conf = {}
        for section in parser.sections():
            conf.update({section: dict(parser.items(section))})
    return conf


def parse_config(conf_path):
    with open(conf_path, 'r') as f:
        conf = load(f)
    return conf


def validate_service_conf(conf):
    ns = conf.get('namespace')
    if not ns:
        raise InvalidServiceConfigError()


def config_paths():
    """
    Yield paths to potential namespace configuration files.
    """
    yield '/etc/oio/sds.conf'
    for conf_path in glob('/etc/oio/sds.conf.d/*'):
        yield conf_path
    yield path.expanduser('~/.oio/sds.conf')


# Keep namespace configurations, avoid loading files everytime
NS_CONF_CACHE = dict()


def load_namespace_conf(namespace, failsafe=False, fresh=False):
    """
    Load configuration for the namespace from the local configuration files.

    :param namespace: name of the namespace.
    :param failsafe: in case of error, return a dummy configuration.
    :param fresh: if True, reload configuration from files,
        do not use the cache.
    :returns: a dictionary with local namespace configuration.
    """
    if not fresh and namespace in NS_CONF_CACHE:
        return NS_CONF_CACHE[namespace]

    conf = {'namespace': namespace}
    parser = SafeConfigParser({})
    success = False
    loaded_files = parser.read(config_paths())
    if not loaded_files:
        print('Unable to read namespace config')
    else:
        if not parser.has_section(namespace):
            print('Unable to find [%s] section in any of %s' % (
                  namespace, loaded_files))
        else:
            conf.update(parser.items(namespace))
            proxy = conf.get('proxy')
            if not proxy:
                print("Missing field proxy in namespace config")
            else:
                success = True
                NS_CONF_CACHE[namespace] = conf
    if not (success or failsafe):
        sys.exit(1)
    return conf


def set_namespace_options(namespace, options, remove=None):
    """
    Set options in the local namespace configuration file.
    Can have nasty effects, be careful, only use in test code.

    :param namespace: the namespace to work with
    :param options: a dictionary with options to set
    :param remove: an iterable of options to remove
    :returns: a dictionary with all options of the namespace
    """
    parser = SafeConfigParser({})
    potential_confs = list(config_paths())
    actual_confs = parser.read(potential_confs)
    if not actual_confs:
        raise ValueError(
            "Could not read configuration from any of %s" % potential_confs)
    if not parser.has_section(namespace):
        print('Namespace %s was not found in %s' % (namespace, actual_confs))
        parser.add_section(namespace)
    for key, val in options.items():
        parser.set(namespace, key, str(val))
    if remove:
        for key in remove:
            parser.remove_option(namespace, key)
    with open(actual_confs[0], 'w') as outfile:
        parser.write(outfile)
    return dict(parser.items(namespace))
