# Copyright (C) 2017 OpenIO SAS, as part of OpenIO SDS
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

from os import path
from sys import exit
from yaml import load
from optparse import OptionParser
from glob import glob
from six.moves.configparser import SafeConfigParser


def parse_options(parser=None):
    if parser is None:
        parser = OptionParser(usage='%prog CONFIG [options]')
    parser.add_option('-v', '--verbose', default=False,
                      action='store_true', help='verbose output')

    options, args = parser.parse_args(args=None)

    if not args:
        parser.print_usage()
        print("Error: missing argument config path")
        exit(1)
    config = path.abspath(args.pop(0))
    if not path.exists(config):
        parser.print_usage()
        print("Error: unable to locate %s" % config)
        exit(1)

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
    c = SafeConfigParser(defaults)
    success = c.read(conf_path)
    if not success:
        print("Unable to read config from %s" % conf_path)
        exit(1)
    if section_name:
        if c.has_section(section_name):
            conf = dict(c.items(section_name))
        else:
            print('Unable to find section %s in config %s' % (section_name,
                                                              conf_path))
            exit(1)
    else:
        conf = {}
        for s in c.sections():
            conf.update({s: dict(c.items(s))})
    return conf


def parse_config(conf_path):
    with open(conf_path, 'r') as f:
        conf = load(f)
    return conf


def validate_service_conf(conf):
    ns = conf.get('namespace')
    if not ns:
        raise InvalidServiceConfigError()


def load_namespace_conf(namespace):
    def places():
        yield '/etc/oio/sds.conf'
        for f in glob('/etc/oio/sds.conf.d/*'):
            yield f
        yield path.expanduser('~/.oio/sds.conf')

    c = SafeConfigParser({})
    success = c.read(places())
    if not success:
        print('Unable to read namespace config')
        exit(1)
    if c.has_section(namespace):
        conf = dict(c.items(namespace))
    else:
        print('Unable to find [%s] section config' % namespace)
        exit(1)
    proxy = conf.get('proxy')
    if not proxy:
        print("Missing field proxy in namespace config")
        exit(1)
    return conf
