import sys
import os
from optparse import OptionParser
from ConfigParser import ConfigParser


def parse_options(parser=None):
    if parser is None:
        parser = OptionParser(usage='%prog CONFIG [options]')
    parser.add_option('-v', '--verbose', default=False, help='verbose output')

    options, args = parser.parse_args(args=None)

    if not args:
        parser.print_usage()
        print("Error: missing argument config path")
        sys.exit(1)
    config = os.path.abspath(args.pop(0))
    if not os.path.exists(config):
        parser.print_usage()
        print("Error: unable to locate %s" % config)
        sys.exit(1)

    options = vars(options)

    return config, options


def read_conf(conf_path, section_name=None, defaults=None):
    if defaults is None:
        defaults = {}
    c = ConfigParser(defaults)
    success = c.read(conf_path)
    if not success:
        print("Unable to read config from %s" % conf_path)
        sys.exit(1)
    if section_name:
        if c.has_section(section_name):
            conf = dict(c.items(section_name))
        else:
            print('Unable to find section %s in config %s' % (section_name,
                                                              conf_path))
            sys.exit(1)
    else:
        conf = {}
        for s in c.sections():
            conf.update({s: dict(c.items(s))})
    return conf