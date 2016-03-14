#!/usr/bin/env python

from optparse import OptionParser

from oio.common.daemon import run_daemon
from oio.common.utils import parse_options
from oio.crawler.storage_tierer import StorageTierer

if __name__ == '__main__':
    parser = OptionParser("%prog CONFIG [options]")
    config, options = parse_options(parser)
    run_daemon(StorageTierer, config, **options)
