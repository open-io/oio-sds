#!/usr/bin/env python

# zk-reset.py, a script resetting a Zookeeper instance for OpenIO SDS.
# Copyright (C) 2014 Worldine, original work as part of Redcurrant
# Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage
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

import sys, logging
import zookeeper
from oio.common.utils import load_namespace_conf

def delete_children (zh, path):
	path = path.replace('//', '/')
	try:
		for n in tuple(zookeeper.get_children(zh, path)):
			p = path + '/' + n
			delete_children(zh, p)
			zookeeper.delete(zh, p)
	except:
		pass

def main():
	from optparse import OptionParser as OptionParser

	parser = OptionParser()
	parser.add_option('-v', '--verbose', action="store_true", dest="flag_verbose",
		help='Triggers debugging traces')
	parser.add_option('-a', '--all', action="store_true", dest="flag_all",
		help='Triggers debugging traces')

	(options, args) = parser.parse_args(sys.argv)

	# Logging configuration
	if options.flag_verbose:
		logging.basicConfig(
			format='%(asctime)s %(message)s',
			datefmt='%m/%d/%Y %I:%M:%S',
			level=logging.DEBUG)
	else:
		logging.basicConfig(
			format='%(asctime)s %(message)s',
			datefmt='%m/%d/%Y %I:%M:%S',
			level=logging.INFO)

	if len(args) < 2:
		raise ValueError("not enough CLI arguments")

	ns = args[1]
	cnxstr = load_namespace_conf(ns)['zookeeper']

	zookeeper.set_debug_level(zookeeper.LOG_LEVEL_INFO)
	zh = zookeeper.init(cnxstr)
	if options.flag_all:
		logging.warn("FLUSHING all the oio-sds entries in the ZK server");
		delete_children(zh, "/hc")
	else:
		logging.info("Cleaning only the meta0 registrations in ZK server");
		delete_children(zh, "/hc/ns/"+ns+"/srv/meta0")
	zookeeper.close(zh)

if __name__ == '__main__':
	main()

