#!/usr/bin/python

import sys, time, random, logging, traceback, itertools
import zookeeper

def delete_tree (zh, path):
	path = path.replace('//', '/')
	try:
		for n in tuple(zookeeper.get_children(zh, path)):
			delete_tree(zh, path + '/' + n)
		zookeeper.delete(zh, path)
	except:
		pass

def load_config():
	import glob
	import ConfigParser as configparser

	cfg = configparser.RawConfigParser()
	cfg.read('/etc/gridstorage.conf')
	cfg.read(glob.glob('/etc/gridstorage.conf.d/*'))
	return cfg

def main():
	from optparse import OptionParser as OptionParser

	parser = OptionParser()
	parser.add_option('-v', '--verbose', action="store_true", dest="flag_verbose",
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
	cnxstr = load_config().get(ns, 'zookeeper')

	zookeeper.set_debug_level(zookeeper.LOG_LEVEL_INFO)
	zh = zookeeper.init(cnxstr)
	delete_tree(zh, "/hc")
	zookeeper.close(zh)

if __name__ == '__main__':
	main()

