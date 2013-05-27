#!/usr/bin/python

import sys, time, random, logging, traceback

import zookeeper

PREFIX='/hc'
PREFIX_NS=PREFIX+'/ns'

default_expr = "pow(host['cpu_idle'] * host['netin_idle'] * host['netout_idle'] * volume['io_idle'] , 0.25)"

def create_tree(zh, tree_nodes, reset=True):
	def new_acl_openbar():
		return [{'perms':zookeeper.PERM_ALL, 'scheme':'world', 'id':'anyone'}]
	def create_ignore_errors(path, data):
		try:
			zookeeper.create(zh, path, data, new_acl_openbar(), 0)
			#print 'create/set('+path+') : OK'
		except zookeeper.NodeExistsException:
			if not reset:
				#print 'create/set('+path+') : ALREADY'
				return
			try:
				zookeeper.set(zh, path, data)
				#print 'create/set('+path+') : OK'
			except:
				print 'create/set('+path+') : FAILED'

	for path, data in tree_nodes:
		create_ignore_errors(path, data)
	print "Created", str(len(tree_nodes)), "nodes starting at", repr(tree_nodes[0])

def delete_tree(zh, path):
	path = path.replace('//', '/')
	try:
		for n in tuple(zookeeper.get_children(zh, path)):
			delete_tree(zh, path + '/' + n)
		zookeeper.delete(zh, path)
	except:
		pass

def init_srvtype(zh, ns, srvtype):
	ns = str(ns)
	srvtype = str(srvtype)
	nodes = (
		(PREFIX_NS+'/'+ns+'/srv/'+srvtype, ''),
		(PREFIX_NS+'/'+ns+'/srv/'+srvtype+'/list', ''),
	)
	create_tree(zh, nodes)

def init_election(zh, basedir, d, w):
	hexa = '0123456789ABCDEF'
	last_level = [ (basedir,'') ]
	create_tree(zh, last_level, reset=False)
	for x in range(0,d):
		print 'd', str(d), 'w', str(w), 'i', x
		level = list()
		for n,c in last_level:
			if w == 1:
				for i in hexa:
					path = n+'/'+i+j
					level.append((path,c))
			elif w == 2:
				for i in hexa:
					for j in hexa:
						path = n+'/'+i+j
						level.append((path,c))
			elif w == 3:
				for i in hexa:
					for j in hexa:
						for k in hexa:
							path = n+'/'+i+j+k
							level.append((path,c))
		create_tree(zh, level, reset=False)
		last_level = level
		d = d - 1

def init_namespace(zh, ns):
	ns = str(ns)
	prefix_el = PREFIX_NS+'/'+ns+'/el'
	nodes = (
		(PREFIX_NS+'/'+ns, str(time.time())),
		(PREFIX_NS+'/'+ns+'/vns', ''),
		(PREFIX_NS+'/'+ns+'/srv', ''),
		(prefix_el, ''),
		(prefix_el+'/meta0', ''),
		(prefix_el+'/meta1', ''),
		(prefix_el+'/meta2', ''),
		(prefix_el+'/sqlx', ''),
	)
	create_tree(zh, nodes)
	for srvtype in [ 'meta0', 'meta1', 'meta2', 'rawx', 'solr', 'sqlx', 'tsmx', 'saver', 'replicator']:
		init_srvtype(zh, ns, srvtype)
	for srvtype,d,w in [ ('',1,3), ('/meta0',0,0), ('/meta1',1,3), ('/meta2',2,2), ('/sqlx',2,2) ]:
		init_election(zh, prefix_el + srvtype, d, w)

def init_boot(zh):
	base_nodes = (
		(PREFIX, ''),
		(PREFIX+'/srv', default_expr),
		(PREFIX+'/srv/meta0', ''),
		(PREFIX+'/srv/meta1', ''),
		(PREFIX+'/srv/meta2', ''),
		(PREFIX+'/srv/rawx', ''),
		(PREFIX+'/srv/solx', ''),
		(PREFIX+'/srv/solr', ''),
		(PREFIX+'/srv/tsmx', ''),
		(PREFIX+'/srv/saver', ''),
		(PREFIX+'/srv/replicator', ''),
		(PREFIX+'/srv/sqlx', ''),
		(PREFIX_NS, ''),
		(PREFIX+'/hosts', ''),
		(PREFIX+'/volumes', ''),
	)
	create_tree(zh, base_nodes, reset=False)

def load_config():
	import glob
	import ConfigParser as configparser

	cfg = configparser.RawConfigParser()
	cfg.read('/etc/gridstorage.conf')
	cfg.read(glob.glob('/etc/gridstorage.conf.d/*'))
	return cfg

#-------------------------------------------------------------------------------

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
	#delete_tree(zh, PREFIX)
	init_boot(zh)
	init_namespace(zh, ns)
	zookeeper.close(zh)

if __name__ == '__main__':
	main()

