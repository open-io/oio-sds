#!/usr/bin/python

import sys, time, random, logging, traceback, itertools
import threading

import zookeeper

PREFIX='/hc'
PREFIX_NS=PREFIX+'/ns'
default_expr = "pow(host['cpu_idle'] * host['netin_idle'] * host['netout_idle'] * volume['io_idle'] , 0.25)"
hexa = '0123456789ABCDEF'
acl_openbar = [{'perms':zookeeper.PERM_ALL, 'scheme':'world', 'id':'anyone'}]

def batch_split (nodes):
	last = 0
	batch = list()
	for x in nodes:
		current = x[0].count('/')
		batch.append(x)
		if len(batch) >= 2048 or last != current:
			yield batch
			batch = list()
		last = current
	yield batch

def batch_create (zh, batch):
	sem = threading.Semaphore(0)
	started = 0
	def create_ignore_errors (zh, path, data):
		def completion (*args, **kwargs):
			rc, zrc, ignored = args
			if rc != 0:
				print "zookeeper.acreate() error"
			else:
				if zrc == 0:
					#print 'create/set('+path+') : OK'
					pass
				elif zrc == zookeeper.NODEEXISTS:
					#print 'create/set('+path+') : ALREADY'
					pass
				else:
					print 'create/set('+path+') : FAILED'
			sem.release()
		zookeeper.acreate(zh, path, data, acl_openbar, 0, completion)
	for path, data in batch:
		create_ignore_errors(zh, path, data)
		started += 1
	for i in range(started):
		sem.acquire()
	return started, 0

def create_tree (zh, nodes):
	ok, ko = 0, 0
	for batch in batch_split(nodes):
		pre = time.time()
		o, k = batch_create(zh, batch)
		post = time.time()
		print " > batch({0},{1}) in {2}s".format(o,k,post-pre)
		ok, ko = ok+o, ko+k
	print "Created nodes : ok", ok,"ko",ko

###--------------------------------------------------------------------------###

def hash_tokens (w):
	if w == 1:
		return itertools.product(hexa)
	elif w == 2:
		return itertools.product(hexa,hexa)
	elif w == 3:
		return itertools.product(hexa,hexa,hexa)
	else:
		return []

def hash_tree (d0, w0):
	tokens = [''.join(x) for x in hash_tokens(w0)]
	def depth (d):
		if d == 1:
			return itertools.product(tokens)
		elif d == 2:
			return itertools.product(tokens, tokens)
		elif d == 3:
			return itertools.product(tokens, tokens, tokens)
		else:
			return []
	for d in range(d0+1):
		for x in depth(d):
			yield '/'.join(x) 

def namespace_tree (ns):
	yield (PREFIX_NS+'/'+ns, str(time.time()))
	yield (PREFIX_NS+'/'+ns+'/vns', '')
	yield (PREFIX_NS+'/'+ns+'/srv', '')
	yield (PREFIX_NS+'/'+ns+'/el', '')
	for srvtype in [ 'meta0', 'meta1', 'meta2', 'rawx', 'solr', 'sqlx', 'tsmx', 'saver', 'replicator']:
		yield (PREFIX_NS+'/'+ns+'/el/'+srvtype, '')
		yield (PREFIX_NS+'/'+ns+'/srv/'+srvtype, '')
		yield (PREFIX_NS+'/'+ns+'/srv/'+srvtype+'/list', '')
	for srvtype,d,w in [ ('',1,3), ('/meta0',0,0), ('/meta1',1,3), ('/meta2',2,2), ('/sqlx',2,2) ]:
		basedir = PREFIX_NS+'/'+ns+'/el'+srvtype
		for x in hash_tree(d,w):
			yield (basedir+'/'+x, '')

def boot_tree ():
	yield (PREFIX+'/srv', default_expr)
	yield (PREFIX+'/srv/meta0', '')
	yield (PREFIX+'/srv/meta1', '')
	yield (PREFIX+'/srv/meta2', '')
	yield (PREFIX+'/srv/rawx', '')
	yield (PREFIX+'/srv/solx', '')
	yield (PREFIX+'/srv/solr', '')
	yield (PREFIX+'/srv/tsmx', '')
	yield (PREFIX+'/srv/saver', '')
	yield (PREFIX+'/srv/replicator', '')
	yield (PREFIX+'/srv/sqlx', '')
	yield (PREFIX_NS, '')
	yield (PREFIX+'/hosts', '')
	yield (PREFIX+'/volumes', '')

#-------------------------------------------------------------------------------

def init_namespace(zh, ns):
	create_tree(zh, namespace_tree(ns))

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
	try:
		zookeeper.create(zh, PREFIX, '', acl_openbar, 0)
	except zookeeper.NodeExistsException:
		pass
	create_tree(zh, boot_tree())
	init_namespace(zh, ns)
	zookeeper.close(zh)

if __name__ == '__main__':
	main()

