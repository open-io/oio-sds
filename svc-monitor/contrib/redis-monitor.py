#!/usr/bin/python

import sys
import redis

stat_keys = ('db0.keys', 'used_memory', 'used_memory_rss')

def parse_info(info):
	parsed_info = dict()
	for k,v in info.iteritems():
		if isinstance(v, dict):
			for subk,subv in v.iteritems():
				parsed_info[k+"."+subk] = str(subv)
		else:
			parsed_info[k] = str(v)
	return parsed_info


if len(sys.argv) < 2 :
	sys.exit()
else:
	ns, type, svc = sys.argv[1].split('|')
	host, port = svc.split(':')

r = redis.Redis(host, int(port))
pinfo = parse_info(r.info())

for stat in stat_keys:
	if stat in pinfo:
		print "stat."+stat+" = "+pinfo[stat]
