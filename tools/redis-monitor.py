#!/usr/bin/python

# redis-monitor.py, a monitoring script for redis services
# Copyright (C) 2014 Worldine, original work aside of Redcurrant
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

import sys
import redis
import syslog

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
