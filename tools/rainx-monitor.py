#!/usr/bin/python

# rainx-monitor.py, a monitoring script for rainx services
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
import urllib2
import syslog

RAINX_STAT_KEYS = [
	("rainx.reqpersec", "total_reqpersec"),
	("rainx.reqputpersec", "put_reqpersec"),
	("rainx.reqgetpersec", "get_reqpersec"),
	("rainx.avreqtime", "total_avreqtime"),
	("rainx.avputreqtime", "put_avreqtime"),
	("rainx.avgetreqtime", "get_avreqtime"),
]

def parse_info(stream):
	data = {}
	for line in stream.readlines():
		parts = line.split()
		if len(parts) > 1:
			# try to cast value to int or float
			try:
				value = int(parts[1])
			except ValueError:
				try:
					value = float(parts[1])
				except ValueError:
					value = parts[1]
			data[parts[0]] = value
		else:
			data[parts[0]] = None
	return data

def get_stat_lines(url, stat_keys):
	try:
		stream = urllib2.urlopen(url, timeout=5)
		data = parse_info(stream)
		stream.close()
		stats = [("stat.%s = %s" % (k[1], str(data[k[0]])))
				for k in stat_keys if k[0] in data]
		return stats
	except urllib2.URLError as e:
		syslog.syslog(syslog.LOG_ERR, "rainx-monitor could not connect to RAINX server at %s: %s" % (url, e.strerror))
		sys.exit(1)

def main(args):
	ip_port = args[1].split("|")[2]
	stats_url = "http://%s/stat" % ip_port
	for stat in get_stat_lines(stats_url, RAINX_STAT_KEYS):
		print stat

if __name__ == "__main__":
	main(sys.argv)

