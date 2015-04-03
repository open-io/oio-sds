#!/usr/bin/env python

# metacd-monitor.py, a monitoring script for oio-proxy services
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

import sys, logging, httplib

logging.basicConfig(
	format='%(asctime)s %(message)s',
	datefmt='%m/%d/%Y %I:%M:%S',
	level=logging.INFO)

if len(sys.argv) < 2 :
	logging.critical("Missing service identifier : NS|TYPE|IP:PORT")
	sys.exit()
else:
	tokens = sys.argv[1].split('|')
	ns, type, svc = tokens[:3]
	host, port = svc.split(':')
	logging.debug("Contacting [%s] at [%s:%d] NS[%s]", type, host, int(port), ns)

body = None
try:
	cnx = httplib.HTTPConnection(svc)
	cnx.request("GET", "/status")
	resp = cnx.getresponse()
	status, reason, body = resp.status, resp.reason, resp.read()
	cnx.close()
except Exception as e:
	logging.error("transport error : %s", str(e))
	sys.exit()

if status / 100 != 2:
	logging.error("metacd error : %s", reason)
	sys.exit()

for line in str(body).splitlines():
	line = line.strip()
	if len(line) <= 0 or line[0] == '#':
		continue
	tokens = [x.strip() for x in line.split('=')]
	if not tokens or tokens is None or len(tokens) < 2:
		logging.debug("Not enough tokens for [%s]", line)
		continue
	k, v = tokens[:2]
	print k+'='+v

