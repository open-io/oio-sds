#!/usr/bin/python

# account-agent.py, a script forwarding notifications to an account service
# Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage
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

import json, logging
from optparse import OptionParser as OptionParser

import zmq, requests
import oio.config

if __name__ == '__main__':

	# CLI Options parsing
	parser = OptionParser()
	parser.add_option('-v', '--verbose', action="store_true", dest="flag_verbose",
		help='Triggers debugging traces')
	options, args = parser.parse_args()
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

	# Local configuration loading
	ns = args[0]
	cfg = oio.config.load()
	url_agent = cfg.get(ns, "account-agent")
	url_endpoint = cfg.get(ns, "endpoint")

	# Forwarding loop
	with zmq.Context() as ctx:
		with ctx.socket(zmq.PULL) as s:
			s.set(zmq.LINGER, 1000)
			logging.info("Binding to [%s]", url_agent)
			s.bind(url_agent)
			try:
				session = requests.Session()
				while True:
					msg = s.recv()
					account, user, subtype = '_', '_', '_'
					url = 'http://'+url_endpoint+'/v1.0/account/{0}/{1}/{2}/{3}' \
						.format(ns, account, user, subtype)
					session.post(url, msg)
			except KeyboardInterrupt, SystemExit:
				pass
			except Exception as e:
				logging.warn("Exception raised : %s", str(e))
			s.unbind(url_agent)
			logging.debug("Closing socket")
		logging.debug("Terminating context")
	logging.debug("Exiting program")

