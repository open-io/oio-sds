#!/usr/bin/env python

import sys
import requests
import oio.config

if len(sys.argv) < 2:
	print "Usage:", sys.argv[0], " NAMESPACE..."
	sys.exit(1)

try:
	cfg = oio.config.load()
except Exception as e:
	print "Failed to load the system configuration", e
	sys.exit(1)

def chunk_url(srv):
	return "http://{0}/{1}".format(str(rawx['addr']),
			"0000000000000000000000000000000000000000000000000000000000000000")

for ns in sys.argv[1:]:

	print ""

	# Get the proxy
	try:
		url = cfg.get(ns, "proxy")
	except:
		print "#", "NS="+str(ns), "Proxy not configured"
		continue

	print "#", "NS="+str(ns), "PROXY="+str(url)

	# Get the list of RAWX
	session = requests.Session()
	r = session.get('http://'+str(url)+'/v2.0/cs/'+str(ns)+'/rawx')
	if r.status_code / 100 != 2:
		print "#", "NS="+str(ns), "Proxy error status="+str(r.status_code)
		continue

	# Check each rawx
	for rawx in r.json():
		if not bool(rawx['tags']['tag.up']):
			print ns, rawx['addr'], "OK"
			continue
		try:
			url = chunk_url (rawx)
			r = session.put(url, "")
			if r.status_code / 100 != 2:
				raise Exception("Upload failed status="+str(r.status_code))
			r = session.delete(url)
			if r.status_code / 100 != 2:
				raise Exception("Delete failed status="+str(r.status_code))
			print ns, rawx['addr'], "OK"
		except Exception as e:
			print ns, rawx['addr'], "Check failed for", str(rawx), ":", str(e)

