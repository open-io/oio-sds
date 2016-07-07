#!/usr/bin/env python

# tool_rawx.py, a script probing the RAWX of an OpenIO SDS platform
# Copyright (C) 2015 OpenIO, original work as part of OpenIO
# Software Defined Storage
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
    return "http://{0}/{1}".format(str(rawx['addr']), "0"*64)

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
            url = chunk_url(rawx)
            r = session.put(url, "")
            if r.status_code / 100 != 2:
                raise Exception("Upload failed status="+str(r.status_code))
            r = session.delete(url)
            if r.status_code / 100 != 2:
                raise Exception("Delete failed status="+str(r.status_code))
            print ns, rawx['addr'], "OK"
        except Exception as e:
            print ns, rawx['addr'], "Check failed for", str(rawx), ":", str(e)
