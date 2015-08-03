#!/usr/bin/python

# account-monitor.py, a monitoring script for the account service
# Copyright (C) 2015 OpenIO, original work as part of
# OpenIO Software Defined Storage
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
import syslog


ACCOUNT_STAT_KEYS = [
    ("account_count", "stat.account_count"),
]


def main(args):
    ip_port = str(args[1]).split("|")[2]
    url = "http://%s/status" % ip_port
    try:
        resp = requests.get(url, timeout=5)
        stats = resp.json()
        for key, stat in ACCOUNT_STAT_KEYS:
            if key in stats:
                print "%s = %s" % (stat, str(stats[key]))
    except Exception as e:
        syslog.syslog(
            syslog.LOG_ERR,
            "account-monitor could not connect to ACCOUNT server at %s: %s" %
            (url, e.strerror)
        )
        sys.exit(1)

if __name__ == "__main__":
    main(sys.argv)
