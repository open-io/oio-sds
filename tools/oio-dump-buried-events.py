#!/usr/bin/env python

# oio-election-dump.py
# Copyright (C) 2018 OpenIO SAS, as part of OpenIO SDS
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
import beanstalkc


def dump_buried(host, port):
    beanstalk = beanstalkc.Connection(host=host, port=int(port))

    beanstalk.use('oio')

    while True:
        job = beanstalk.peek_buried()
        if not job:
            break
        print("job")
        print(job.stats())
        print(job.body)
        job.delete()


if __name__ == "__main__":
    host, port = sys.argv[1].split(':')
    dump_buried(host, port)
