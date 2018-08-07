#!/usr/bin/env python

# Copyright (C) 2015-2018 OpenIO SAS, as part of OpenIO SDS
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

import argparse
import shlex
import subprocess
from oio.common.json import json as jsonlib

def execute(cmd, stdin=None):
    """Executes command."""
    cmdlist = shlex.split(cmd)
    result = ''
    result_err = ''
    print(cmd)
    stdout = subprocess.PIPE
    stderr = subprocess.PIPE
    in_ = subprocess.PIPE if stdin else None
    proc = subprocess.Popen(cmdlist, stdin=in_, stdout=stdout, stderr=stderr)
    result, result_err = proc.communicate(stdin)
    result = result.decode('utf-8')
    if proc.returncode != 0:
        print result_err
        raise
    return result

def openio(cmd):
    """Executes openio CLI command."""
    return execute('openio ' + cmd)



def json_loads(data):
    try:
        return jsonlib.loads(data)
    except ValueError:
        raise

def make_arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('user', help="System user")
    parser.add_argument('namespace', help="Namespace")
    return parser

def main():
    args = make_arg_parser().parse_args()
    output = openio('cluster list rawx --stats --format json')
    data = json_loads(output)
    # Sort rawx by disk usage
    data.sort(key=lambda c:c['Stats'].split(' ')[2].split('=')[1])
    dic = dict()
    sum_size = 0
    nrawx = 0
    for rawx in data:
        addr = rawx['Addr']
        stats = rawx['Stats'].split(' ')
        volume = rawx['Volume']
        du = float(stats[2].split('=')[1])
        # Keep only rawx with big disk usage
        if nrawx < len(data)/2:
            dic[du] = (addr, volume)
        sum_size += du
        nrawx += 1
    av = sum_size/nrawx
    # Lock rawx, run blob-mover and unlock rawx
    for du in dic:
            openio('cluster lock rawx ' + dic[du][0])
            output = execute('oio-blob-mover mover-conf.cfg --generate-config ' +
                    '--user ' + args.user + ' --ns ' + args.namespace +
                    ' --usage-target ' + str(int(av))+ ' --volume ' +
                    dic[du][1] + ' -v')
            print(output)
            openio('cluster unlock rawx ' +  dic[du][0])

if __name__ == '__main__':
    main()
