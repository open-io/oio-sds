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

from __future__ import print_function
from os import remove
from oio.conscience.client import ConscienceClient
import argparse
import subprocess


def move_rawx(volume, target_use, user, namespace, conf):
    result = ''
    result_err = ''
    stdout = subprocess.PIPE
    stderr = subprocess.PIPE
    cmd = 'oio-blob-mover ' + conf + ' --generate-config --user ' + user
    cmd += ' --ns ' + namespace + ' --usage-target ' + target_use
    cmd += ' --volume ' + volume + ' -vvv'
    proc = subprocess.Popen(cmd, stdin=None, stdout=stdout,
                            stderr=stderr, shell=True)
    result, result_err = proc.communicate()
    if result == "":
        result = result_err
    result = result.decode('utf-8')
    if proc.returncode != 0:
        raise Exception("Mover failed on rawx " + volume)
    return result


def make_arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('user', help="System user")
    parser.add_argument('namespace', help="Namespace")
    parser.add_argument('--dry-run', action="store_true",
                        help="Show rebalanced rawx")
    parser.add_argument('--conf-file',
                        help="Path to store configuration file.")
    return parser


def main():
    args = make_arg_parser().parse_args()
    conf = args.conf_file if args.conf_file else "mover.conf"
    cs = ConscienceClient({"namespace": args.namespace})
    all_rawx = cs.all_services('rawx', full=True)
    # Sort rawx by disk usage
    all_rawx.sort(key=lambda c: c['tags']['stat.space'])
    dic = dict()
    sum_size = 0
    nrawx = 0
    for rawx in all_rawx:
        addr = rawx['addr']
        volume = rawx['tags']['tag.vol']
        du = float(rawx['tags']['stat.space'])
        # Keep only rawx with big disk usage
        if nrawx < len(all_rawx)/2:
            dic[addr] = volume
        sum_size += du
        nrawx += 1
    if nrawx == 0:
        return
    av = sum_size/nrawx
    # Lock rawx, run blob-mover and unlock rawx
    target_use = str(int(av))
    for addr in dic:
        infos_srv = {"addr": addr, "type": "rawx"}
        print("Lock rawx at " + addr)
        if not args.dry_run:
            cs.lock_score(infos_srv)
        print("Run mover on rawx at " + addr +
              " to get disk usage under " + str(target_use))
        if not args.dry_run:
            try:
                output = move_rawx(dic[addr], target_use,
                                   args.user, args.namespace, conf)
                print(output)
            except Exception as err:
                print("ERROR: " + str(err))
        print("Unlock rawx at " + addr)
        if not args.dry_run:
            cs.unlock_score(infos_srv)
    # Delete mover configuration file
    if not args.dry_run:
        remove(conf)


if __name__ == '__main__':
    main()
