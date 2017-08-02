#!/usr/bin/env bash

# oio-flush-all.sh
# Copyright (C) 2016 OpenIO, as part of OpenIO SDS
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

set -e

PREFIX="@EXE_PREFIX@"
NS=

list () {
    oio-test-config.py -t meta0 -t meta1 -t meta2
}

while getopts "s:n:l" opt ; do
    case $opt in
	n) NS="${OPTARG}" ;;
	\?) exit 1 ;;
    esac
done

if [ -z "$NS" ] ; then
    echo "No namespace configured"
    exit 1
fi

PROXY_URL=`oio-test-config.py -t proxy -1`

if [ -z "$PROXY_URL" ] ; then
    echo "No proxy configured"
    exit 1
fi

list | while read services;
do
    RESPONSE=$(curl -sS -X POST "http://${PROXY_URL}/v3.0/forward/flush?id=${services}")
done
