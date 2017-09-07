#!/usr/bin/env bash

# oio-unlock-all.sh
# Copyright (C) 2016 OpenIO SAS, as part of OpenIO SDS
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

LOCAL=
NS=
SRVTYPE=

list () {
	if [ -n "$SRVTYPE" ] ; then
		oio-cluster -r "$NS" | egrep -E -e "|${SRVTYPE}|"
	else
		oio-cluster -r "$NS"
	fi
}

while getopts "s:n:l" opt ; do
	case $opt in
		s) SRVTYPE="${OPTARG}" ;;
		n) NS="${OPTARG}" ;;
		l) LOCAL=1 ;;
		\?) exit 1 ;;
	esac
done

if [ -z "$NS" ] ; then
	echo "No namespace configured"
	exit 1
fi

list | while read S ; do
	oio-cluster --unlock-score -S "$S"
done

