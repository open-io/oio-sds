#!/usr/bin/env bash

# @EXE_PREFIX@-unlock-all, a CLI tool of OpenIO
# Copyright (C) 2016 OpenIO, original work as part of OpenIO Software Defined Storage
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
LOCAL=
NS=
SRVTYPE=

list () {
	if [ -n "$SRVTYPE" ] ; then
		${PREFIX}-cluster -r "$NS" | egrep -E -e "|${SRVTYPE}|"
	else
		${PREFIX}-cluster -r "$NS"
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
	echo "No namespace configured - Please use oio-unlock-all.sh -n \$NS"
	exit 1
fi

list | while read S ; do
	${PREFIX}-cluster --unlock-score -S "$S"
done

