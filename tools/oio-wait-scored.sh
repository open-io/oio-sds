#!/usr/bin/env bash

# @EXE_PREFIX@-wait-scored, a CLI tool of OpenIO SDS
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

LOCAL=
NS=
SRVTYPE=
MAXWAIT=0
MINSRV=1
UNLOCK=

list () {
	if [ -n "$SRVTYPE" ] ; then
		openio cluster list --oio-ns "$NS" -f value -c Score $SRVTYPE
	else
		openio cluster list --oio-ns "$NS" -f value -c Score
	fi
}

maybe_unlock () {
	if [ -n "$UNLOCK" ] ; then
		openio --oio-ns "$NS" cluster unlockall $SRVTYPE
	fi
}

while getopts "N:s:t:n:lu" opt ; do
	case $opt in
		t) MAXWAIT="${OPTARG}" ;;
		s) SRVTYPE="${OPTARG}" ;;
		n) NS="${OPTARG}" ;;
		l) LOCAL=1 ;;
		u) UNLOCK=1 ;;
		N) MINSRV="${OPTARG}" ;;
		\?) exit 1 ;;
	esac
done

if [ -z "$NS" ] ; then
	echo "No namespace configured"
	exit 1
fi

count=0
while true ; do
	count_scored=$(list | grep -c -v '^0$' || exit 0)
	count_down=$(list | grep -c '^0$' || exit 0)
	if [ "$count_scored" -ge "$MINSRV" ] && [ "$count_down" -eq 0 ] ; then
		exit 0
	else
		if [ "$MAXWAIT" -gt 0 ] ; then
			if [ $count -ge "$MAXWAIT" ] ; then
				echo "Timeout!"
				exit 2
			else
				maybe_unlock
				sleep 1
				((count=count+1))
			fi
		else
			maybe_unlock
			sleep 1
		fi
	fi
done

