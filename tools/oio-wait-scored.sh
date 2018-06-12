#!/usr/bin/env bash

# oio-wait-scored.sh
# Copyright (C) 2016-2017 OpenIO SAS, as part of OpenIO SDS
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

VERBOSE=
NS=
SRVTYPE=
MAXWAIT=
MINSRV=
UNLOCK=

while getopts "N:s:t:n:uv" opt ; do
	case $opt in
		t) MAXWAIT="-d ${OPTARG}" ;;
		s) SRVTYPE="${SRVTYPE} ${OPTARG}" ;;
		n) NS="--oio-ns ${OPTARG}" ;;
		u) UNLOCK="-u" ;;
		v) VERBOSE="-v --debug" ;;
		N) MINSRV="-n ${OPTARG}" ;;
		\?) exit 1 ;;
	esac
done

exec openio $VERBOSE $NS cluster wait $MINSRV $UNLOCK $MAXWAIT $SRVTYPE
