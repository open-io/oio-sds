#!/usr/bin/env bash

# @EXE_PREFIX@-reset, a script initating from scratch a local installation of OpenIO SDS.
# Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage
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
set -x
set -e

PREFIX="@EXE_PREFIX@"
NS=NS
OIO=$HOME/.oio
SDS=$OIO/sds
GRIDINIT_SOCK=${SDS}/run/gridinit.sock

# Stop and clean everything
while pkill --full -0 gridinit ; do
	pkill --full gridinit
	sleep 2
done

mkdir -p "$OIO"
( cd "$OIO" && (rm -rf sds.conf sds/{conf,data,run,logs}))

${PREFIX}-bootstrap.py

nice gridinit -s RC,gridinit -d ${SDS}/conf/gridinit.conf

ZK=$(${PREFIX}-cluster --local-cfg | grep "$NS/zookeeper" ; exit 0)
if [ -n "$ZK" ] ; then
	#zk-reset.py "$NS"
	zk-bootstrap.py "$NS"
fi

# wait for the gridinit to startup
while ! pkill -0 gridinit ; do sleep 1 ; done
# wait for the gridinit's socket to appear
while ! [ -e "$GRIDINIT_SOCK" ] ; do sleep 1 ; done

gridinit_cmd -S "$GRIDINIT_SOCK" reload
gridinit_cmd -S "$GRIDINIT_SOCK" start "@conscience" "@proxy" "@agent" "@meta0" "@meta1"

# wait for the meta0 to start
sleep 1
while ! pkill --full -0 ${PREFIX}-meta0-server ; do
	sleep 2
done

# wait for meta1 to be known in the conscience (this is necessary for the
# init phase of the meta0
while [ 0 -ge $(${PREFIX}-cluster -r "$NS" | grep -c meta1) ] ; do
	sleep 1
done

# Init the meta0's content
${PREFIX}-cluster -r "$NS" | awk -F\| '/meta0/{print $3}' | while read URL ; do
	${PREFIX}-meta0-init -O NbReplicas=3 -O IgnoreDistance=on "$URL"
	${PREFIX}-meta0-client "$URL" reload
done

# then start all the services
gridinit_cmd -S "$GRIDINIT_SOCK" start "@${NS}"


