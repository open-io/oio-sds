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
set -e

PREFIX="@EXE_PREFIX@"
NS=NS
IP=127.0.0.1
OIO=$HOME/.oio
SDS=$OIO/sds
GRIDINIT_SOCK=${SDS}/run/gridinit.sock

REPLICATION_DIRECTORY=1
REPLICATION_BUCKET=1
STGPOL="SINGLE"
VERSIONING=1
AVOID=""
ZKSLOW=0
CHUNKSIZE=
REDIS=0
PORT=
verbose=0

OPENSUSE=`grep -i opensuse /etc/*release || echo -n ''`

while getopts ":B:C:D:E:I:M:N:P:R:S:V:X:Zv" opt; do
	case $opt in
		B) REPLICATION_BUCKET="${OPTARG}" ;;
		C) CHUNKSIZE="${OPTARG}" ;;
		D) REPLICATION_DIRECTORY="${OPTARG}" ;;
		E) NB_RAWX="${OPTARG}" ;;
		I) IP="${OPTARG}" ;;
		M) MONITOR_PERIOD="${OPTARG}" ;;
		N) NS="${OPTARG}" ;;
		P) PORT="${OPTARG}" ;;
		R) REDIS="${OPTARG}" ;;
		S) STGPOL="${OPTARG}" ;;
		V) VERSIONING="${OPTARG}" ;;
		X) AVOID="${AVOID} ${OPTARG}" ;;
		Z) ZKSLOW=1 ;;
		v) ((verbose=verbose+1)) ;;
		\?) ;;
	esac
done

NB_META2=${REPLICATION_BUCKET}
if [ -n "$ADD_META2" ] && [ "$ADD_META2" -gt 0 ] ; then
	NB_META2=$((NB_META2+$ADD_META2))
fi

NB_META1=${REPLICATION_DIRECTORY}
if [ -n "$ADD_META1" ] && [ "$ADD_META1" -gt 0 ] ; then
	NB_META1=$((NB_META1+$ADD_META1))
fi

opts="--nb-meta1=${NB_META1} --nb-meta2=${NB_META2}"
if [ -n "$PORT" ] ; then opts="${opts} --port=${PORT}" ; fi
if [ -n "$NB_RAWX" ] ; then opts="${opts} --nb-rawx=${NB_RAWX}" ; fi
if [ -n "$CHUNKSIZE" ] ; then opts="${opts} --chunk-size=${CHUNKSIZE}" ; fi
if [ -n "$MONITOR_PERIOD" ] ; then opts="${opts} --monitor-period=${MONITOR_PERIOD}" ; fi
if [ "$REDIS" -gt 0 ] ; then opts="${opts} --allow-redis" ; fi
for srvtype in ${AVOID} ; do opts="${opts} --no-${srvtype}"; done
if [ -n "$OPENSUSE" ]
then
	echo $PATH | grep -q '/usr/sbin' || PATH="$PATH:/usr/sbin"
	opts="${opts} --opensuse"
fi

timeout () {
	local max="$1" ; shift
	if [ $count -gt $max ] ; then echo "TIMEOUT: $@" 1>&2 ; exit 1 ; fi
	sleep 2
	((count=count+2))
}

dump () {
	if [ $verbose -ge 1 ] ; then /bin/cat ; else /bin/cat >/dev/null ; fi
}

#-------------------------------------------------------------------------------

G_DEBUG_LEVEL=WARN
if [ $verbose != 0 ] ; then
	G_DEBUG_LEVEL=TRACE
	echo "# $0" \
		"-B \"${REPLICATION_BUCKET}\"" \
		"-C \"${CHUNKSIZE}\"" \
		"-D \"${REPLICATION_DIRECTORY}\"" \
		"-E \"${NB_RAWX}\"" \
		"-I \"${IP}\"" \
		"-M \"${MONITOR_PERIOD}\"" \
		"-N \"${NS}\"" \
		"-P \"${PORT}\"" \
		"-R \"${REDIS}\"" \
		"-S \"${STGPOL}\"" \
		"-V \"${VERSIONING}\"" \
		"-X \"${AVOID}\"" \
		"-Z \"${ZKSLOW}\""
fi
export G_DEBUG_LEVEL

if [ $verbose -ge 2 ] ; then set -x ; fi

## Stop and clean a previous installation.
pidof_gridinit=$(pgrep -u "$UID" --full gridinit || echo)
if [ -n "$pidof_gridinit" ] ; then
	# First try a clean stop of gridinit's children
	if [ -e "$GRIDINIT_SOCK" ] ; then
		if ! gridinit_cmd -S "$GRIDINIT_SOCK" stop ; then
			echo "Failed to send 'stop' to gridinit"
		fi
	fi
	# We know by experience this might fail, so try to kill gridinit's children
	if ! pkill -u "$UID" -P "$pidof_gridinit" ; then
		echo "Failed to kill gridinit children" 1>&2
	fi
	# Kill gridinit until it dies with its children
	count=0
	while kill "$pidof_gridinit" ; do
		echo
		ps -o pid,ppid,cmd $(pgrep -u $UID -P $(pgrep gridinit))
		timeout 30 "(previous) gridinit exit"
	done
fi 2>&1 | dump

# Generate a new configuraiton and start the new gridinit
mkdir -p "$OIO" && cd "$OIO" && (rm -rf sds.conf sds/{conf,data,run,logs})
${PREFIX}-bootstrap.py \
		-B "$REPLICATION_BUCKET" \
		-V "$VERSIONING" \
		-S "$STGPOL" \
		${opts} "$NS" "$IP" 2>&1 | dump
nice gridinit -s OIO,gridinit -d ${SDS}/conf/gridinit.conf

# If the configuration requires Zookeeper, initiate it
ZK=$(${PREFIX}-cluster --local-cfg | grep "$NS/zookeeper" ; exit 0)
if [ -n "$ZK" ] ; then
	opts=
	for srvtype in ${AVOID} ; do opts="${opts} --avoid=${srvtype}" ; done
	if [ $ZKSLOW -ne 0 ] ; then opts="${opts} --slow" ; fi
	zk-reset.py "$NS"
	zk-bootstrap.py $opts "$NS"
fi 2>&1 | dump

# wait for the gridinit to startup and readyness
count=0
while ! pkill -u "$UID" --full -0 gridinit ; do
	timeout 5 "gridinit startup"
done
while ! [ -e "$GRIDINIT_SOCK" ] ; do
	timeout 15 "gridinit readyness"
done

gridinit_cmd -S "$GRIDINIT_SOCK" reload 2>&1 | dump
gridinit_cmd -S "$GRIDINIT_SOCK" start "@conscience" "@proxy" "@agent" "@meta0" "@meta1" 2>&1 | dump

# wait for the meta0 to start
count=0
while ! pkill -u "$UID" --full -0 ${PREFIX}-meta0-server ; do
	timeout 30 "meta0 startup"
done

# wait for meta1 to be registered
count=0
while [ ${REPLICATION_DIRECTORY} -gt $(${PREFIX}-cluster -r "$NS" | grep -c meta1) ] ; do
	timeout 30 "meta1 registration"
done

# Init the meta0's content
${PREFIX}-cluster -r "$NS" | awk -F\| '/meta0/{print $3}' | while read URL ; do
	${PREFIX}-meta0-init -O "NbReplicas=${REPLICATION_DIRECTORY}" -O IgnoreDistance=on "$URL"
	${PREFIX}-meta0-client "$URL" reload
done 2>&1 | dump

# then start all the services
gridinit_cmd -S "$GRIDINIT_SOCK" start "@${NS}" 2>&1 | dump
find $SDS -type d | xargs chmod a+rx

gridinit_cmd -S "$GRIDINIT_SOCK" status2

