#!/usr/bin/env bash

# @EXE_PREFIX@-reset.sh, a CLI tool of OpenIO
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
NB_RAWX=3
BIG=0
MONITOR_PERIOD=

OPENSUSE=`grep -i opensuse /etc/*release || echo -n ''`

while getopts "B:C:D:E:I:M:N:P:R:S:V:X:Zvb" opt; do
	case $opt in
		b) BIG=1 ;;
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
		\?) exit 1 ;;
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

if [ "$BIG" -gt 0 ] ; then opts="${opts} -b" ; fi

timeout () {
	num=$1 ; shift
	if [ $count -gt "$num" ] ; then
		echo "TIMEOUT! $@"
		${PREFIX}-cluster -r "$NS"
		( ps -o pid,ppid,cmd $(pgrep -u $UID -P "$pidof_gridinit" | sed 's/^/-p /') || exit 0 )
		exit 1
	fi
	sleep 1
	((count=count+1))
}

list_services () {
	${PREFIX}-cluster -r "$NS" | awk -F\| "/$1/{print \$3}"
}

wait_for_srvtype () {
	echo "Waiting for the $2 $1 to get a score"
	$PREFIX-wait-scored.sh -u -N "$2" -n "$NS" -s "$1" -t 15
}

reload_service_type () {
	list_services "$1" | while read IP ; do
		curl -X POST "http://${PROXY}/v3.0/forward/reload?id=$IP"
	done
}

timestamp () {
	echo
	date '+%Y-%m-%d %H:%M:%S.%N'
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

if [ $verbose -ge 1 ] ; then set -x ; fi

# Stop and clean a previous installation.
pgrep -u "$UID" --full gridinit | while read pidof_gridinit ; do
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
		# Waiting for gridinit ...
		if [ "$count" -gt 20 ] ; then
			echo "Gridinit doesn't want to die gracefully. Go for euthanasy"
			( pkill -9 -u "$UID" ${PREFIX}-event-agent || exit 0 )
		fi
		timeout 30
	done
done

# Generate a new configuration and start the new gridinit
mkdir -p "$OIO" && cd "$OIO" && (rm -rf sds.conf sds/{conf,data,run,logs})
${PREFIX}-bootstrap.py \
		-B "$REPLICATION_BUCKET" \
		-V "$VERSIONING" \
		-S "$STGPOL" \
		${opts} "$NS" "$IP"

gridinit -s OIO,gridinit -d ${SDS}/conf/gridinit.conf

PROXY=$(${PREFIX}-test-config.py -1 -t proxy)

# Initiate Zookeeper (if necessary)
ZK=$(${PREFIX}-cluster --local-cfg | grep "$NS/zookeeper" ; exit 0)
if [ -n "$ZK" ] ; then
	opts=
	for srvtype in ${AVOID} ; do opts="${opts} --avoid=${srvtype}" ; done
	if [ $ZKSLOW -ne 0 ] ; then opts="${opts} --slow" ; fi
	zk-reset.py "$NS"
	zk-bootstrap.py $opts "$NS"
fi


# Wait for the gridinit's startup
count=0
while ! pkill -u "$UID" --full -0 gridinit ; do
	timeout 15 "gridinit startup"
done
while ! [ -e "$GRIDINIT_SOCK" ] ; do
	timeout 30 "gridinit readyness"
done
pidof_gridinit=$(pgrep -u "$UID" --full gridinit)

timestamp
gridinit_cmd -S "$GRIDINIT_SOCK" reload >/dev/null
gridinit_cmd -S "$GRIDINIT_SOCK" start "@${NS}"
timestamp
wait_for_srvtype "(sqlx|rawx|rainx|meta2)" $((2+NB_RAWX+REPLICATION_BUCKET))
timestamp
wait_for_srvtype "(meta0|meta1)" $((1+REPLICATION_DIRECTORY))

timestamp
list_services "meta0" | while read URL ; do
	${PREFIX}-meta0-init -O "NbReplicas=${REPLICATION_DIRECTORY}" -O IgnoreDistance=on "$URL"
	${PREFIX}-meta0-client "$URL" reload
done

timestamp
${PREFIX}-unlock-all.sh -n "$NS"
${PREFIX}-wait-scored.sh -n "$NS" -t 60

timestamp
reload_service_type "meta1"
reload_service_type "meta2"

timestamp
find $SDS -type d | xargs chmod a+rx
gridinit_cmd -S "$GRIDINIT_SOCK" status2
${PREFIX}-cluster -r "$NS"

timestamp
