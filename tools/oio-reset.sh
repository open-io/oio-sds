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
ZKSLOW=0
PORT=
verbose=0
OPENSUSE=`grep -i opensuse /etc/*release || echo -n ''`
while getopts "I:N:f:S:V:X:Zvb" opt; do
    case $opt in
		I) IP="${OPTARG}" ;;
		N) NS="${OPTARG}" ;;
		f) FILE_BOOTSTRAP_CONFIG="${OPTARG}" ;;
		Z) ZKSLOW=1 ;;
		v) ((verbose=verbose+1)) ;;
		\?) exit 1 ;;
	esac
done
SERVICES="nb-services"
M1_STR="meta1"
M2_STR="meta2"
M2_REPLICAS="m2-replicas"
if [ -n "$FILE_BOOTSTRAP_CONFIG" ]; then
    CMD_NB_M1=`oio-get-parameters-from-config.py ${FILE_BOOTSTRAP_CONFIG} ${M1_STR} ${SERVICES}`
    CMD_NB_M2=`oio-get-parameters-from-config.py ${FILE_BOOTSTRAP_CONFIG} ${M2_STR} ${SERVICES}`
    CMD_NB_M2_REPLICAS=`oio-get-parameters-from-config.py ${FILE_BOOTSTRAP_CONFIG} ${M2_REPLICAS}`
fi
   
if [ -n "$CMD_NB_M2_REPLICAS" ]; then
    REPLICATION_BUCKET=$CMD_NB_M2_REPLICAS
fi

if [ -n "$CMD_NB_M1" ]; then
    REPLICATION_DIRECTORY=$CMD_NB_M1
fi

if [ -n "CMD_NB_M2" ]; then
    NB_META2=${CMD_NB_M2}
else
    NB_META2=${REPLICATION_BUCKET}
fi

NB_META1=${REPLICATION_DIRECTORY}

opts=""

if [ -n "$FILE_BOOTSTRAP_CONFIG" ] ; then
    opts="--file=$FILE_BOOTSTRAP_CONFIG" ;
fi

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

wait_for_srvtype () {
	echo "Waiting for the $2 $1 to get a score"
	$PREFIX-wait-scored.sh -u -N "$2" -n "$NS" -s "$1" -t 15
}

reload_service_type () {
	${PREFIX}-test-config.py -t "$1" | while read IP ; do
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
		"-I \"${IP}\"" \
		"-N \"${NS}\"" \
		"-Z \"${ZKSLOW}\"" \
		"-f \"${FILE_BOOTSTRAP_CONFIG}\""
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

M0=$(${PREFIX}-test-config.py -t meta0 -1)
openio directory bootstrap --replicas ${REPLICATION_DIRECTORY} "$NS"

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
