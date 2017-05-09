#!/usr/bin/env bash

# oio-reset.sh, a CLI tool of OpenIO SDS
# Copyright (C) 2015-2016 OpenIO, original work as part of OpenIO SDS
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
NS=OPENIO
IP=
PORT=
OIO=$HOME/.oio
SDS=$OIO/sds
GRIDINIT_SOCK=${SDS}/run/gridinit.sock
BOOTSTRAP_CONFIG=

ZKSLOW=0
verbose=0
OPENSUSE=`grep -i opensuse /etc/*release || echo -n ''`

while getopts "P:I:N:f:Z:Cvb" opt; do
    case $opt in
        P) PORT="${OPTARG}" ;;
        I) IP="${OPTARG}" ;;
        N) NS="${OPTARG}" ;;
        f) if [ -n "$OPTARG" ]; then
			if  [ ${OPTARG::1} != "/" ]; then
				BOOTSTRAP_CONFIG="${BOOTSTRAP_CONFIG} --conf ${PWD}/${OPTARG}"
			else
				BOOTSTRAP_CONFIG="${BOOTSTRAP_CONFIG} --conf ${OPTARG}"
			fi
		fi ;;
        Z) ZKSLOW=1 ;;
        v) ((verbose=verbose+1)) ;;
        \?) exit 1 ;;
    esac
done

SERVICES="nb-services"
M1_STR="meta1"
M2_STR="meta2"
M2_REPLICAS="m2-replicas"

timeout () {
    num=$1 ; shift
    if [ $count -gt "$num" ] ; then
        echo "TIMEOUT! $@"
        $PREFIX-cluster -r "$NS"
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
        "-P \"${PORT}\"" \
        "-N \"${NS}\"" \
        "-Z \"${ZKSLOW}\"" \
        "${BOOTSTRAP_CONFIG}"
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
            ( pkill -9 -u "$UID" $PREFIX-event-agent || exit 0 )
        fi
            timeout 30
        done
done

# Generate a new configuration and start the new gridinit

mkdir -p "$OIO" && cd "$OIO" && (rm -rf sds.conf sds/{conf,data,run,logs})
bootstrap_opt=
if [[ -n "${PORT}" ]] ; then bootstrap_opt="${bootstrap_opt} --port ${PORT}" ; fi
${PREFIX}-bootstrap.py "$NS" "$IP" $bootstrap_opt -d ${BOOTSTRAP_CONFIG} > /tmp/oio-bootstrap.$$

# Variables
# PROXY
# REPLI_DIRECTORY

. /tmp/oio-bootstrap.$$
rm -f /tmp/oio-bootstrap.$$


gridinit -s OIO,gridinit -d ${SDS}/conf/gridinit.conf

# Initiate Zookeeper (if necessary)
ZK=$(${PREFIX}-cluster --local-cfg | grep "$NS/zookeeper" ; exit 0)
if [ -n "$ZK" ] ; then
    opts=--lazy
    for srvtype in ${AVOID} ; do opts="${opts} --avoid=${srvtype}" ; done
    if [ $ZKSLOW -ne 0 ] ; then opts="${opts} --slow" ; fi
	zk-reset.py "$NS" ;
    zk-bootstrap.py --lazy $opts "$NS"
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
COUNT=$(${PREFIX}-test-config.py -c -t meta2 -t rawx -t sqlx)
wait_for_srvtype "sqlx rawx meta2" "$COUNT"
timestamp
COUNT=$(${PREFIX}-test-config.py -c -t meta0 -t meta1)
wait_for_srvtype "meta0 meta1" "$COUNT"

timestamp

COUNT=$(${PREFIX}-test-config.py -c -t rdir)
wait_for_srvtype "rdir" "$COUNT"
openio \
	--oio-ns "$NS" -v directory bootstrap --check \
	--replicas $(${PREFIX}-test-config.py -v directory_replicas)

timestamp
# unlock all services
openio --oio-ns "$NS" cluster unlockall
$PREFIX-wait-scored.sh -n "$NS" -t 60
$PREFIX-flush-all.sh -n "$NS"

timestamp
find $SDS -type d | xargs chmod a+rx
gridinit_cmd -S "$GRIDINIT_SOCK" status2
$PREFIX-cluster -r "$NS"

timestamp
