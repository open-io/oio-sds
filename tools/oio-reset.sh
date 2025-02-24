#!/usr/bin/env bash

# oio-reset.sh
# Copyright (C) 2015-2019 OpenIO SAS, original work as part of OpenIO SDS
# Copyright (C) 2021-2024 OVH SAS
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

if [ -v OIO_SYSTEMD_SYSTEM ]; then
  SYSTEMCTL="systemctl"
  SYSTEMD_DIR="/etc/systemd/system"
else
  SYSTEMCTL="systemctl --user"
  SYSTEMD_DIR="$HOME/.config/systemd/user"
fi

OPENIOCTL=$(command -v openioctl.sh)
NS=OPENIO
IP=
PORT=
OIO="$HOME/.oio"
SDS="$OIO/sds"
BOOTSTRAP_CONFIG=
REGION=
# Force service id option to be used as it is mandatory
# (at least for internal rawxes to start).
SERVICE_ID=1
RANDOM_SERVICE_ID=
PROFILE=
DATADIR="$SDS/data"

ZKSLOW=0
verbose=0

# For compatibility (some options are kept but unused)
# -U: to use service id option
# -C: not used since at least 2016, but it might break some old scripts
while getopts "D:P:I:N:f:Z:p:r:CRUv" opt; do
    case $opt in
        D) DATADIR="${OPTARG}" ;;
        P) PORT="${OPTARG}" ;;
        I) IP="${OPTARG}" ;;
        N) NS="${OPTARG}" ;;
        r) REGION="${OPTARG}" ;;
        R) RANDOM_SERVICE_ID=1 ;;
        f) if [ -n "$OPTARG" ]; then
            if  [ ${OPTARG::1} != "/" ]; then
                BOOTSTRAP_CONFIG="${BOOTSTRAP_CONFIG} --conf ${PWD}/${OPTARG}"
            else
                BOOTSTRAP_CONFIG="${BOOTSTRAP_CONFIG} --conf ${OPTARG}"
            fi
        fi ;;
        Z) ZKSLOW=1 ;;
        p) PROFILE="${OPTARG}" ;;
        v) ((verbose=verbose+1)) ;;
        \?) exit 1 ;;
    esac
done

SERVICES="nb-services"
M1_STR="meta1"
M2_STR="meta2"
M2_REPLICAS="m2-replicas"

#-------------------------------------------------------------------------------

cmd_openio="openio --oio-ns $NS"
cmd_openio_admin="openio-admin"
G_DEBUG_LEVEL=WARN
if [ $verbose != 0 ] ; then
    G_DEBUG_LEVEL=TRACE
    echo "# $0" \
        "-I \"${IP}\"" \
        "-P \"${PORT}\"" \
        "-r \"${REGION}\"" \
        "-N \"${NS}\"" \
        "-Z \"${ZKSLOW}\"" \
        "${BOOTSTRAP_CONFIG}"
    cmd_openio="$cmd_openio -v --debug"
fi
export G_DEBUG_LEVEL

if [ $verbose -ge 1 ] ; then set -x ; fi

# Check the datadir is a directory the current user owns
[ -n "$DATADIR" ]
if [[ -e "$DATADIR" ]] ; then
    [ -d "$DATADIR" ]
    [ -O "$DATADIR" ]
    [ -r "$DATADIR" ]
    [ -x "$DATADIR" ]
    [ -w "$DATADIR" ]
fi
# stop oneshot service
$SYSTEMCTL stop oio-meta2-crawler-2.service || true
# stop current cluster and clean services and targets
$SYSTEMCTL stop oio-cluster.target || true
rm -f $SYSTEMD_DIR/oio-*

mkdir -p "$OIO"
cd "$OIO"
rm -rf sds.conf sds/{conf,run,logs}
if [[ -d "$DATADIR" ]] ; then
    rm -rf $DATADIR/${NS}*
fi

bootstrap_opt=
if [[ -n "${PORT}" ]] ; then bootstrap_opt="${bootstrap_opt} --port ${PORT}" ; fi
if [[ -n "${REGION}" ]] ; then bootstrap_opt="${bootstrap_opt} --region ${REGION}" ; fi
if [[ -n "${SERVICE_ID}" ]] ; then bootstrap_opt="${bootstrap_opt} --with-service-id" ; fi
if [[ -n "${RANDOM_SERVICE_ID}" ]] ; then bootstrap_opt="${bootstrap_opt} --random-service-id" ; fi
if [[ -n "${DATADIR}" ]] ; then bootstrap_opt="${bootstrap_opt} --data ${DATADIR}" ; fi
if [[ -n "${PROFILE}" ]] ; then bootstrap_opt="${bootstrap_opt} --profile ${PROFILE}" ; fi
bootstrap_opt="$bootstrap_opt -d ${BOOTSTRAP_CONFIG} $NS $IP"
echo oio-bootstrap.py $bootstrap_opt
oio-bootstrap.py $bootstrap_opt > /tmp/oio-bootstrap.$$

. /tmp/oio-bootstrap.$$
rm -f /tmp/oio-bootstrap.$$

# Initiate Zookeeper (if necessary)
if grep -q ^zookeeper $HOME/.oio/sds.conf ; then
    #opts="--fuck-the-world"
    #if [ $verbose -ge 1 ] ; then opts="${opts} -v" ; fi
    #openio --oio-ns "$NS" zk armageddon ${opts}

    opts="--lazy"
    if [ $verbose -ge 1 ] ; then opts="${opts} -v" ; fi
    if [ $ZKSLOW -ne 0 ] ; then opts="${opts} --slow" ; fi
    openio --oio-ns "$NS" zk bootstrap ${opts}
fi
if grep -q kafka $HOME/.oio/sds.conf ; then
    echo -e "\n### creating kafka topics"
    $cmd_openio_admin kafka create-topics --ns "${NS}" --reset $HOME/.oio/sds/conf/topics.yml
fi

$SYSTEMCTL daemon-reload
$SYSTEMCTL start oio-cluster.target

COUNT=$(oio-test-config.py -c -t meta2 -t rawx -t meta0 -t meta1 -t rdir)
$cmd_openio cluster wait -vvv --debug -d 60 -u -n "$COUNT" rawx meta2 meta0 meta1 rdir
# We cannot use cluster wait command for internal rawx as the conscience does not know them
# To check that the internal rawx are up we send requests to internal rawx to see if we get responses
# Expected addresses for two internal rawx services running on port 6033 and 6035
# INTERNAl_RAWX_ADDRS = ["http://127.0.0.1:6033", "http://127.0.0.1:6335"]
INTERNAl_RAWX_ADDRS=$($cmd_openio cluster list rawx --tags | awk '{split($4, a, ":"); split($(NF-1), b, "=") ; print "http://"a[1] ":" b[2]}' | tail -n +4 | head -n -1)
MAX_WAITING="60"
for i in $(seq 1 "$MAX_WAITING"); do
    ALL_INTERNAL_RAWX_UP=true
    for internal_addr in $INTERNAl_RAWX_ADDRS;
    do
        RESP_CODE=$(curl --write-out %{http_code} --silent --output /dev/null -X GET "$internal_addr/info")
        if [[ $RESP_CODE -eq 000 ]]; then
            ALL_INTERNAL_RAWX_UP=false
            echo -e "\nInternal rawx $internal_addr not up"
        fi
    done
    if [[ "$ALL_INTERNAL_RAWX_UP" = true ]]; then
        break
    fi
    if [ "$i" -eq "$MAX_WAITING" ]; then
        echo -e "\nSome internal rawx are not running"
        exit 1
    fi
    sleep 1
done

echo -e "\n### Init the meta0/meta1 directory"
$cmd_openio directory bootstrap --check \
    --replicas $(oio-test-config.py -v directory_replicas)

# Help debugging "The current META0 service is not ready yet [...]"
if [ "$(oio-test-config.py -v directory_replicas)" -gt 1 ]
then
    $cmd_openio election status meta0 0000
fi

echo -e "\n### Assign rdir services"
# Force meta1 services to reload meta0 cache
$SYSTEMCTL stop oio-meta1.target
# Wait until the scores are at 0
MAX_WAITING="30"
COUNT_META1=$(oio-test-config.py -c -t meta1)
for i in $(seq 1 "$MAX_WAITING"); do
    COUNT_META1_0=$($cmd_openio cluster list meta1 -f value -c Score | grep -c "^0$" || true)
    if [ "$COUNT_META1_0" -eq "$COUNT_META1" ]; then
        break
    fi
    if [ "$i" -eq "$MAX_WAITING" ]; then
        exit 1
    fi
    sleep 1
done
$SYSTEMCTL start oio-meta1.target
$cmd_openio cluster wait -d 30 -n "$COUNT_META1" meta1

$cmd_openio rdir bootstrap rawx --replicas $(oio-test-config.py -v directory_replicas)
$cmd_openio rdir bootstrap meta2 --replicas $(oio-test-config.py -v directory_replicas)

echo -e "\n### Wait for the services to have a score"
$cmd_openio cluster unlockall
oio-flush-all.sh -n "$NS" >/dev/null

echo -e "\n### Congrats, it's a NS"
find $SDS -type d | xargs chmod a+rx
$OPENIOCTL status2
$cmd_openio cluster list

echo -e "\n### Create internal buckets"
$cmd_openio bucket create -a internal internal_lifecycle

echo -e "\nexport OIO_NS=$NS OIO_ACCT=ACCT-$RANDOM"
