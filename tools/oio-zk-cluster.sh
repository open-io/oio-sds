#!/bin/bash
# Helper script to start a ZooKeeper cluster without root privileges.

CLS=org.apache.zookeeper.server.quorum.QuorumPeerMain

OPTS="-Dcom.sun.management.jmxremote"
OPTS="$OPTS -Dcom.sun.management.jmxremote.local.only=false"
OPTS="$OPTS -Dzookeeper.root.logger=INFO,ROLLINGFILE"
OPTS="$OPTS -Dcom.sun.management.jmxremote.host=127.0.0.1"
OPTS="$OPTS -Djute.maxbuffer=262144"

ZOOBASEPORT=2190
ZOOBASEPORTLOW=2880
ZOOBASEPORTHIGH=3880
ZOOCFGROOT=$HOME/.oio/zookeeper

ZOO_LOG4J_PROP="INFO,ROLLINGFILE"
export ZOO_LOG4J_PROP


TEMPDYN=$(mktemp -t zoo.cfg.dynamic.1.XXXX)

bootstrap_cfg() {
  MYID=$1
  MYCFGDIR="$ZOOCFGROOT/$MYID"
  MYPORT=$(($ZOOBASEPORT + $MYID))
  MYPORTLOW=$(($ZOOBASEPORTLOW + $MYID))
  MYPORTHIGH=$(($ZOOBASEPORTHIGH + $MYID))
  mkdir -p "$MYCFGDIR/data" "$MYCFGDIR/logs"

  cat > "$MYCFGDIR/zoo.cfg" << ZOOCFG
# The number of milliseconds of each tick
tickTime=2000
# The number of ticks that the initial
# synchronization phase can take
initLimit=20
# The number of ticks that can pass between
# sending a request and getting an acknowledgement
syncLimit=5
# the directory where the snapshot is stored.
# do not use /tmp for storage, /tmp here is just
# example sakes.
dataDir=$MYCFGDIR/data
dataLogDir=$MYCFGDIR/data
dynamicConfigFile=$MYCFGDIR/zoo.cfg.dynamic.1
# the port at which the clients will connect
clientPort=$MYPORT
clientPortAddress=127.0.0.1
# the maximum number of client connections.
# increase this if you need to handle more clients
#maxClientCnxns=60
#
# The number of snapshots to retain in dataDir
autopurge.snapRetainCount=3
# Purge task interval in hours
# Set to "0" to disable auto purge feature
autopurge.purgeInterval=10

## Metrics Providers
#
# https://prometheus.io Metrics Exporter
#metricsProvider.className=org.apache.zookeeper.metrics.prometheus.PrometheusMetricsProvider
#metricsProvider.httpPort=7000
#metricsProvider.exportJvmInfo=true

admin.enableServer=false
skipACL=true
4lw.commands.whitelist=stat, ruok, conf, isro, srvr, mntr
ZOOCFG

  echo "${MYID}" > "${MYCFGDIR}/data/myid"
  echo "server.$MYID=127.0.0.1:$MYPORTLOW:$MYPORTHIGH" >> $TEMPDYN
}

find_process() {
  MYID=$1
  ZOOCFGDIR=$ZOOCFGROOT/${MYID}
  ZOOCFG=${ZOOCFGDIR}/zoo.cfg

  ps -o pid,cmd -C java | grep "$ZOOCFG" | sed -r -e 's,^[ ]*([0-9]+)[ ].*,\1,'
}

finish_cfg() {
  MYID=$1
  MYCFGDIR="$ZOOCFGROOT/$MYID"
  cp $TEMPDYN $MYCFGDIR/zoo.cfg.dynamic.1
}

start_id() {
  MYID=$1
  ZOOCFGDIR=$ZOOCFGROOT/${MYID}
  ZOOCFG=${ZOOCFGDIR}/zoo.cfg
  ZOO_LOG_DIR=$ZOOCFGDIR/logs

  export ZOOCFG ZOOCFGDIR ZOO_LOG_DIR
  (
  nohup /usr/bin/java \
    -cp "$ZOOCFGDIR:$CLASSPATH" \
    $OPTS "-Dzookeeper.log.dir=$ZOO_LOG_DIR" \
    $CLS "$ZOOCFG" >/dev/null 2>/dev/null &
  )
  echo "Process $(find_process $MYID) started."
}

stop_id() {
  MYID=$1
  ZOOCFGDIR=$ZOOCFGROOT/${MYID}
  ZOOCFG=${ZOOCFGDIR}/zoo.cfg

  PID=$(find_process $MYID)
  if [ -n "$PID" ]
  then
    echo "Killing process $PID"
    kill $PID
  else
    echo "No process found."
  fi
}

clean_id() {
  MYID=$1
  ZOOCFGDIR=$ZOOCFGROOT/${MYID}

  rm -v $ZOOCFGDIR/data/version-2/{log,snapshot}.*
  rm -v $ZOOCFGDIR/logs/zookeeper*.log*
}

usage() {
  echo "usage: $0 bootstrap|clean|start|stop [NUMBER]..."
  echo
  echo "Helper script to start a ZooKeeper cluster."
  echo
  echo "Actions:"
  echo "    bootstrap: prepare configuration files"
  echo "    clean:     clean logs and snapshots"
  echo "    start:     start ZooKeeper node NUMBER"
  echo "    stop:      stop ZooKeeper node NUMBER"
  echo
  echo "    NUMBER:	indices of ZooKeeper nodes (\"1 2 3\" to deploy 3 nodes)"
  echo
  echo "Environment:"
  echo "    ZOOBINDIR: path to the directory of ZooKeeper utility scripts"
  echo "               (required if installed from source)"
}

if [ -n "$ZOOBINDIR" ]
then
  . $ZOOBINDIR/zkEnv.sh
else
  . /usr/bin/zkEnv.sh
fi

OPERATION=$1
shift

case $OPERATION in
  bootstrap)
    for NUM in $@
    do
      bootstrap_cfg $NUM
    done
    for NUM in $@
    do
      finish_cfg $NUM
    done
    rm -f $TEMPDYN
    ;;
  clean)
    for NUM in $@
    do
      clean_id $NUM
    done
    ;;
  start)
    for NUM in $@
    do
      start_id $NUM
    done
    ;;
  stop)
    for NUM in $@
    do
      stop_id $NUM
    done
    ;;
  *)
    usage
    exit 1
    ;;
esac
