#!/bin/bash

# This script install FoundationDB for non-sudoer user.
# Usage:
#    ./oio-install-fdb.sh [install_dir]
#
#   install_dir: root installation dir, default '$HOME/.local'
#   set FORCE environment variable to overwrite configurations files

set -e
trap 'catch $? $LINENO' EXIT

TMP_DIR=$(mktemp -d -t oio-fdb-XXXXXXXXXX)
LOG_FILE=$TMP_DIR/install.log
INSTALL_DIR="$HOME/.local"

if [ ! -z $1 ]; then
    INSTALL_DIR=$1
fi

catch() {
    popd > /dev/null
    echo 'Cleanup'
    [ ! -d  $TMP_DIR ] || rm -fr $TMP_DIR
    if [ "$1" != "0" ]; then
        echo 'Failed to install'
        [ ! -f $LOG_FILE ] || cat $LOG_FILE
    fi
}

with_log() {
    if [[ "$VERBOSE" == "1" ]]; then
        "$@" 2>&1 | tee $LOG_FILE
    else
        "$@" 2>&1 >> $LOG_FILE
    fi
}

mkdir -p $INSTALL_DIR

echo "Create $TMP_DIR"
pushd $TMP_DIR > /dev/null

FDB_VERSION='6.3.23'

echo 'Download archives'
with_log wget -q https://github.com/apple/foundationdb/releases/download/${FDB_VERSION}/foundationdb-clients_${FDB_VERSION}-1_amd64.deb
with_log wget -q https://github.com/apple/foundationdb/releases/download/${FDB_VERSION}/foundationdb-server_${FDB_VERSION}-1_amd64.deb

echo 'Extract files'
with_log ar xv foundationdb-clients_${FDB_VERSION}-1_amd64.deb
with_log tar xzvf data.tar.gz
with_log ar xv foundationdb-server_${FDB_VERSION}-1_amd64.deb
with_log tar xzvf data.tar.gz

echo 'Copy files'
with_log cp -r usr $INSTALL_DIR
with_log mv etc/foundationdb/foundationdb.conf etc/foundationdb/foundationdb.conf.orig
with_log cp -r etc $INSTALL_DIR
with_log cp -r var $INSTALL_DIR

echo 'Install service'
mkdir -p $HOME/.config/systemd/user
if [ ! -f $HOME/.config/systemd/user/foundationdb.service ] || [[ -v FORCE ]]; then
    cat << EOF > $HOME/.config/systemd/user/foundationdb.service
[Unit]
Description=FoundationDB Server
After=network-online.target

[Service]
Type=simple
TimeoutSec=120
ExecStart=$INSTALL_DIR/usr/lib/foundationdb/fdbmonitor --conffile $INSTALL_DIR/etc/foundationdb/foundationdb.conf --lockfile $INSTALL_DIR/var/run/fdbmonitor.pid

Restart=on-failure
EOF
fi

echo 'Configure'
if [ ! -f $INSTALL_DIR/etc/foundationdb/foundationdb.conf ] || [[ -v FORCE ]]; then
    USER=$(id -un)
    GROUP=$(id -gn)
    cat << EOF > $INSTALL_DIR/etc/foundationdb/foundationdb.conf
## foundationdb.conf
##
## Configuration file for FoundationDB server processes
## Full documentation is available at
## https://apple.github.io/foundationdb/configuration.html#the-configuration-file

[fdbmonitor]
user = $USER
group = $GROUP

[general]
restart_delay = 60
cluster_file = $INSTALL_DIR/etc/foundationdb/fdb.cluster

[fdbserver]
command = $INSTALL_DIR/usr/sbin/fdbserver
public_address = auto:\$ID
listen_address = public
datadir = $INSTALL_DIR/var/lib/foundationdb/data/\$ID
logdir = $INSTALL_DIR/var/log/foundationdb

[fdbserver.4500]

[backup_agent]
command = $INSTALL_DIR/usr/lib/foundationdb/backup_agent/backup_agent
logdir = $INSTALL_DIR/var/log/foundationdb

[backup_agent.1]
EOF
fi

if [ ! -f $INSTALL_DIR/etc/foundationdb/fdb.cluster ] || [[ -v FORCE ]]; then
    description=`LC_CTYPE=C tr -dc A-Za-z0-9 < /dev/urandom | head -c 8`
    random_str=`LC_CTYPE=C tr -dc A-Za-z0-9 < /dev/urandom | head -c 8`
    echo $description:$random_str@127.0.0.1:4500 > $INSTALL_DIR/etc/foundationdb/fdb.cluster
    NEWDB=1
fi

echo 'Start FoundationDB service'
with_log systemctl --user daemon-reload
with_log systemctl --user restart foundationdb.service

if [ "$NEWDB" != "" ]; then
    echo 'Initialize database'
    with_log $INSTALL_DIR/usr/bin/fdbcli -C $INSTALL_DIR/etc/foundationdb/fdb.cluster --exec 'configure new single memory; status' --timeout 20
fi

with_log systemctl --user stop foundationdb.service

echo "FoundationDB ${FDB_VERSION} successfully installed in directory: ${INSTALL_DIR}"
echo "Next step is to add install dir in your environment. Add this in your .bashrc"
echo -e "\t- export PATH=${INSTALL_DIR}/usr/bin:${INSTALL_DIR}/usr/sbin:${INSTALL_DIR}/usr/lib/foundationdb:${INSTALL_DIR}/usr/lib/foundationdb/backup_agent:\$PATH"
echo -e "\t- export LD_LIBRARY_PATH=${INSTALL_DIR}/usr/lib:\$LD_LIBRARY_PATH"
echo -e "\t- export FDB_CLUSTER_FILE=${INSTALL_DIR}/etc/foundationdb/fdb.cluster"
