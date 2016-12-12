set -e
export COLUMNS=512 LANG=

export G_DEBUG=fatal_warnings
export G_SLICE=always-malloc

SRCDIR=$PWD
WRKDIR=$PWD
if [ $# -eq 2 ] ; then
    SRCDIR="$1"
    WRKDIR="$2"
fi

function dump_syslog {
    cmd=tail
    if ! [ -r /var/log/syslog ] ; then
        cmd="sudo tail"
    fi
    echo
    $cmd -n 1000 /var/log/syslog
    echo
    ps -efjH
    echo
    ulimit -a
    echo
    python --version
    pip show setuptools
    echo
    gridinit_cmd -S $HOME/.oio/sds/run/gridinit.sock status2
}

#trap dump_syslog EXIT

func_tests () {
    echo -e "\n### FUNC tests : $@\n" | logger -t TEST
    export OIO_NS="NS-${RANDOM}" OIO_ACCOUNT="ACCT-$RANDOM" OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM
    oio-reset.sh -v -v -N $OIO_NS $@
    echo -e "END OF RESET" | logger -t TEST
    cd $SRCDIR
    tox && tox -e func
    cd $WRKDIR
    make -C tests/func test
    ./core/tool_roundtrip /etc/passwd
}

test_worm () {
    export OIO_NS="NS-${RANDOM}" OIO_ACCOUNT="ACCT-$RANDOM" OIO_USER=USER-$\
       RANDOM OIO_PATH=PATH-$RANDOM
    oio-reset.sh -v -v -N $OIO_NS $@
    echo -e "END OF RESET" | logger -t TEST
    cd $SRCDIR
    export WORM=1
    tox
    echo "test_filters: begin WORM test"
    nosetests tests.functional.m2_filters.test_filters
    unset WORM
}

test_slave () {
    export OIO_NS="NS-${RANDOM}" OIO_ACCOUNT="ACCT-$RANDOM" OIO_USER=USER-$\
       RANDOM OIO_PATH=PATH-$RANDOM
    oio-reset.sh -v -v -N $OIO_NS $@
    echo -e "END OF RESET" | logger -t TEST
    cd $SRCDIR
    export SLAVE=1
    tox
    echo "test_filters: begin SLAVE test"
    nosetests tests.functional.m2_filters.test_filters
    unset SLAVE
}

echo -e "\n### UNIT tests\n"
cd $WRKDIR
make -C tests/unit test

test_worm -f "${SRCDIR}/etc/bootstrap-WORM.yml"
test_slave -f "${SRCDIR}/etc/bootstrap-SLAVE.yml"
func_tests -f "${SRCDIR}/etc/bootstrap-SINGLE.yml" -f "${SRCDIR}/etc/bootstrap-smallcache.yml"
func_tests -f "${SRCDIR}/etc/bootstrap-3COPIES-11RAWX.yml"
func_tests -f "${SRCDIR}/etc/bootstrap-EC.yml"
