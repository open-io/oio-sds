set -e
export COLUMNS=512 LANG=

export G_DEBUG=fatal_warnings
export G_SLICE=always-malloc

export PYTHON=python

if [ "${PYTHON_COVERAGE:-}" == "1" ]; then
    PYTHON="coverage run -p --omit=/home/travis/oio/lib/python2.7/*"
fi

SRCDIR=$PWD
WRKDIR=$PWD
if [ $# -eq 2 ] ; then
    SRCDIR="$1"
    WRKDIR="$2"
fi

run_folded () {
	TAG=$0 ; shift
	echo "travis_fold:start:$TAG"
	time $@
	echo "travis_fold:end:$TAG"
}

function dump_syslog {
    cmd=tail
    if ! [ -r /var/log/syslog ] ; then
        cmd="sudo tail"
    fi
    $cmd -n 500 /var/log/syslog
    pip list
    gridinit_cmd -S $HOME/.oio/sds/run/gridinit.sock status3
}

#trap dump_syslog EXIT

func_tests () {
    export OIO_NS="NS-${RANDOM}" OIO_ACCOUNT="ACCT-$RANDOM" OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM
    oio-reset.sh -N $OIO_NS $@

    # test a content with a strange name, through the CLI and the API
    /usr/bin/fallocate -l $RANDOM /tmp/blob%
    ${PYTHON} $(which openio) object create $RANDOM /tmp/blob%

    cd $SRCDIR
    tox -e coverage && tox -e func,coverage
    cd $WRKDIR
    make -C tests/func test
    ./core/tool_roundtrip /etc/passwd
}

test_worm () {
    export OIO_NS="NS-${RANDOM}" OIO_ACCOUNT="ACCT-$RANDOM" OIO_USER=USER-$\
       RANDOM OIO_PATH=PATH-$RANDOM
    oio-reset.sh -N $OIO_NS $@
    cd $SRCDIR
    export WORM=1
    tox -e coverage
    ${PYTHON} $(which nosetests) tests.functional.m2_filters.test_filters
    unset WORM
}

test_slave () {
    export OIO_NS="NS-${RANDOM}" OIO_ACCOUNT="ACCT-$RANDOM" OIO_USER=USER-$\
       RANDOM OIO_PATH=PATH-$RANDOM
    oio-reset.sh -N $OIO_NS $@
    cd $SRCDIR
    export SLAVE=1
    tox
    ${PYTHON} $(which nosetests) tests.functional.m2_filters.test_filters
    unset SLAVE
}

cd $WRKDIR

is_running_test_suite () {
	[ -n "$COVERAGE" ] || [ -z "$TEST_SUITE" ] || [ "$TEST_SUITE" == "$1" ]
}

if is_running_test_suite "unit" ; then
	make -C tests/unit test
fi

if is_running_test_suite "repli" ; then
	func_tests -f "${SRCDIR}/etc/bootstrap-preset-smallrepli.yml"
fi

if is_running_test_suite "worm" ; then
	test_worm  -f "${SRCDIR}/etc/bootstrap-preset-SINGLE.yml" -f "${SRCDIR}/etc/bootstrap-option-worm.yml"
fi

if is_running_test_suite "slave" ; then
	test_slave -f "${SRCDIR}/etc/bootstrap-preset-SINGLE.yml" -f "${SRCDIR}/etc/bootstrap-option-slave.yml"
fi

if is_running_test_suite "single" ; then
	func_tests -f "${SRCDIR}/etc/bootstrap-preset-SINGLE.yml" -f "${SRCDIR}/etc/bootstrap-option-smallcache.yml"
	func_tests -f "${SRCDIR}/etc/bootstrap-preset-3COPIES-11RAWX.yml"
fi

if is_running_test_suite "ec" ; then
	func_tests -f "${SRCDIR}/etc/bootstrap-preset-EC.yml"
fi

