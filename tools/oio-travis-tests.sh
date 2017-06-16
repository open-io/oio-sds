set -e
set -x
export COLUMNS=512 LANG= LANGUAGE=

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

has_coverage () { [ -n "$COVERAGE" ] ; }

is_running_test_suite () {
    has_coverage || [ -z "$TEST_SUITE" ] || [ "${TEST_SUITE/*$1*/$1}" == "$1" ]
}

randomize_env () {
    export OIO_NS="NS-${RANDOM}" OIO_ACCOUNT="ACCT-$RANDOM" \
        OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM
}

func_tests () {
	randomize_env
    oio-reset.sh -N $OIO_NS $@

    # test a content with a strange name, through the CLI and the API
    /usr/bin/fallocate -l $RANDOM /tmp/blob%
    ${PYTHON} $(which openio) object create $RANDOM /tmp/blob%

	# Run the whole suite of functional tests (Python)
    cd $SRCDIR
    if has_coverage ; then
		tox -e coverage && tox -e cover,func
	else
		tox -e func
    fi

	# Run the whole suite of functional tests (C)
    cd $WRKDIR
    make -C tests/func test

    # Create a file just bigger than chunk size
    SOURCE=$(mktemp)
    dd if=/dev/urandom of=$SOURCE bs=128K count=9
	# Run the test-suite of the C API
    ./core/tool_roundtrip $SOURCE
    rm -f $SOURCE
}


test_meta2_filters () {
	randomize_env
    oio-reset.sh -N $OIO_NS $@

    cd $SRCDIR
    if has_coverage ; then
		tox -e coverage
    fi
    ${PYTHON} $(which nosetests) tests.functional.m2_filters.test_filters
}


if is_running_test_suite "unit" ; then
	echo -e "\n### UNIT tests"
	cd $SRCDIR && tox -e pep8 && tox -e py27
	cd $WRKDIR && make -C tests/unit test
fi

if is_running_test_suite "repli" ; then
	echo -e "\n### Replication tests"
    func_tests -f "${SRCDIR}/etc/bootstrap-preset-smallrepli.yml"
fi

if is_running_test_suite "worm" ; then
	echo -e "\n### WORM tests"
    export WORM=1
    test_meta2_filters -f "${SRCDIR}/etc/bootstrap-preset-SINGLE.yml" \
		-f "${SRCDIR}/etc/bootstrap-option-worm.yml"
	unset WORM
fi

if is_running_test_suite "slave" ; then
	echo -e "\n### SLAVE tests"
    export SLAVE=1
    test_meta2_filters -f "${SRCDIR}/etc/bootstrap-preset-SINGLE.yml" \
		-f "${SRCDIR}/etc/bootstrap-option-slave.yml"
	unset SLAVE
fi

if is_running_test_suite "small-cache" ; then
	echo -e "\n### Small Cache tests"
    func_tests -f "${SRCDIR}/etc/bootstrap-preset-SINGLE.yml" \
		-f "${SRCDIR}/etc/bootstrap-option-smallcache.yml"
fi

if is_running_test_suite "3copies" ; then
	echo -e "\n### 3copies tests"
    func_tests -f "${SRCDIR}/etc/bootstrap-preset-3COPIES-11RAWX.yml"
fi

if is_running_test_suite "ec" ; then
	echo -e "\n### EC tests"
    func_tests -f "${SRCDIR}/etc/bootstrap-preset-EC.yml"
fi

