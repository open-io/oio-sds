#!/usr/bin/env bash

# oio-travis-tests.sh
# Copyright (C) 2016-2017 OpenIO SAS, as part of OpenIO SDS
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

is_running_test_suite () {
    [ -z "$TEST_SUITE" ] || [ "${TEST_SUITE/*$1*/$1}" == "$1" ]
}

randomize_env () {
    export OIO_NS="NS-${RANDOM}" OIO_ACCOUNT="ACCT-$RANDOM" \
        OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM
}

test_oio_cluster () {
	oio-cluster -h >/dev/null
	oio-cluster --unlock-score -S "$OIO_NS|echo|127.0.0.2:80" >/dev/null
	oio-cluster --set-score=0 -S "$OIO_NS|echo|127.0.0.2:80" >/dev/null
	oio-cluster --unlock-score -S "$OIO_NS|echo|127.0.0.2:80" >/dev/null
	oio-cluster --clear-services echo $OIO_NS >/dev/null
	if oio-cluster --clear-services NotFoundXxX $OIO_NS >/dev/null ; then exit 1 ; fi
	oio-cluster --local-cfg >/dev/null
	oio-cluster --local-ns >/dev/null
}

test_oio_tool () {
	oio-tool -h >/dev/null
	oio-tool config "$OIO_NS" >/dev/null
	if oio-tool >/dev/null ; then exit 1 ; fi
	oio-tool stat / /tmp /usr | head -n 1
	oio-tool location A.B.C.D
	for url in $(oio-test-config.py -t conscience) ; do
		oio-tool ping "$url" >/dev/null
		if oio-tool info "$url" >/dev/null ; then exit 1 ; fi
		if oio-tool redirect "$url" >/dev/null ; then exit 1 ; fi
	done
	for url in $(oio-test-config.py -t meta2 -t meta0 -t meta1) ; do
		oio-tool ping "$url" >/dev/null
		oio-tool info "$url" >/dev/null
		oio-tool redirect "$url" >/dev/null
	done
	if oio-tool ping 127.0.0.1:2 >/dev/null ; then exit 1 ; fi
	if [ 1 -ne $(oio-tool addr a 127.0.0.1:1234 | wc -l) ] ; then exit 1 ; fi
	if [ 1 -ne $(oio-tool cid OPENIO/ACCT/JFS | wc -l) ] ; then exit 1 ; fi
	oio-tool hash XXX | head -n 2 >/dev/null
}

test_proxy_forward () {
	proxy=$(oio-test-config.py -t proxy -1)

	curl -X GET "http://$proxy/v3.0/status" >/dev/null
	curl -X GET "http://$proxy/v3.0/cache/status" >/dev/null
	curl -X GET "http://$proxy/v3.0/config" >/dev/null
	curl -X POST "http://$proxy/v3.0/cache/flush/local" >/dev/null
	curl -X POST "http://$proxy/v3.0/cache/flush/high" >/dev/null
	curl -X POST "http://$proxy/v3.0/cache/flush/low" >/dev/null
	curl -X POST -d '{"socket.nodelay.enabled":"on"}' \
		"http://$proxy/v3.0/config" >/dev/null

	for url in $(oio-test-config.py -t meta2 -t meta0 -t meta1) ; do
		curl -X GET "http://$proxy/v3.0/forward/config&id=$url" >/dev/null
		curl -X POST -d '{"socket.nodelay.enabled":"on"}' \
			"http://$proxy/v3.0/forward/config&id=$url" >/dev/null
		curl -X POST "http://$proxy/v3.0/forward/flush&id=$url" >/dev/null
		curl -X POST "http://$proxy/v3.0/forward/reload&id=$url" >/dev/null
		curl -X POST "http://$proxy/v3.0/forward/ping&id=$url" >/dev/null
		curl -X POST "http://$proxy/v3.0/forward/lean-glib&id=$url" >/dev/null
		curl -X POST "http://$proxy/v3.0/forward/lean-sqlx&id=$url" >/dev/null
		curl -X POST "http://$proxy/v3.0/forward/version&id=$url" >/dev/null
		curl -X POST "http://$proxy/v3.0/forward/handlers&id=$url" >/dev/null
		curl -X POST "http://$proxy/v3.0/forward/info&id=$url" >/dev/null
	done
}

func_tests () {
	randomize_env
    oio-reset.sh -N $OIO_NS $@

	test_proxy_forward

    # test a content with a strange name, through the CLI and the API
    /usr/bin/fallocate -l $RANDOM /tmp/blob%
    CNAME=$RANDOM
    ${PYTHON} $(which openio) object create $CNAME /tmp/blob%

    # At least spawn one oio-crawler-integrity on a container that exists
    # TODO(jfs): Move in a tests/functional/cli python test
    ${PYTHON} $(which oio-crawler-integrity) $OIO_NS $OIO_ACCOUNT $CNAME

	# Run the whole suite of functional tests (Python)
    cd $SRCDIR
    tox -e coverage
    tox -e func

	# Run the whole suite of functional tests (C)
    cd $WRKDIR
    make -C tests/func test

    # Create a file just bigger than chunk size
    SOURCE=$(mktemp)
    dd if=/dev/urandom of=$SOURCE bs=128K count=9
	# Run the test-suite of the C API
    ./core/tool_roundtrip $SOURCE
    rm -f $SOURCE

	test_oio_cluster
	test_oio_tool

	# Must be final, it removes the system config
	rm "/$HOME/.oio/sds.conf"
	export OIO_PROXY=$(oio-test-config.py -t proxy -1)
	export OIO_ECD=$(oio-test-config.py -t ecd -1)
	./core/tool_sdk_noconf

    gridinit_cmd -S $HOME/.oio/sds/run/gridinit.sock stop
    sleep 0.5
}

test_meta2_filters () {
	randomize_env
    oio-reset.sh -N $OIO_NS $@

    cd $SRCDIR
    tox -e coverage
    ${PYTHON} $(which nosetests) tests.functional.m2_filters.test_filters

    gridinit_cmd -S $HOME/.oio/sds/run/gridinit.sock stop
    sleep 0.5
}

test_cli () {
    randomize_env
    oio-reset.sh -N $OIO_NS $@

    cd $SRCDIR
    tox -e cli

    gridinit_cmd -S $HOME/.oio/sds/run/gridinit.sock stop
    sleep 0.5
}

/sbin/sysctl net.ipv4.ip_local_port_range

if is_running_test_suite "copyright" ; then
	echo -e "\n### Checking the presence of Copyright mentions"
	${SRCDIR}/tools/oio-check-copyright.sh ${SRCDIR}
fi

if is_running_test_suite "unit" ; then
	echo -e "\n### UNIT tests"
	cd $SRCDIR
	tox -e pep8
	tox -e py27
	cd $WRKDIR
	make -C tests/unit test
fi

if is_running_test_suite "repli" ; then
	echo -e "\n### Replication tests"
    func_tests -f "${SRCDIR}/etc/bootstrap-preset-smallrepli.yml" \
		-f "${SRCDIR}/etc/bootstrap-option-udp.yml"
	fi

if is_running_test_suite "worm" ; then
	echo -e "\n### WORM tests"
    export WORM=1
	for nb in 0 1 2 3 ; do
		test_meta2_filters -f "${SRCDIR}/etc/bootstrap-preset-SINGLE.yml" \
			-f "${SRCDIR}/etc/bootstrap-option-worm.yml" \
			-f "${SRCDIR}/etc/bootstrap-meta1-${nb}digits.yml"
	done
	unset WORM
fi

if is_running_test_suite "slave" ; then
	echo -e "\n### SLAVE tests"
    export SLAVE=1
	for nb in 0 1 2 3 ; do
		test_meta2_filters -f "${SRCDIR}/etc/bootstrap-preset-SINGLE.yml" \
			-f "${SRCDIR}/etc/bootstrap-option-slave.yml" \
			-f "${SRCDIR}/etc/bootstrap-meta1-${nb}digits.yml"
	done
	unset SLAVE
fi

if is_running_test_suite "cli" ; then
    echo -e "\n### CLI tests"
    test_cli -f "${SRCDIR}/etc/bootstrap-preset-SINGLE.yml" \
        -f "${SRCDIR}/etc/bootstrap-option-cache.yml"
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

