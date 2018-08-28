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

export G_DEBUG=fatal_warnings
export G_SLICE=always-malloc

export PYTHON=python
if [ "${PYTHON_COVERAGE:-}" == "1" ]; then
	PYTHON="coverage run -p --omit=/home/travis/oio/lib/python2.7/*"
fi

OIO_RESET="oio-reset.sh -v"

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

function trap_exit {
	set +e
	#pip list
	BEANSTALK=$(oio-test-config.py -t beanstalkd)
	if [ ! -z "${BEANSTALK}" ]; then
		oio-dump-buried-events.py ${BEANSTALK}
	fi
	gridinit_cmd -S $HOME/.oio/sds/run/gridinit.sock status3
	#dump_syslog
	oio-gdb.py
}

trap trap_exit EXIT

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
		curl -X GET "http://$proxy/v3.0/forward/config?id=$url" >/dev/null
		curl -X POST -d '{"socket.nodelay.enabled":"on"}' \
			"http://$proxy/v3.0/forward/config?id=$url" >/dev/null
		curl -X POST "http://$proxy/v3.0/forward/flush?id=$url" >/dev/null
		curl -X POST "http://$proxy/v3.0/forward/reload?id=$url" >/dev/null
		curl -X POST "http://$proxy/v3.0/forward/ping?id=$url" >/dev/null
		curl -X POST "http://$proxy/v3.0/forward/lean-glib?id=$url" >/dev/null
		curl -X POST "http://$proxy/v3.0/forward/lean-sqlx?id=$url" >/dev/null
		curl -X POST "http://$proxy/v3.0/forward/version?id=$url" >/dev/null
		curl -X POST "http://$proxy/v3.0/forward/handlers?id=$url" >/dev/null
		curl -X POST "http://$proxy/v3.0/forward/info?id=$url" >/dev/null
	done
}

wait_proxy_cache() {
    cnt=$(oio-test-config.py -t rawx | wc -l)
    while true; do
        rawx=$(curl -s http://$proxy/v3.0/cache/show | python -m json.tool | grep -c rawx | cat)
        if [ $cnt -eq $rawx ]; then
            break
        fi
        sleep 0.1
    done

    cnt=$(oio-test-config.py -t meta2 | wc -l)
    while true; do
        meta2=$(curl -s http://$proxy/v3.0/cache/show | python -m json.tool | grep -c meta2 | cat)
        if [ $cnt -eq $meta2 ]; then
            break
        fi
        sleep 0.1
    done
}

ec_tests () {
	randomize_env
    $OIO_RESET -N $OIO_NS $@

	SIZE0=$((256*1024*1024))
	export OIO_USER=user-$RANDOM OIO_PATH=path-$RANDOM
	echo $OIO_NS $OIO_ACCOUNT $OIO_USER $OIO_PATH
	( export G_DEBUG_LEVEL=W ; ./core/tool_sdk put $SIZE0 )
	openio object save $OIO_USER $OIO_PATH
	SIZE=$(stat --printf='%s' $OIO_PATH)
	/bin/rm "$OIO_PATH"
	[ "$SIZE0" == "$SIZE" ]

    gridinit_cmd -S $HOME/.oio/sds/run/gridinit.sock stop
	sleep 0.5
}

func_tests () {
	randomize_env
	args=
	if is_running_test_suite "with-service-id"; then
		args="${args} -U"
	fi
	if is_running_test_suite "with-random-service-id"; then
		args="${args} -R"
	fi
	$OIO_RESET ${args} -N $OIO_NS $@

	test_proxy_forward

	wait_proxy_cache

	# test a content with a strange name, through the CLI and the API
	/usr/bin/fallocate -l $RANDOM /tmp/blob%
	CNAME=$RANDOM
	${PYTHON} $(which openio) object create $CNAME /tmp/blob%

	if is_running_test_suite "repli"; then
		oio-check-directory ${OIO_NS} meta0 meta1 dir rdir
		oio-check-master --oio-account $OIO_USER --oio-ns $OIO_NS $CNAME
	fi

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

    # test a content with a strange name, through the CLI and the API
    /usr/bin/fallocate -l $RANDOM /tmp/blob%
    CNAME=$RANDOM
    ${PYTHON} $(which openio) object create $CNAME /tmp/blob%
    # At least spawn one oio-crawler-integrity on a container that exists
    # TODO(jfs): Move in a tests/functional/cli python test
    ${PYTHON} $(which oio-crawler-integrity) $OIO_NS $OIO_ACCOUNT $CNAME

	# Create a file just bigger than chunk size
	SOURCE=$(mktemp)
	dd if=/dev/urandom of=$SOURCE bs=128K count=9

	# Run the test-suite of the C API
	${WRKDIR}/core/tool_roundtrip $SOURCE
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
	$OIO_RESET -N $OIO_NS $@

	cd $SRCDIR
	tox -e coverage
	${PYTHON} $(which nosetests) tests.functional.m2_filters.test_filters

	gridinit_cmd -S $HOME/.oio/sds/run/gridinit.sock stop
	sleep 0.5
}

test_cli () {
	randomize_env
	$OIO_RESET -N $OIO_NS $@

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

if is_running_test_suite "variables" ; then
	echo -e "\n### Checking Variables.md"
	cd $SRCDIR
	tox -e variables
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
		-f "${SRCDIR}/etc/bootstrap-option-udp.yml" \
		-f "${SRCDIR}/etc/bootstrap-option-long-timeouts.yml" \
		-f "${SRCDIR}/etc/bootstrap-meta1-1digits.yml"
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
	ec_tests -f "${SRCDIR}/etc/bootstrap-preset-EC.yml" \
		-f "${SRCDIR}/etc/bootstrap-option-chunksize-512MiB.yml"

	func_tests -f "${SRCDIR}/etc/bootstrap-preset-EC.yml"
fi

if is_running_test_suite "multi-beanstalk" ; then
	echo -e "\n### Tests with multiple beanstalkd"
	func_tests \
		-f "${SRCDIR}/etc/bootstrap-preset-SINGLE.yml" \
		-f "${SRCDIR}/etc/bootstrap-option-3beanstalkd.yml"
fi

func_tests_rebuilder_mover () {
	randomize_env
	args=
	if is_running_test_suite "with-service-id"; then
		args="${args} -U"
	fi
	if is_running_test_suite "with-random-service-id"; then
		args="${args} -R"
	fi
	$OIO_RESET ${args} -N $OIO_NS $@

	test_proxy_forward

	wait_proxy_cache

	for i in $(seq 1 100); do
		dd if=/dev/urandom of=/tmp/openio_object_$i bs=1K \
				count=$(shuf -i 1-2000 -n 1) 2> /dev/null
		echo "object create container-${RANDOM} /tmp/openio_object_$i" \
				"--name object-${RANDOM}"
	done | ${PYTHON} $(which openio)

	if [ -n "${REBUILDER}" ]; then
		${SRCDIR}/tools/oio-test-rebuilder.sh -n "${OIO_NS}"
	fi
	if [ -n "${MOVER}" ]; then
		${SRCDIR}/tools/oio-test-mover.sh -n "${OIO_NS}"
	fi

	gridinit_cmd -S $HOME/.oio/sds/run/gridinit.sock stop
	sleep 0.5
}

if is_running_test_suite "rebuilder" ; then
	echo -e "\n### Tests all rebuilders"

	export REBUILDER=1

	func_tests_rebuilder_mover \
		-f "${SRCDIR}/etc/bootstrap-preset-smallrepli.yml" \
		-f "${SRCDIR}/etc/bootstrap-option-udp.yml" \
		-f "${SRCDIR}/etc/bootstrap-option-long-timeouts.yml" \
		-f "${SRCDIR}/etc/bootstrap-meta1-1digits.yml"

	func_tests_rebuilder_mover \
		-f "${SRCDIR}/etc/bootstrap-preset-3COPIES-11RAWX.yml"

	func_tests_rebuilder_mover \
		-f "${SRCDIR}/etc/bootstrap-preset-EC.yml"

	unset REBUILDER
fi

if is_running_test_suite "mover" ; then
	echo -e "\n### Tests meta2 mover"

	export MOVER=1

	func_tests_rebuilder_mover \
		-f "${SRCDIR}/etc/bootstrap-preset-smallrepli.yml" \
		-f "${SRCDIR}/etc/bootstrap-option-udp.yml" \
		-f "${SRCDIR}/etc/bootstrap-option-long-timeouts.yml" \
		-f "${SRCDIR}/etc/bootstrap-meta1-1digits.yml"

	unset MOVER
fi
