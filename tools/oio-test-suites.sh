#!/usr/bin/env bash
# vim: ts=4 shiftwidth=4 noexpandtab

# oio-test-suites.sh
# Copyright (C) 2016-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021 OVH SAS
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

function dump_syslog {
	cmd="tail"
	if ! [ -r /var/log/syslog ] ; then
		cmd="sudo tail"
	fi
	$cmd -n 500 /var/log/syslog
	#$cmd -n 500 $HOME/.oio/sds/logs/*.log
	#journalctl -o short-precise -n 500
	pip list
	gridinit_cmd -S "$HOME/.oio/sds/run/gridinit.sock" status3
}

function trap_exit {
	echo "--------------------"
	echo "EXIT signal trapped"
	echo "--------------------"
	set +e
	#pip list
	BEANSTALK=$(oio-test-config.py -t beanstalkd)
	if [ -n "${BEANSTALK}" ]; then
		# some tests stop all services, we must start beanstalk to dump events
		gridinit_cmd -S "$HOME/.oio/sds/run/gridinit.sock" start @beanstalkd
		oio-dump-buried-events.py ${BEANSTALK}
	fi
	gridinit_cmd -S "$HOME/.oio/sds/run/gridinit.sock" status3
	#dump_syslog
	${SRCDIR}/tools/oio-gdb.py
}

trap trap_exit EXIT

is_running_test_suite () {
	[ -z "$TEST_SUITE" ] || [ "${TEST_SUITE/*$1*/$1}" == "$1" ]
}

randomize_env () {
	export OIO_NS="NS-${RANDOM}" OIO_ACCOUNT="ACCT-$RANDOM" \
		OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM
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

test_oio_file_tool () {
	head -c 1M </dev/urandom > /tmp/test_oio_file.txt
	oio-file-tool --upload -n $OIO_NS -a $OIO_ACCOUNT -c testfiletool -f /tmp/test_oio_file.txt -o remote_file_test.txt
	oio-file-tool -n $OIO_NS -a $OIO_ACCOUNT -c testfiletool -f /tmp/test_oio_file2.txt -o remote_file_test.txt
	DIFF=$(diff /tmp/test_oio_file2.txt /tmp/test_oio_file.txt)
	rm /tmp/test_oio_file2.txt
	rm /tmp/test_oio_file.txt
	openio object delete testfiletool remote_file_test.txt
	openio container delete testfiletool
	if [ "$DIFF" != "" ] ; then exit 1; fi
}

test_oio_lb_benchmark() {
	# This is to test the tool, not the various datasets or pool
	# configurations. The datasets are tested by tests/unit/test_lb.
	${WRKDIR}/tools/oio-lb-benchmark -O iterations=1000 \
		"${SRCDIR}/tests/datasets/lb-3-5-4.txt" "6,rawx;min_dist=2" \
		2> lb-benchmark.log
	if [ $(grep -qv 'no service polled from' lb-benchmark.log) ]; then exit 1; fi
}

test_oio_logger() {
	# Expect the thing to exit with error 1. If it crashes in an uncontrolled
	# way, it will return 128+.
	set +e
	python ${WRKDIR}/tools/oio-crash-logger.py
	CODE=$?
	set -e
	if [ $CODE -ne 1 ]; then exit 1; fi
}

test_proxy_forward () {
	proxy=$(oio-test-config.py -t proxy -1)

	curl -sS  -X GET "http://$proxy/v3.0/status" >/dev/null
	curl -sS  -X GET "http://$proxy/v3.0/cache/status" >/dev/null
	curl -sS  -X GET "http://$proxy/v3.0/config" >/dev/null
	curl -sS  -X POST "http://$proxy/v3.0/cache/flush/local" >/dev/null
	curl -sS  -X POST "http://$proxy/v3.0/cache/flush/high" >/dev/null
	curl -sS  -X POST "http://$proxy/v3.0/cache/flush/low" >/dev/null
	curl -sS  -X POST -d '{"socket.nodelay.enabled":"on"}' \
		"http://$proxy/v3.0/config" >/dev/null

	for url in $(oio-test-config.py -t meta2 -t meta0 -t meta1) ; do
		curl -sS  -X GET "http://$proxy/v3.0/forward/config?id=$url" >/dev/null
		curl -sS  -X POST -d '{"socket.nodelay.enabled":"on"}' \
			"http://$proxy/v3.0/forward/config?id=$url" >/dev/null
		curl -sS  -X POST "http://$proxy/v3.0/forward/flush?id=$url" >/dev/null
		curl -sS  -X POST "http://$proxy/v3.0/forward/reload?id=$url" >/dev/null
		curl -sS  -X POST "http://$proxy/v3.0/forward/ping?id=$url" >/dev/null
		curl -sS  -X POST "http://$proxy/v3.0/forward/lean-glib?id=$url" >/dev/null
		curl -sS  -X POST "http://$proxy/v3.0/forward/lean-sqlx?id=$url" >/dev/null
		curl -sS  -X POST "http://$proxy/v3.0/forward/version?id=$url" >/dev/null
		curl -sS  -X POST "http://$proxy/v3.0/forward/handlers?id=$url" >/dev/null
		curl -sS  -X POST "http://$proxy/v3.0/forward/info?id=$url" >/dev/null
	done
}

wait_proxy_cache() {
	cnt=$(oio-test-config.py -t rawx | wc -l)
	while true; do
		rawx=$(curl -sS http://$proxy/v3.0/cache/show | python -m json.tool | grep -c rawx | cat)
		if [ "$cnt" -eq "$rawx" ]; then
			break
		fi
		sleep 0.1
	done

	cnt=$(oio-test-config.py -t meta2 | wc -l)
	while true; do
		meta2=$(curl -sS http://$proxy/v3.0/cache/show | python -m json.tool | grep -c meta2 | cat)
		if [ "$cnt" -eq "$meta2" ]; then
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
	( export G_DEBUG_LEVEL=W ; ${WRKDIR}/core/tool_sdk put $SIZE0 )
	openio object save $OIO_USER $OIO_PATH
	SIZE=$(stat --printf='%s' $OIO_PATH)
	/bin/rm "$OIO_PATH"
	[ "$SIZE0" == "$SIZE" ]

	gridinit_cmd -S "$HOME/.oio/sds/run/gridinit.sock" stop
	sleep 0.5
}

test_zookeeper_failure() {
	openio container create test_zookeeper_failure
	openio election debug meta2 test_zookeeper_failure

	date "+%s.%N"
	echo "Simulating a Zookeeper outage"
	# Old systemd versions do not recognize --value, whence the eval hack
	#MainPID=$(sudo systemctl show -p MainPID --value zookeeper)
	eval $(sudo systemctl show -p MainPID zookeeper)
	if [[ -n "$MainPID" ]] && [[ $MainPID -gt 0 ]] ; then
		sudo kill -STOP $MainPID
		openio election debug meta2 test_zookeeper_failure
		sleep 11
		sudo kill -CONT $MainPID

		openio election debug meta2 test_zookeeper_failure
		openio container locate test_zookeeper_failure
		openio election debug meta2 test_zookeeper_failure
		openio container delete test_zookeeper_failure
	fi
}

func_tests () {
	randomize_env
	# Some functional tests require events to be preserved after being handled
	args="-f ${SRCDIR}/etc/bootstrap-option-preserve-events.yml"
	if is_running_test_suite "with-service-id"; then
		args="${args} -U"
	fi
	if is_running_test_suite "with-random-service-id"; then
		args="${args} -R"
	fi
	if is_running_test_suite "fsync"; then
		args="${args} -f ${SRCDIR}/etc/bootstrap-option-rawx-fsync.yml"
	fi
	if is_running_test_suite "small-cache"; then
		args="${args} -f ${SRCDIR}/etc/bootstrap-option-smallcache.yml"
	fi
	if is_running_test_suite "webhook"; then
		args="${args} -f ${SRCDIR}/etc/bootstrap-option-webhook.yml"
	fi
	if is_running_test_suite "with_tls"; then
		args="${args} -f ${SRCDIR}/etc/bootstrap-option-tls.yml"
	fi
	if is_running_test_suite "predictible-chunk-ids"; then
		args="${args} -f ${SRCDIR}/etc/bootstrap-option-predictible-chunk-ids.yml"
	fi
	$OIO_RESET ${args} -N $OIO_NS $@

	test_proxy_forward

	wait_proxy_cache

	# The next commands often fail because the account service is slow to start
	${PYTHON} ${CLI} cluster wait -s 20 account

	# test a content with a strange name, through the CLI and the API
	/usr/bin/fallocate -l $RANDOM /tmp/blob%
	CNAME=$RANDOM
	${PYTHON} $CLI object create $CNAME /tmp/blob%

	${PYTHON} ${ADMIN_CLI} meta0 check
	${PYTHON} ${ADMIN_CLI} meta1 check
	${PYTHON} ${ADMIN_CLI} directory check
	${PYTHON} $(command -v oio-check-master) --oio-account $OIO_USER --oio-ns $OIO_NS $CNAME
	if is_running_test_suite "repli"; then
		test_zookeeper_failure
	fi
	${PYTHON} ${ADMIN_CLI} rdir check

	# At least spawn one oio-crawler-integrity on a container that exists
	# TODO(jfs): Move in a tests/functional/cli python test
	${PYTHON} $(command -v oio-crawler-integrity) $OIO_NS $OIO_ACCOUNT $CNAME

	# Run the whole suite of functional tests (Python)
	cd "$SRCDIR"
	tox -e coverage
	tox -e func

	# Run the whole suite of functional tests (C)
	cd $WRKDIR
	make -C tests/func test

	# test a content with a strange name, through the CLI and the API
	/usr/bin/fallocate -l $RANDOM /tmp/blob%
	CNAME=$RANDOM
	${PYTHON} $CLI object create $CNAME /tmp/blob%
	# At least spawn one oio-crawler-integrity on a container that exists
	# TODO(jfs): Move in a tests/functional/cli python test
	${PYTHON} $(command -v oio-crawler-integrity) $OIO_NS $OIO_ACCOUNT $CNAME

	# Create a file just bigger than chunk size
	SOURCE=$(mktemp)
	dd if=/dev/urandom of=$SOURCE bs=128K count=100

	# Run the test-suite of the C API
	${WRKDIR}/core/tool_roundtrip $SOURCE
	rm -f $SOURCE

	test_oio_tool
	test_oio_file_tool

	# Must be final, it removes the system config
	rm "/$HOME/.oio/sds.conf"
	export OIO_PROXY=$(oio-test-config.py -t proxy -1)
	export OIO_ECD=$(oio-test-config.py -t ecd -1)
	${WRKDIR}/core/tool_sdk_noconf

	gridinit_cmd -S $HOME/.oio/sds/run/gridinit.sock stop
	sleep 0.5
}

test_meta2_filters () {
	randomize_env
	$OIO_RESET -N $OIO_NS $@

	cd $SRCDIR
	tox -e coverage
	${PYTHON} $(command -v nosetests) tests.functional.m2_filters.test_filters

	gridinit_cmd -S $HOME/.oio/sds/run/gridinit.sock stop
	sleep 0.5
}

test_cli () {
	randomize_env
	# Some tests require events to be preserved after being handled
	args="-f ${SRCDIR}/etc/bootstrap-option-preserve-events.yml"
	$OIO_RESET ${args} -N $OIO_NS $@

	cd $SRCDIR
	tox -e cli

	gridinit_cmd -S $HOME/.oio/sds/run/gridinit.sock stop
	sleep 0.5

	# This is tested here because we do not need to test it several times,
	# and for some reason it cannot run with unit tests.
	test_oio_lb_benchmark
	test_oio_logger
}

#-------------------------------------------------------------------------------

set -e
SRCDIR="$1" ; [[ -n "$SRCDIR" ]] ; [[ -d "$SRCDIR" ]]
WRKDIR="$2" ; [[ -n "$WRKDIR" ]] ; [[ -d "$WRKDIR" ]]

export PYTHON=python
if [[ -n "$PYTHON_COVERAGE" ]] ; then
	export PYTHON="coverage run -p --omit=/home/travis/oio/lib/python2.7/*"
fi

OIO_RESET="oio-reset.sh"
CLI=$(command -v openio)
ADMIN_CLI=$(command -v openio-admin)

if is_running_test_suite "single" ; then
	opts=
	if is_running_test_suite "zlib" ; then
		opts="-f ${SRCDIR}/etc/bootstrap-option-compression-zlib.yml"
	fi
	func_tests $opts \
		-f "${SRCDIR}/etc/bootstrap-preset-SINGLE.yml" \
		-f "${SRCDIR}/etc/bootstrap-option-udp.yml" \
		-f "${SRCDIR}/etc/bootstrap-option-long-timeouts.yml" \
		-f "${SRCDIR}/etc/bootstrap-meta1-1digits.yml"
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

if is_running_test_suite "3copies" ; then
	echo -e "\n### 3copies tests"
	func_tests -f "${SRCDIR}/etc/bootstrap-preset-3COPIES-11RAWX.yml" \
		-f "${SRCDIR}/etc/bootstrap-option-3hosts.yml"
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
	if is_running_test_suite "zlib"; then
		args="-f ${SRCDIR}/etc/bootstrap-option-compression-zlib.yml"
	fi
	if is_running_test_suite "with-service-id"; then
		args="${args} -U"
	fi
	if is_running_test_suite "with-random-service-id"; then
		args="${args} -R"
	fi
	if is_running_test_suite "predictible-chunk-ids"; then
		args="${args} -f ${SRCDIR}/etc/bootstrap-option-predictible-chunk-ids.yml"
	fi
	$OIO_RESET ${args} -N $OIO_NS $@

	test_proxy_forward

	wait_proxy_cache

	for i in $(seq 1 100); do
		dd if=/dev/urandom of=/tmp/openio_object_$i bs=1K \
				count=$(shuf -i 1-2000 -n 1) 2> /dev/null
		echo "object create container-${RANDOM} /tmp/openio_object_$i" \
				"--name object-${RANDOM} -f value"
	done | ${PYTHON} $CLI

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
		-f "${SRCDIR}/etc/bootstrap-meta1-1digits.yml" \
		-f "${SRCDIR}/etc/bootstrap-option-3beanstalkd.yml"

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

# Reaching the end of this script means we didn't get any error,
# and thus we do not need to print logs.
trap - EXIT
