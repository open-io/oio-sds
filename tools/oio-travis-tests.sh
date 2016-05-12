set -e
export COLUMNS=512 LANG=

function dump_syslog {
	cmd=tail
	if ! [ -r /var/log/syslog ] ; then
		cmd="sudo tail"
	fi
	$cmd -n 500 /var/log/syslog
}

trap dump_syslog EXIT

func_tests () {
	echo -e "\n### FUNC tests : $@\n" | logger -t TEST
	export OIO_NS="NS-${RANDOM}" OIO_ACCOUNT="ACCT-$RANDOM" OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM
	oio-reset.sh -v -v -N $OIO_NS $@ 
	echo -e "END OF RESET" | logger -t TEST
	tox && tox -e func
	make -C tests/func test
	./core/tool_roundtrip /etc/passwd
}

echo -e "\n### UNIT tests\n"
make -C tests/unit test

func_tests -B 1 -D 1 -f "${PWD}/etc/oio-bootstrap-config-test1.json"
func_tests -B 1 -D 1 -f "${PWD}/etc/oio-bootstrap-config-test2.json"

