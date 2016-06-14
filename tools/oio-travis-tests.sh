set -e
export COLUMNS=512 LANG=

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

trap dump_syslog EXIT

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

echo -e "\n### UNIT tests\n"
cd $WRKDIR
make -C tests/unit test

func_tests -f "${SRCDIR}/etc/bootstrap-SINGLE.yml"
func_tests -f "${SRCDIR}/etc/bootstrap-THREECOPIES.yml"
func_tests -f "${SRCDIR}/etc/bootstrap-EC.yml"
