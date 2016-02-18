set -x
export COLUMNS=512 LANG=

func_tests () {
	policy=$1 ; shift
	echo -e "\n### FUNC tests : $@\n"
	export OIO_NS="NS-${RANDOM}" OIO_ACCOUNT="ACCT-$RANDOM" OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM
	oio-reset.sh -v -v -N $OIO_NS $@
	# if [ -d python ] ; then ( cd python && tox ) ; fi
	make -C tests/func test
	./core/tool_roundtrip /etc/passwd
}

echo -e "\n### UNIT tests\n"
make -C tests/unit test

func_tests -- -S "SINGLE" -E 3 -C 1000 -B 1 -D 1 -R 1 -X zookeeper
func_tests -- -S "THREECOPIES" -E 5 -C 65536 -B 1 -D 1 -R 1 -X zookeeper

