

optSudo="LD_LIBRARY_PATH=:/lib:/usr/lib:/usr/lib64:/usr/local/lib64"
optTrp1="-trip_prefix.s=/DATA/TESTNS/sdgrid08s/meta1-1"
optTrp2="-trip_prefix.s=/DATA/TESTNS/sdgrid08s/meta1-2"
optTrp3="-trip_prefix.s=/DATA/TESTNS/sdgrid08s/meta1-3"
optAct="-action_list_container.n=TESTNS,meta2|127.0.0.1:6031,meta2|127.0.0.1:6006,meta2|127.0.0.1:6005"
#optAct="-action_list_container.n=TESTNS"
optCrawl="-Olistener=127.0.0.1:6150 -Otrip=trip_prefix -Oaction=action_list_container"

argsTrp="" #"-trip_prefix.v=FALSE -trip_prefix.a=FALSE"
argsAct="-action_list_container.v=FALSE -action_list_container.d=TRUE"

sudo $optSudo crawler $optCrawl -- ${optTrp1} ${optAct} ${argsTrp} ${argsAct} &
sudo $optSudo crawler -Olistener=127.0.0.1:6150 -Otrip=trip_test -Oaction=action_test -- -trip_test.s=/home/a555727/src/git/grid -action_test.s=/home/a555727/src/git/grid -trip_test.e=txt:sh:spec &
sudo $optSudo crawler $optCrawl -- ${optTrp2} ${optAct} ${argsTrp} ${argsAct} &
sudo $optSudo crawler $optCrawl -- ${optTrp3} ${optAct} ${argsTrp} ${argsAct} &


