# PROXY test functions

The test repository contains useful tools to be sure that the OIO-SDS proxy functionalities would correctly run after code modifications.

## Initialization

To launch the tests functions, the user needs to already possess the SDS environnement ready to run, as well as a Python development tool (Pycharm, ...), then do the following steps on his terminal :

  * Install nosetests (pip install nose) to run the tests
  * Create a "test.conf" file in the .oio/sds/conf repository containing the following fields :
	[func_test]
	proxyd_uri=<user's proxyd_uri> # E.g. http://192.168.0.0:6000
	namespace=<user's openio namespace> # E.g. OPENIO_NS

The user is now ready to run the tests.

## Launching

  * To launch the procedure, the user must go in the oio-sds/proxy/tests repository and run the .functests file

**Note : to keep the environment clean, it is recommended to run the oio-reset procedure before and after the tests

Results of the tests will progressively appear on the line following the instruction.
  * A ``.`` means the tested function is operational
  * A ``F`` means the test has failed
  * A ``E`` means the test raised an exception
Once all the tests run, the console will display the trace of all those which failed