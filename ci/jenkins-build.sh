#!/bin/bash

export

. ./ci/user-deps.sh

set -e
mkdir /tmp/oio
export CMAKE_OPTS='-DCMAKE_INSTALL_PREFIX=/tmp/oio -DLD_LIBDIR=lib -DZK_LIBDIR=/usr/lib -DZK_INCDIR=/usr/include/zookeeper -DAPACHE2_LIBDIR=/usr/lib/apache2 -DAPACHE2_INCDIR=/usr/include/apache2 -DAPACHE2_MODDIR=/tmp/oio/lib/apache2/module'

# TEST
export PYTHON_COVERAGE=1 CMAKE_OPTS="${CMAKE_OPTS} -DENABLE_CODECOVERAGE=on"
cmake ${CMAKE_OPTS} -DCMAKE_BUILD_TYPE="Debug" . && make all install
git fetch --tags
python setup.py develop
bash ./tools/oio-check-version.sh
export G_DEBUG_LEVEL=D PATH="$PATH:/tmp/oio/bin" LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/tmp/oio/lib"

export TEST_SUITE=3copies,with-service-id
./tools/oio-travis-suites.sh

export TEST_SUITE=rebuilder,with-service-id
./tools/oio-travis-suites.sh
