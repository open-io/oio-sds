#!/bin/bash

go get gopkg.in/ini.v1 gopkg.in/tylerb/graceful.v1

virtualenv $HOME/oio && source $HOME/oio/bin/activate
pip install --upgrade pip setuptools virtualenv tox
pip install --upgrade -r all-requirements.txt -r test-requirements.txt
pip install --upgrade zkpython

export TEST_SUITE=build,3copies
set -e
mkdir /tmp/oio
export CMAKE_OPTS='-DCMAKE_INSTALL_PREFIX=/tmp/oio -DLD_LIBDIR=lib -DZK_LIBDIR=/usr/lib -DZK_INCDIR=/usr/include/zookeeper -DAPACHE2_LIBDIR=/usr/lib/apache2 -DAPACHE2_INCDIR=/usr/include/apache2 -DAPACHE2_MODDIR=/tmp/oio/lib/apache2/module'

# RELEASE COMPILATION
# cmake ${CMAKE_OPTS} -DCMAKE_BUILD_TYPE="Release" .
# make all
# make clean

# TEST
export PYTHON_COVERAGE=1 CMAKE_OPTS="${CMAKE_OPTS} -DENABLE_CODECOVERAGE=on"
cmake ${CMAKE_OPTS} -DCMAKE_BUILD_TYPE="Debug" . && make all install
git fetch --tags
python setup.py develop
bash ./tools/oio-check-version.sh
export G_DEBUG_LEVEL=D PATH="$PATH:/tmp/oio/bin" LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/tmp/oio/lib"
./tools/oio-travis-tests.sh
