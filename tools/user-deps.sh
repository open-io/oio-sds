#!/bin/bash

VENV_PATH=${1:-"$HOME/oio"}

set -x
set -e

echo "Versions"
gcc --version
go version
cmake --version
python --version

echo "Deploy virtualenv"
virtualenv ${VENV_PATH}
. ${VENV_PATH}/bin/activate
pip install --upgrade pip setuptools virtualenv tox
pip install --upgrade -r all-requirements.txt -r test-requirements.txt
pip install --upgrade zkpython

echo "Install GO dependencies"
go get gopkg.in/ini.v1
go get gopkg.in/tylerb/graceful.v1
go get golang.org/x/sys/unix
