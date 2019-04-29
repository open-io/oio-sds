#!/usr/bin/env bash
VENV=$1

virtualenv $VENV
source $VENV/bin/activate

pip install --upgrade pip setuptools virtualenv tox
pip install --upgrade -r all-requirements.txt -r test-requirements.txt
pip install --upgrade zkpython

go get gopkg.in/ini.v1 gopkg.in/tylerb/graceful.v1
go get golang.org/x/sys/unix
