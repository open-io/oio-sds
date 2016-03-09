#!/bin/sh

set -e

export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$HOME/leveldb/lib";
cd python;
flake8 oio tests setup.py;
nosetests tests/unit; 
