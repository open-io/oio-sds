#!/bin/sh
set -e
cd python;
CPATH="$HOME/leveldb/include" LIBRARY_PATH="$HOME/leveldb/lib" pip install plyvel;
pip install -r requirements.txt;
python setup.py install;
pip install -r test-requirements.txt;
