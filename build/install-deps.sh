#!/bin/sh
set -e

# leveldb 1.18
if [ ! -d "$HOME/leveldb/lib" ]; then
  wget https://github.com/google/leveldb/archive/v1.18.tar.gz;
  tar -xf v1.18.tar.gz;
  mkdir -p $HOME/leveldb/{lib,include};
  cd leveldb-1.18 && make && mv libleveldb.* $HOME/leveldb/lib && cp -R include/leveldb $HOME/leveldb/include;
else
  echo 'Using cached leveldb';
fi
