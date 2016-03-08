#!/bin/sh
set -e

OIO=$HOME/oio
mkdir $OIO;
cmake -DCMAKE_INSTALL_PREFIX=$OIO \
	-DCMAKE_BUILD_TYPE="Debug" \
	-DAPACHE2_LIBDIR="/usr/lib/apache2" \
	-DAPACHE2_INCDIR="/usr/include/apache2"
	-DAPACHE2_MODDIR=$OIO/lib/apache2/module \
	.;
make all install;
	


