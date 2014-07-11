# Redcurrant

Redcurrant is a software solution for objects storage, targetting very large-scale unstructured data volumes.

As described [here](http://www.redcurrant.io/legal/licenses), the code is licensed under the terms of two licenses: LGPL3 for client-relaed files, AGPL3 for all the others. Please find in the LICENSE file more details about this.

## Install

There are a few different ways you can install Redcurrant:

* Download the zipfile from the [downloads](https://github.com/redcurrant/redcurrant/archives/master) page and install it. 
* Checkout the source: `git clone git://github.com/redcurrant/redcurrant.git` and install it yourself.

## Getting Started

Go to http://www.redcurrant.io for documentations about installation and configuration of Redcurrant.

## Build

### Dependencies

The build process of Redcurrant's core depends on:
* cmake, make, cp, seq, bison, flex
* asn1c
* glib2
* openssl
* libevent
* perl, perl-Template-Toolkit: in its early years, these were used as code generators. This is a legacy code.
* python: more recently, the code generators became base-python scripts.

In additon, the build process of Redcurrant's crawler tools repends on:
* json-c
* zeromq3
* debus

### Configuration

The Makefile's generation is performed by [cmake](http://cmake.org). The master
CMake directives files accepts several options. Each option has to be specified
on the cmake's command line with the following format:
```
cmake -D${K}=${V} ${SRCDIR}
```

In addition to common cmake options, these specific options are also available:
* ``PREFIX`` : an alternative to the cmake's CMAKE_INSTALL_PREFIX
* ``MOCKS`` : define it to allow mock'ing syscalls and socket operations.
* ``SOCKET_OPTIMIZED`` : define if to use socket3 and accept4 syscalls
* ``EXE_PREFIX`` : define it to a prefix to be prepended to every executable generated. If not specified, a legacy format will be used.
* ``SOCKET_LINGER_ONOFF`` : (integer value) triggers the onoff value of the SO_LINGER configuration.
* ``SOCKET_LINGER_DELAY`` : (integer value) set it to the delay in milliseconds, this will the delay part of the SO_LINGER configuration.
* ``ALLOW_DEPRECATED`` : define it to hide warnings for deprecated symbols from the GLib2

In addition, some options axist to specify uncommon installation paths. Their
format is ``${DEP}_INCDIR`` or ``${DEP}_LIBDIR``, and ``DEP`` might take the given values:
* ``MYSQL`` : idem for MySQL
* ``ZK`` : [Apache ZooKeeper](http://zookeeper.apache.org)
* ``ZMQ`` : [ZeroMQ](http://zeromq.org) (>=3.1)
* ``ASN1C`` : [asn1c](https://github.com/redcurrant/asn1c), our modified version of the original [asn1c](http://lionet.info/asn1c/)
* ``GRIDINIT`` : [gridinit](https://github.com/redcurrant/gridinit)
* ``LIBRAIN`` : ?

### Building

Now that ``cmake`` succeeded, it is time to build and install the binaries with ``make``.
```
make
make test
make DESTDIR=${install_dir} install
```

