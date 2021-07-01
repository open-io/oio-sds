# Build

## Dependencies

The build process of OpenIO SDS depends on several third-party projects.

When building only the SDK, OpenIO only depends on:
* cmake, make: involved in the build process.
* bison, flex: generates expression parsers.
* glib2, glib2-devel
* curl, libcurl, libcurl-devel
* json-c, json-c-devel
* [asn1c](https://github.com/open-io/asn1c): Now only necessary at the compile time, this is our ASN.1 codec forked from [Lev Walkin's excellent ASN.1 codec](https://github.com/vlm/asn1c). The purpose of our fork is simply to provide codec for explicitely sized integers (int{8,16,32,64} instead of long int) and GLib-2.0 memory allocations. The forked version is required only when building code prior to version 6.0.0.

Building the entire project will require the SDK dependencies, but also:
* python: Pure python code generator (no dependency), and python modules.
* python-distutils-extra: required for the installation process
* httpd, httpd-devel: server base for ECD service (and rawx for code prior to version 6.0.0)
* apr, apr-util-devel, apr-devel: internally used by rawx modules (prior to version 6.0.0)
* attr, libattr-devel: we use xattr a lot to stamp rawx chunks and repositories base directory.
* [gridinit](https://github.com/open-io/gridinit)
* sqlite, sqlite-devel: base storage for META{0,1,2} services.
* zeromq3, zeromq3-devel: communication of events between services and forward agents.
* zookeeper-devel, libzookeeper\_mt.so: building with distribution's zookeeper client is OK, but the package ships with a lot of dependencies, including the openjdk. We recommand to use the official Oracle/Sun JDK, and to build your own zookeeper client from the source to avoid a huge waste of space and bandwith.
* python-setuptools
* python-pbr
* beanstalkd: you need it to have the event-agent working

In addition, there some dependencies at runtime (the up-to-date list is in [all-requirements.txt](./all-requirements.txt)):
* python-eventlet
* python-werkzeug
* python-gunicorn
* python-redis
* python-requests
* python-simplejson
* pyxattr (python-xattr on Debian/Ubuntu)
* libapache2-mod-wsgi (as named on Ubuntu), the WSGI module for apache2
* python-cliff
* python-pyeclib
* python-futures

The account service will require an up and running backend:
* redis

Generating the documentation will require:
* epydoc: available in your python virtualenv

## Configuration

The Makefile's generation is performed by [cmake](http://cmake.org). The master
CMake directives files accepts several options. Each option has to be specified
on the cmake's command line with the following format:
```
cmake -D${K}=${V} ${SRCDIR}
```

In addition to common cmake options, these specific options are also available:

| Directive | Help |
| --------- | ---- |
| LD\_LIBDIR | Path suffix to the installation prefix, to define the default directory for libraries. E.g. "lib" or "lib64", depending on the architecture. |
| STACK\_PROTECTOR | Trigger stack protection code. Only active when CMAKE\_BUILD\_TYPE is set to "Debug" or "RelWithDebInfo" |
| APACHE2\_MODDIR | Installation directory for apache2 modules. |
| ALLOW\_BACKTRACE | generate backtraces in errors. |
| FORBID\_DEPRECATED | define it to turn into errors the warnings for deprecated symbols from the GLib2. |
| EXE\_PREFIX | Defines a prefix to all CLI tool. By default, set to "sds". |
| SOCKET\_OPTIMIZED | define if to use socket3 and accept4 syscalls |
| SOCKET\_DEFAULT\_LINGER\_ONOFF | (integer value) triggers the onoff value of the SO\_LINGER configuration. |
| SOCKET\_DEFAULT\_LINGER\_DELAY | (integer value) set it to the delay in milliseconds, this will the delay part of the SO\_LINGER configuration. |
| SOCKET\_DEFAULT\_QUICKACK | boolean |
| SOCKET\_DEFAULT\_NODELAY | boolean |

In addition, some options axist to specify uncommon installation paths. Their format is ``${DEP}_INCDIR`` or ``${DEP}_LIBDIR``, and ``DEP`` might take the given values ``APACHE2``, ``ASN1C``, ``ATTR``, ``CURL``, ``JSONC``, ``ZK``, ``ZLIB``, ``ZMQ``

## Building

Now that ``cmake`` succeeded, it is time to build and install the binaries with ``make``.
```
make
make test
make DESTDIR=${install_dir} install
```

We suggest to install Python dependencies in a virtualenv instead of directly on the system.
```
python3 -m venv oiovenv
# or "virtualenv -p /usr/bin/python3 oiovenv"
source oiovenv/bin/activate
pip install -r ${SRCDIR}/all-requirements.txt
```

Then install the python module inside your virtualenv:
```
pip install -e ${SRCDIR}
```

A lot of variables are available, consider reading [Variables.md](./Variables.md) for more information.

