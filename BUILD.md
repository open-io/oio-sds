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
* attr, libattr-devel: we use xattr a lot to stamp rawx chunks and repositories base directory.
* sqlite, sqlite-devel: base storage for META{0,1,2} services.
* zeromq3, zeromq3-devel: communication of events between services and forward agents.
* zookeeper-devel, libzookeeper\_mt.so: building with distribution's zookeeper client is OK, but the package ships with a lot of dependencies, including the openjdk. We recommand to use the official Oracle/Sun JDK, and to build your own zookeeper client from the source to avoid a huge waste of space and bandwith.
* python-setuptools
* python-pbr
* beanstalkd: you need it to have the event-agent working

In addition, there some dependencies at runtime (the up-to-date list is in [requirements.txt](./requirements.txt)). You don't need to install them on the system, they will be installed by pip in your virtualenv (see [Building](#Building)).
* python-eventlet
* python-werkzeug
* python-gunicorn
* python-redis
* python-requests
* python-simplejson
* python-cliff
* python-pyeclib
* python-futures

The account service will require an up and running backend:
* FoundationDB

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
| ALLOW\_BACKTRACE | generate backtraces in errors. |
| FORBID\_DEPRECATED | define it to turn into errors the warnings for deprecated symbols from the GLib2. |
| EXE\_PREFIX | Defines a prefix to all CLI tool. By default, set to "sds". |
| SOCKET\_OPTIMIZED | define if to use socket3 and accept4 syscalls |
| SOCKET\_DEFAULT\_LINGER\_ONOFF | (integer value) triggers the onoff value of the SO\_LINGER configuration. |
| SOCKET\_DEFAULT\_LINGER\_DELAY | (integer value) set it to the delay in milliseconds, this will the delay part of the SO\_LINGER configuration. |
| SOCKET\_DEFAULT\_QUICKACK | boolean |
| SOCKET\_DEFAULT\_NODELAY | boolean |

Also, some options exist to specify uncommon installation paths. Their format is ``${DEP}_INCDIR`` or ``${DEP}_LIBDIR``, and ``DEP`` might take the given values ``ASN1C``, ``ATTR``, ``CURL``, ``JSONC``, ``LEVELDB``, ``ZK``, ``ZLIB``, ``ZMQ``

We recommend that you specify the installation directory (especially if you are not root)
at this step so you don't need to repeat it when calling ``make install``:
```
cmake -DCMAKE_INSTALL_PREFIX=$HOME/.local [OTHER CMAKE PARAMETERS] ${SRCDIR}
```

## Building

Now that ``cmake`` succeeded, it is time to build and install the binaries with ``make``.
```
make
make test
make install  # or make DESTDIR=${install_dir} install
```

We suggest to install Python dependencies in a virtualenv instead of directly on the system.
```
python3 -m venv oiovenv
# or "virtualenv -p /usr/bin/python3 oiovenv"
source oiovenv/bin/activate
```

Then install the python module inside your virtualenv:
```
pip install -e ${SRCDIR}
${SRCDIR}/tools/patch-python-modules.sh
```

Then install FoundationDB with oio-install-fdb.sh
```
./tools/oio-install-fdb.sh
```

A lot of variables are available, consider reading [Variables.md](./Variables.md) for more information.



# Step by step

### Run redpanda server and console
- docker compose file is available in `./docker/` folder
- just rename env_file to .env and fill the variables to be able to use it (locally or not)
- update `./etc/bootstrap-option-kafka.yml` file with IPs and ports

### FoundationDB install
- install et conf FondationDB (cf script `./tools/oio-install-fdb.sh`)

### Zookeeper install
We need a zookeeper >= 3.6.0.
Building zookeeper from source requires maven.
- `JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64`
- `git clone -b branch-3.8 git@github.com:apache/zookeeper.git`
- `cd zookeeper`
- `mvn clean install -Pfull-build -DskipTests`
- `ln -s {zookerper_dir}/zookeeper-client/zookeeper-client-c/target/c/lib/libzookeeper_mt.so ~/.local/lib64`
- `ln -s {zookerper_dir}/zookeeper-client/zookeeper-client-c/target/c/include/zookeeper ~/.local/include/zookeeper`
- Start zookeeper:
    - `export ZOOBINDIR="{zookerper_dir}/bin"`
    - `./tools/oio-zk-cluster.sh bootstrap 1 2 3`
    - `./tools/oio-zk-cluster.sh start 1 2 3`
    - `export ZK=127.0.0.1:2191,127.0.0.1:2192,127.0.0.1:2193`

### Golang install
- install [golang](https://go.dev/doc/install) version 1.22.5 and place it where you want (I did in ~/bin)

### Ubuntu packages install
- `sudo apt-get install -y $(tr '\n' ' ' < .cds/deps-ubuntu-focal.txt)`

### Prepare venv to install packages inside
- `python3 -m venv venv` (python3 version 3.10.12)
- `source venv/bin/activate`

### Build repo
- `mkdir build && cd build`
- `mkdir ~/local`
- `export SDS="~/local"`
- `export PATH="$PATH:/~/bin/go/bin/:~/local/bin" < change go/bin directory if not in ~/bin`
- `cmake -DCMAKE_INSTALL_PREFIX=${SDS} -DLD_LIBDIR=lib -DCMAKE_BUILD_TYPE=Debug ..`
- `make install -j`
- `cd ..`

### Start redpanda
- `export OIO_NS=OPENIO`
- `export OIO_ACCOUNT=AUTH_demo`
- start redpanda from oio-sds/docker -> `docker-compose -f redpanda.docker-compose.yml up -d`

### Install python3 packages
- `pip install .`
- `pip install -r test-requirements.txt`

### Reset stack and start it all
- `oio-reset.sh -f oio-sds/etc/bootstrap-preset-SINGLE.yml -r RegionOne -U`

#### Check if openio responds correctly
- `openio cluster show`
#### Check the services in systemctl
- `systemctl --user list-dependencies oio-cluster.target`  
(alternative would be `openioctl.sh -c status|status2`)
