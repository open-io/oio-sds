# OpenIO Software Defined Storage

OpenIO SDS is a software solution for object storage, targeting very large-scale unstructured data volumes.

## Install

Either you go from scratch (the source) or you download the packages for your Linux distribution, install, and run!

## Getting Started

There is one simple script to execute:

  oio-reset.sh

And if it succeeds you will have the joy to experiment your own little SDS instance. No root privileges are required!

## Build

### Dependencies

The build process of OpenIO SDS depends on:
* cmake, make, cp, sed, bison, flex
* python: more recently, the code generators became pythonic scripts. Pure python, no dependency.
* python-devel: required for the integrityloop
* python-distutils-extra: required for the installation process
* httpd, httpd-devel
* apr, apr-util-devel, apr-devel
* [asn1c](https://github.com/vlm/asn1c)
* attr, libattr-devel
* glib2, glib2-devel
* [gridinit](https://github.com/open-io/gridinit)
* json-c, json-c-devel
* libevent-devel
* [librain](https://github.com/open-io/redcurrant-librain)
* lzo, lzo-devel
* curl, libcurl, libcurl-devel
* neon, neon-devel
* net-snmp, net-snmp-devel
* openssl, openssl-devel
* sqlite, sqlite-devel
* zeromq3, zeromq3-devel
* zookeeper-devel, libzookeeper\_mt.so : building with distribution's zookeeper client is OK, but the package ships with a lot of dependencies, including the openjdk. We recommand to use the official Oracle/Su JDK, and to build your own zookeeper client from the source to avoid a huge waste of space and bandwith.

### Configuration

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
| TRIP\_PATH | Installation directory for crawler plugins. |
| GRIDD\_PLUGINS | Installation directory for gridd plugins. |
| APACHE2\_MODDIR | Installation directory for apache2 modules. |
| ALLOW\_DEPRECATED | define it to hide warnings for deprecated symbols from the GLib2. |
| EXE\_PREFIX | Defines a prefix to all CLI tool. By default, set to "sds". |
| MOCKS | Activate mocks to wrap syscalls. |
| SOCKET\_OPTIMIZED | define if to use socket3 and accept4 syscalls |
| SOCKET\_LINGER\_ONOFF | (integer value) triggers the onoff value of the SO\_LINGER configuration. |
| SOCKET\_LINGER\_DELAY | (integer value) set it to the delay in milliseconds, this will the delay part of the SO\_LINGER configuration. |

In addition, some options axist to specify uncommon installation paths. Their format is ``${DEP}_INCDIR`` or ``${DEP}_LIBDIR``, and ``DEP`` might take the given values ``APACHE2``, ``ASN1C``, ``ATTR``, ``CURL``, ``DB``, ``GRIDINIT``, ``JSONC``, ``LIBRAIN``, ``LZO``, ``MICROHTTPD``, ``NETSNMP``, ``ZK``, ``ZLIB``, ``ZMQ``

### Building

Now that ``cmake`` succeeded, it is time to build and install the binaries with ``make``.
```
make
make test
make DESTDIR=${install_dir} install
```

## Compile-time configuration

| Macro | Default | Description |
| ----- | ------- | ----------- |
| GCLUSTER\_ETC\_DIR | "/etc/oio" | System-wide configuration directory |
| GCLUSTER\_SPOOL\_DIR | "/var/spool" | Top-level directory for namespace spool dirs for events. |
| GCLUSTER\_RUN\_DIR | "/var/run" | Prefix to spool. |
| GCLUSTER\_CONFIG\_FILE\_PATH | "/etc/oio/sds.conf" | System-wide configuration file |
| GCLUSTER\_CONFIG\_DIR\_PATH | "/etc/oio/sds.conf.d" | System-wide configuration directory for additional files. |
| GCLUSTER\_CONFIG\_LOCAL\_PATH | ".oio/sds.conf" | Local configuration directory. |
| GCLUSTER\_AGENT\_SOCK\_PATH | "/var/run/oio-sds-agent.sock" | Default path for agent's socket. |
| GS\_CONFIG\_EVENT\_DELAY | "event\_delay" | Default pre-treatment delay applied to gridagent's events. |
| GS\_CONFIG\_EVENT\_REFRESH | "event\_refresh" | Default refresh period for event's management configuration. |
| GS\_CONFIG\_NSINFO\_REFRESH | "nsinfo\_refresh" | Default refresh period for 
| PROXYD\_PREFIX | "/v1.0" | Prefix applied to proxyd's URL |
| PROXYD_PATH_MAXLEN | 2048 | Maximum length for path to be accepted in requests. |
| PROXYD_DEFAULT_TTL_CSM0 | 0 | Maximum TTL (in seconds) for conscience entries in the proxyd cache. |
| PROXYD_DEFAULT_TTL_SERVICES | 3600 | Idem for services entries. |
| PROXYD_DEFAULT_MAX_CSM0 | 0 | Maximum number of conscience's items in the proxyd cache. |
| PROXYD_DEFAULT_MAX_SERVICES | 200000 | Idem for service entries. |
| PROXYD_DIR_TIMEOUT_SINGLE | 30.0 | Timeout for directory operations (single request) |
| PROXYD_DIR_TIMEOUT_GLOBAL | 30.0 | Timeout for directory operations (global operations) |
| PROXYD_HEADER_PREFIX | "X-oio-" | Prefix for all the headers sent to the proxy |
| PROXYD_HEADER_REQID | PROXYD_HEADER_PREFIX "req-id" | Header whose value is printed in access log, destined to agregate several requests belonging to the same session. |
| PROXYD_HEADER_NOEMPTY | PROXYD_HEADER_PREFIX "no-empty-list" | Flag sent to the proxy to turn empty list (results) into 404 not found. |
| DAEMON_DEFAULT_TIMEOUT_READ | 1000 | How long a gridd will block on a recv() (in milliseconds) |
| DAEMON_DEFAULT_TIMEOUT_ACCEPT | 1000 | How long a gridd will block on a accept() (in milliseconds) |
| SQLX_ADMIN_PREFIX_SYS  | "sys." | Prefix used for keys used in admin table of sqlite bases |
| SQLX_ADMIN_PREFIX_USER | "user." | Prefix used for keys used in admin table of sqlite bases |
| SQLX_ADMIN_INITFLAG  | SQLX_ADMIN_PREFIX_SYS "sqlx.init" | Key used in admin table of sqlite bases |
| SQLX_ADMIN_STATUS    | SQLX_ADMIN_PREFIX_SYS "sqlx.flags" | Key used in admin table of sqlite bases |
| SQLX_ADMIN_REFERENCE | SQLX_ADMIN_PREFIX_SYS "sqlx.reference" | Key used in admin table of sqlite bases |
| SQLX_ADMIN_BASENAME  | SQLX_ADMIN_PREFIX_SYS "sqlx.name" | Key used in admin table of sqlite bases |
| SQLX_ADMIN_BASETYPE  | SQLX_ADMIN_PREFIX_SYS "sqlx.type" | Key used in admin table of sqlite bases |
| SQLX_ADMIN_NAMESPACE | SQLX_ADMIN_PREFIX_SYS "sqlx.ns" | Key used in admin table of sqlite bases |
| M2V2_ADMIN_PREFIX_SYS | SQLX_ADMIN_PREFIX_SYS "m2." |  |
| M2V2_ADMIN_PREFIX_USER | SQLX_ADMIN_PREFIX_USER "m2." |  |
| M2V2_ADMIN_VERSION | M2V2_ADMIN_PREFIX_SYS "version" |  |
| M2V2_ADMIN_QUOTA | M2V2_ADMIN_PREFIX_SYS "quota" |  |
| M2V2_ADMIN_SIZE | M2V2_ADMIN_PREFIX_SYS "usage" |  |
| M2V2_ADMIN_CTIME | M2V2_ADMIN_PREFIX_SYS "ctime" |  |
| M2V2_ADMIN_VERSIONING_POLICY | M2V2_ADMIN_PREFIX_SYS "policy.version" |  |
| M2V2_ADMIN_STORAGE_POLICY | M2V2_ADMIN_PREFIX_SYS "policy.storage" |  |
| M2V2_ADMIN_KEEP_DELETED_DELAY | M2V2_ADMIN_PREFIX_SYS "keep_deleted_delay" |  |
| META2_INIT_FLAG | M2V2_ADMIN_PREFIX_SYS "init" |  |
| CS_CLIENT_TIMEOUT | 10.0 | <double> value telling the default timeout for conscience requests, in seconds. |
| M0V2_CLIENT_TIMEOUT | 10.0 | <double> value telling the default timeout for meta0 requests, in seconds. |
| M1V2_CLIENT_TIMEOUT | 10.0 | <double> value telling the default timeout for meta1 requests, in seconds. |
| M2V2_CLIENT_TIMEOUT | 10.0 | <double> value telling the default timeout for meta2 requests, in seconds. |
