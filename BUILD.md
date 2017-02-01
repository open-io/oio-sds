# Build

## Dependencies

The build process of OpenIO SDS depends on several third-party projects.

When building only the SDK, OpenIO only depends on:
* cmake, make : involved in the build process.
* bison, flex : generates expression parsers.
* glib2, glib2-devel
* curl, libcurl, libcurl-devel
* json-c, json-c-devel
* [asn1c](https://github.com/open-io/asn1c) : our ASN.1 codec, forked from [Lev Walkin's excellent ASN.1 codec](https://github.com/vlm/asn1c). The purpose of our fork is simply to provide codec for explicitely sized integers (int{8,16,32,64} instead of long int).

Building the entire project will require the SDK dependencies, but also:
* python: Pure python code generator (no dependency), and python modules.
* python-distutils-extra: required for the installation process
* httpd, httpd-devel : server base for RAWX and RAINX services
* apr, apr-util-devel, apr-devel : internally used by RAINX and RAWX modules
* attr, libattr-devel : we use xattr a lot to stamp RAWX chunks and repositories base directory.
* [gridinit](https://github.com/open-io/gridinit)
* lzo, lzo-devel : RAWX compression
* sqlite, sqlite-devel : base storage for META{0,1,2} and SQLX services.
* zeromq3, zeromq3-devel : communication of events between services and forward agents.
* zookeeper-devel, libzookeeper\_mt.so : building with distribution's zookeeper client is OK, but the package ships with a lot of dependencies, including the openjdk. We recommand to use the official Oracle/Sun JDK, and to build your own zookeeper client from the source to avoid a huge waste of space and bandwith.
* python-setuptools
* python-pbr
* beanstalkd: you need it to have the event-agent working

In addition, there some additional dependencies at runtime:
* python-eventlet
* python-werkzeug
* python-gunicorn
* python-plyvel
* python-redis
* python-requests
* python-simplejson
* pyxattr (python-xattr on Debian/Ubuntu)
* libapache2-mod-wsgi (as named on Ubuntu), the WSGI module pour apache2
* python-cliff
* python-pyeclib

The account service will require an up and running backend:
* redis

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
| GRIDD\_PLUGINS | Installation directory for gridd plugins. |
| APACHE2\_MODDIR | Installation directory for apache2 modules. |
| ALLOW\_BACKTRACE | generate backtraces in errors. |
| FORBID\_DEPRECATED | define it to turn into errors the warnings for deprecated symbols from the GLib2. |
| EXE\_PREFIX | Defines a prefix to all CLI tool. By default, set to "sds". |
| SOCKET\_OPTIMIZED | define if to use socket3 and accept4 syscalls |
| SOCKET\_LINGER\_ONOFF | (integer value) triggers the onoff value of the SO\_LINGER configuration. |
| SOCKET\_LINGER\_DELAY | (integer value) set it to the delay in milliseconds, this will the delay part of the SO\_LINGER configuration. |

In addition, some options axist to specify uncommon installation paths. Their format is ``${DEP}_INCDIR`` or ``${DEP}_LIBDIR``, and ``DEP`` might take the given values ``APACHE2``, ``ASN1C``, ``ATTR``, ``CURL``, ``JSONC``, ``LIBRAIN``, ``LZO``, ``ZK``, ``ZLIB``, ``ZMQ``

## Building

Now that ``cmake`` succeeded, it is time to build and install the binaries with ``make``.
```
make
make test
make DESTDIR=${install_dir} install
```

Install python module (preferably inside a virtualenv):
```
python setup.py develop
```


## Compile-time configuration

Used by `cmake`

| Macro | Default | Description |
| ----- | ------- | ----------- |
| OIOSDS_RELEASE | "master" | Global release name |
| OIOSDS_PROJECT_VERSION_SHORT | "1.0" | Minor version number |

Used by `gcc`

| Macro | Default | Description |
| ----- | ------- | ----------- |
| SERVER_DEFAULT_EPOLL_MAXEV | 128 | How many events maight be raised by epoll_wait() each round |
| SERVER_DEFAULT_ACCEPT_MAX | 64 | How many clients are accepted each time the server has activity |
| SERVER_DEFAULT_THP_MAXUNUSED | -1 | How many idle workers are allowed |
| SERVER_DEFAULT_THP_MAXWORKERS | -1 | How many workers are allowed |
| SERVER_DEFAULT_THP_IDLE | 30000 | How long (in milliseconds) a worker might remain idle before exiting. |
| SERVER_DEFAULT_CNX_IDLE | "5 * G_TIME_SPAN_MINUTE" | How long (in microseconds) a connection might stay idle between two requests |
| SERVER_DEFAULT_CNX_LIFETIME | "2 * G_TIME_SPAN_HOUR" | How long (in microseconds) a connection might exist since its creation (whatever it is active or not) |
| SERVER_DEFAULT_CNX_INACTIVE | "30 * G_TIME_SPAN_SECOND" | How long (in microseconds) a connection might exist since its creation when it received no request at all. |
| DAEMON_DEFAULT_TIMEOUT_READ | 1000 | How long a gridd will block on a recv() (in milliseconds) |
| DAEMON_DEFAULT_TIMEOUT_ACCEPT | 1000 | How long a gridd will block on a accept() (in milliseconds) |

| Macro | Default | Description |
| ----- | ------- | ----------- |
| OIO_EVT_BEANSTALKD_DEFAULT_PRIO | 1<<31 |  |
| OIO_EVT_BEANSTALKD_DEFAULT_DELAY | 0 |  |
| OIO_EVT_BEANSTALKD_DEFAULT_TTR | 120 |  |
| OIO_EVT_BEANSTALKD_DEFAULT_TUBE | "oio" |  |

| Macro | Default | Description |
| ----- | ------- | ----------- |
| OIO_EVTQ_BUFFER_DELAY | 5 | ----------- |
| OIO_CFG_EVTQ_MAXPENDING | "events-max-pending" |  |
| OIO_CFG_EVTQ_BUFFER_DELAY | "events-buffer-delay" |  |
| OIO_EVTQ_MAXPENDING | 1000 | Default queue length for services emitting events (meta1, meta2). Beyond this limit, the queue will be reported as 'stalled' so that the services can properly manage this. |

| Macro | Default | Description |
| ----- | ------- | ----------- |
| GCLUSTER_RUN_DIR | "/var/run" | Prefix to spool. |
| GCLUSTER_CONFIG_FILE_PATH | "/etc/oio/sds.conf" | System-wide configuration file |
| GCLUSTER_CONFIG_DIR_PATH | "/etc/oio/sds.conf.d" | System-wide configuration directory for additional files. |
| GCLUSTER_CONFIG_LOCAL_PATH | ".oio/sds.conf" | Local configuration directory. |
| GCLUSTER_AGENT_SOCK_PATH | "/var/run/oio-sds-agent.sock" | Default path for agent's socket. |
| GS_CONFIG_NSINFO_REFRESH | "nsinfo_refresh" | Default refresh period for 

| Macro | Default | Description |
| ----- | ------- | ----------- |
| PROXYD_PREFIX | "v3.0" | Prefix applied to proxyd's URL, second version (with accounts) |
| PROXYD_HEADER_PREFIX | "X-oio-" | Prefix for all the headers sent to the proxy |
| PROXYD_HEADER_REQID | PROXYD_HEADER_PREFIX "req-id" | Header whose value is printed in access log, destined to agregate several requests belonging to the same session. |
| PROXYD_HEADER_NOEMPTY | PROXYD_HEADER_PREFIX "no-empty-list" | Flag sent to the proxy to turn empty list (results) into 404 not found. |
| PROXYD_PATH_MAXLEN | 2048 | Maximum length for path to be accepted in requests. |
| PROXYD_DEFAULT_TTL_SERVICES | G_TIME_SPAN_HOUR | Idem for services entries. |
| PROXYD_DEFAULT_MAX_SERVICES | 200000 | Idem for service entries. |
| PROXYD_DEFAULT_TTL_CSM0 | 0 | Maximum TTL (in seconds) for conscience entries in the proxyd cache. |
| PROXYD_DEFAULT_MAX_CSM0 | 0 | Maximum number of conscience's items in the proxyd cache. |
| PROXYD_PERIOD_RELOAD_NSINFO | 30 |  |
| PROXYD_PERIOD_RELOAD_CSURL | 30 |  |
| PROXYD_PERIOD_RELOAD_SRVTYPES | 30 |  |
| PROXYD_PERIOD_RELOAD_M0INFO | 30 |  |
| PROXYD_DEFAULT_PERIOD_DOWNSTREAM | 2 |  |
| PROXYD_DEFAULT_PERIOD_UPSTREAM | 1 |  |
| PROXYD_TTL_DEAD_LOCAL_SERVICES | 30 * G_TIME_SPAN_SECOND |  |
| PROXYD_TTL_DOWN_SERVICES | 5 * G_TIME_SPAN_SECOND |  |
| PROXYD_TTL_KNOWN_SERVICES | 5 * G_TIME_SPAN_DAY |  |
| PROXYD_TTL_MASTER_SERVICES | 5 * G_TIME_SPAN_SECOND |  |

| Macro | Default | Description |
| ----- | ------- | ----------- |
| MALLOC_TRIM_SIZE | 0 |  |
| PERIODIC_MALLOC_TRIM_SIZE | 0 |  |
| OIO_STAT_PREFIX_REQ | "counter req.hits" |  |
| OIO_STAT_PREFIX_TIME | "counter req.time" |  |
| SQLITE_RELEASE_SIZE | 64MiB |  |

| Macro | Default | Description |
| ----- | ------- | ----------- |
| SQLX_HEAVYLOAD_ALERT | TRUE | Should the server fail a request for the purpose of a heavy duty on a base |
| SQLX_HEAVYLOAD_FAIL | FALSE | Should the server alert (if not failing) for a heavy duty on a base |
| SQLX_MAX_WAITING | 16 | How many waiters on a cache slot necessary to consider the duty is heavy |
| SQLX_MAX_BASES | 8192 | Default max number of bases, if not overriden at runtime. |
| SQLX_SYNC_DEFAULT_ZK_TIMEOUT | 8765 |  |
| SQLX_DIR_SCHEMAS | NULL | Default directory used to gather applicative schema of SQLX bases. NULL by default, meaning that no directory is set, so that there is no attempt to load a schema. |
| SQLX_ADMIN_PREFIX_SYS  | "sys." | Prefix used for keys used in admin table of sqlite bases |
| SQLX_ADMIN_PREFIX_USER | "user." | Prefix used for keys used in admin table of sqlite bases |
| SQLX_ADMIN_INITFLAG  | SQLX_ADMIN_PREFIX_SYS "sqlx.init" | Key used in admin table of sqlite bases |
| SQLX_ADMIN_STATUS    | SQLX_ADMIN_PREFIX_SYS "sqlx.flags" | Key used in admin table of sqlite bases |
| SQLX_ADMIN_REFERENCE | SQLX_ADMIN_PREFIX_SYS "sqlx.reference" | Key used in admin table of sqlite bases |
| SQLX_ADMIN_BASENAME  | SQLX_ADMIN_PREFIX_SYS "sqlx.name" | Key used in admin table of sqlite bases |
| SQLX_ADMIN_BASETYPE  | SQLX_ADMIN_PREFIX_SYS "sqlx.type" | Key used in admin table of sqlite bases |
| SQLX_ADMIN_NAMESPACE | SQLX_ADMIN_PREFIX_SYS "sqlx.ns" | Key used in admin table of sqlite bases |

| Macro | Default | Description |
| ----- | ------- | ----------- |
| OIO_M2V2_LISTRESULT_BATCH | 1000 |  |
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

| Macro | Default | Description |
| ----- | ------- | ----------- |
| OIO_META1_DIGITS_KEY | "meta1_digits" | Variable name in the /etc/oio/sds.conf to configure the number of digits that name a meta1 base. |
| OIO_META1_DIGITS_DEFAULT | 4 | Default number of digits to name a meta1 database |

| Macro | Default | Description |
| ----- | ------- | ----------- |
| RAWX_HEADER_PREFIX | "X-oio-chunk-meta-" | Prefix applied to proxyd's URL, second version (with accounts) |

| Macro | Default | Description |
| ----- | ------- | ----------- |
| CS_CLIENT_TIMEOUT | 2.0 | <double> value telling the default timeout for conscience requests, in seconds. |
| M0V2_CLIENT_TIMEOUT | 10.0 | <double> value telling the default timeout for meta0 requests, in seconds. |
| M0V2_INIT_TIMEOUT | 30.0 | <double> value telling the default timeout for meta0 requests, in seconds. |
| M1V2_CLIENT_TIMEOUT | 10.0 | <double> value telling the default timeout for meta1 requests, in seconds. |
| M2V2_CLIENT_TIMEOUT | 10.0 | <double> value telling the default timeout for meta2 requests, in seconds. |
| M2V2_CLIENT_TIMEOUT_HUGE | 10.0 | <double> value telling the default timeout for meta2 requests, in seconds. |
| SQLX_CLIENT_TIMEOUT | 30.0 | <double> value telling the default timeout for sqlx requests, in seconds. |
| SQLX_CNX_TIMEOUT_GETVERS | 0.5 | <double> value telling the default timeout for DB_VERS requests, in seconds. |
| SQLX_CNX_TIMEOUT_USE | 0.25 | <double> value telling the default timeout for DB_USE (tcp) requests, in seconds. |
| SQLX_USE_TIMEOUT | 1.0 | <double> value telling the default timeout for sqlx requests, in seconds. |
| SQLX_GETVERS_TIMEOUT | 2.0 | <double> value telling the default timeout for sqlx requests, in seconds. |
| SQLX_REPLI_TIMEOUT | 10.0 | <double> value telling the default timeout for sqlx requests, in seconds. |
| SQLX_RESYNC_TIMEOUT | 30.0 | <double> value telling the default timeout for sqlx requests, in seconds. |
| COMMON_CNX_TIMEOUT | 2.0 | <double> value in seconds |
| COMMON_CLIENT_TIMEOUT | 30.0 | In monotonic clock's precision |
| COMMON_STAT_TIMEOUT | 5.0 | <double> value telling the default timeout for /stat requests outgoing the proxy, in seconds. |

| Macro | Default | Description |
| ----- | ------- | ----------- |
|OIO_USE_OLD_FMEMOPEN|_undefined_|Use the old implementation of glibc's `fmemopen`. Starting from glibc 2.22 the new implementation lacks the binary mode which made things work.|
