# OpenIO SDS configuration

`oio-sds` allows you to alter a lot of configuration at compile-time as well at runtime. We use a minimal generation tool for a set of variables that can be modified at runtime, and whose default value can be changed at the compile-time. Those variabes are described [here](./Variables.md)

Some variables, though, are not configurable yet, and still require a value to be fixed once for all when compiling the code. Please find below the list of the `cmake` directives to control such variables.

## Compile-time only configuration

| Macro | Default | Description |
| ----- | ------- | ----------- |
| OIOSDS_RELEASE | "master" | Global release name |
| OIOSDS_PROJECT_VERSION_SHORT | "1.0" | Minor version number |

Used by `gcc`

| Macro | Default | Description |
| ----- | ------- | ----------- |
| DAEMON_DEFAULT_TIMEOUT_READ | 1000 | How long a gridd will block on a recv() (in milliseconds) |
| DAEMON_DEFAULT_TIMEOUT_ACCEPT | 1000 | How long a gridd will block on a accept() (in milliseconds) |

| Macro | Default | Description |
| ----- | ------- | ----------- |
| OIO_EVT_BEANSTALKD_DEFAULT_TUBE | "oio" |  |

| Macro | Default | Description |
| ----- | ------- | ----------- |
| GCLUSTER_RUN_DIR | "/var/run" | Prefix to spool. |
| GCLUSTER_CONFIG_FILE_PATH | "/etc/oio/sds.conf" | System-wide configuration file |
| GCLUSTER_CONFIG_DIR_PATH | "/etc/oio/sds.conf.d" | System-wide configuration directory for additional files. |
| GCLUSTER_CONFIG_LOCAL_PATH | ".oio/sds.conf" | Local configuration directory. |
| GCLUSTER_AGENT_SOCK_PATH | "/var/run/oio-sds-agent.sock" | Default path for agent's socket. |

| Macro | Default | Description |
| ----- | ------- | ----------- |
| PROXYD_PREFIX | "v3.0" | Prefix applied to proxyd's URL, second version (with accounts) |
| PROXYD_HEADER_PREFIX | "X-oio-" | Prefix for all the headers sent to the proxy |
| PROXYD_HEADER_REQID | PROXYD_HEADER_PREFIX "req-id" | Header whose value is printed in access log, destined to agregate several requests belonging to the same session. |
| PROXYD_HEADER_NOEMPTY | PROXYD_HEADER_PREFIX "no-empty-list" | Flag sent to the proxy to turn empty list (results) into 404 not found. |

| Macro | Default | Description |
| ----- | ------- | ----------- |
| OIO_STAT_PREFIX_REQ | "counter req.hits" |  |
| OIO_STAT_PREFIX_TIME | "counter req.time" |  |

| Macro | Default | Description |
| ----- | ------- | ----------- |
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
|OIO_USE_OLD_FMEMOPEN|_undefined_|Use the old implementation of glibc's `fmemopen`. Starting from glibc 2.22 the new implementation lacks the binary mode which made things work.|

