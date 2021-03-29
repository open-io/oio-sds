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
| RAWX_HEADER_PREFIX | "X-oio-chunk-meta-" | Prefix for all the headers sent/received with the rawx |

| Macro | Default | Description |
| ----- | ------- | ----------- |
|OIO_USE_OLD_FMEMOPEN|_undefined_|Use the old implementation of glibc's `fmemopen`. Starting from glibc 2.22 the new implementation lacks the binary mode which made things work.|

## Start-up configuration

### RAWX

| Name | Type | Default | Description |
| ---- | ---- | ------- | ----------- |
| grid_docroot | string | *MANDATORY* | Chunks root directory |
| grid_namespace | string | *MANDATORY* | Namespace name |
| grid_dir_run | string | *MANDATORY* | Run directory |
| grid_hash_width | number | 3 | How many hexdigits must be used to name the indirection directories |
| grid_hash_depth | number | 1 | How many levels of directories are used to store chunks |
| grid_fsync | boolean | disabled | At the end of an upload, perform a fsync() on the chunk file itself |
| grid_fsync_dir | boolean | enabled | At the end of an upload, perform a fsync() on the directory holding the chunk |
| grid_fallocate | boolean | enabled | Preallocate space for the chunk file |
| grid_acl | boolean | *IGNORED* | Enable ACL |
| grid_checksum | string (enabled,disabled,smart) | enabled | Enable checksuming the body of PUT |


## Fully configurable variables (compilation & runtime)

### Variables for production purposes

### client.down_cache.avoid

> Should an error be raised when the peer is marked down, instead of trying to contact the peer.

 * default: **TRUE**
 * type: gboolean
 * cmake directive: *OIO_CLIENT_DOWN_CACHE_AVOID*

### client.down_cache.shorten

> Should the connection timeout be dramatically shortened when talking to a peer that has been reported down. Set to false by default, this is evaluated after the avoidance of those peers.

 * default: **FALSE**
 * type: gboolean
 * cmake directive: *OIO_CLIENT_DOWN_CACHE_SHORTEN*

### client.errors_cache.enabled

> Should the client feed a cache with the network errors it encounters, and should those errors be used to prevent RPC to be performed toward 'too-faulty' peers.

 * default: **FALSE**
 * type: gboolean
 * cmake directive: *OIO_CLIENT_ERRORS_CACHE_ENABLED*

### client.errors_cache.max

> Sets the number of faults (on the period given by client.errors_cache.period) beyond which a peer is considered as too faulty to try a new RPC.

 * default: **60**
 * type: guint64
 * cmake directive: *OIO_CLIENT_ERRORS_CACHE_MAX*
 * range: 1 -> 4294967296

### client.errors_cache.period

> Sets the size of the time window used to count the number of network errors.

 * default: **60**
 * type: gint64
 * cmake directive: *OIO_CLIENT_ERRORS_CACHE_PERIOD*
 * range: 1 -> 3600

### common.verbosity.reset_delay

> Tells how long the verbosity remains higher before being reset to the default, after a SIGUSR1 has been received.

 * default: **5 * G_TIME_SPAN_MINUTE**
 * type: gint64
 * cmake directive: *OIO_COMMON_VERBOSITY_RESET_DELAY*
 * range: 1 * G_TIME_SPAN_SECOND -> 1 * G_TIME_SPAN_HOUR

### core.chunk_size.max

> Should the C API adjust the chunk size when over this ceiling. Set to 0 for no action.

 * default: **0**
 * type: gint64
 * cmake directive: *OIO_CORE_CHUNK_SIZE_MAX*
 * range: 0 -> G_MAXINT64

### core.chunk_size.min

> Should the C API adjust the chunk size when below this threshold. Set to 0 for no action

 * default: **10000000**
 * type: gint64
 * cmake directive: *OIO_CORE_CHUNK_SIZE_MIN*
 * range: 0 -> G_MAXINT64

### core.http.user_agent

> HTTP User-Agent to be used between any C client and the proxy

 * default: ****
 * type: string
 * cmake directive: *OIO_CORE_HTTP_USER_AGENT*

### core.lb.allow_distance_bypass

> Compare the number of items to select to the number of items available at the current location level, and decide if it is desirable to bypass or slacken the time-consuming distance checks. Disable this if you detect too many situations where distance between selected items could have been bigger.

 * default: **TRUE**
 * type: gboolean
 * cmake directive: *OIO_CORE_LB_ALLOW_DISTANCE_BYPASS*

### core.lb.generate_random_chunk_ids

> Generate random, 64 bytes long chunk IDs. If set to false, the chunk IDs will be generated from the container and object names, object version and storage policy, and chunk position.

 * default: **TRUE**
 * type: gboolean
 * cmake directive: *OIO_CORE_LB_GENERATE_RANDOM_CHUNK_IDS*

### core.lb.weighted_random_attempts

> How many times shall we try to select a service using a weighted random algorithm, before switching to the shuffled selection. Increase this if you observe too many choices of low-score services while high-score services are available.

 * default: **1**
 * type: guint
 * cmake directive: *OIO_CORE_LB_WEIGHTED_RANDOM_ATTEMPTS*
 * range: 1 -> 64000

### core.lb.writer_lock_alert_delay

> Dump the time spent while holding the global writer lock, when the lock is held for longer than this threshold (in microseconds).

 * default: **5000**
 * type: gint64
 * cmake directive: *OIO_CORE_LB_WRITER_LOCK_ALERT_DELAY*
 * range: 1 -> 60 * G_TIME_SPAN_SECOND

### core.period.refresh.cpu_idle

> Sets the miniimal amount of time between two refreshed of the known CPU-idle counters for the current host. Keep this value small.

 * default: **1 * G_TIME_SPAN_SECOND**
 * type: gint64
 * cmake directive: *OIO_CORE_PERIOD_REFRESH_CPU_IDLE*
 * range: 100 * G_TIME_SPAN_MILLISECOND -> 1 * G_TIME_SPAN_HOUR

### core.period.refresh.io_idle

> Sets the minimal amount of time between two refreshes of the known IO-idle counters for the current host. Keep this small.

 * default: **1 * G_TIME_SPAN_SECOND**
 * type: gint64
 * cmake directive: *OIO_CORE_PERIOD_REFRESH_IO_IDLE*
 * range: 100 * G_TIME_SPAN_MILLISECOND -> 1 * G_TIME_SPAN_HOUR

### core.period.refresh.major_minor

> Sets the minimal amount of time between two refreshes of the list of the major/minor numbers of the known devices, currently mounted on the current host. If the set of mounted file systems doesn't change, keep this value high.

 * default: **30 * G_TIME_SPAN_SECOND**
 * type: gint64
 * cmake directive: *OIO_CORE_PERIOD_REFRESH_MAJOR_MINOR*
 * range: 100 * G_TIME_SPAN_MILLISECOND -> 1 * G_TIME_SPAN_HOUR

### core.resolver.dir_shuffle

> TODO: to be documented

 * default: **TRUE**
 * type: gboolean
 * cmake directive: *OIO_CORE_RESOLVER_DIR_SHUFFLE*

### core.resolver.srv_shuffle

> TODO: to be documented

 * default: **TRUE**
 * type: gboolean
 * cmake directive: *OIO_CORE_RESOLVER_SRV_SHUFFLE*

### core.sds.adapt_metachunk_size

> Should the client adapt metachunk size to EC policy parameters? Letting this on will make bigger metachunks, but chunks on storage will stay at normal chunk size. Disabling this option allows clients to do write alignment.

 * default: **TRUE**
 * type: gboolean
 * cmake directive: *OIO_CORE_SDS_ADAPT_METACHUNK_SIZE*

### core.sds.autocreate

> In the current oio-sds client SDK, should the entities be autocreated while accessed for the first time. So, when pushing a content in a container, when this option is set to 'true', the USER and the CONTAINER will be created and configured to the namespace's defaults.

 * default: **FALSE**
 * type: gboolean
 * cmake directive: *OIO_CORE_SDS_AUTOCREATE*

### core.sds.noshuffle

> In the current oio-sds client SDK, should the rawx services be shuffled before accessed. This helps ensuring a little load-balancing on the client side.

 * default: **FALSE**
 * type: gboolean
 * cmake directive: *OIO_CORE_SDS_NOSHUFFLE*

### core.sds.strict_utf8

> Should the object URLs be checked for non-UTF-8 characters? Disable this only if you have trouble reading old objects, uploaded before we check for invalid names.

 * default: **TRUE**
 * type: gboolean
 * cmake directive: *OIO_CORE_SDS_STRICT_UTF8*

### core.sds.timeout.cnx.rawx

> Sets the connection timeout for requests issued to rawx services.

 * default: **5.0**
 * type: gdouble
 * cmake directive: *OIO_CORE_SDS_TIMEOUT_CNX_RAWX*
 * range: 0.001 -> 300.0

### core.sds.timeout.req.rawx

> Sets the global timeout when uploading a chunk to a rawx service.

 * default: **60.0**
 * type: gdouble
 * cmake directive: *OIO_CORE_SDS_TIMEOUT_REQ_RAWX*
 * range: 0.001 -> 600.0

### core.sds.version

> The version of the sds. It's used to know the expected metadata of a chunk

 * default: **4.2**
 * type: string
 * cmake directive: *OIO_CORE_SDS_VERSION*

### events.beanstalkd.check_level_alert

> Set a threshold for the number of items in the beanstalkd, so that the service will alert past that value. Set to 0 for no alert sent.

 * default: **0**
 * type: gint64
 * cmake directive: *OIO_EVENTS_BEANSTALKD_CHECK_LEVEL_ALERT*
 * range: 0 -> G_MAXINT64

### events.beanstalkd.check_level_deny

> Set the maximum number of items in beanstalkd before considering it full

 * default: **512000**
 * type: gint64
 * cmake directive: *OIO_EVENTS_BEANSTALKD_CHECK_LEVEL_DENY*
 * range: 0 -> G_MAXINT64

### events.beanstalkd.check_period

> Set the interval between each check of the beanstalkd availability. Set to 0 to never check.

 * default: **0**
 * type: gint64
 * cmake directive: *OIO_EVENTS_BEANSTALKD_CHECK_PERIOD*
 * range: 0 -> 1 * G_TIME_SPAN_DAY

### events.beanstalkd.delay

> Sets the delay on each notification sent to the BEANSTALK endpoint

 * default: **0**
 * type: gint64
 * cmake directive: *OIO_EVENTS_BEANSTALKD_DELAY*
 * range: 0 -> 86400

### events.beanstalkd.prio

> Sets the priority of each notification sent to the BEANSTALK endpoint

 * default: **2147483648**
 * type: guint
 * cmake directive: *OIO_EVENTS_BEANSTALKD_PRIO*
 * range: 0 -> 2147483648

### events.beanstalkd.timeout

> Set the interval between each check of the beanstalkd availability. Set to 0 to never check.

 * default: **4 * G_TIME_SPAN_SECOND**
 * type: gint64
 * cmake directive: *OIO_EVENTS_BEANSTALKD_TIMEOUT*
 * range: 100 * G_TIME_SPAN_MILLISECOND -> 90 * G_TIME_SPAN_SECOND

### events.beanstalkd.ttr

> Sets the TTR (time to run) allow on the treatment of the notificatio sent to the beanstalkd

 * default: **120**
 * type: gint64
 * cmake directive: *OIO_EVENTS_BEANSTALKD_TTR*
 * range: 0 -> 86400

### events.common.pending.delay

> Sets the buffering delay of the events emitted by the application

 * default: **1 * G_TIME_SPAN_SECOND**
 * type: gint64
 * cmake directive: *OIO_EVENTS_COMMON_PENDING_DELAY*
 * range: 1 * G_TIME_SPAN_MILLISECOND -> 1 * G_TIME_SPAN_HOUR

### events.common.pending.max

> Sets the maximum number of pending events, not received yet by the endpoint

 * default: **10000**
 * type: guint32
 * cmake directive: *OIO_EVENTS_COMMON_PENDING_MAX*
 * range: 1 -> 1048576

### events.zmq.max_recv

> Sets the maximum number of ACK managed by the ZMQ notification client

 * default: **32**
 * type: guint
 * cmake directive: *OIO_EVENTS_ZMQ_MAX_RECV*
 * range: 1 -> 1073741824

### gridd.timeout.connect.common

> Sets the connection timeout, involved in any RPC to a 'meta' service.

 * default: **4.0**
 * type: gdouble
 * cmake directive: *OIO_GRIDD_TIMEOUT_CONNECT_COMMON*
 * range: 0.1 -> 30.0

### gridd.timeout.single.common

> Sets the default timeout for unitary (request/response) RPC, without considering the possible redirection.

 * default: **30.0**
 * type: gdouble
 * cmake directive: *OIO_GRIDD_TIMEOUT_SINGLE_COMMON*
 * range: 0.01 -> 120.0

### gridd.timeout.whole.common

> Sets the global timeout of a RPC to e 'meta' service, considering all the possible redirections.

 * default: **30.0**
 * type: gdouble
 * cmake directive: *OIO_GRIDD_TIMEOUT_WHOLE_COMMON*
 * range: 0.1 -> 120.0

### meta.queue.max_delay

> Anti-DDoS counter-mesure. In the current server, sets the maximum amount of time a queued TCP event may remain in the queue. If an event is polled and the thread sees the event stayed longer than that delay, A '503 Unavailabe' error is replied.

 * default: **40 * G_TIME_SPAN_SECOND**
 * type: gint64
 * cmake directive: *OIO_META_QUEUE_MAX_DELAY*
 * range: 10 * G_TIME_SPAN_MILLISECOND -> 1 * G_TIME_SPAN_HOUR

### meta0.outgoing.timeout.common.req

> Sets the timeout to the set of (quick) RPC that query a meta0 service

 * default: **10.0**
 * type: gdouble
 * cmake directive: *OIO_META0_OUTGOING_TIMEOUT_COMMON_REQ*
 * range: 0.01 -> 60.0

### meta1.outgoing.timeout.common.req

> Sets the timeout to the set of (quick) RPC that query a meta1 service

 * default: **10.0**
 * type: gdouble
 * cmake directive: *OIO_META1_OUTGOING_TIMEOUT_COMMON_REQ*
 * range: 0.01 -> 60.0

### meta1.tube.references

> TODO: to be documented

 * default: **oio**
 * type: string
 * cmake directive: *OIO_META1_TUBE_REFERENCES*

### meta1.tube.services

> TODO: to be documented

 * default: **oio**
 * type: string
 * cmake directive: *OIO_META1_TUBE_SERVICES*

### meta2.batch.maxlen

> When listing a container, limits the number of items to that value.

 * default: **1000**
 * type: guint
 * cmake directive: *OIO_META2_BATCH_MAXLEN*
 * range: 1 -> 100000

### meta2.container.max_size

> How many bytes may be stored in each container.

 * default: **0**
 * type: gint64
 * cmake directive: *OIO_META2_CONTAINER_MAX_SIZE*
 * range: 0 -> G_MAXINT64

### meta2.delete_exceeding_versions

> When adding alias with versioning, deletes exceeding versions.

 * default: **FALSE**
 * type: gboolean
 * cmake directive: *OIO_META2_DELETE_EXCEEDING_VERSIONS*

### meta2.flush_limit

> When flushing a container, limits the number of deleted objects.

 * default: **1000**
 * type: gint64
 * cmake directive: *OIO_META2_FLUSH_LIMIT*
 * range: 0 -> G_MAXINT64

### meta2.generate.precheck

> Should the meta2 check the container state (quota, etc) before generating chunks.

 * default: **FALSE**
 * type: gboolean
 * cmake directive: *OIO_META2_GENERATE_PRECHECK*

### meta2.max_versions

> Namespace configuration of the max number of versions for a single alias, in a container.

 * default: **1**
 * type: gint64
 * cmake directive: *OIO_META2_MAX_VERSIONS*
 * range: -1 -> G_MAXINT64

### meta2.reload.lb.period

> Sets the period of the periodical reloading of the Load-balancing state, in the current meta2 service.

 * default: **10**
 * type: gint64
 * cmake directive: *OIO_META2_RELOAD_LB_PERIOD*
 * range: 1 -> 3600

### meta2.reload.nsinfo.period

> Sets the period of the periodical reloading of the namespace configuration, in the current meta2 service.

 * default: **5**
 * type: gint64
 * cmake directive: *OIO_META2_RELOAD_NSINFO_PERIOD*
 * range: 1 -> 3600

### meta2.retention_period

> How long should deleted content be kept.

 * default: **604800**
 * type: gint64
 * cmake directive: *OIO_META2_RETENTION_PERIOD*
 * range: 1 -> 2592000

### meta2.store_chunk_ids

> Should the meta2 store complete chunk IDs (URL) or just store service IDs. If this is set to false, core.lb.generate_random_chunk_ids should be set to false also.

 * default: **TRUE**
 * type: gboolean
 * cmake directive: *OIO_META2_STORE_CHUNK_IDS*

### meta2.tube.container_deleted

> TODO: to be documented

 * default: **oio**
 * type: string
 * cmake directive: *OIO_META2_TUBE_CONTAINER_DELETED*

### meta2.tube.container_new

> TODO: to be documented

 * default: **oio**
 * type: string
 * cmake directive: *OIO_META2_TUBE_CONTAINER_NEW*

### meta2.tube.container_state

> TODO: to be documented

 * default: **oio**
 * type: string
 * cmake directive: *OIO_META2_TUBE_CONTAINER_STATE*

### meta2.tube.container_updated

> TODO: to be documented

 * default: **oio**
 * type: string
 * cmake directive: *OIO_META2_TUBE_CONTAINER_UPDATED*

### meta2.tube.content_appended

> TODO: to be documented

 * default: **oio**
 * type: string
 * cmake directive: *OIO_META2_TUBE_CONTENT_APPENDED*

### meta2.tube.content_broken

> TODO: to be documented

 * default: **oio**
 * type: string
 * cmake directive: *OIO_META2_TUBE_CONTENT_BROKEN*

### meta2.tube.content_created

> TODO: to be documented

 * default: **oio**
 * type: string
 * cmake directive: *OIO_META2_TUBE_CONTENT_CREATED*

### meta2.tube.content_deleted

> TODO: to be documented

 * default: **oio**
 * type: string
 * cmake directive: *OIO_META2_TUBE_CONTENT_DELETED*

### meta2.tube.content_drained

> TODO: to be documented

 * default: **oio**
 * type: string
 * cmake directive: *OIO_META2_TUBE_CONTENT_DRAINED*

### meta2.tube.content_updated

> TODO: to be documented

 * default: **oio**
 * type: string
 * cmake directive: *OIO_META2_TUBE_CONTENT_UPDATED*

### meta2.tube.meta2_deleted

> TODO: to be documented

 * default: **oio**
 * type: string
 * cmake directive: *OIO_META2_TUBE_META2_DELETED*

### ns.chunk_size

> Default chunk size for the given namespace.

 * default: **10485760**
 * type: gint64
 * cmake directive: *OIO_NS_CHUNK_SIZE*
 * range: 1 -> G_MAXINT64

### ns.flat_bits

> Default number of bits with flat-NS computation.

 * default: **17**
 * type: guint
 * cmake directive: *OIO_NS_FLAT_BITS*
 * range: 0 -> 64

### ns.master

> TODO: to be documented

 * default: **TRUE**
 * type: gboolean
 * cmake directive: *OIO_NS_MASTER*

### ns.meta1_digits

> Default number of digits to agregate meta1 databases.

 * default: **4**
 * type: guint
 * cmake directive: *OIO_NS_META1_DIGITS*
 * range: 0 -> 4

### ns.service_update_policy

> TODO: to be documented

 * default: **meta2=KEEP|3|1;sqlx=KEEP|1|1|;rdir=KEEP|1|1|**
 * type: string
 * cmake directive: *OIO_NS_SERVICE_UPDATE_POLICY*

### ns.storage_policy

> TODO: to be documented

 * default: **NONE**
 * type: string
 * cmake directive: *OIO_NS_STORAGE_POLICY*

### ns.worm

> Is the NS in a WORM (for Write Once, Read Many --but never delete).

 * default: **FALSE**
 * type: gboolean
 * cmake directive: *OIO_NS_WORM*

### proxy.bulk.max.create_many

> In a proxy, sets how many containers can be created at once.

 * default: **100**
 * type: guint
 * cmake directive: *OIO_PROXY_BULK_MAX_CREATE_MANY*
 * range: 0 -> 10000

### proxy.bulk.max.delete_many

> In a proxy, sets how many objects can be deleted at once.

 * default: **100**
 * type: guint
 * cmake directive: *OIO_PROXY_BULK_MAX_DELETE_MANY*
 * range: 0 -> 10000

### proxy.cache.enabled

> In a proxy, sets if any form of caching is allowed. Supersedes the value of resolver.cache.enabled.

 * default: **TRUE**
 * type: gboolean
 * cmake directive: *OIO_PROXY_CACHE_ENABLED*

### proxy.dir_shuffle

> Should the proxy shuffle the meta1 addresses before contacting them, thus trying to perform a better fanout of the requests.

 * default: **TRUE**
 * type: gboolean
 * cmake directive: *OIO_PROXY_DIR_SHUFFLE*

### proxy.force.master

> In a proxy, should the process ask the target service (with the help of an option in each RPC) to accept the RPC only if it is MASTER on that DB.

 * default: **FALSE**
 * type: gboolean
 * cmake directive: *OIO_PROXY_FORCE_MASTER*

### proxy.location

> Specify the OpenIO SDS location of the service.

 * default: ****
 * type: string
 * cmake directive: *OIO_PROXY_LOCATION*

### proxy.outgoing.timeout.common

> In a proxy, sets the global timeout for all the other RPC issued (not conscience, not stats-related)

 * default: **30.0**
 * type: gdouble
 * cmake directive: *OIO_PROXY_OUTGOING_TIMEOUT_COMMON*
 * range: 0.1 -> 60.0

### proxy.outgoing.timeout.config

> In a proxy, sets the global timeout for 'config' requests issued

 * default: **10.0**
 * type: gdouble
 * cmake directive: *OIO_PROXY_OUTGOING_TIMEOUT_CONFIG*
 * range: 0.1 -> 60.0

### proxy.outgoing.timeout.conscience

> In a proxy, sets the global timeout for the RPC to the central cosnience service.

 * default: **10.0**
 * type: gdouble
 * cmake directive: *OIO_PROXY_OUTGOING_TIMEOUT_CONSCIENCE*
 * range: 0.1 -> 60.0

### proxy.outgoing.timeout.info

> In a proxy, sets the global timeout for 'info' requests issued

 * default: **5.0**
 * type: gdouble
 * cmake directive: *OIO_PROXY_OUTGOING_TIMEOUT_INFO*
 * range: 0.01 -> 60.0

### proxy.outgoing.timeout.stat

> In a proxy, sets the global timeout for 'stat' requests issued (mostly forwarded for the event-agent)

 * default: **10.0**
 * type: gdouble
 * cmake directive: *OIO_PROXY_OUTGOING_TIMEOUT_STAT*
 * range: 0.1 -> 60.0

### proxy.period.cs.downstream

> In a proxy, sets the period between the refreshes of the load-balancing state from the central conscience.

 * default: **5**
 * type: gint64
 * cmake directive: *OIO_PROXY_PERIOD_CS_DOWNSTREAM*
 * range: 0 -> 60

### proxy.period.cs.upstream

> In a proxy, sets the period between two sendings of services states to the conscience.

 * default: **1**
 * type: gint64
 * cmake directive: *OIO_PROXY_PERIOD_CS_UPSTREAM*
 * range: 1 -> 60

### proxy.period.refresh.csurl

> In the proxy, tells the period between the reloadings of the conscience URL, known from the local configuration

 * default: **30**
 * type: gint64
 * cmake directive: *OIO_PROXY_PERIOD_REFRESH_CSURL*
 * range: 0 -> 86400

### proxy.period.refresh.srvtypes

> In the proxy, tells the period between two refreshes of the known service types, from the conscience

 * default: **30**
 * type: gint64
 * cmake directive: *OIO_PROXY_PERIOD_REFRESH_SRVTYPES*
 * range: 1 -> 86400

### proxy.period.reload.nsinfo

> In the proxy, tells the period between two refreshes of the namespace configuration, from the conscience

 * default: **30**
 * type: gint64
 * cmake directive: *OIO_PROXY_PERIOD_RELOAD_NSINFO*
 * range: 1 -> 3600

### proxy.prefer.master_for_read

> In a proxy, upon a read request, should the proxy prefer a service known to host a MASTER copy of the DB. Supersedes proxy.prefer.slave_for_read

 * default: **FALSE**
 * type: gboolean
 * cmake directive: *OIO_PROXY_PREFER_MASTER_FOR_READ*

### proxy.prefer.master_for_write

> In a proxy, upon a write request, should the proxy prefer services known to host the MASTER copy of the DB 

 * default: **TRUE**
 * type: gboolean
 * cmake directive: *OIO_PROXY_PREFER_MASTER_FOR_WRITE*

### proxy.prefer.slave_for_read

> In a proxy, upon a read request, should the proxy prefer a service known to host a SLAVE copy of the DB.

 * default: **TRUE**
 * type: gboolean
 * cmake directive: *OIO_PROXY_PREFER_SLAVE_FOR_READ*

### proxy.quirk.local_scores

> In a proxy, tells if the (ugly-as-hell) quirk that sets the score known from the conscience on the corresponding entries in the cache of services 'known to be local'

 * default: **FALSE**
 * type: gboolean
 * cmake directive: *OIO_PROXY_QUIRK_LOCAL_SCORES*

### proxy.request.max_delay

> How long a request might take to execute, when no specific deadline has been received. Used to compute a deadline transmitted to backend services, when no timeout is present in the request.

 * default: **1 * G_TIME_SPAN_MINUTE**
 * type: gint64
 * cmake directive: *OIO_PROXY_REQUEST_MAX_DELAY*
 * range: 1 * G_TIME_SPAN_MILLISECOND -> 1 * G_TIME_SPAN_HOUR

### proxy.srv_local.patch

> Should the proxy patch the services descriptions to let the caller prefer local services.

 * default: **FALSE**
 * type: gboolean
 * cmake directive: *OIO_PROXY_SRV_LOCAL_PATCH*

### proxy.srv_local.prepare

> Should the proxy allocate services with a local preference. 0 for no, 1 for only one local service and 2 for a maximum of services in spite of the location constraints. The value 2 is a quirk that should be avoided unless upon exceptional conditon wherein you accept the risk.

 * default: **0**
 * type: gint
 * cmake directive: *OIO_PROXY_SRV_LOCAL_PREPARE*
 * range: 0 -> 2

### proxy.srv_shuffle

> Should the proxy shuffle the meta2 addresses before the query, to do a better load-balancing of the requests.

 * default: **TRUE**
 * type: gboolean
 * cmake directive: *OIO_PROXY_SRV_SHUFFLE*

### proxy.ttl.services.down

> In the proxy cache, sets the TTL of a service known to be down

 * default: **5 * G_TIME_SPAN_SECOND**
 * type: gint64
 * cmake directive: *OIO_PROXY_TTL_SERVICES_DOWN*
 * range: 0 -> 1 * G_TIME_SPAN_DAY

### proxy.ttl.services.known

> In a proxy, sets the TTL of each service already encountered

 * default: **5 * G_TIME_SPAN_DAY**
 * type: gint64
 * cmake directive: *OIO_PROXY_TTL_SERVICES_KNOWN*
 * range: 0 -> 7 * G_TIME_SPAN_DAY

### proxy.ttl.services.local

> In the proxy cache, sets the TTL of a local service

 * default: **30 * G_TIME_SPAN_SECOND**
 * type: gint64
 * cmake directive: *OIO_PROXY_TTL_SERVICES_LOCAL*
 * range: 0 -> 1 * G_TIME_SPAN_DAY

### proxy.ttl.services.master

> In a proxy, sets the TTL on each 'known master' entry. That cache is filled each time a redirection to a MASTER occurs, so that we can immediately direct write operation to the service that owns the MASTER copy.

 * default: **30 * G_TIME_SPAN_MINUTE**
 * type: gint64
 * cmake directive: *OIO_PROXY_TTL_SERVICES_MASTER*
 * range: 0 -> 7 * G_TIME_SPAN_DAY

### proxy.url.path.maxlen

> In a proxy, sets the maximum length for the URL it receives. This options protects stack allocation for that URL.

 * default: **2048**
 * type: guint
 * cmake directive: *OIO_PROXY_URL_PATH_MAXLEN*
 * range: 32 -> 65536

### rawx.events_allowed

> Is the RAWX allowed to emit events in the beansatlkd?

 * default: **TRUE**
 * type: gboolean
 * cmake directive: *OIO_RAWX_EVENTS_ALLOWED*

### rawx.slash_allowed

> Is the RAWX allowed to run if its base directory is hosted in the root partition, a.k.a. '/'.

 * default: **TRUE**
 * type: gboolean
 * cmake directive: *OIO_RAWX_SLASH_ALLOWED*

### rawx.tube.chunk_created

> TODO: to be documented

 * default: **oio**
 * type: string
 * cmake directive: *OIO_RAWX_TUBE_CHUNK_CREATED*

### rawx.tube.chunk_deleted

> TODO: to be documented

 * default: **oio**
 * type: string
 * cmake directive: *OIO_RAWX_TUBE_CHUNK_DELETED*

### rdir.fd_per_base

> Configure the maximum number of file descriptors allowed to each leveldb database. Set to 0 to autodetermine the value (cf. rdir.fd_reserve). The real value will be clamped at least to 8. Will only be applied on bases opened after the configuration change.

 * default: **0**
 * type: guint
 * cmake directive: *OIO_RDIR_FD_PER_BASE*
 * range: 0 -> 16384

### rdir.fd_reserve

> Configure the total number of file descriptors the leveldb backend may use. Set to 0 to autodetermine the value. Will only be applied on bases opened after the configuration change.

 * default: **0**
 * type: guint
 * cmake directive: *OIO_RDIR_FD_RESERVE*
 * range: 0 -> 32768

### resolver.cache.csm0.max.default

> In any service resolver instanciated, sets the maximum number of entries related to meta0 (meta1 addresses) and conscience (meta0 address)

 * default: **4194304**
 * type: guint
 * cmake directive: *OIO_RESOLVER_CACHE_CSM0_MAX_DEFAULT*
 * range: 0 -> G_MAXUINT

### resolver.cache.csm0.ttl.default

> In any service resolver instanciated, sets the default TTL on the entries related meta0 (meta1 addresses) and conscience (meta0 address)

 * default: **0**
 * type: gint64
 * cmake directive: *OIO_RESOLVER_CACHE_CSM0_TTL_DEFAULT*
 * range: 0 -> G_MAXINT64

### resolver.cache.enabled

> Allows the resolver instances to cache entries

 * default: **FALSE**
 * type: gboolean
 * cmake directive: *OIO_RESOLVER_CACHE_ENABLED*

### resolver.cache.srv.max.default

> In any service resolver instanciated, sets the maximum number of meta1 entries (data-bound services)

 * default: **4194304**
 * type: guint
 * cmake directive: *OIO_RESOLVER_CACHE_SRV_MAX_DEFAULT*
 * range: 0 -> G_MAXUINT

### resolver.cache.srv.ttl.default

> In any service resolver instanciated, sets the default TTL on the meta1 entries (data-bound services)

 * default: **0**
 * type: gint64
 * cmake directive: *OIO_RESOLVER_CACHE_SRV_TTL_DEFAULT*
 * range: 0 -> G_MAXINT64

### server.batch.accept

> In the network core, when the server socket wakes the call to epoll_wait(), that value sets the number of subsequent calls to accept(). Setting it to a low value allows to quickly switch to other events (established connection) and can lead to a strvation on the new connections. Setting to a high value might spend too much time in accepting and ease denials of service (with established but idle cnx).

 * default: **64**
 * type: guint
 * cmake directive: *OIO_SERVER_BATCH_ACCEPT*
 * range: 1 -> 4096

### server.batch.events

> In the network core of a server, how many events do you manage in each call to epoll_wait(). Set to a low value to quickly react on new connections, to an higher value to rather treat established connections. The value is bound to a stack-allocated buffer, keep it rather small.

 * default: **128**
 * type: guint
 * cmake directive: *OIO_SERVER_BATCH_EVENTS*
 * range: 1 -> 4096

### server.cnx.timeout.idle

> In the current server, sets the maximumu amount of time a connection may live without activity since the last activity (i.e. the last reply sent)

 * default: **5 * G_TIME_SPAN_MINUTE**
 * type: gint64
 * cmake directive: *OIO_SERVER_CNX_TIMEOUT_IDLE*
 * range: 0 -> 1 * G_TIME_SPAN_DAY

### server.cnx.timeout.never

> In the current server, sets the maximum amount of time an established connection is allowed to live when it has no activity at all.

 * default: **30 * G_TIME_SPAN_SECOND**
 * type: gint64
 * cmake directive: *OIO_SERVER_CNX_TIMEOUT_NEVER*
 * range: 0 -> 1 * G_TIME_SPAN_DAY

### server.cnx.timeout.persist

> In the current server, sets the maximum amount of time a connection is allowed to live, since its creation by the accept() call, wheter it presents activity or not.

 * default: **2 * G_TIME_SPAN_HOUR**
 * type: gint64
 * cmake directive: *OIO_SERVER_CNX_TIMEOUT_PERSIST*
 * range: 0 -> 1 * G_TIME_SPAN_DAY

### server.fd_max_passive

> Maximum number of simultaneous incoming connections. Set to 0 for an automatic detection (50% of available file descriptors).

 * default: **0**
 * type: guint
 * cmake directive: *OIO_SERVER_FD_MAX_PASSIVE*
 * range: 0 -> 65536

### server.log_outgoing

> TODO: to be documented

 * default: **FALSE**
 * type: gboolean
 * cmake directive: *OIO_SERVER_LOG_OUTGOING*

### server.malloc_trim_size.ondemand

> Sets how many bytes bytes are released when the LEAN request is received by the current 'meta' service.

 * default: **0**
 * type: guint
 * cmake directive: *OIO_SERVER_MALLOC_TRIM_SIZE_ONDEMAND*
 * range: 0 -> 2147483648

### server.malloc_trim_size.periodic

> Sets how many bytes bytes are released when the LEAN request is received by the current 'meta' service.

 * default: **0**
 * type: guint
 * cmake directive: *OIO_SERVER_MALLOC_TRIM_SIZE_PERIODIC*
 * range: 0 -> 2147483648

### server.perfdata.enabled

> Enable server-side performance data collection.

 * default: **FALSE**
 * type: gboolean
 * cmake directive: *OIO_SERVER_PERFDATA_ENABLED*

### server.periodic_decache.max_bases

> How many bases may be decached each time the background task performs its Dance of Death

 * default: **1**
 * type: guint
 * cmake directive: *OIO_SERVER_PERIODIC_DECACHE_MAX_BASES*
 * range: 1 -> 4194304

### server.periodic_decache.max_delay

> How long may the decache routine take

 * default: **500 * G_TIME_SPAN_MILLISECOND**
 * type: gint64
 * cmake directive: *OIO_SERVER_PERIODIC_DECACHE_MAX_DELAY*
 * range: 1 * G_TIME_SPAN_MILLISECOND -> 1 * G_TIME_SPAN_MINUTE

### server.periodic_decache.period

> In ticks / jiffies, with approx. 1 tick per second. 0 means never

 * default: **0**
 * type: guint
 * cmake directive: *OIO_SERVER_PERIODIC_DECACHE_PERIOD*
 * range: 0 -> 1048576

### server.pool.max_idle

> In the current server, sets how long a thread can remain unused before considered as idle (and thus to be stopped)

 * default: **30 * G_TIME_SPAN_SECOND**
 * type: gint64
 * cmake directive: *OIO_SERVER_POOL_MAX_IDLE*
 * range: 1 -> 1 * G_TIME_SPAN_HOUR

### server.pool.max_tcp

> In the current server, sets the maximum number of threads for the pool responsible for the TCP connections (threading model is one thread per request being managed, and one request at once per TCP connection). Set to 0 for no limit.

 * default: **0**
 * type: gint
 * cmake directive: *OIO_SERVER_POOL_MAX_TCP*
 * range: 0 -> 1073741824

### server.pool.max_udp

> In the current server, sets the maximum number of threads for pool responsible for the UDP messages handling. UDP is only used for quick synchronisation messages during MASTER elections. Set ot 0 for no limit.

 * default: **4**
 * type: gint
 * cmake directive: *OIO_SERVER_POOL_MAX_UDP*
 * range: 0 -> 1073741824

### server.pool.max_unused

> In the current server, sets how many threads may remain unused. This value is, in the GLib, common to all the threadpools.

 * default: **20**
 * type: gint
 * cmake directive: *OIO_SERVER_POOL_MAX_UNUSED*
 * range: 0 -> 1073741824

### server.queue.max_delay

> Anti-DDoS counter-mesure. In the current server, sets the maximum amount of time a queued TCP event may remain in the queue. If an event is polled and the thread sees the event stayed longer than that delay, the connection is immediately closed. Keep this value rather high because the connection closing doesn't involve a reply that will help the client to retry with an exponential back-off.

 * default: **60 * G_TIME_SPAN_SECOND**
 * type: gint64
 * cmake directive: *OIO_SERVER_QUEUE_MAX_DELAY*
 * range: 10 * G_TIME_SPAN_MILLISECOND -> 1 * G_TIME_SPAN_HOUR

### server.queue.warn_delay

> In the current server, set the time threshold after which a warning is sent when a file descriptor stays longer than that in the queue of the Thread Pool.

 * default: **4 * G_TIME_SPAN_SECOND**
 * type: gint64
 * cmake directive: *OIO_SERVER_QUEUE_WARN_DELAY*
 * range: 10 * G_TIME_SPAN_MILLISECOND -> 1 * G_TIME_SPAN_HOUR

### server.request.max_run_time

> How long a request might take to run on the server side. This value is used to compute a deadline for several waitings (DB cache, manager of elections, etc). Common to all sqliterepo-based services, it might be overriden.

 * default: **300 * G_TIME_SPAN_SECOND**
 * type: gint64
 * cmake directive: *OIO_SERVER_REQUEST_MAX_RUN_TIME*
 * range: 1 * G_TIME_SPAN_MILLISECOND -> 1 * G_TIME_SPAN_HOUR

### server.task.malloc_trim.period

> In jiffies, how often the periodic task that calls malloc_trim() is fired.

 * default: **3600**
 * type: guint
 * cmake directive: *OIO_SERVER_TASK_MALLOC_TRIM_PERIOD*
 * range: 0 -> 86400

### server.udp_queue.max

> In the current server, sets the maximum length of the queue for UDP messages. When that number has been reached and a new message arrives, the message will be dropped.

 * default: **512**
 * type: guint
 * cmake directive: *OIO_SERVER_UDP_QUEUE_MAX*
 * range: 0 -> 2147483648

### server.udp_queue.ttl

> In the current server, sets the maximum amount of time a queued UDP frame may remain in the queue. When unqueued, if the message was queued for too long, it will be dropped. The purpose of such a mechanism is to avoid clogging the queue and the whole election/cache mechanisms with old messages, those messages having already been resent.

 * default: **1 * G_TIME_SPAN_SECOND**
 * type: gint64
 * cmake directive: *OIO_SERVER_UDP_QUEUE_TTL*
 * range: 100 * G_TIME_SPAN_MILLISECOND -> 1 * G_TIME_SPAN_DAY

### socket.fastopen.enabled

> Should the socket to meta~ services use TCP_FASTOPEN flag.

 * default: **TRUE**
 * type: gboolean
 * cmake directive: *OIO_SOCKET_FASTOPEN_ENABLED*

### socket.gridd.rcvbuf

> Set to a non-zero value to explicitely force a RCVBUF option on client sockets to gridd services. Set to 0 to keep the OS default.

 * default: **0**
 * type: guint
 * cmake directive: *OIO_SOCKET_GRIDD_RCVBUF*
 * range: 0 -> 16777216

### socket.gridd.sndbuf

> Set to a non-zero value to explicitely force a SNDBUF option on client sockets to gridd services. Set to 0 to keep the OS default.

 * default: **0**
 * type: guint
 * cmake directive: *OIO_SOCKET_GRIDD_SNDBUF*
 * range: 0 -> 16777216

### socket.linger.delay

> When socket.linger.enabled is set to TRUE, socket.linger.delat tells how the socket remains in the TIME_WAIT state after the close() has been called.

 * default: **1**
 * type: gint64
 * cmake directive: *OIO_SOCKET_LINGER_DELAY*
 * range: 0 -> 60

### socket.linger.enabled

> Set to TRUE to allow the LINGER behavior of TCP sockets, as a default. The connections then end with a normal FIN packet, and go in the TIME_WAIT state for a given delay. Setting to FALSE causes connections to be closed with a RST packet, then avoiding a lot of TCP sockets in the TIME_WAIT state.

 * default: **FALSE**
 * type: gboolean
 * cmake directive: *OIO_SOCKET_LINGER_ENABLED*

### socket.nodelay.enabled

> Should the socket to meta~ services receive the TCP_NODELAY flag. When TRUE, it disables the Naggle's algorithm.

 * default: **TRUE**
 * type: gboolean
 * cmake directive: *OIO_SOCKET_NODELAY_ENABLED*

### socket.proxy.buflen

> Advice the libcurl to use that buffer size for the interactions with the proxy. libcurl gives no guaranty to take the advice into account. Set to 0 to let the default. libcurl applies its own range, usually between 1k and 512k.

 * default: **0**
 * type: guint
 * cmake directive: *OIO_SOCKET_PROXY_BUFLEN*
 * range: 0 -> 512000

### socket.quickack.enabled

> Should the sockets opened by the application receive the TCP_QUICKACK flag.

 * default: **TRUE**
 * type: gboolean
 * cmake directive: *OIO_SOCKET_QUICKACK_ENABLED*

### socket.rawx.buflen

> Advice the libcurl to use that buffer size for the interactions with the rawx services. libcurl gives no guaranty to take the advice into account. Set to 0 to let the default. libcurl applies its own range, usually between 1k and 512k.

 * default: **0**
 * type: guint
 * cmake directive: *OIO_SOCKET_RAWX_BUFLEN*
 * range: 0 -> 512000

### sqliterepo.cache.heat_threshold

> Sets the heat value below which a databse is considered hot

 * default: **1**
 * type: guint32
 * cmake directive: *OIO_SQLITEREPO_CACHE_HEAT_THRESHOLD*
 * range: 1 -> 2147483648

### sqliterepo.cache.heavyload.alert

> Triggers an alert when a thread tries to wait for an overloaded database.

 * default: **TRUE**
 * type: gboolean
 * cmake directive: *OIO_SQLITEREPO_CACHE_HEAVYLOAD_ALERT*

### sqliterepo.cache.heavyload.fail

> Triggers an error when a thread waits for an overloaded database.

 * default: **FALSE**
 * type: gboolean
 * cmake directive: *OIO_SQLITEREPO_CACHE_HEAVYLOAD_FAIL*

### sqliterepo.cache.kbytes_per_db

> Number of kibibytes (kiB) of cache per open DB.

 * default: **0**
 * type: guint
 * cmake directive: *OIO_SQLITEREPO_CACHE_KBYTES_PER_DB*
 * range: 0 -> 1048576

### sqliterepo.cache.timeout.lock

> Sets how long we (unit)wait on the lock around the databases. Keep it small.

 * default: **1 * G_TIME_SPAN_SECOND**
 * type: gint64
 * cmake directive: *OIO_SQLITEREPO_CACHE_TIMEOUT_LOCK*
 * range: 1 * G_TIME_SPAN_MILLISECOND -> 1 * G_TIME_SPAN_HOUR

### sqliterepo.cache.timeout.open

> Sets how long a worker thread accepts for a DB to become available.

 * default: **20 * G_TIME_SPAN_SECOND**
 * type: gint64
 * cmake directive: *OIO_SQLITEREPO_CACHE_TIMEOUT_OPEN*
 * range: 1 * G_TIME_SPAN_MILLISECOND -> 1 * G_TIME_SPAN_DAY

### sqliterepo.cache.ttl.cool

> Sets the period after the return to the IDLE/COLD state, during which the recycling is forbidden. 0 means the base won't be decached.

 * default: **1 * G_TIME_SPAN_MILLISECOND**
 * type: gint64
 * cmake directive: *OIO_SQLITEREPO_CACHE_TTL_COOL*
 * range: 0 -> 1 * G_TIME_SPAN_DAY

### sqliterepo.cache.ttl.hot

> Sets the period after the return to the IDLE/HOT state, during which the recycling is forbidden. 0 means the base won't be decached.

 * default: **1 * G_TIME_SPAN_MILLISECOND**
 * type: gint64
 * cmake directive: *OIO_SQLITEREPO_CACHE_TTL_HOT*
 * range: 0 -> 1 * G_TIME_SPAN_DAY

### sqliterepo.cache.waiting.max

> Sets how many threads can wait on a single database. All the additional waiters will be denied with any wait attempt.

 * default: **16**
 * type: guint32
 * cmake directive: *OIO_SQLITEREPO_CACHE_WAITING_MAX*
 * range: 0 -> 2147483648

### sqliterepo.client.timeout.alert_if_longer

> In the current sqliterepo repository, sets the maximum amount of time a periodical task may take, while checking for the timeouts on the outbound connections.

 * default: **5 * G_TIME_SPAN_SECOND**
 * type: gint64
 * cmake directive: *OIO_SQLITEREPO_CLIENT_TIMEOUT_ALERT_IF_LONGER*
 * range: 1 * G_TIME_SPAN_MILLISECOND -> 1 * G_TIME_SPAN_HOUR

### sqliterepo.dump.check_type

> How to check the database before executing a DB_DUMP request. 0: no check. 1: quick_check (the default). 2: integrity_check.

 * default: **1**
 * type: gint
 * cmake directive: *OIO_SQLITEREPO_DUMP_CHECK_TYPE*
 * range: 0 -> 2

### sqliterepo.dump.chunk_size

> Size of data chunks when copying a database using the chunked DB_PIPEFROM/DB_DUMP mechanism.

 * default: **8388608**
 * type: gint64
 * cmake directive: *OIO_SQLITEREPO_DUMP_CHUNK_SIZE*
 * range: 4096 -> 2146435072

### sqliterepo.dump.max_size

> Maximum size of a database dump. If a base is bigger than this size, it will be refused the synchronous DB_RESTORE mechanism, and will be ansynchronously restored with the DB_DUMP/DB_PIPEFROM mechanism.

 * default: **1073741824**
 * type: gint64
 * cmake directive: *OIO_SQLITEREPO_DUMP_MAX_SIZE*
 * range: 0 -> 2146435072

### sqliterepo.dumps.max

> How many concurrent DB dumps may happen in a single process.

 * default: **1024**
 * type: gint
 * cmake directive: *OIO_SQLITEREPO_DUMPS_MAX*
 * range: 1 -> G_MAXINT

### sqliterepo.dumps.timeout

> How long to wait for a concurrent DB dump to finish. Should be set accordingly with sqliterepo.outgoing.timeout.req.resync.

 * default: **4 * G_TIME_SPAN_MINUTE**
 * type: gint64
 * cmake directive: *OIO_SQLITEREPO_DUMPS_TIMEOUT*
 * range: 1 * G_TIME_SPAN_SECOND -> 1 * G_TIME_SPAN_DAY

### sqliterepo.election.allow_master

> Allow the role of MASTER in any election.

 * default: **TRUE**
 * type: gboolean
 * cmake directive: *OIO_SQLITEREPO_ELECTION_ALLOW_MASTER*

### sqliterepo.election.delay.expire_master

> In the current sqliterepo repository, sets the amount of time after which a MASTER election will drop its status and return to the NONE status. This helps recycling established-but-unused elections, and save Zookeeper nodes. Keep this value greater than sqliterepo.election.delay.expire_slave to avoid rotating the master service.

 * default: **240 * G_TIME_SPAN_MINUTE**
 * type: gint64
 * cmake directive: *OIO_SQLITEREPO_ELECTION_DELAY_EXPIRE_MASTER*
 * range: 1 * G_TIME_SPAN_MILLISECOND -> 7 * G_TIME_SPAN_DAY

### sqliterepo.election.delay.expire_none

> In the current sqliterepo repository, sets the amount of time an election without status will be forgotten 

 * default: **30 * G_TIME_SPAN_MINUTE**
 * type: gint64
 * cmake directive: *OIO_SQLITEREPO_ELECTION_DELAY_EXPIRE_NONE*
 * range: 1 * G_TIME_SPAN_SECOND -> 1 * G_TIME_SPAN_DAY

### sqliterepo.election.delay.expire_pending

> Sets the amount of time after which a pending election (without any status change) will be reset and return to the NONE status. This helps recovering after a ZooKeeper failure. Should be set between sqliterepo.zk.timeout and sqliterepo.election.wait.delay.

 * default: **12 * G_TIME_SPAN_SECOND**
 * type: gint64
 * cmake directive: *OIO_SQLITEREPO_ELECTION_DELAY_EXPIRE_PENDING*
 * range: 1 * G_TIME_SPAN_SECOND -> 7 * G_TIME_SPAN_DAY

### sqliterepo.election.delay.expire_slave

> In the current sqliterepo repository, sets the amount of time after which a SLAVE election will drop its status and return to the NONE status. This helps recycling established-but-unused elections, and save Zookeeper nodes.

 * default: **210 * G_TIME_SPAN_MINUTE**
 * type: gint64
 * cmake directive: *OIO_SQLITEREPO_ELECTION_DELAY_EXPIRE_SLAVE*
 * range: 1 * G_TIME_SPAN_SECOND -> 7 * G_TIME_SPAN_DAY

### sqliterepo.election.delay.retry_failed

> In the current sqliterepo repository, sets the amount of time after which a failed election leaves its FAILED status and returns to the NONE status.

 * default: **250 * G_TIME_SPAN_MILLISECOND**
 * type: gint64
 * cmake directive: *OIO_SQLITEREPO_ELECTION_DELAY_RETRY_FAILED*
 * range: 1 * G_TIME_SPAN_MILLISECOND -> 7 * G_TIME_SPAN_DAY

### sqliterepo.election.lazy_recover

> Should the election mecanism try to recreate missing DB?

 * default: **FALSE**
 * type: gboolean
 * cmake directive: *OIO_SQLITEREPO_ELECTION_LAZY_RECOVER*

### sqliterepo.election.lock_alert_delay

> Only effective when built in DEBUG mode. Dump the long critical sections around the elections lock, when the lock is held for longer than this threshold (in microseconds).

 * default: **500**
 * type: gint64
 * cmake directive: *OIO_SQLITEREPO_ELECTION_LOCK_ALERT_DELAY*
 * range: 1 -> 60 * G_TIME_SPAN_SECOND

### sqliterepo.election.nowait.after

> In the current sqliterepo repository, sets the amount of time spent in an election resolution that will make a worker thread won't wait at all and consider that election is stalled.

 * default: **15 * G_TIME_SPAN_MINUTE**
 * type: gint64
 * cmake directive: *OIO_SQLITEREPO_ELECTION_NOWAIT_AFTER*
 * range: 1 * G_TIME_SPAN_MILLISECOND -> G_MAXINT64

### sqliterepo.election.nowait.enable

> Check of the election is pending since too long. If it is, don't way for it.

 * default: **FALSE**
 * type: gboolean
 * cmake directive: *OIO_SQLITEREPO_ELECTION_NOWAIT_ENABLE*

### sqliterepo.election.wait.delay

> In the current sqliterepo repository, sets the maximum amount of time a worker thread is allowed to wait for an election to get its final status.

 * default: **20 * G_TIME_SPAN_SECOND**
 * type: gint64
 * cmake directive: *OIO_SQLITEREPO_ELECTION_WAIT_DELAY*
 * range: 100 * G_TIME_SPAN_MILLISECOND -> 1 * G_TIME_SPAN_HOUR

### sqliterepo.election.wait.quantum

> In the current sqliterepo repository, while loop-waiting for a final election status to be reached, this value sets the unit amount of time of eacch unit wait on the lock. Keep this value rather small to avoid waiting for too long, but not too small to avoid dumping CPU cycles in active waiting.

 * default: **4 * G_TIME_SPAN_SECOND**
 * type: gint64
 * cmake directive: *OIO_SQLITEREPO_ELECTION_WAIT_QUANTUM*
 * range: 100 * G_TIME_SPAN_MILLISECOND -> 1 * G_TIME_SPAN_HOUR

### sqliterepo.outgoing.timeout.cnx.getvers

> Sets the connection timeout when exchanging versions between databases replicas.

 * default: **5.0**
 * type: gdouble
 * cmake directive: *OIO_SQLITEREPO_OUTGOING_TIMEOUT_CNX_GETVERS*
 * range: 0.01 -> 30.0

### sqliterepo.outgoing.timeout.cnx.replicate

> Sets the connection timeout sending a replication request.

 * default: **5.0**
 * type: gdouble
 * cmake directive: *OIO_SQLITEREPO_OUTGOING_TIMEOUT_CNX_REPLICATE*
 * range: 0.01 -> 30.0

### sqliterepo.outgoing.timeout.cnx.resync

> Set the connection timeout during RPC to ask for a SLAVE database to be resync on its MASTER

 * default: **5.0**
 * type: gdouble
 * cmake directive: *OIO_SQLITEREPO_OUTGOING_TIMEOUT_CNX_RESYNC*
 * range: 0.01 -> 30.0

### sqliterepo.outgoing.timeout.cnx.use

> Sets the connection timeout when ping'ing a peer database. Keep it small. Only used when UDP is disabled.

 * default: **1.0**
 * type: gdouble
 * cmake directive: *OIO_SQLITEREPO_OUTGOING_TIMEOUT_CNX_USE*
 * range: 0.01 -> 30.0

### sqliterepo.outgoing.timeout.req.getvers

> Sets the global timeout when performing a version exchange RPC. Keep it rather small, to let election quickly fail on network troubles. Only used when UDP is disabled.

 * default: **10.0**
 * type: gdouble
 * cmake directive: *OIO_SQLITEREPO_OUTGOING_TIMEOUT_REQ_GETVERS*
 * range: 0.01 -> 30.0

### sqliterepo.outgoing.timeout.req.replicate

> Sets the global timeout when sending a replication RPC, from the current MASTER to a SLAVE

 * default: **10.0**
 * type: gdouble
 * cmake directive: *OIO_SQLITEREPO_OUTGOING_TIMEOUT_REQ_REPLICATE*
 * range: 0.01 -> 30.0

### sqliterepo.outgoing.timeout.req.resync

> Sets the global timeout of a RESYNC request sent to a 'meta' service. Sent to a SLAVE DB, the RESYNC operation involves a RPC from the SLAVE to the MASTER, then a DB dump on the MASTER and restoration on the SLAVE. Thus that operation might be rather long, due to the possibility of network/disk latency/bandwidth, etc. Should be set accordingly with sqliterepo.dumps.timeout

 * default: **241.0**
 * type: gdouble
 * cmake directive: *OIO_SQLITEREPO_OUTGOING_TIMEOUT_REQ_RESYNC*
 * range: 0.01 -> 300.0

### sqliterepo.outgoing.timeout.req.use

> Sets the global timeout when ping'ing a peer database. Keep it small.

 * default: **10.0**
 * type: gdouble
 * cmake directive: *OIO_SQLITEREPO_OUTGOING_TIMEOUT_REQ_USE*
 * range: 0.01 -> 30.0

### sqliterepo.page_size

> In the current sqliterepo repository, sets the page size of all the databases used. This value only has effects on databases created with that value.

 * default: **4096**
 * type: guint
 * cmake directive: *OIO_SQLITEREPO_PAGE_SIZE*
 * range: 512 -> 1048576

### sqliterepo.release_size

> Sets how many bytes bytes are released when the LEAN request is received by the current 'meta' service.

 * default: **67108864**
 * type: guint
 * cmake directive: *OIO_SQLITEREPO_RELEASE_SIZE*
 * range: 1 -> 2147483648

### sqliterepo.repo.active_queue_ttl

> In the current server, sets the maximum amount of time a queued DB_USE, DB_GETVERS or DB_PIPEFROM request may remain in the queue. If the message was queued for too long before being sent, it will be dropped. The purpose of such a mechanism is to avoid clogging the queue and the whole election/cache mechanisms with old messages, those messages having already been resent.

 * default: **4 * G_TIME_SPAN_SECOND**
 * type: gint64
 * cmake directive: *OIO_SQLITEREPO_REPO_ACTIVE_QUEUE_TTL*
 * range: 100 * G_TIME_SPAN_MILLISECOND -> 60 * G_TIME_SPAN_SECOND

### sqliterepo.repo.fd_max_active

> Maximum number of simultaneous outgoing connections. Set to 0 for an automatic detection (2% of available file descriptors).

 * default: **512**
 * type: guint
 * cmake directive: *OIO_SQLITEREPO_REPO_FD_MAX_ACTIVE*
 * range: 0 -> 65536

### sqliterepo.repo.fd_min_active

> Minimum number of simultaneous outgoing connections.

 * default: **32**
 * type: guint
 * cmake directive: *OIO_SQLITEREPO_REPO_FD_MIN_ACTIVE*
 * range: 0 -> 65536

### sqliterepo.repo.getvers_attempts

> Sets how many versions exchanges are allowed during the journey in the election FSM.

 * default: **5**
 * type: guint
 * cmake directive: *OIO_SQLITEREPO_REPO_GETVERS_ATTEMPTS*
 * range: 1 -> 64

### sqliterepo.repo.getvers_delay

> .

 * default: **100 * G_TIME_SPAN_MILLISECOND**
 * type: gint64
 * cmake directive: *OIO_SQLITEREPO_REPO_GETVERS_DELAY*
 * range: 10 * G_TIME_SPAN_MILLISECOND -> 1 * G_TIME_SPAN_MINUTE

### sqliterepo.repo.hard_max

> Sets how many databases can be kept simultaneously open (in use or idle) in the current service. If defined to 0, it is set to 48% of available file descriptors.

 * default: **0**
 * type: guint
 * cmake directive: *OIO_SQLITEREPO_REPO_HARD_MAX*
 * range: 0 -> 131072

### sqliterepo.repo.soft_max

> Sets how many databases can be in use at the same moment in the current service. If defined to 0, it is set to sqliterepo.repo.hard_max.

 * default: **0**
 * type: guint
 * cmake directive: *OIO_SQLITEREPO_REPO_SOFT_MAX*
 * range: 0 -> 131072

### sqliterepo.rss.max

> Memory size ceiling we try to honor. The check is performed while closing databases. Set to -1 to autodetect the max RSS from the resource limits (see `man getrlimit` for more information) or 0 to disable. The autodetection considers the environment and is not aware of all the processes that could share that environment.

 * default: **-1**
 * type: gint64
 * cmake directive: *OIO_SQLITEREPO_RSS_MAX*
 * range: -1 -> G_MAXINT64

### sqliterepo.service.exit_ttl

> .

 * default: **10 * G_TIME_SPAN_SECOND**
 * type: gint64
 * cmake directive: *OIO_SQLITEREPO_SERVICE_EXIT_TTL*
 * range: 1 * G_TIME_SPAN_MILLISECOND -> 1 * G_TIME_SPAN_HOUR

### sqliterepo.udp_deferred

> Should the sendto() of DB_USE be deferred to a thread-pool. Only effective when `oio_udp_allowed` is set. Set to 0 to keep the OS default.

 * default: **TRUE**
 * type: gboolean
 * cmake directive: *OIO_SQLITEREPO_UDP_DEFERRED*

### sqliterepo.zk.mux_factor

> For testing purposes. The value simulates ZK sharding on different connection to the same cluster.

 * default: **1**
 * type: guint
 * cmake directive: *OIO_SQLITEREPO_ZK_MUX_FACTOR*
 * range: 1 -> 64

### sqliterepo.zk.rrd.threshold

> Sets the maximum number of reconnections to the ZK that remains acceptable. Beyond that limit, we consider the current service has been disconnected, and that it loast all its nodes.

 * default: **5**
 * type: guint
 * cmake directive: *OIO_SQLITEREPO_ZK_RRD_THRESHOLD*
 * range: 1 -> 2147483648

### sqliterepo.zk.rrd.window

> Sets the time window to remember the reconnection events, on a ZK connection.

 * default: **30**
 * type: guint
 * cmake directive: *OIO_SQLITEREPO_ZK_RRD_WINDOW*
 * range: 1 -> 4095

### sqliterepo.zk.shuffle

> Should the synchronism mechanism shuffle the set of URL in the ZK connection string? Set to yes as an attempt to a better balancing of the connections to the nodes of the ZK cluster.

 * default: **TRUE**
 * type: gboolean
 * cmake directive: *OIO_SQLITEREPO_ZK_SHUFFLE*

### sqliterepo.zk.timeout

> Sets the timeout of the zookeeper handle (in the meaning of the zookeeper client library)

 * default: **10 * G_TIME_SPAN_SECOND**
 * type: gint64
 * cmake directive: *OIO_SQLITEREPO_ZK_TIMEOUT*
 * range: 1 * G_TIME_SPAN_MILLISECOND -> 1 * G_TIME_SPAN_HOUR

### sqlx.lb.refresh_period

> In the current sqlx-based service, tells the period (in seconds) at which the service will refresh its load-balancing information.

 * default: **1**
 * type: gint64
 * cmake directive: *OIO_SQLX_LB_REFRESH_PERIOD*
 * range: 1 -> 60

### sqlx.outgoing.timeout.req

> Sets the timeout for the requests issued to the SQLX services.

 * default: **30.0**
 * type: gdouble
 * cmake directive: *OIO_SQLX_OUTGOING_TIMEOUT_REQ*
 * range: 0.01 -> 60.0

### udp_allowed

> Allow the sqlx client DB_USE RPC to be sent via UDP instead of the default TCP channel.

 * default: **TRUE**
 * type: gboolean
 * cmake directive: *OIO_UDP_ALLOWED*

### volume.lazy_lock

> Allow the services to self-assign to the volume they find in their configuration. This was the default behaviour in pre 5.2 versions of oio-sds.

 * default: **TRUE**
 * type: gboolean
 * cmake directive: *OIO_VOLUME_LAZY_LOCK*

## Variables only for testing purposes

These variables are only active when the **ENBUG** option has been specified on
the cmake command line.


### enbug.client.fake_timeout.threshold

> Set the probability of fake timeout failures, in any client RPC to a 'meta' service

 * default: **0**
 * type: gint32
 * cmake directive: *OIO_ENBUG_CLIENT_FAKE_TIMEOUT_THRESHOLD*
 * range: 0 -> 100

### enbug.election.double_master.db

> CID of the base to force a double master condition on.

 * default: ****
 * type: string
 * cmake directive: *OIO_ENBUG_ELECTION_DOUBLE_MASTER_DB*

### enbug.proxy.cs.failure_rate

> Proxy probability to fail with 503 on a /cs route

 * default: **0**
 * type: gint32
 * cmake directive: *OIO_ENBUG_PROXY_CS_FAILURE_RATE*
 * range: 0 -> 100

### enbug.proxy.request_failure.alone

> Really, do not use this!

 * default: **0**
 * type: gint32
 * cmake directive: *OIO_ENBUG_PROXY_REQUEST_FAILURE_ALONE*
 * range: 0 -> 100

### enbug.proxy.request_failure.first

> Really, do not use this!

 * default: **0**
 * type: gint32
 * cmake directive: *OIO_ENBUG_PROXY_REQUEST_FAILURE_FIRST*
 * range: 0 -> 100

### enbug.proxy.request_failure.last

> Really, do not use this!

 * default: **0**
 * type: gint32
 * cmake directive: *OIO_ENBUG_PROXY_REQUEST_FAILURE_LAST*
 * range: 0 -> 100

### enbug.proxy.request_failure.middle

> Really, do not use this!

 * default: **0**
 * type: gint32
 * cmake directive: *OIO_ENBUG_PROXY_REQUEST_FAILURE_MIDDLE*
 * range: 0 -> 100

### enbug.server.request.failure.threshold

> In testing situations, sets the average ratio of requests failing for a fake reason (from the peer). This helps testing the retrial mechanisms.

 * default: **0**
 * type: gint32
 * cmake directive: *OIO_ENBUG_SERVER_REQUEST_FAILURE_THRESHOLD*
 * range: 0 -> 100

### enbug.sqliterepo.client.failure.threshold

> In testing situations, sets the average ratio of requests failing for a fake reason (from the peer). This helps testing the retrial mechanisms.

 * default: **0**
 * type: gint32
 * cmake directive: *OIO_ENBUG_SQLITEREPO_CLIENT_FAILURE_THRESHOLD*
 * range: 0 -> 100

### enbug.sqliterepo.client.timeout.period

> In testing situations, sets the average ratio of requests failing for a fake reason (connection timeout). This helps testing the retrial mechanisms and the behavior under strong network split-brain.

 * default: **1 * G_TIME_SPAN_SECOND**
 * type: gint64
 * cmake directive: *OIO_ENBUG_SQLITEREPO_CLIENT_TIMEOUT_PERIOD*
 * range: 1 * G_TIME_SPAN_MILLISECOND -> 1 * G_TIME_SPAN_DAY

### enbug.sqliterepo.synchro.failure

> Fake Error rate on synchronism RPC (a.k.a. ZK) 

 * default: **0**
 * type: gint32
 * cmake directive: *OIO_ENBUG_SQLITEREPO_SYNCHRO_FAILURE*
 * range: 0 -> 100
