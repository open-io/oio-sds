/*
OpenIO SDS core library
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#ifndef OIO_SDS__core__config_h
# define OIO_SDS__core__config_h 1

#ifdef __cplusplus
extern "C" {
#endif

# include <glib.h>

# ifndef  OIO_ETC_DIR
#  define OIO_ETC_DIR "/etc/oio"
# endif

# ifndef  OIO_CONFIG_FILE_PATH
#  define OIO_CONFIG_FILE_PATH OIO_ETC_DIR "/sds.conf"
# endif

# ifndef  OIO_CONFIG_DIR_PATH
#  define OIO_CONFIG_DIR_PATH OIO_ETC_DIR "/sds.conf.d"
# endif

# ifndef  OIO_CONFIG_LOCAL_PATH
#  define OIO_CONFIG_LOCAL_PATH ".oio/sds.conf"
# endif

# ifndef OIO_DEFAULT_STGPOL
#  define OIO_DEFAULT_STGPOL "NONE"
# endif

# ifndef OIO_DEFAULT_CHUNKMETHOD
#  define OIO_DEFAULT_CHUNKMETHOD "plain"
# endif

# ifndef OIO_DEFAULT_MIMETYPE
#  define OIO_DEFAULT_MIMETYPE "application/octet-stream"
# endif

# ifndef PROXYD_PREFIX
#  define PROXYD_PREFIX "v3.0"
# endif

# ifndef PROXYD_HEADER_PREFIX
#  define PROXYD_HEADER_PREFIX "x-oio-"
# endif

# ifndef PROXYD_HEADER_MODE
#  define PROXYD_HEADER_MODE PROXYD_HEADER_PREFIX "action-mode"
# endif

# ifndef PROXYD_HEADER_REQID
#  define PROXYD_HEADER_REQID PROXYD_HEADER_PREFIX "req-id"
# endif

# ifndef PROXYD_HEADER_ADMIN
# define PROXYD_HEADER_ADMIN PROXYD_HEADER_PREFIX "admin"
# endif

# ifndef PROXYD_HEADER_NOEMPTY
#  define PROXYD_HEADER_NOEMPTY PROXYD_HEADER_PREFIX "no-empty-list"
# endif

/* in bytes */
# ifndef PROXYD_PATH_MAXLEN
#  define PROXYD_PATH_MAXLEN 2048
# endif

/* in oio_ext_monotonic_time() precision */
# ifndef PROXYD_DEFAULT_TTL_SERVICES
#  define PROXYD_DEFAULT_TTL_SERVICES G_TIME_SPAN_HOUR
# endif

# ifndef PROXYD_DEFAULT_MAX_SERVICES
#  define PROXYD_DEFAULT_MAX_SERVICES 200000
# endif

/* in oio_ext_monotonic_time() precision */
# ifndef PROXYD_DEFAULT_TTL_CSM0
#  define PROXYD_DEFAULT_TTL_CSM0 0
# endif

# ifndef PROXYD_DEFAULT_MAX_CSM0
#  define PROXYD_DEFAULT_MAX_CSM0 0
# endif

/* in seconds */
# ifndef PROXYD_PERIOD_RELOAD_CSURL
#  define PROXYD_PERIOD_RELOAD_CSURL 30
# endif

/* in seconds */
# ifndef PROXYD_PERIOD_RELOAD_SRVTYPES
#  define PROXYD_PERIOD_RELOAD_SRVTYPES 30
# endif

/* in seconds */
# ifndef PROXYD_PERIOD_RELOAD_NSINFO
#  define PROXYD_PERIOD_RELOAD_NSINFO 30
# endif

/* in seconds */
# ifndef PROXYD_PERIOD_RELOAD_M0INFO
#  define PROXYD_PERIOD_RELOAD_M0INFO 30
# endif

/* in seconds */
# ifndef PROXYD_DEFAULT_PERIOD_DOWNSTREAM
#  define PROXYD_DEFAULT_PERIOD_DOWNSTREAM 2
# endif

/* in seconds */
# ifndef PROXYD_DEFAULT_PERIOD_UPSTREAM
#  define PROXYD_DEFAULT_PERIOD_UPSTREAM 1
# endif

/* in oio_ext_monotonic_time() precision */
# ifndef PROXYD_TTL_DEAD_LOCAL_SERVICES
#  define PROXYD_TTL_DEAD_LOCAL_SERVICES (30*G_TIME_SPAN_SECOND)
# endif

/* in oio_ext_monotonic_time() precision */
# ifndef PROXYD_TTL_MASTER_SERVICES
#  define PROXYD_TTL_MASTER_SERVICES (1*G_TIME_SPAN_HOUR)
# endif

/* in oio_ext_monotonic_time() precision */
# ifndef PROXYD_TTL_DOWN_SERVICES
#  define PROXYD_TTL_DOWN_SERVICES (5*G_TIME_SPAN_SECOND)
# endif

/* in oio_ext_monotonic_time() precision */
# ifndef PROXYD_TTL_KNOWN_SERVICES
#  define PROXYD_TTL_KNOWN_SERVICES (5*G_TIME_SPAN_DAY)
# endif

# ifndef GCLUSTER_RUN_DIR
#  define GCLUSTER_RUN_DIR "/var/run"
# endif

# ifndef GCLUSTER_AGENT_SOCK_PATH
#  define GCLUSTER_AGENT_SOCK_PATH GCLUSTER_RUN_DIR "/oio-sds-agent.sock"
# endif

# ifndef OIO_M2V2_LISTRESULT_BATCH
#  define OIO_M2V2_LISTRESULT_BATCH 1000
# endif

# ifndef MALLOC_TRIM_SIZE
#  define MALLOC_TRIM_SIZE (0)
# endif

# ifndef PERIODIC_MALLOC_TRIM_SIZE
#  define PERIODIC_MALLOC_TRIM_SIZE (0)
# endif

# ifndef SQLITE_RELEASE_SIZE
#  define SQLITE_RELEASE_SIZE  (64*1024*1024)
# endif

# ifndef  COMMON_STAT_TIMEOUT
#  define COMMON_STAT_TIMEOUT 5.0
# endif

# ifndef  COMMON_CNX_TIMEOUT
#  define COMMON_CNX_TIMEOUT (2*G_TIME_SPAN_SECOND)
# endif

# ifndef COMMON_CLIENT_TIMEOUT
#  define COMMON_CLIENT_TIMEOUT 30.0
# endif

#ifndef SQLX_SYNC_DEFAULT_ZK_TIMEOUT
# define SQLX_SYNC_DEFAULT_ZK_TIMEOUT 8765
#endif

# ifndef SQLX_CLIENT_TIMEOUT
#  define SQLX_CLIENT_TIMEOUT 30.0
# endif

/* Timeout for synchronisation requests (USE, GETVERS)
   in seconds */
# ifndef SQLX_SYNC_TIMEOUT
#  define SQLX_SYNC_TIMEOUT 4.0
# endif

/* Timeout for SQLX_REPLICATE requests, in seconds */
# ifndef SQLX_REPLI_TIMEOUT
#  define SQLX_REPLI_TIMEOUT 10.0
# endif

/* Timeout for operations that require copying a DB */
# ifndef SQLX_RESYNC_TIMEOUT
#  define SQLX_RESYNC_TIMEOUT 30.0
# endif

# ifndef M2V2_CLIENT_TIMEOUT
#  define M2V2_CLIENT_TIMEOUT 10.0
# endif

# ifndef M2V2_CLIENT_TIMEOUT_HUGE
#  define M2V2_CLIENT_TIMEOUT_HUGE 10.0
# endif

# ifndef M1V2_CLIENT_TIMEOUT
#  define M1V2_CLIENT_TIMEOUT 10.0
# endif

# ifndef M0V2_INIT_TIMEOUT
#  define M0V2_INIT_TIMEOUT 60.0
# endif

# ifndef M0V2_CLIENT_TIMEOUT
#  define M0V2_CLIENT_TIMEOUT 10.0
# endif

# ifndef CS_CLIENT_TIMEOUT
#  define CS_CLIENT_TIMEOUT 2.0
# endif

# ifndef RAWX_HEADER_PREFIX
#  define RAWX_HEADER_PREFIX "X-oio-chunk-meta-"
# endif

# ifndef OIO_EVTQ_MAXPENDING
#  define OIO_EVTQ_MAXPENDING 1000
# endif

/* Delay between events queue flushes in seconds */
# ifndef OIO_EVTQ_BUFFER_DELAY
#  define OIO_EVTQ_BUFFER_DELAY 5
# endif

# ifndef  OIO_CFG_EVTQ_MAXPENDING
#  define OIO_CFG_EVTQ_MAXPENDING "events-max-pending"
# endif

# ifndef  OIO_CFG_EVTQ_BUFFER_DELAY
#  define OIO_CFG_EVTQ_BUFFER_DELAY "events-buffer-delay"
# endif

/* Max number of events raised by epoll_wait */
# ifndef  SERVER_DEFAULT_EPOLL_MAXEV
#  define SERVER_DEFAULT_EPOLL_MAXEV 128
# endif

/* Number of acccept() performed each time epoll mentions the server socket
   has activity */
# ifndef  SERVER_DEFAULT_ACCEPT_MAX
#  define SERVER_DEFAULT_ACCEPT_MAX 64
# endif

/* Max number of threads for the GThreadPool of the workers */
# ifndef  SERVER_DEFAULT_THP_MAXWORKERS
#  define SERVER_DEFAULT_THP_MAXWORKERS  -1
# endif

/* in number of threads */
# ifndef  SERVER_DEFAULT_THP_MAXUNUSED
#  define SERVER_DEFAULT_THP_MAXUNUSED  -1
# endif

/* in millisecond */
# ifndef  SERVER_DEFAULT_THP_IDLE
#  define SERVER_DEFAULT_THP_IDLE  30000
# endif

/* How long (in microseconds) a connection might stay idle between two
 * requests */
#ifndef  SERVER_DEFAULT_CNX_IDLE
# define SERVER_DEFAULT_CNX_IDLE  (5 * G_TIME_SPAN_MINUTE)
#endif

/* How long (in microseconds) a connection might exist since its creation
 * (whatever it is active or not) */
#ifndef  SERVER_DEFAULT_CNX_LIFETIME
# define SERVER_DEFAULT_CNX_LIFETIME  (2 * G_TIME_SPAN_HOUR)
#endif

/* How long (in microseconds) a connection might exist since its creation
 * when it received no request at all */
#ifndef  SERVER_DEFAULT_CNX_INACTIVE
# define SERVER_DEFAULT_CNX_INACTIVE  (30 * G_TIME_SPAN_SECOND)
#endif

# ifndef  OIO_STAT_PREFIX_REQ
#  define OIO_STAT_PREFIX_REQ "counter req.hits"
# endif

# ifndef  OIO_STAT_PREFIX_TIME
#  define OIO_STAT_PREFIX_TIME "counter req.time"
# endif

# define OIO_CFG_PROXY        "proxy"
# define OIO_CFG_PROXYLOCAL   "proxy-local"
# define OIO_CFG_PROXY_CONSCIENCE "proxy-conscience"
# define OIO_CFG_PROXY_DIRECTORY  "proxy-directory"
# define OIO_CFG_PROXY_CONTAINERS "proxy-containers"

# define OIO_CFG_ZOOKEEPER    "zookeeper"
# define OIO_CFG_CONSCIENCE   "conscience"
# define OIO_CFG_ACCOUNTAGENT "event-agent"
# define OIO_CFG_SWIFT        "swift"
# define OIO_CFG_ECD          "ecd"

# define gridcluster_get_zookeeper(ns)  oio_cfg_get_value((ns), OIO_CFG_ZOOKEEPER)
# define gridcluster_get_eventagent(ns) oio_cfg_get_value((ns), OIO_CFG_ACCOUNTAGENT)
# define oio_cfg_get_proxy(ns)          oio_cfg_get_value((ns), OIO_CFG_PROXY)
# define oio_cfg_get_proxylocal(ns)     oio_cfg_get_value((ns), OIO_CFG_PROXYLOCAL)
# define oio_cfg_get_ecd(ns)            oio_cfg_get_value((ns), OIO_CFG_ECD)

/** @return NULL if the NS was not found or the key not defined for the NS */
gchar* oio_cfg_get_value (const gchar *ns, const gchar *what);

/** List all the configuration variables locally set.  */
GHashTable* oio_cfg_parse (void);

/** List all the namespaces locally known */
gchar** oio_cfg_list_ns (void);

/** get the url of the proxy dedicated to the conscience, with a fallback
 * on a proxy capable of everything */
gchar * oio_cfg_get_proxy_conscience (const char *ns);

/** get the url of the proxy dedicated to the directory, with a fallback
 * on a proxy capable of everything */
gchar * oio_cfg_get_proxy_directory (const char *ns);

/** get the url of the proxy dedicated to the containers, with a fallback
 * on a proxy capable of everything */
gchar * oio_cfg_get_proxy_containers (const char *ns);

/** get the url of the swift gateway */
gchar * oio_cfg_get_swift(const char *ns);

#ifdef __cplusplus
}
#endif
#endif /*OIO_SDS__core__config_h*/
