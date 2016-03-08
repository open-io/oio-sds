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
#  define OIO_DEFAULT_CHUNKMETHOD "bytes"
# endif

# ifndef OIO_DEFAULT_MIMETYPE
#  define OIO_DEFAULT_MIMETYPE "application/octet-stream"
# endif

# ifndef PROXYD_PREFIX
#  define PROXYD_PREFIX "v3.0"
# endif

# ifndef PROXYD_HEADER_PREFIX
#  define PROXYD_HEADER_PREFIX "X-oio-"
# endif

# ifndef PROXYD_HEADER_MODE
#  define PROXYD_HEADER_MODE PROXYD_HEADER_PREFIX "action-mode"
# endif

# ifndef PROXYD_HEADER_REQID
#  define PROXYD_HEADER_REQID PROXYD_HEADER_PREFIX "req-id"
# endif

# ifndef PROXYD_HEADER_NOEMPTY
#  define PROXYD_HEADER_NOEMPTY PROXYD_HEADER_PREFIX "no-empty-list"
# endif

/* in bytes */
# ifndef PROXYD_PATH_MAXLEN
#  define PROXYD_PATH_MAXLEN 2048
# endif

# ifndef PROXYD_DEFAULT_TTL_SERVICES
#  define PROXYD_DEFAULT_TTL_SERVICES 3600
# endif

# ifndef PROXYD_DEFAULT_MAX_SERVICES
#  define PROXYD_DEFAULT_MAX_SERVICES 200000
# endif

# ifndef PROXYD_DEFAULT_TTL_CSM0
#  define PROXYD_DEFAULT_TTL_CSM0 0
# endif

# ifndef PROXYD_DEFAULT_MAX_CSM0
#  define PROXYD_DEFAULT_MAX_CSM0 0
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
# ifndef PROXYD_TTL_DEAD_LOCAL_SERVICES
#  define PROXYD_TTL_DEAD_LOCAL_SERVICES 30
# endif

/* in seconds */
# ifndef PROXYD_TTL_DOWN_SERVICES
#  define PROXYD_TTL_DOWN_SERVICES 5
# endif

# ifndef PROXYD_DEFAULT_PERIOD_DOWNSTREAM
#  define PROXYD_DEFAULT_PERIOD_DOWNSTREAM 10 /*s*/
# endif

# ifndef PROXYD_DEFAULT_PERIOD_UPSTREAM
#  define PROXYD_DEFAULT_PERIOD_UPSTREAM 1 /*s*/
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

# ifndef COMMON_CLIENT_TIMEOUT
#  define COMMON_CLIENT_TIMEOUT 30.0
# endif

# ifndef SQLX_CLIENT_TIMEOUT
#  define SQLX_CLIENT_TIMEOUT 30.0
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

# ifndef M0V2_CLIENT_TIMEOUT
#  define M0V2_CLIENT_TIMEOUT 10.0
# endif

# ifndef CS_CLIENT_TIMEOUT
#  define CS_CLIENT_TIMEOUT 3.0
# endif

# ifndef RAWX_BUF_MIN
#  define RAWX_BUF_MIN 8192
# endif

# ifndef RAWX_BUF_MAX
#  define RAWX_BUF_MAX 1048576
# endif

# ifndef RAWX_LOSTFOUND_FOLDER
#  define RAWX_LOSTFOUND_FOLDER "_lost+found"
# endif

# ifndef RAWX_HEADER_PREFIX
#  define RAWX_HEADER_PREFIX "X-oio-chunk-meta-"
# endif

# ifndef OIO_EVTQ_MAXPENDING
#  define OIO_EVTQ_MAXPENDING 1000
# endif

# define OIO_CFG_PROXY        "proxy"
# define OIO_CFG_PROXYLOCAL   "proxy-local"
# define OIO_CFG_PROXY_CONSCIENCE "proxy-conscience"
# define OIO_CFG_PROXY_DIRECTORY  "proxy-directory"
# define OIO_CFG_PROXY_CONTAINERS "proxy-containers"

# define oio_cfg_get_proxy(ns)        oio_cfg_get_value((ns), OIO_CFG_PROXY)
# define oio_cfg_get_proxylocal(ns)   oio_cfg_get_value((ns), OIO_CFG_PROXYLOCAL)

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

#ifdef __cplusplus
}
#endif
#endif /*OIO_SDS__core__config_h*/
