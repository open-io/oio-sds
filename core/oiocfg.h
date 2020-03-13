/*
OpenIO SDS core library
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

# ifndef PROXYD_HEADER_FORCE_MASTER
#  define PROXYD_HEADER_FORCE_MASTER PROXYD_HEADER_PREFIX "force-master"
# endif

# ifndef PROXYD_HEADER_UPGRADE_TO_TLS
#  define PROXYD_HEADER_UPGRADE_TO_TLS PROXYD_HEADER_PREFIX "upgrade-to-tls"
# endif

# ifndef PROXYD_HEADER_TIMEOUT
#  define PROXYD_HEADER_TIMEOUT PROXYD_HEADER_PREFIX "timeout"
# endif

# ifndef PROXYD_HEADER_NOEMPTY
#  define PROXYD_HEADER_NOEMPTY PROXYD_HEADER_PREFIX "no-empty-list"
# endif

# ifndef PROXYD_HEADER_PERFDATA
#  define PROXYD_HEADER_PERFDATA PROXYD_HEADER_PREFIX "perfdata"
# endif

# ifndef PROXYD_HEADER_FORCE_VERSIONING
#  define PROXYD_HEADER_FORCE_VERSIONING PROXYD_HEADER_PREFIX "force-versioning"
# endif

# ifndef PROXYD_HEADER_SIMULATE_VERSIONING
#  define PROXYD_HEADER_SIMULATE_VERSIONING PROXYD_HEADER_PREFIX "simulate-versioning"
# endif

/* in oio_ext_monotonic_time() precision */
# ifndef PROXYD_DEFAULT_TTL_SERVICES
#  define PROXYD_DEFAULT_TTL_SERVICES G_TIME_SPAN_HOUR
# endif

# ifndef GCLUSTER_RUN_DIR
#  define GCLUSTER_RUN_DIR "/var/run"
# endif

# ifndef GCLUSTER_AGENT_SOCK_PATH
#  define GCLUSTER_AGENT_SOCK_PATH GCLUSTER_RUN_DIR "/oio-sds-agent.sock"
# endif

# ifndef RAWX_HEADER_PREFIX
#  define RAWX_HEADER_PREFIX "X-oio-chunk-meta-"
# endif

# ifndef RAWX_HEADER_OIO_VERSION
#  define RAWX_HEADER_OIO_VERSION RAWX_HEADER_PREFIX "oio-version"
# endif

# ifndef RAWX_HEADER_CHUNK_ID
#  define RAWX_HEADER_CHUNK_ID RAWX_HEADER_PREFIX "chunk-id"
# endif

# ifndef RAWX_HEADER_CHUNK_HASH
#  define RAWX_HEADER_CHUNK_HASH RAWX_HEADER_PREFIX "chunk-hash"
# endif

# ifndef RAWX_HEADER_CHUNKS_NB
#  define RAWX_HEADER_CHUNKS_NB RAWX_HEADER_PREFIX "chunks-nb"
# endif

# ifndef RAWX_HEADER_CHUNK_POS
#  define RAWX_HEADER_CHUNK_POS RAWX_HEADER_PREFIX "chunk-pos"
# endif

# ifndef RAWX_HEADER_CHUNK_SIZE
#  define RAWX_HEADER_CHUNK_SIZE RAWX_HEADER_PREFIX "chunk-size"
# endif

# ifndef RAWX_HEADER_CONTENT_CHUNK_METHOD
#  define RAWX_HEADER_CONTENT_CHUNK_METHOD RAWX_HEADER_PREFIX "content-chunk-method"
# endif

# ifndef RAWX_HEADER_CONTENT_ID
#  define RAWX_HEADER_CONTENT_ID RAWX_HEADER_PREFIX "content-id"
# endif

# ifndef RAWX_HEADER_CONTENT_MIMETYPE
#  define RAWX_HEADER_CONTENT_MIMETYPE RAWX_HEADER_PREFIX "content-mime-type"
# endif

# ifndef RAWX_HEADER_CONTENT_PATH
#  define RAWX_HEADER_CONTENT_PATH RAWX_HEADER_PREFIX "content-path"
# endif

# ifndef RAWX_HEADER_CONTENT_POLICY
#  define RAWX_HEADER_CONTENT_POLICY RAWX_HEADER_PREFIX "content-storage-policy"
# endif

# ifndef RAWX_HEADER_CONTENT_VERSION
#  define RAWX_HEADER_CONTENT_VERSION RAWX_HEADER_PREFIX "content-version"
# endif

# ifndef RAWX_HEADER_CONTAINER_ID
#  define RAWX_HEADER_CONTAINER_ID RAWX_HEADER_PREFIX "container-id"
# endif

# ifndef RAWX_HEADER_CHECKHASH
#  define RAWX_HEADER_CHECKHASH "X-oio-check-hash"
# endif

# ifndef RAWX_HEADER_FULLATTR
#  define RAWX_HEADER_FULLATTR "X-oio-xattr"
# endif

# ifndef RAWX_HEADER_FULLPATH
#  define RAWX_HEADER_FULLPATH RAWX_HEADER_PREFIX "full-path"
# endif

# ifndef  OIO_STAT_PREFIX_REQ
#  define OIO_STAT_PREFIX_REQ "counter req.hits"
# endif

# ifndef  OIO_STAT_PREFIX_TIME
#  define OIO_STAT_PREFIX_TIME "counter req.time"
# endif

# ifndef  OIO_CHUNK_SYSMETA_PREFIX
#  define OIO_CHUNK_SYSMETA_PREFIX "__OIO_CHUNK__"
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

# define USER_AGENT_HEADER "user-agent"

# define EVENT_FIELD_REQUEST_ID "request_id"
# define EVENT_FIELD_ORIGIN     "origin"

# define oio_cfg_get_eventagent(ns)     oio_cfg_get_value((ns), OIO_CFG_ACCOUNTAGENT)
# define oio_cfg_get_proxy(ns)          oio_cfg_get_value((ns), OIO_CFG_PROXY)
# define oio_cfg_get_proxylocal(ns)     oio_cfg_get_value((ns), OIO_CFG_PROXYLOCAL)
# define oio_cfg_get_ecd(ns)            oio_cfg_get_value((ns), OIO_CFG_ECD)

/** @return NULL if the NS was not found or the key not defined for the NS */
gchar* oio_cfg_get_value (const gchar *ns, const gchar *what);

/** Return the parsed boolean of the value at key ns/what. If not set or not
 * successfully parsed, def is returned. */
gboolean oio_cfg_get_bool (const char *ns, const char *what, gboolean def);

/** List all the configuration variables locally set. This loads the system
 * configuration and it overrides that configuration with any variable found
 * in the local files. */
GHashTable* oio_cfg_parse (void);

/** List all the connfiguration variables in the given file */
GHashTable* oio_cfg_parse_file (const char *path);

/** List all the namespaces locally known. Never returns NULL. */
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

/* -------------------------------------------------------------------------- */

struct oio_cfg_handle_s;

struct oio_cfg_handle_vtable_s
{
	void (*clean) (struct oio_cfg_handle_s *self);
	gchar** (*namespaces) (struct oio_cfg_handle_s *self);
	gchar* (*get) (struct oio_cfg_handle_s *self, const char *ns, const char *k);
};

struct oio_cfg_handle_abstract_s
{
	struct oio_cfg_handle_vtable_s *vtable;
};

gchar *oio_cfg_build_key(const gchar *ns, const gchar *what);

/* wraps self->clean() */
void oio_cfg_handle_clean (struct oio_cfg_handle_s *self);

/* wraps self->namespaces() */
gchar ** oio_cfg_handle_namespaces (struct oio_cfg_handle_s *self);

/* wraps self->get(ns, k) */
gchar * oio_cfg_handle_get (struct oio_cfg_handle_s *self,
		const char *ns, const char *k);

/* wraps self->get(...) and check for the presence of the given NS
 * in the config */
gboolean oio_cfg_handle_has_ns(struct oio_cfg_handle_s *self, const char *ns);

/* Replaces the default handle to manage configuration by yourself. */
void oio_cfg_set_handle (struct oio_cfg_handle_s *self);

/* Create a cache handle that does caching. */
struct oio_cfg_handle_s * oio_cfg_cache_create(void);

/* Create a caching configuration that just hold the value found in the file
 * whose path has been given. */
struct oio_cfg_handle_s * oio_cfg_cache_create_fragment(const char *path);

#ifdef __cplusplus
}
#endif
#endif /*OIO_SDS__core__config_h*/
