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

#ifndef PROXYD_PREFIX
#define PROXYD_PREFIX "v3.0"
#endif

#ifndef PROXYD_HEADER_PREFIX
#define PROXYD_HEADER_PREFIX "X-oio-"
#endif

#ifndef PROXYD_HEADER_MODE
# define PROXYD_HEADER_MODE PROXYD_HEADER_PREFIX "action-mode"
#endif

#ifndef PROXYD_HEADER_REQID
#define PROXYD_HEADER_REQID PROXYD_HEADER_PREFIX "req-id"
#endif

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
