/*
OpenIO SDS rawx-apache2
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef OIO_SDS__rawx_apache2__src__rawx_internals_h
# define OIO_SDS__rawx_apache2__src__rawx_internals_h 1

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>

#include <apr.h>
#include <apr_strings.h>
#include <apr_shm.h>
#include <apr_global_mutex.h>
#include <mod_dav.h>

#include <rawx-lib/src/rawx.h>
#include "mod_dav_rawx.h"
#include "rawx_config.h"

#if MODULE_MAGIC_COOKIE == 0x41503234UL /* "AP24" */
# define __ap_log_rerror(L,S,R,FMT,...) ap_log_rerror(__FILE__, __LINE__, 0, (L), (S), (R), FMT, ##__VA_ARGS__)
# define __ap_log_perror(L,S,P,FMT,...) ap_log_perror(__FILE__, __LINE__, 0, (L), (S), (P), FMT, ##__VA_ARGS__)
# define __dav_new_error(P,S,E,FMT,...) dav_new_error((P), (S), (E), 0, FMT, ##__VA_ARGS__)
#else
# define __ap_log_rerror(L,S,R,FMT,...) ap_log_rerror(__FILE__, __LINE__, (L), (S), (R), FMT, ##__VA_ARGS__)
# define __ap_log_perror(L,S,P,FMT,...) ap_log_perror(__FILE__, __LINE__, (L), (S), (P), FMT, ##__VA_ARGS__)
# define __dav_new_error(P,S,E,FMT,...) dav_new_error((P), (S), (E), FMT, ##__VA_ARGS__)
#endif

#if 0
# define DAV_DEBUG_REQ(R,STATUS,FMT,...)       __ap_log_rerror(APLOG_NOTICE, (STATUS), (R),  "%d "FMT, getpid(), ##__VA_ARGS__)
# define DAV_DEBUG_POOL(POOL,STATUS,FMT,...)   __ap_log_perror(APLOG_NOTICE, (STATUS), POOL, "%d "FMT, getpid(), ##__VA_ARGS__)
# define DAV_DEBUG_RES(R,STATUS,FMT,...)       DAV_DEBUG_REQ((R)->info->request, (STATUS), FMT, ##__VA_ARGS__)
#else
# define DAV_DEBUG_REQ(R,STATUS,FMT,...)       __ap_log_rerror(APLOG_DEBUG, (STATUS), (R),  FMT, ##__VA_ARGS__)
# define DAV_DEBUG_POOL(POOL,STATUS,FMT,...)   __ap_log_perror(APLOG_DEBUG, (STATUS), POOL, FMT, ##__VA_ARGS__)
# define DAV_DEBUG_RES(R,STATUS,FMT,...)       DAV_DEBUG_REQ((R)->info->request, (STATUS), FMT, ##__VA_ARGS__)
#endif

#ifdef HAVE_EXTRA_DEBUG
# define DAV_XDEBUG_REQ(R,STATUS,FMT,...)       DAV_DEBUG_REQ(R,STATUS,FMT,##__VA_ARGS__)
# define DAV_XDEBUG_POOL(POOL,STATUS,FMT,...)   DAV_DEBUG_POOL(POOL,STATUS,FMT,##__VA_ARGS__)
# define DAV_XDEBUG_RES(R,STATUS,FMT,...)       DAV_DEBUG_RES(R,STATUS,FMT,##__VA_ARGS__)
#else
# define DAV_XDEBUG_REQ(R,STATUS,FMT,...)
# define DAV_XDEBUG_POOL(POOL,STATUS,FMT,...)
# define DAV_XDEBUG_RES(R,STATUS,FMT,...)
#endif

#define DAV_ERROR_RES(R,STATUS,FMT,...)     DAV_ERROR_REQ((R)->info->request, (STATUS), FMT, ##__VA_ARGS__)
#define DAV_ERROR_REQ(R,STATUS,FMT,...)     __ap_log_rerror(APLOG_ERR, (STATUS), (R),  FMT, ##__VA_ARGS__)
#define DAV_ERROR_POOL(POOL,STATUS,FMT,...) __ap_log_perror(APLOG_ERR, (STATUS), POOL, FMT, ##__VA_ARGS__)

#define HEADER_SCHEME_V1 0x00000001
#define HEADER_SCHEME_V2 0x00000002

#define NS_COMPRESSION_ON "on"
#define NS_COMPRESSION_OFF "off"
#define DEFAULT_STREAM_BUFF_SIZE 512000

#define DAV_ERROR_RES(R,STATUS,FMT,...) DAV_ERROR_REQ((R)->info->request, (STATUS), FMT, ##__VA_ARGS__)
#define DAV_DEBUG_RES(R,STATUS,FMT,...) DAV_DEBUG_REQ((R)->info->request, (STATUS), FMT, ##__VA_ARGS__)

/*
 ** Does this platform support an executable flag?
 **
 ** ### need a way to portably abstract this query
 */
#ifndef WIN32
#define DAV_FS_HAS_EXECUTABLE
#endif

/*
 ** The single property that we define (in the DAV_FS_URI_MYPROPS namespace)
 */
#define DAV_PROPID_FS_executable        1

/* returns an appropriate HTTP status code given an APR status code for a
 * failed I/O operation.  ### use something besides 500? */
#define MAP_IO2HTTP(e) (APR_STATUS_IS_ENOSPC(e) ? HTTP_INSUFFICIENT_STORAGE : \
		HTTP_INTERNAL_SERVER_ERROR)

#define SHM_HANDLE_KEY "rawx_shm_master_handle"

dav_rawx_server_conf * resource_get_server_config(const dav_resource *resource);

apr_pool_t * resource_get_pool(const dav_resource *resource);

const char * resource_get_pathname(const dav_resource *resource);


dav_rawx_server_conf * request_get_server_config(const request_rec *r);

apr_uint64_t request_get_duration(const request_rec *req);


void str_replace_by_pooled_str(apr_pool_t *pool, char ** pstr);

# define REPLACE_FIELD(P,S,W) str_replace_by_pooled_str((P), &(ctx-> S . W ))

void dav_format_time(int style, apr_time_t sec, char *buf);

void send_chunk_event(const char *type, const dav_resource *resource);

#endif /*OIO_SDS__rawx_apache2__src__rawx_internals_h*/
