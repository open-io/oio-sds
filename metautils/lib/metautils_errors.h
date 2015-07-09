/*
OpenIO SDS metautils
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

#ifndef OIO_SDS__metautils__lib__metautils_errors_h
# define OIO_SDS__metautils__lib__metautils_errors_h 1

#include <glib.h>

/**
 * @param timer
 */
#define START_TIMER(timer) g_timer_start(timer)

/**
 * @param timer
 * @param action_str
 */
#define STOP_TIMER(timer, action_str) do { \
	g_timer_stop(timer);\
	DEBUG_DOMAIN("timer", "Action [%s] in thread[%p] took %f sec", action_str, g_thread_self(), g_timer_elapsed(timer, NULL)); \
} while (0)

/**
 * @defgroup metautils_errors GError features
 * @ingroup metautils_utils
 * @{
 */

/* Some well known codes used by read functions */

# define GSETCODE(e,C,FMT,...) g_error_trace (e, G_LOG_DOMAIN, (C), __LINE__, __FUNCTION__, __FILE__, FMT, ##__VA_ARGS__)

# define GSETERROR(e,FMT,...)  g_error_trace (e, G_LOG_DOMAIN, 0,   __LINE__, __FUNCTION__, __FILE__, FMT, ##__VA_ARGS__)
# define GSETRAW(e,CODE,MSG)  g_error_trace (e, G_LOG_DOMAIN, CODE, 0,0,0 , "%s", MSG)

#define GQ() g_quark_from_static_string(G_LOG_DOMAIN)
#define NEWERROR(CODE, FMT,...) g_error_new(GQ(), (CODE), FMT, ##__VA_ARGS__)

#define CODE_IS_NETWORK_ERROR(C) ((C) < CODE_TEMPORARY)
#define CODE_IS_OK(C)            (((C) >= CODE_FINAL_OK) && ((C) < CODE_BEACON_REDIRECT))
#define CODE_IS_TEMP(C)          (((C) >= CODE_TEMPORARY) && ((C) < CODE_FINAL_OK))
#define CODE_IS_FINAL(C)         ((C) == CODE_FINAL_OK || (!CODE_IS_OK(C) && !CODE_IS_TEMP(C)))
#define CODE_IS_REDIRECT(C) (((C) > CODE_BEACON_REDIRECT) && ((C) < CODE_BEACON_ERROR))

#define CODE_IS_NOTFOUND(C) ((C)==CODE_CONTAINER_NOTFOUND \
		|| (C)==CODE_USER_NOTFOUND \
		|| (C)==CODE_ACCOUNT_NOTFOUND \
		|| (C)==CODE_CONTENT_NOTFOUND)

enum {
	ERRCODE_UNKNOWN_ERROR = 0,
	ERRCODE_PARAM = 1,
	ERRCODE_CONN_REFUSED = 2,
	ERRCODE_CONN_RESET = 3,
	ERRCODE_CONN_CLOSED = 4,
	ERRCODE_CONN_TIMEOUT = 5,
	ERRCODE_CONN_NOROUTE = 6,
	ERRCODE_CONN_NOTCONNECTED = 7,
	ERRCODE_READ_TIMEOUT = 8,
	CODE_NETWORK_ERROR = 9,

	CODE_TEMPORARY = 100, // XXX beacon, network errors below

	CODE_FINAL_OK = 200, // XXX beacon, denote the first success code
	CODE_PART_CONTENT = 201,
	CODE_PART_ADMIN = 202,
	CODE_PART_PROPS = 203,
	CODE_PROGRESS = 204,
	CODE_PARTIAL_CONTENT = 206,

	CODE_BEACON_REDIRECT = 300, // XXX

	CODE_BADOPFORSLAVE = 301,
	CODE_REDIRECT = 303,
	CODE_LOOP_REDIRECT = 304,
	CODE_TOOMANY_REDIRECT = 305,

	CODE_BEACON_ERROR = 399, // XXX

	CODE_BAD_REQUEST = 400,
	CODE_NOT_ALLOWED = 403,
	CODE_NOT_FOUND = 404,

	/*  */
	CODE_SERVICE_NOTFOUND,

	/*  */
	CODE_USER_NOTFOUND,
	CODE_USER_INUSE,
	CODE_USER_EXISTS,

	CODE_ACCOUNT_NOTFOUND,

	CODE_NAMESPACE_NOTMANAGED = 418,

	CODE_CONTENT_NOTFOUND = 420,
	CODE_CONTENT_EXISTS = 421,
	CODE_CONTENT_ONLINE = 422,
	CODE_CONTENT_UNCOMPLETE = 423,
	CODE_CONTENT_PRECONDITION = 424,
	CODE_CONTENT_CORRUPTED = 425,
	CODE_CONTENT_DELETED = 426,
	CODE_CONTAINER_MIGRATED = 430,
	CODE_CONTAINER_NOTFOUND = 431,
	CODE_CONTAINER_CLOSED = 432,
	CODE_CONTAINER_EXISTS = 433,
	CODE_CONTAINER_LOCKED = 434,
	CODE_CONTAINER_INUSE = 435,
	CODE_CONTAINER_FROZEN = 436,
	CODE_CONTAINER_DISABLED = 437,
	CODE_CONTAINER_NOTEMPTY = 438,
	CODE_CONTAINER_ENABLED = 439,
	CODE_CONTAINER_FULL = 445,
	CODE_NAMESPACE_FULL = 446,
	CODE_RANGE_NOTFOUND = 450,
	CODE_SRVTYPE_NOTMANAGED = 453,
	CODE_SRV_NOLINK = 454,
	CODE_CONTAINER_PROP_NOTFOUND = 460,
	CODE_CONTENT_PROP_NOTFOUND = 461,
	CODE_WRONG_PROP_PREFIX = 462,
	CODE_EMPTY_CONTAINER_EVENT_LIST = 463,
	CODE_SNAPSHOT_NOTFOUND = 465,
	CODE_SNAPSHOT_EXISTS = 466,
	CODE_PIPETO = 470,
	CODE_PIPEFROM = 471,
	CODE_CONCURRENT = 472,
	CODE_POLICY_NOT_SUPPORTED = 480,
	CODE_POLICY_NOT_SATISFIABLE = 481,

	CODE_INTERNAL_ERROR = 500,
	CODE_NOT_IMPLEMENTED = 501,
	CODE_PROXY_ERROR = 502, // unknown error when contacting an other service
	CODE_UNAVAILABLE = 503,
	CODE_CONFIG_ERROR = 510, // appeared in POLIX

	CODE_PLATFORM_ERROR = 600,
};

enum {
	HTTP_CODE_OK                 = 200,
	HTTP_CODE_CREATED            = 201,
	HTTP_CODE_ACCEPTED           = 202,
	HTTP_CODE_NO_CONTENT         = 204,
	HTTP_CODE_BAD_REQUEST        = 400,
	HTTP_CODE_FORBIDDEN          = 403,
	HTTP_CODE_NOT_FOUND          = 404,
	HTTP_CODE_METHOD_NOT_ALLOWED = 405,
	HTTP_CODE_CONFLICT           = 409,
	HTTP_CODE_INTERNAL_ERROR     = 500,
	HTTP_CODE_NOT_IMPLEMENTED    = 501,
	HTTP_CODE_BAD_GATEWAY        = 502,
};

/** Sets the error structure pointed by the first argument, keeping trace of the
 * previous content of this structure. */
void g_error_trace(GError ** e, const char *dom, int code,
		int line, const char *func, const char *file,
		const char *fmt, ...) __attribute__ ((format (printf, 7, 8)));

void g_error_transmit(GError **err, GError *e);

/** Returns the internal error code of <err> or 0 if <err> is NULL */
gint gerror_get_code(GError * err);

/** Returns the internal error message of <err> or NULL if <err> is NULL */
const gchar *gerror_get_message(GError * err);

#endif /*OIO_SDS__metautils__lib__metautils_errors_h*/
