/*
OpenIO SDS core library
Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage

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

#ifndef OIO_SDS__core__internals_h
# define OIO_SDS__core__internals_h 1

#ifdef __cplusplus
extern "C" {
#endif

# ifdef HAVE_EXTRA_ASSERT
#  define EXTRA_ASSERT(X) g_assert(X)
# else
#  define EXTRA_ASSERT(X)
# endif

#define OLDEST(now,delay) (((now)>(delay)) ? ((now)-(delay)) : 0)

#define UNUSED __attribute__ ((unused))

#define ON_ENUM(P,E) case P##E: return #E

#define CODE_IS_NETWORK_ERROR(C) ((C) < CODE_TEMPORARY)
#define CODE_IS_OK(C)            (((C) >= CODE_FINAL_OK) && ((C) < CODE_BEACON_REDIRECT))
#define CODE_IS_TEMP(C)          (((C) >= CODE_TEMPORARY) && ((C) < CODE_FINAL_OK))
#define CODE_IS_FINAL(C)         ((C) == CODE_FINAL_OK || (!CODE_IS_OK(C) && !CODE_IS_TEMP(C)))
#define CODE_IS_REDIRECT(C) (((C) > CODE_BEACON_REDIRECT) && ((C) < CODE_BEACON_ERROR))

#define CODE_IS_NOTFOUND(C) ((C)==CODE_CONTAINER_NOTFOUND \
		|| (C)==CODE_SRV_NOLINK \
		|| (C)==CODE_USER_NOTFOUND \
		|| (C)==CODE_ACCOUNT_NOTFOUND \
		|| (C)==CODE_CONTENT_NOTFOUND)

#define CODE_IS_NSIMPOSSIBLE(C) ((C)==CODE_POLICY_NOT_SATISFIABLE \
		|| (C)==CODE_POLICY_NOT_SUPPORTED \
		|| (C)==CODE_NAMESPACE_NOTMANAGED)

#define VTABLE_HAS(self,T,F) (((T)self)->vtable-> F != NULL)

#define VTABLE_CHECK(self,T,F) do { \
	g_assert(self != NULL); \
	g_assert(((T)self)->vtable != NULL); \
	g_assert(((T)self)->vtable-> F != NULL); \
} while (0)

#define VTABLE_CALL(self,T,F) \
	VTABLE_CHECK(self,T,F); \
	return ((T)self)->vtable-> F

#define ADAPTIVE_PERIOD_DECLARE() \
	static volatile gboolean already_succeeded = FALSE; \
	static volatile guint tick_reload = 0; \
	static volatile guint period_reload = 1

#define ADAPTIVE_PERIOD_SKIP() \
	(already_succeeded && 0 != (tick_reload++ % period_reload))

#define ADAPTIVE_PERIOD_ONSUCCESS(P) \
	already_succeeded = TRUE; \
	period_reload ++; \
	period_reload = CLAMP(period_reload,2,(P)); \
	tick_reload = 1

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
	CODE_SRV_ALREADY = 455,
	CODE_CONTAINER_PROP_NOTFOUND = 460,
	CODE_CONTENT_PROP_NOTFOUND = 461,
	CODE_WRONG_PROP_PREFIX = 462,
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
	HTTP_CODE_SRV_UNAVAILABLE    = 503,
	HTTP_CODE_GATEWAY_TIMEOUT    = 504,
};

typedef gint64 (*time_hook_f) (void);

/* Must the service addresses be shuffled or not when uploading chunks */
extern volatile int oio_sds_no_shuffle;

/* Must the service addresses be shuffled or not (out from the directory) */
extern volatile int oio_dir_no_shuffle;

/* Let/Set it to NULL for the system time.
 * Microsecond precision */
extern time_hook_f oio_time_monotonic;

/* Let/Set it to NULL for the system real time.
 * Microsecond precision */
extern time_hook_f oio_time_real;

/* -------------------------------------------------------------------------- */

# ifndef GQ
#  define GQ() g_quark_from_static_string(G_LOG_DOMAIN)
# endif

# ifdef HAVE_BACKTRACE
#  define NEWERROR(CODE, FMT, ...) oio_error_debug(GQ(), (CODE), FMT, ##__VA_ARGS__)
GError * oio_error_debug (GQuark gq, int code, const char *fmt, ...);
# else
#  define NEWERROR(CODE, FMT,...) g_error_new(GQ(), (CODE), FMT, ##__VA_ARGS__)
# endif

#define NYI()           NEWERROR(CODE_NOT_IMPLEMENTED, "NYI")
#define BADREQ(FMT,...) NEWERROR(CODE_BAD_REQUEST, FMT, ##__VA_ARGS__)
#define BADNS()         NEWERROR(CODE_NAMESPACE_NOTMANAGED, "Unexpected NS")
#define BUSY(FMT,...)   NEWERROR(CODE_UNAVAILABLE, FMT, ##__VA_ARGS__)
#define BADSRVTYPE()    NEWERROR(CODE_SRVTYPE_NOTMANAGED, "Unexpected service type")
#define SYSERR(FMT,...) NEWERROR(CODE_INTERNAL_ERROR, FMT, ##__VA_ARGS__)

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

/* wraps self->clean() */
void oio_cfg_handle_clean (struct oio_cfg_handle_s *self);

/* wraps self->namespaces() */
gchar ** oio_cfg_handle_namespaces (struct oio_cfg_handle_s *self);

/* wraps self->get(ns, k) */
gchar * oio_cfg_handle_get (struct oio_cfg_handle_s *self,
		const char *ns, const char *k);

/* Replaces the default handle to manage configuration by yourself. */
void oio_cfg_set_handle (struct oio_cfg_handle_s *self);

#ifdef __cplusplus
}
#endif
#endif /*OIO_SDS__core__internals_h*/
