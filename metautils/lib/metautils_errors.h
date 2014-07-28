#ifndef __REDCURRANT__metautils_errors__h
# define __REDCURRANT__metautils_errors__h 1

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
# define ERRCODE_PARAM 1
# define ERRCODE_CONN_REFUSED 2
# define ERRCODE_CONN_RESET 3
# define ERRCODE_CONN_CLOSED 4
# define ERRCODE_CONN_TIMEOUT 5
# define ERRCODE_CONN_NOROUTE 6
# define ERRCODE_CONN_NOTCONNECTED 7

# define GSETCODE(e,C,FMT,...) g_error_trace (e, G_LOG_DOMAIN, (C), __LINE__, __FUNCTION__, __FILE__, FMT, ##__VA_ARGS__)
# define GSETERROR(e,FMT,...)  g_error_trace (e, G_LOG_DOMAIN, 0,   __LINE__, __FUNCTION__, __FILE__, FMT, ##__VA_ARGS__)
# define GSETMARK(e) g_error_prefix_place(e, __FILE__, __FUNCTION__, __LINE__);
# define GSETRAW(e,CODE,MSG)  g_error_trace (e, G_LOG_DOMAIN, CODE, 0,0,0 , MSG)

#define GQ() g_quark_from_static_string(G_LOG_DOMAIN)
#define NEWERROR(CODE, FMT,...) g_error_new(GQ(), (CODE), FMT, ##__VA_ARGS__)

#define CODE_NETWORK_ERROR        1

#define CODE_FINAL_OK             200
#define CODE_IS_OK(C)            ((C)/100 == 2)
#define CODE_IS_FINAL(C)         ((C) == CODE_FINAL_OK || !CODE_IS_OK(C))

/* MASTER/SLAVE codes */
#define CODE_BADOPFORSLAVE        301
#define CODE_REDIRECT             303
#define CODE_LOOP_REDIRECT        304
#define CODE_TOOMANY_REDIRECT     305

#define CODE_BAD_REQUEST          400

/* ACL codes */
#define CODE_NOT_ALLOWED          403

#define CODE_NOT_FOUND            404
#define CODE_NAMESPACE_NOTMANAGED 418

/* Content-related codes */
#define CODE_CONTENT_NOTFOUND     420
#define CODE_CONTENT_EXISTS       421
#define CODE_CONTENT_ONLINE       422
#define CODE_CONTENT_UNCOMPLETE   423
#define CODE_CONTENT_PRECONDITION 424
#define CODE_CONTENT_CORRUPTED    425

/* Container-related codes */
#define CODE_CONTAINER_MIGRATED  430
#define CODE_CONTAINER_NOTFOUND  431
#define CODE_CONTAINER_CLOSED    432
#define CODE_CONTAINER_EXISTS    433
#define CODE_CONTAINER_LOCKED    434
#define CODE_CONTAINER_INUSE     435
#define CODE_CONTAINER_FROZEN    436
#define CODE_CONTAINER_DISABLED  437
#define CODE_CONTAINER_NOTEMPTY  438

/* Quotas-level codes */
#define CODE_CONTAINER_FULL 445
#define CODE_NAMESPACE_FULL 446

/* Meta1 prefixes codes */
#define CODE_RANGE_NOTFOUND  450	/**< refresh meta2 */
#define CODE_RANGE_MIGRATING 451	/**< the request cannot be satisfied on this
									   META1 due to a migration. the body
									   might contain a list of addresses */
#define CODE_RANGE_EXISTS    452

/* Properties codes */
#define CODE_CONTAINER_PROP_NOTFOUND    460
#define CODE_CONTENT_PROP_NOTFOUND      461
#define CODE_WRONG_PROP_PREFIX          462
#define CODE_EMPTY_CONTAINER_EVENT_LIST 463

/* Snapshot-related codes */
#define CODE_SNAPSHOT_NOTFOUND    465
#define CODE_SNAPSHOT_EXISTS      466

/* Resynchronisation codes */
#define CODE_PIPETO    470 /**< Local copy more recent, send a dump */
#define CODE_PIPEFROM  471 /**< Local copy out of date, restore it */
#define CODE_CONCURRENT 472 /**< Concurrent diff, both sides have changed */

#define CODE_POLICY_NOT_SUPPORTED 480 /**< Wrong storage policy specified */
#define CODE_POLICY_NOT_SATISFIABLE 481 /**< No enough service or service not enough spaced */

/* Internals */
#define CODE_INTERNAL_ERROR  500 /* internal error: memory allocation... */
#define CODE_NOT_IMPLEMENTED 501
#define CODE_UNAVAILABLE     503

/*Platform */
#define CODE_PLATFORM_ERROR 600 /* platform error ; all services unavailable */

/**
 * Sets the error structure pointed by the first argument, keeping trace of the
 * previous content of this structure.
 * 
 * @param e
 * @param dom
 * @param code
 * @param fmt
 * @param ...
 */
void g_error_trace(GError ** e, const char *dom, int code,
		int line, const char *func, const char *file,
		const char *fmt, ...);

void g_error_transmit(GError **err, GError *e);

/**
 * @param e
 * @param file
 * @param func
 * @param line
 */
void g_error_prefix_place(GError **e, const gchar *file, const gchar *func,
	int line);


/**
 * @param err
 * @return
 */
gint gerror_get_code(GError * err);


/**
 * @param err
 * @return
 */
const gchar *gerror_get_message(GError * err);

#endif // __REDCURRANT__metautils_errors__h
