#ifndef __REDCURRANT_metatype_addrinfo__h
#define __REDCURRANT_metatype_addrinfo__h 1
#include <glib/gtypes.h>

/**
 * @defgroup metautils_addrinfo Addrinfo (IP:PORT) features
 * @ingroup metautils_utils
 * @{
 */

/**
 * @param a
 * @param b
 * @return
 */
gboolean addr_info_equal(gconstpointer a, gconstpointer b);


/**
 * @param a
 * @param b
 * @return
 */
gint addr_info_compare(gconstpointer a, gconstpointer b);


/**
 * @param k
 * @return
 */
guint addr_info_hash(gconstpointer k);


/**
 * Opens a non-blocking TCP/IP socket and connects to a remote host
 * identified by the given addr_info_t strucutre.
 *
 * Internally, the function will be mapped to a sockaddr structure used
 * with regular sockets.
 *
 * @param a the.ddress to connect to
 * @param ms the maximum of time spent in network latencies. If this duration
 *           is reached, its is an error.
 * @param err filled with a pointer to an error strucutre if an error occurs
 *
 * @return the opened socket in case of success of -1 in case of error (err
 *         is set)
 */
gint addrinfo_connect_nopoll(const addr_info_t * a, gint ms, GError ** err);

gint addrinfo_connect(const addr_info_t * a, gint ms, GError ** err);


/**
 * convert a service string (as returned by meta1) into an addr_info
 *
 * @param service the service str to convert
 */
addr_info_t * addr_info_from_service_str(const gchar *service);


/**
 * @param p
 */
void addr_info_clean(gpointer p);

/**
 * Simple utility function intented to be used with g_slist_foreach().
 * to free whole lists of addr_info_t.
 *
 * @param d assumed to be a pointer to a addr_info_t*, freed if not NULL
 * @param u ignored
 */
void addr_info_gclean(gpointer d, gpointer u);

/** @} */


#endif // __REDCURRANT_metatype_addrinfo__h
