/**
 * @file resolv.h
 */

#ifndef GRID__RESOLV__H
# define GRID__RESOLV__H 1
# include <glib.h>

struct sockaddr;
struct addr_info_s;

/**
 * @defgroup metautils_resolv Address resolution features
 * @ingroup metautils_utils
 * @{
 */


/**
 * @param s
 * @param dst
 * @param dst_size
 */
gssize grid_sockaddr_to_string(const struct sockaddr *s, gchar *dst,
		gsize dst_size);


/**
 * @param a
 * @param dst
 * @param dst_size
 */
gsize grid_addrinfo_to_string(const struct addr_info_s *a, gchar *dst,
		gsize dst_size);


/**
 * @param src
 * @param end
 * @param a
 * @return
 */
gboolean grid_string_to_addrinfo(const gchar *src, const gchar *end,
		struct addr_info_s *a);


/**
 * @param src
 * @param end
 * @param s
 * @param slen
 * @return
 */
gboolean grid_string_to_sockaddr(const gchar *src, const gchar *end,
		struct sockaddr *s, gsize *slen);


#define addr_info_to_string(ai,dst,dstsize) grid_addrinfo_to_string(ai,dst,dstsize)


/**
 * @param ai
 * @param dst
 * @param dstsize
 * @param port
 * @param error
 * @return
 */
gboolean addr_info_get_addr(const struct addr_info_s * ai, gchar * dst,
		gsize dstsize, guint16* port);


/**
 * Map the struct addr_info_s structure in the corresponding sockaddr structure.
 *
 * The pointed sockaddr structure will be altered in place and must be
 * large enough to store at least one IPv6 address. We recommand to use a
 * struct sockaddr_storage address (see the POSIX-2001 norm).
 *
 * @see addrinfo_from_sockaddr()
 * @param ai a not-NULL pointer to a valid struct addr_info_s structure
 * @param sa the sockaddr to be filled with the given struct addr_info_s address
 * @param saSize the size of the sockaddr address
 *
 * @return 1 if the mapping succeeded, 0 in case of error
 */
gint addrinfo_to_sockaddr(const struct addr_info_s * ai, struct sockaddr *sa,
		gsize * saSize);


/**
 * Map the given sockaddr structure in the given struct addr_info_s structure.
 *
 * @see addrinfo_to_sockaddr()
 * @param ai the strucutre to be filled
 * @param sa the source sockaddr
 * @param saSize the size of the source sockaddr
 *
 * @return 1 if the mapping succeeded, 0 in case of error
 */
gint addrinfo_from_sockaddr(struct addr_info_s * ai, struct sockaddr *sa,
		gsize saSize);


/**
 * Splits the given IP/PORT couple assuming the following formats:
 * - [MAYBE-AGREGATED-IPv6]:PORT
 * - DOTTED-NUMERICAL-IPv4:PORT
 */
gboolean l4_address_split(const gchar * url, gchar ** host, gchar ** port);


/**
 * Inits the given address with the given texual representation (as accepted by l4_address_split()).
 * @param dst
 * @param url
 * @param err
 * @return
 */
gboolean l4_address_init_with_url(struct addr_info_s * dst, const gchar * url,
		GError ** err);


/**
 *	Build a new filled struct addr_info_s struct
 *
 *	@param ip the addr in string format
 *	@param port the port
 *	@param err
 *	@return a new struct addr_info_s pointer which must be freed with g_free()
 */
struct addr_info_s *build_addr_info(const gchar * ip, int port, GError ** err);

gboolean metautils_addr_valid_for_connect(const struct addr_info_s *a);

gboolean metautils_url_valid_for_connect(const gchar *url);

/** @} */

#endif /* GRID__RESOLV__H */
