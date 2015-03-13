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

#ifndef OIO_SDS__metautils__lib__metatype_addrinfo_h
# define OIO_SDS__metautils__lib__metatype_addrinfo_h 1

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

#endif /*OIO_SDS__metautils__lib__metatype_addrinfo_h*/