/*
OpenIO SDS core library
Copyright (C) 2014 Worldline, as part of Redcurrant
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

#ifndef OIO_SDS__sdk__http_put_h
# define OIO_SDS__sdk__http_put_h 1

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>

struct http_put_s;

/* Create a new http put request. Specifying <content_length> and <soft_length>
 * both equal to -1 means a pure streamed upload. */
struct http_put_s * http_put_create (gint64 content_length,
		gint64 soft_length);

struct http_put_s *http_put_create_with_ec(gint64 content_length,
		gint64 soft_length, int handle, int k, int m, GChecksum * chk);

int http_put_ec_get_fragment_size(int ec_handle);

/* Add a new destination where to send data.
 * @param p http request handle
 * @param url destination url
 * @param k whatever the caller want but two dests must not have the same
 *          user data pointer
 * @return handle on this destination
 * @note k is used as id to obtain information about the request so
 *       all destinations must have different k.
 */
struct http_put_dest_s *http_put_add_dest(struct http_put_s *p,
		const char *url, gpointer k);

/* Add a header for this destination. */
void http_put_dest_add_header(struct http_put_dest_s *dest, const char *key,
		const char *fmt, ...) __attribute__ ((format (printf, 3, 4)));

void http_put_feed (struct http_put_s *p, GBytes *b);

GError * http_put_step (struct http_put_s *p);

gboolean http_put_done (struct http_put_s *p);

gint64 http_put_expected_bytes (struct http_put_s *p);

/* Get the number of failed requests. */
guint http_put_get_failure_number(struct http_put_s *p);

/* Compute the md5 of the whole buffer so it must be called after run function.
 * @param p http put handle
 * @param buffer will be filled with the hash
 * @param size buffer size (must be the same as md5 size)
 */
void http_put_get_md5(struct http_put_s *p, guint8 *buffer, gsize size);

/* Get response header for destination represented its user_data.
 * @param p http put handle
 * @param k data pointer used to add a destination
 * @param header header key
 * @return value corresponding to this header or NULL if k or
 * header not found
 * @note the return value must not be freed by caller, it will be free
 * during http_put_destroy.
 */
const char *http_put_get_header(struct http_put_s *p, gpointer k, const char *header);

/* Get http code for destination represented its user_data.
 * @param p http put handle
 * @param k data pointer used to add a destination
 * @return valid http code or 0 if request failed (connection failed...)
 */
guint http_put_get_http_code(struct http_put_s *p, gpointer k);

/* Free http_put and all destinations
 * @param p http_put to free
 */
void http_put_destroy(struct http_put_s *p);

#ifdef __cplusplus
}
#endif
#endif /*OIO_SDS__sdk__http_put_h*/
