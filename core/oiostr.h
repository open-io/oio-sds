/*
OpenIO SDS oio core 
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

#ifndef OIO_SDS__core__oiostr_h
# define OIO_SDS__core__oiostr_h 1
# include <glib.h>

#define oio_pfree0(pp,repl) do { \
	if (NULL != *(pp)) \
		g_free(*pp); \
	*(pp) = (repl); \
} while (0)

#define oio_pfree(pp,repl) do { \
	if (NULL != (pp)) \
		oio_pfree0(pp,repl); \
} while (0)

void oio_str_reuse(gchar **dst, gchar *src);

/** frees *s and set it to NULL */
void oio_str_clean(gchar **s);

/** frees *dst and set it to src */
void oio_str_replace(gchar **dst, const char *src);

/** Returns FALSE if 's' is not 'slen' long and contains a non-hexa character. */
gboolean oio_str_ishexa(const char *s, gsize slen);

/** Returns is 's' is an even number of hexadecimal characters */
gboolean oio_str_ishexa1(const char *s);

/** Convert an hexa string to its binary form */
gboolean oio_str_hex2bin(const char * src, guint8* dst, gsize dlen);

/** Fills d (which size is dS) with the hexadecimal alpha-numerical
 * representation of the content of s (which size is sS) */
gsize oio_str_bin2hex(const void *s, size_t sS, char *d, size_t dS);

/** Computes the "unique ID" of the given user. That ID is used for sharding
 * in the directory. */
void oio_str_hash_name(guint8 *d, const char *ns, const char *account, const char *user);

/** Fills 'buf' with buflen random bytes */
void oio_str_randomize(guint8 *b, gsize blen);

struct oio_str_autocontainer_config_s {
	gsize src_offset;
	gsize src_size;
	gsize dst_bits;
};

/** Fills 'dst' with the name of the container deduced from the given 'path'.
 * 'dst' must be at least 65 characters long. */
const char * oio_str_autocontainer (const char *path, gchar *dst,
		const struct oio_str_autocontainer_config_s *cfg);

#endif /*OIO_SDS__core__oiostr_h*/
