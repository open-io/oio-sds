/*
OpenIO SDS core library
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

#ifndef OIO_SDS__core__oiostr_h
# define OIO_SDS__core__oiostr_h 1
# include <glib.h>
# include <json-c/json.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OIO_CSV_SEP_C  ','
#define OIO_CSV_SEP    ","
#define OIO_CSV_SEP2_C ';'
#define OIO_CSV_SEP2   ";"

#define oio_pfree0(pp,repl) do { if (*pp) g_free(*pp); *(pp) = (repl); } while (0)

#define oio_pfree(pp,repl) do { \
	if (NULL != (pp)) \
		oio_pfree0(pp,repl); \
} while (0)

#define OIO_STRV_APPEND_COPY(Tab,S0) do { (Tab) = oio_strv_append((Tab), g_strdup(S0)); } while (0)

#define g_string_append_static(out,Static) \
	g_string_append_len(out, Static, sizeof(Static)-1) \

/* Count the items in the array */
size_t oio_strv_length (const char * const *v);

/* Count the size of the concatenation of all the strings in <v> */
size_t oio_strv_length_total (const char * const *v);

size_t oio_constptrv_length (const void * const *v);

#define oio_ptrv_length(v) oio_constptrv_length((const void * const *)(v))

void oio_str_reuse(gchar **dst, gchar *src);

/* Reallocs <dst> and appends it <s>. <s> is reused and is not duplicated */
gchar ** oio_strv_append(gchar **dst, gchar *s);

/** frees *s and set it to NULL */
void oio_str_clean(gchar **s);

/** g_strfreev *p and set it to NULL */
void oio_str_cleanv(gchar ***p);

/** frees *dst and set it to src */
void oio_str_replace(gchar **dst, const char *src);

/** Returns FALSE if 's' is not 'slen' long and contains a non-hexa character. */
gboolean oio_str_ishexa(const char *s, gsize slen);

/** Returns TRUE if 's' contains only printable ascii characters. */
gboolean oio_str_is_printable(const char *s, gsize slen);

/** Returns is 's' is an even number of hexadecimal characters */
gboolean oio_str_ishexa1(const char *s);

/** Convert an hexa string to its binary form */
gboolean oio_str_hex2bin(const char * src, guint8* dst, gsize dlen);

/** Convert a string into a boolean */
gboolean oio_str_parse_bool(const gchar *value, gboolean def);

/** Fills d (which size is dS) with the hexadecimal alpha-numerical
 * representation of the content of s (which size is sS) */
gsize oio_str_bin2hex(const void *s, size_t sS, char *d, size_t dS);

/** Computes the "unique ID" of the given user. That ID is used for sharding
 * in the directory. */
void oio_str_hash_name(guint8 *d, const char *ns, const char *account, const char *user);

/** Fills 'd' with 'dlen' random characters */
void oio_str_randomize(gchar *d, const gsize dlen, const char *set);

/** Fills 'b' with 'blen' random bytes */
void oio_buf_randomize(guint8 *b, gsize blen);

/** Fills 'dst' with the name of the container deduced from the given 'src'
 * which is 'srclen' bytes long. If 'srclen' is 0, then src is expected to be
 * NULL-terminated and its strlen() is considered.
 * 'dst' must be at least '(bits-1)/4 + 2' bytes long, to hold the hexadecimal
 * form of the 'bits' first bits of the hash of 'src'.
 * Because a SHA256 checksum is used, the hash will always be 32 bytes longs,
 * and any hexadecimal prefix won't ever use more than 65 bytes including the
 * final NULL character. */
const char * oio_str_autocontainer (const char *src, guint srclen,
		char *dst, guint bits);

/** Get the hexadecimal form of the 'bits' first bits of the input
 * 'src' buffer of size 'len'. The 'dst' buffer is used to store the result
 * and a pointer to 'dst' is returned upon success. */
const char * oio_buf_prefix (const guint8 *src, guint len,
		char *dst, guint bits);

/** In place transform the input 's' string in its uppercase form */
void oio_str_upper(register gchar *s);

/** In place transform the input 's' string in its lowercase form */
void oio_str_lower(register gchar *s);

/* appends to 'base' the JSON acceptable version of 's', i.e. 's' with its
 * double quotes escaped and other characters are valid UTF-8 */
void oio_str_gstring_append_json_string (GString *base, const char *s);

/* calls oio_str_gstring_append_json_string() surrounded with double quotes */
void oio_str_gstring_append_json_quote (GString *base, const char *s);

/* appends to 'base' the JSON acceptable version of 's'. If 'len' is less
 * than zero, stop at the first null-character. */
void oio_str_gstring_append_json_blob(GString *base, const char *s, int len);

/* appends "<k>":"<v>" where k and v are added with
 * oio_str_gstring_append_json_string() */
void oio_str_gstring_append_json_pair (GString *base,
		const char *k, const char *v);

/* TODO add a macro version of oio_str_gstring_append_json_pair() taking a
 * static string as the key, to avoid computing its length for trusted keys,
 * as for oio_url, ns_info, etc. */

void oio_str_gstring_append_json_pair_int (GString *base,
		const char *k, gint64 v);

void oio_str_gstring_append_json_pair_boolean (GString *base,
		const char *k, gboolean v);

#define OIO_JSON_append_bool(g,k,v) do { \
	g_string_append_static(g, "\"" k "\":"); \
	if (v) \
		g_string_append_static(g, "true"); \
	else \
		g_string_append_static(g, "false"); \
} while (0)

#define OIO_JSON_append_int(g,k,v) do { \
	g_string_append_static(g, "\"" k "\":"); \
	g_string_append_printf(g, "%" G_GINT64_FORMAT, (gint64)v); \
} while (0)

#define OIO_JSON_append_gstr(g,k,v) do { \
	if (v) { \
		g_string_append_static(g, "\"" k "\":\""); \
		oio_str_gstring_append_json_blob(g, v->str, v->len); \
		g_string_append_c(g, '"'); \
	} else { \
		g_string_append_static(g, "\"" k "\":null"); \
	} \
} while (0)

#define OIO_JSON_append_blob(g,k,S,L) do { \
	if (S != NULL) { \
		g_string_append_static(g, "\"" k "\":\""); \
		oio_str_gstring_append_json_blob(g, S, L); \
		g_string_append_c(g, '"'); \
	} else { \
		g_string_append_static(g, "\"" k "\":null"); \
	} \
} while (0)

#define OIO_JSON_append_str(g,k,S) do { \
	if (S != NULL) { \
		g_string_append_static(g, "\"" k "\":"); \
		oio_str_gstring_append_json_quote(g, S); \
	} else { \
		g_string_append_static(g, "\"" k "\":null"); \
	} \
} while (0)

#define OIO_JSON_append_gba(g,k,gba) do { \
	if (gba != NULL) { \
		g_string_append_static(g, "\"" k "\":\""); \
		metautils_gba_to_hexgstr(g, gba); \
		g_string_append_c(g, '"'); \
	} else { \
		g_string_append_static(g, "\"" k "\":null"); \
	} \
} while (0)


static inline int oio_str_is_set (const char *s) { return NULL!=s && 0!=*s; }

int oio_str_prefixed (const char *s, const char *p, const char *sep);

int oio_str_caseprefixed(const char *str, const char *prefix);

/* pi64 is left untouched if the overall return is FALSE */
gboolean oio_str_is_number (const char *s, gint64 *pi64);

int oio_str_cmp3 (const void *a, const void *b, void *ignored);

/* Light wrappers around json-c, to return GLib errors */
GError* JSON_parse_buffer (const guint8 *b, gsize l, struct json_object **o);
GError* JSON_parse_gba (GByteArray *gba, struct json_object **o);

/* JSON codec for arrays of strings */
GString * STRV_encode_gstr(gchar **tab);
GByteArray * STRV_encode_gba(gchar **tab);
GError * STRV_decode_object (struct json_object *j, gchar ***out);
GError * STRV_decode_buffer (guint8 *buf, gsize len, gchar ***out);

/* JSON codec for <string> to <string> maps */
GString * KV_encode_gstr(gchar **kv);
void KV_encode_gstr2(GString *out, gchar **kv);
GByteArray * KV_encode_gba(gchar **kv);
GError * KV_decode_object(struct json_object *j, gchar ***out);
GError * KV_decode_buffer(guint8 *buf, gsize len, gchar ***out);

/* Returns a valid KV where all the keys have the given prefix.
 * WARNING the array returned holds pointers to the same buffer than the
 * input, so DO NOT FREE each string but just the holder array.
 * Example:
 *   KV_extract_prefixed({"a.b", "v0", "b.c", "v1", NULL}, "a.")
 *    -> {"b", "v0", NULL}
 */
gchar ** KV_extract_prefixed (gchar **kv, const char *prefix);

/* @see KV_extract_prefixed(), with the keys left untouched */
gchar ** KV_extract_not_prefixed (gchar **kv, const char *prefix);


#ifdef __cplusplus
}
#endif
#endif /*OIO_SDS__core__oiostr_h*/
