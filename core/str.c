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

#include <core/oiostr.h>

#include <string.h>
#include <errno.h>

#include <oioext.h>

#include "internals.h"

static guint8 masks[] = {
	0x00, 0x80, 0xC0, 0xE0,
	0xF0, 0xF8, 0xFC, 0xFE,
	0xFF
};

static gchar b2h[][2] =
{
	{'0','0'}, {'0','1'}, {'0','2'}, {'0','3'}, {'0','4'}, {'0','5'}, {'0','6'}, {'0','7'},
	{'0','8'}, {'0','9'}, {'0','A'}, {'0','B'}, {'0','C'}, {'0','D'}, {'0','E'}, {'0','F'},
	{'1','0'}, {'1','1'}, {'1','2'}, {'1','3'}, {'1','4'}, {'1','5'}, {'1','6'}, {'1','7'},
	{'1','8'}, {'1','9'}, {'1','A'}, {'1','B'}, {'1','C'}, {'1','D'}, {'1','E'}, {'1','F'},
	{'2','0'}, {'2','1'}, {'2','2'}, {'2','3'}, {'2','4'}, {'2','5'}, {'2','6'}, {'2','7'},
	{'2','8'}, {'2','9'}, {'2','A'}, {'2','B'}, {'2','C'}, {'2','D'}, {'2','E'}, {'2','F'},
	{'3','0'}, {'3','1'}, {'3','2'}, {'3','3'}, {'3','4'}, {'3','5'}, {'3','6'}, {'3','7'},
	{'3','8'}, {'3','9'}, {'3','A'}, {'3','B'}, {'3','C'}, {'3','D'}, {'3','E'}, {'3','F'},
	{'4','0'}, {'4','1'}, {'4','2'}, {'4','3'}, {'4','4'}, {'4','5'}, {'4','6'}, {'4','7'},
	{'4','8'}, {'4','9'}, {'4','A'}, {'4','B'}, {'4','C'}, {'4','D'}, {'4','E'}, {'4','F'},
	{'5','0'}, {'5','1'}, {'5','2'}, {'5','3'}, {'5','4'}, {'5','5'}, {'5','6'}, {'5','7'},
	{'5','8'}, {'5','9'}, {'5','A'}, {'5','B'}, {'5','C'}, {'5','D'}, {'5','E'}, {'5','F'},
	{'6','0'}, {'6','1'}, {'6','2'}, {'6','3'}, {'6','4'}, {'6','5'}, {'6','6'}, {'6','7'},
	{'6','8'}, {'6','9'}, {'6','A'}, {'6','B'}, {'6','C'}, {'6','D'}, {'6','E'}, {'6','F'},
	{'7','0'}, {'7','1'}, {'7','2'}, {'7','3'}, {'7','4'}, {'7','5'}, {'7','6'}, {'7','7'},
	{'7','8'}, {'7','9'}, {'7','A'}, {'7','B'}, {'7','C'}, {'7','D'}, {'7','E'}, {'7','F'},
	{'8','0'}, {'8','1'}, {'8','2'}, {'8','3'}, {'8','4'}, {'8','5'}, {'8','6'}, {'8','7'},
	{'8','8'}, {'8','9'}, {'8','A'}, {'8','B'}, {'8','C'}, {'8','D'}, {'8','E'}, {'8','F'},
	{'9','0'}, {'9','1'}, {'9','2'}, {'9','3'}, {'9','4'}, {'9','5'}, {'9','6'}, {'9','7'},
	{'9','8'}, {'9','9'}, {'9','A'}, {'9','B'}, {'9','C'}, {'9','D'}, {'9','E'}, {'9','F'},
	{'A','0'}, {'A','1'}, {'A','2'}, {'A','3'}, {'A','4'}, {'A','5'}, {'A','6'}, {'A','7'},
	{'A','8'}, {'A','9'}, {'A','A'}, {'A','B'}, {'A','C'}, {'A','D'}, {'A','E'}, {'A','F'},
	{'B','0'}, {'B','1'}, {'B','2'}, {'B','3'}, {'B','4'}, {'B','5'}, {'B','6'}, {'B','7'},
	{'B','8'}, {'B','9'}, {'B','A'}, {'B','B'}, {'B','C'}, {'B','D'}, {'B','E'}, {'B','F'},
	{'C','0'}, {'C','1'}, {'C','2'}, {'C','3'}, {'C','4'}, {'C','5'}, {'C','6'}, {'C','7'},
	{'C','8'}, {'C','9'}, {'C','A'}, {'C','B'}, {'C','C'}, {'C','D'}, {'C','E'}, {'C','F'},
	{'D','0'}, {'D','1'}, {'D','2'}, {'D','3'}, {'D','4'}, {'D','5'}, {'D','6'}, {'D','7'},
	{'D','8'}, {'D','9'}, {'D','A'}, {'D','B'}, {'D','C'}, {'D','D'}, {'D','E'}, {'D','F'},
	{'E','0'}, {'E','1'}, {'E','2'}, {'E','3'}, {'E','4'}, {'E','5'}, {'E','6'}, {'E','7'},
	{'E','8'}, {'E','9'}, {'E','A'}, {'E','B'}, {'E','C'}, {'E','D'}, {'E','E'}, {'E','F'},
	{'F','0'}, {'F','1'}, {'F','2'}, {'F','3'}, {'F','4'}, {'F','5'}, {'F','6'}, {'F','7'},
	{'F','8'}, {'F','9'}, {'F','A'}, {'F','B'}, {'F','C'}, {'F','D'}, {'F','E'}, {'F','F'}
};

static gchar hexa[] =
{
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

static const gchar json_basic_translations[] =
{
	  0,   0,   0,   0,   0,   0,   0,   0,
	'b', 't', 'n',   0, 'f', 'r',   0,   0,
};

void oio_str_reuse(gchar **dst, gchar *src) {
	oio_pfree(dst, src);
}

void oio_str_clean(gchar **s) {
	oio_pfree(s, NULL);
}

void oio_str_replace(gchar **dst, const gchar *src) {
	if (src)
		oio_str_reuse(dst, g_strdup(src));
	else
		oio_str_reuse(dst, NULL);
}

gboolean oio_str_ishexa(const char *s, gsize slen) {
	if (!slen || (slen%2))
		return FALSE;
	for (; *s && slen > 0 ;++s,--slen) {
		if (!g_ascii_isxdigit(*s))
			return FALSE;
	}
	return !*s && !slen;
}

gboolean oio_str_ishexa1(const char *s) {
	gsize len = 0;
	for (; *s ;++s) {
		if (!g_ascii_isxdigit(*s))
			return FALSE;
		len ++;
	}
	return len > 0 && (len%2) == 0;
}

gboolean oio_str_is_printable(const char *s, gsize slen) {
	gsize len = 0;
	for (; len < slen && *s; ++s, ++len) {
		if (!g_ascii_isprint(*s))
			return FALSE;
	}
	return TRUE;
}

gboolean oio_str_hex2bin(const char *s0, guint8 *d, gsize dlen) {
	const guint8 *s = (const guint8*) s0;
	if (!s || !d)
		return FALSE;

	gsize sS = strlen(s0);
	if (sS > dlen * 2)
		return FALSE;

	while ((dlen--) > 0) {
		if (!*s) return TRUE;
		if (!*(s+1)) return FALSE;
		register const int i0 = hexa[*(s++)];
		register const int i1 = hexa[*(s++)];
		if (i0<0 || i1<0) return FALSE;
		*(d++) = (i0 & 0x0F) << 4 | (i1 & 0x0F);
	}

	return TRUE;
}

gboolean oio_str_parse_bool(const gchar *value, gboolean def) {
	static const gchar *array_yes[] = {
		"yes", "true", "on", "enable", "enabled", "1", "yeah", NULL
	};
	static const gchar *array_no[] = {
		"no", "false", "off", "disable", "disabled", "0", "nope", NULL
	};

	if (!value)
		return def;

	for (const gchar **s=array_yes; *s ;s++) {
		if (!g_ascii_strcasecmp(value, *s))
			return TRUE;
	}

	for (const gchar **s=array_no; *s ;s++) {
		if (!g_ascii_strcasecmp(value, *s))
			return FALSE;
	}

	return def;
}

gsize oio_str_bin2hex(const void *s, size_t sS, char *d, size_t dS) {
	gsize i, j;

	if (!d || !dS)
		return 0;
	*d = 0;
	if (!s || !sS)
		return 0;

	#pragma GCC diagnostic push
	#pragma GCC diagnostic ignored "-Wunsafe-loop-optimizations"
	for (i = j = 0; i < sS && j < (dS - 1); ) {
		register const gchar *h = b2h[((guint8*)s)[i++]];
		d[j++] = h[0];
		d[j++] = h[1];
	}
	#pragma GCC diagnostic pop

	d[(j < dS ? j : dS - 1)] = 0;
	return j;
}

void oio_str_hash_name(guint8 *p,
		const char *ns UNUSED, const char *account, const char *user) {
	EXTRA_ASSERT (oio_str_is_set(account));
	EXTRA_ASSERT (oio_str_is_set(user));

	guint8 zero = 0;
	GChecksum *sum = g_checksum_new(G_CHECKSUM_SHA256);

	g_checksum_update(sum, (guint8*)account, strlen(account));
	g_checksum_update(sum, &zero, 1);
	g_checksum_update(sum, (guint8*)user, strlen(user));

	gsize s = 32;
	memset(p, 0, 32);
	g_checksum_get_digest(sum, p, &s);
	g_checksum_free(sum);
}

void oio_buf_randomize(guint8 *buf, gsize buflen) {
	union {
		guint32 r32;
		guint8 r8[4];
	} raw;

	if (NULL == buf || 0 == buflen)
		return;

	// Fill 4 by 4
	GRand *r = oio_ext_local_prng ();
	gsize mod32 = buflen % 4;
	gsize max32 = buflen / 4;
	for (register gsize i32=0; i32 < max32 ; ++i32) {
		raw.r32 = g_rand_int(r);
		((guint32*)buf)[i32] = raw.r32;
	}

	// Finish with the potentially remaining unset bytes
	raw.r32 = g_rand_int(r);
	switch (mod32) {
		case 3:
			buf[ (max32*4) + 2 ] = raw.r8[2];
			// FALLTHROUGH
		case 2:
			buf[ (max32*4) + 1 ] = raw.r8[1];
			// FALLTHROUGH
		case 1:
			buf[ (max32*4) + 0 ] = raw.r8[0];
	}
}

void oio_str_randomize (gchar *d, const gsize dlen, const char *set) {
	size_t len = strlen (set);
	GRand *r = oio_ext_local_prng ();
	for (gsize i=0; i<dlen ;i++)
		d[i] = set [g_rand_int_range (r, 0, len)];
	d[dlen-1] = '\0';
}

const char * oio_str_autocontainer (const char *src, guint size,
		char *dst, guint bits) {
	guint8 bin[64];
	gsize len = sizeof(bin);

	g_assert (src != NULL);
	g_assert (dst != NULL);
	if (size == 0)
		size = strlen(src);

	GChecksum *checksum = g_checksum_new (G_CHECKSUM_SHA256);
	g_checksum_update (checksum, (guint8*)src, size);
	g_checksum_get_digest (checksum, bin, &len);
	g_checksum_free (checksum);

	return oio_buf_prefix (bin, len, dst, bits);
}

const char * oio_buf_prefix (const guint8 *bin, guint len,
		char *dst, guint bits) {
	g_assert (bin != NULL);
	g_assert (len > 0);
	g_assert (dst != NULL);

	if (!bits || bits >= len*8)
		return NULL;

	const guint div = bits / 8;
	const guint mod = bits % 8;
	const guint last = mod ? div+1 : div;
	if (last > len)
		return NULL;

	gchar *p = dst;
	for (guint i=0; i<div ;i++) {
		const char *s = b2h[ bin[i] ];
		*(p++) = s[0];
		*(p++) = s[1];
	}
	if (mod) {
		register guint8 x = bin[last-1] & masks[mod];
		const char *s = b2h[x];
		*(p++) = s[0];
		if (mod > 4)
			*(p++) = s[1];
	}
	*p = '\0';

	return dst;
}

gchar **oio_strv_append(gchar **tab, gchar *s) {
	EXTRA_ASSERT (tab != NULL);
	EXTRA_ASSERT (s != NULL);
	gsize l = g_strv_length (tab);
	tab = g_try_realloc (tab, (l+2) * sizeof(gchar*));
	tab[l] = s;
	tab[l+1] = NULL;
	return tab;
}

size_t oio_strv_length_total (const char * const *v) {
	register gsize total = 0;
	for (; *v; v++)
		total += 1+strlen(*v);
	return total;
}

void oio_str_upper(register gchar *s) {
	if (!s) return;
	for (; *s ;++s)
		*s = g_ascii_toupper(*s);
}

void oio_str_lower(register gchar *s) {
	for (; *s ;++s)
		*s = g_ascii_tolower(*s);
}

void oio_str_gstring_append_json_blob(GString *base, const char *s0, int len) {
	for (const char *s = s0; (len < 0 && *s) || (s - s0) < len ;) {
		if (*s & (const char)0x80) {  // (part of a) unicode character
			gunichar c = g_utf8_get_char_validated(s, -1);
			if (c == (gunichar)-1) {
				// something wrong happened, let the client deal with it
				g_string_append_c(base, *(s++));
			} else if (c == (gunichar)-2) {
				// middle of a unicode character
				char *end = g_utf8_next_char(s);
				while (s < end && *s)
					g_string_append_c(base, *(s++));
			} else {
				g_string_append_unichar(base, c);
				s = g_utf8_next_char(s);
			}
		} else if (*s < ' ') {  // control character
			g_string_append_c(base, '\\');
			switch (*s) {
			case '\b':
			case '\t':
			case '\n':
			case '\f':
			case '\r':
				g_string_append_c(base, json_basic_translations[(int)*(s++)]);
				break;
			default:
				g_string_append_printf(base, "u%04x", *(s++));
				break;
			}
		} else {  // printable ASCII character
			switch (*s) {
			case '"':
			case '\\':
			case '/':
				g_string_append_c(base, '\\');
				/* FALLTHROUGH */
			default:
				g_string_append_c(base, *(s++));
				break;
			}
		}
	}
}

void oio_str_gstring_append_json_string (GString *base, const char *s) {
	return oio_str_gstring_append_json_blob(base, s, -1);
}

void oio_str_gstring_append_json_quote (GString *base, const char *s) {
	g_string_append_c (base, '"');
	oio_str_gstring_append_json_string(base, s);
	g_string_append_c (base, '"');
}

void oio_str_gstring_append_json_pair (GString *base,
		const char *k, const char *v) {
	oio_str_gstring_append_json_quote(base, k);
	g_string_append_c (base, ':');
	if (v == NULL) {
		g_string_append_static(base, "null");
	} else {
		oio_str_gstring_append_json_quote(base, v);
	}
}

void oio_str_gstring_append_json_pair_int (GString *base,
		const char *k, gint64 v) {
	oio_str_gstring_append_json_quote(base, k);
	g_string_append_c (base, ':');
	g_string_append_printf(base, "%"G_GINT64_FORMAT, v);
}

void oio_str_gstring_append_json_pair_boolean (GString *base,
		const char *k, gboolean v) {
	oio_str_gstring_append_json_quote(base, k);
	g_string_append_c (base, ':');
	if (v) {
		g_string_append_static(base, "true");
	} else {
		g_string_append_static(base, "false");
	}
}

size_t oio_constptrv_length (const void * const *v) {
	size_t count = 0;
	if (v) while (*(v++)) { ++count; }
	return count;
}

size_t oio_strv_length (const char * const *v) {
	return oio_ptrv_length (v);
}

int oio_str_prefixed (const char *s, const char *p, const char *sep) {
	if (!oio_str_is_set(s) || !g_str_has_prefix (s, p))
		return FALSE;
	s += strlen(p);
	return !*s || g_str_has_prefix (s, sep);
}

int oio_str_caseprefixed(const char *str, const char *prefix) {
	const char *s = str, *p = prefix;
	for (; *s && *p ;++s,++p) {
		if (g_ascii_tolower (*s) != g_ascii_tolower (*p))
			return FALSE;
	}
	return !*p;
}

gboolean oio_str_is_number (const char *s, gint64 *pi64) {
	if (!oio_str_is_set(s))
		return FALSE;
	gchar *end = NULL;
	errno = 0;
	gint64 mcs = g_ascii_strtoll(s, &end, 10);
	if (errno == ERANGE || (mcs == 0 && errno == EINVAL))
		return FALSE;
	if (!end || *end != '\0')
		return FALSE;
	if (pi64)
		*pi64 = mcs;
	return TRUE;
}

int oio_str_cmp3 (const void *a, const void *b, void *i UNUSED) {
	return g_strcmp0 (a,b);
}


GError* JSON_parse_buffer (const guint8 *b, gsize l, struct json_object **o) {
	EXTRA_ASSERT(o != NULL);

	if (!b || !l) {
		*o = NULL;
		return NULL;
	}

	GError *err = NULL;
	json_object *jbody = NULL;
	json_tokener *parser = json_tokener_new();

	jbody = json_tokener_parse_ex(parser, (char *) b, l);
	if (json_tokener_success != json_tokener_get_error(parser))
		err = BADREQ("Invalid JSON");
	json_tokener_free(parser);
	if (err) {
		if (jbody)
			json_object_put(jbody);
		*o = NULL;
		return err;
	}

	*o = jbody;
	return NULL;
}

GError* JSON_parse_gba (GByteArray *gba, struct json_object **out) {
	EXTRA_ASSERT(out != NULL);
	if (!gba || !gba->data || !gba->len) {
	   *out = NULL;
	   return NULL;
	}
	return JSON_parse_buffer(gba->data, gba->len, out);
}


GString *STRV_encode_gstr(gchar **tab) {
	if (!tab)
		return g_string_new("");
	if (!*tab)
		return g_string_new("[]");
	GString *gs = g_string_new("[");
	gboolean first = TRUE;
	for (gchar **p = tab; *p ;++p) {
		if (!first)
			g_string_append_c(gs, ',');
		first = FALSE;
		oio_str_gstring_append_json_quote(gs, *p);
	}
	g_string_append_c(gs, ']');
	return gs;
}

GByteArray *STRV_encode_gba(gchar **kv) {
	GString *gs = STRV_encode_gstr(kv);
	return g_bytes_unref_to_array(g_string_free_to_bytes(gs));
}

GError * STRV_decode_object (struct json_object *jobj, gchar ***out) {
	EXTRA_ASSERT(out != NULL);

	if (!jobj || json_object_is_type(jobj, json_type_null)) {
		*out = g_malloc0(sizeof(gchar*));
		return NULL;
	}
	if (!json_object_is_type(jobj, json_type_array))
		return BADREQ("json: not a valid array");

	GError *err = NULL;
	GPtrArray *v = g_ptr_array_new ();
	for (int i=0, max=json_object_array_length(jobj); !err && i<max ;++i) {
		struct json_object *item = json_object_array_get_idx(jobj, i);
		if (!json_object_is_type (item, json_type_string)) {
			err = BADREQ ("Invalid string at %d", i);
		} else {
			g_ptr_array_add(v, g_strdup(json_object_get_string(item)));
		}
	}

	if (err) {
		g_ptr_array_set_free_func(v, g_free);
		g_ptr_array_free(v, TRUE);
		*out = NULL;
		return err;
	}

	g_ptr_array_add (v, NULL);
	*out = (gchar**) g_ptr_array_free (v, FALSE);
	return NULL;
}

GError * STRV_decode_buffer (guint8 *buf, gsize len, gchar ***out) {
	g_assert_nonnull(out);
	if (!buf || !len) {
		*out = g_malloc0(sizeof(gchar*));
		return NULL;
	}
	json_object *jbody = NULL;
	GError *err = JSON_parse_buffer(buf, len, &jbody);
	if (err)
		return err;

	err = STRV_decode_object(jbody, out);
	json_object_put(jbody);
	return err;
}

void KV_encode_gstr2(GString *out, gchar **kv) {
	gboolean first = TRUE;
	if (!kv) {
		g_string_append_static(out, "null");
		return;
	}
	g_string_append_c(out, '{');
	for (gchar **p = kv; *p && *(p + 1); p += 2) {
		if (!first)
			g_string_append_c(out, ',');
		first = FALSE;
		oio_str_gstring_append_json_pair(out, *p, *(p + 1));
	}
	g_string_append_c(out, '}');
}

GString *KV_encode_gstr(gchar **kv) {
	if (!kv)
		return g_string_new("");
	if (!*kv)
		return g_string_new("{}");
	GString *gs = g_string_sized_new(128);
	KV_encode_gstr2(gs, kv);
	return gs;
}

GByteArray *KV_encode_gba(gchar **kv) {
	GString *gs = KV_encode_gstr(kv);
	return g_bytes_unref_to_array(g_string_free_to_bytes(gs));
}

GError * KV_decode_buffer(guint8 *buf, gsize len, gchar ***out) {
	EXTRA_ASSERT(out != NULL);
	if (!buf || !len) {
		*out = g_malloc0(sizeof(gchar*));
		return NULL;
	}

	json_object *jbody = NULL;
	GError *err = JSON_parse_buffer(buf, len, &jbody);
	if (err)
		return err;

	err = KV_decode_object(jbody, out);
	json_object_put(jbody);
	return err;
}

GError * KV_decode_object(struct json_object *jobj, gchar ***out) {
	EXTRA_ASSERT(out != NULL);
	if (!jobj || json_object_is_type(jobj, json_type_null)) {
		*out = g_malloc0(sizeof(gchar*));
		return NULL;
	}
	if (!json_object_is_type(jobj, json_type_object))
		return BADREQ("json: not a valid KV object");

	GError *err = NULL;
	GPtrArray *v = g_ptr_array_new ();
	json_object_object_foreach (jobj, key, val) {
		if (!json_object_is_type (val, json_type_string)) {
			err = BADREQ ("Invalid property '%s'", key);
			break;
		} else {
			g_ptr_array_add(v, g_strdup(key));
			g_ptr_array_add(v, g_strdup(json_object_get_string(val)));
		}
	}

	if (err) {
		g_ptr_array_set_free_func(v, g_free);
		g_ptr_array_free(v, TRUE);
		*out = NULL;
		return err;
	}

	g_ptr_array_add (v, NULL);
	*out = (gchar**) g_ptr_array_free (v, FALSE);
	return NULL;
}

gchar ** KV_extract_prefixed (gchar **kv, const char *prefix) {

	/* only possible output: empty array */
	if (!kv || !*kv || !*(kv+1))
		return g_malloc0(sizeof(gchar*));

	/* no prefix: keep all the items */
	if (!oio_str_is_set(prefix)) {
		gsize len = g_strv_length(kv);
		return g_memdup(kv, (len+1) * sizeof(gchar*));
	}

	gsize prefix_len = strlen(prefix);
	GPtrArray *tmp = g_ptr_array_new();
	for (gchar **p=kv; *p && *(p+1) ;p+=2) {
		if (g_str_has_prefix(*p, prefix)) {
			g_ptr_array_add(tmp, (*p) + prefix_len);
			g_ptr_array_add(tmp, *(p+1));
		}
	}
	g_ptr_array_add(tmp, NULL);
	return (gchar**) g_ptr_array_free(tmp, FALSE);
}

gchar ** KV_extract_not_prefixed (gchar **kv, const char *prefix) {

	/* only possible output: empty array */
	if (!kv || !*kv || !*(kv+1))
		return g_malloc0(sizeof(gchar*));

	/* no prefix: keep all the items */
	if (!oio_str_is_set(prefix)) {
		gsize len = g_strv_length(kv);
		return g_memdup(kv, (len+1) * sizeof(gchar*));
	}

	GPtrArray *tmp = g_ptr_array_new();
	for (gchar **p=kv; *p && *(p+1) ;p+=2) {
		if (!g_str_has_prefix(*p, prefix)) {
			g_ptr_array_add(tmp, *p);
			g_ptr_array_add(tmp, *(p+1));
		}
	}
	g_ptr_array_add(tmp, NULL);
	return (gchar**) g_ptr_array_free(tmp, FALSE);
}

void oio_str_cleanv(gchar ***p) {
	if (unlikely(p == NULL))
		return;
	if (*p) {
		g_strfreev(*p);
		*p = NULL;
	}
}

