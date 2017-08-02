/*
OpenIO SDS metautils
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

#include <string.h>
#include <stdarg.h>

#include "metautils.h"

hashstr_t*
hashstr_create(const gchar *s)
{
	if (unlikely(NULL == s))
		return NULL;

	struct hash_len_s hl = djb_hash_str(s);
	hashstr_t *result = g_malloc0(HASHSTR_PREFIX + hl.l + 1);

	result->hl = hl;
	memcpy(result->s0, s, hl.l);
	return result;
}

hashstr_t*
hashstr_create_len(const gchar *s, gsize l)
{
	if (unlikely(NULL == s))
		return NULL;

	guint32 h = djb_hash_buf((guint8 *) s, l);
	hashstr_t *result = g_malloc0(HASHSTR_PREFIX + l + 1);

	result->hl.h = h;
	result->hl.l = l;
	memcpy(result->s0, s, l);
	return result;
}

hashstr_t*
hashstr_create_from_gstring(GString *gstr)
{
	return hashstr_create_len(gstr->str, gstr->len);
}

hashstr_t *
hashstr_printf(const gchar *fmt, ...)
{
	va_list arg;
	GString *gstr;
	hashstr_t *result;

	gstr = g_string_sized_new(64);
	if (unlikely(NULL == gstr))
		return NULL;

	va_start(arg, fmt);
	g_string_vprintf(gstr, fmt, arg);
	va_end(arg);

	result = hashstr_create_from_gstring(gstr);
	g_string_free(gstr, TRUE);
	return result;
}

hashstr_t*
hashstr_dup(const hashstr_t *hs)
{
	if (unlikely(NULL == hs))
		return NULL;

	hashstr_t *result = g_malloc0(HASHSTR_PREFIX + hs->hl.l + 1);

	result->hl = hs->hl;
	memcpy(result->s0, hs->s0, hs->hl.l);
	return result;
}

const char *
hashstr_str(const hashstr_t *hs)
{
	return unlikely(NULL == hs) ? 0 : hs->s0;
}

gsize
hashstr_len(const hashstr_t *hs)
{
	return unlikely(NULL == hs) ? 0 : hs->hl.l;
}

gsize
hashstr_struct_len(const hashstr_t *hs)
{
	return sizeof(hashstr_t) + hashstr_len(hs) + 1;
}

guint
hashstr_hash(const hashstr_t *hs)
{
	return unlikely(NULL == hs) ? 0 : hs->hl.h;
}

gboolean
hashstr_equal(const hashstr_t *hs1, const hashstr_t *hs2)
{
	return (hs1->hl.h == hs2->hl.h) && (hs1->hl.l == hs2->hl.l)
		&& !g_strcmp0(hashstr_str(hs1), hashstr_str(hs2));
}

gint
hashstr_quick_cmp(const hashstr_t *hs1, const hashstr_t *hs2)
{
	register int rc = CMP(hs1->hl.h, hs2->hl.h);

	if (unlikely(rc != 0))
		return rc;
	return g_strcmp0(hashstr_str(hs1), hashstr_str(hs2));
}

gint
hashstr_quick_cmpdata(gconstpointer p1, gconstpointer p2, gpointer u)
{
	(void) u;
	return hashstr_quick_cmp(p1, p2);
}
