/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.utils.hashstr"
#endif

#include <string.h>
#include <stdarg.h>

#include <glib.h>

#include "./hashstr.h"

hashstr_t*
hashstr_create(const gchar *s)
{
	guint h;
	hashstr_t *result;
	gsize len = 0;
	
	h = _str_hash(s, &len);
	g_assert(len < 65536);

	result = g_malloc0(offsetof(struct hashstr_s, s0) + len + 1);
	result->h = h;
	result->len = len;
	memcpy(result->s0, s, len);
	return result;
}

hashstr_t*
hashstr_create_len(const gchar *s, gsize l)
{
	guint h;
	hashstr_t *result;
	gsize len;
	
	h = _str_hash2(s, l, &len);
	g_assert(len < 65536);

	result = g_malloc0(offsetof(struct hashstr_s, s0) + len + 1);
	result->h = h;
	result->len = len;
	memcpy(result->s0, s, len);
	return result;
}

hashstr_t*
hashstr_create_from_gstring(GString *gstr)
{
	hashstr_t *result;
	gsize len;
	
	len = gstr->len;
	g_assert(len < 65536);

	result = g_malloc0(offsetof(struct hashstr_s, s0) + len + 1);
	result->h = _str_hash(gstr->str, NULL);
	result->len = len;
	memcpy(result->s0, gstr->str, len);
	return result;
}

hashstr_t *
hashstr_printf(const gchar *fmt, ...)
{
	va_list arg;
	GString *gstr;
	hashstr_t *result;

	gstr = g_string_sized_new(64);

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
	gsize size;
	hashstr_t *result;

	if (!hs)
		return NULL;

	size = offsetof(struct hashstr_s, s0) + hs->len + 1;
	result = g_malloc0(size);
	result->len = hs->len;
	result->h = hs->h;
	memcpy(result->s0, hs->s0, hs->len);

	return result;
}

const gchar *
hashstr_str(const hashstr_t *hs)
{
	return hs ? hs->s0 : NULL;
}

guint
hashstr_ulen(const hashstr_t *hs)
{
	guint i;
	if (!hs)
		return 0;
	i = hs->len;
	return i;
}

gsize
hashstr_len(const hashstr_t *hs)
{
	gsize i;
	if (!hs)
		return 0;
	i = hs->len;
	return i;
}

gsize
hashstr_struct_size(const struct hashstr_s *hs)
{
	return !hs ? 0 : hs->len + offsetof(struct hashstr_s,s0);
}

guint
hashstr_hash(const hashstr_t *hs)
{
	return hs->h;
}

gboolean
hashstr_equal(const hashstr_t *hs1, const hashstr_t *hs2)
{
	return (hs1->h == hs2->h) && (hs1->len == hs2->len)
		&& !hashstr_cmp(hs1, hs2);
}

gint
hashstr_cmp(const hashstr_t *hs1, const hashstr_t *hs2)
{
	return g_strcmp0(hashstr_str(hs1), hashstr_str(hs2));
}

gint
hashstr_quick_cmp(const hashstr_t *hs1, const hashstr_t *hs2)
{
	if (!hs1 && hs2)
		return -1;
	if (hs1 && !hs2)
		return 1;
	if (hs1 == hs2)
		return 0;
 
	if (hs1->h == hs2->h)
		return hashstr_cmp(hs1, hs2);
	return (hs1->h < hs2->h) ? -1 : 1;
}

gint
hashstr_quick_cmpdata(gconstpointer p1, gconstpointer p2, gpointer u)
{
	(void) u;
	return hashstr_quick_cmp(p1, p2);
}

gchar*
hashstr_dump(const hashstr_t *hs)
{
	if (!hs)
		return g_memdup("", 1);
	return g_strdup_printf("(h=%u;l=%u;s=%s)", hs->h, hs->len, hs->s0);
}

void
hashstr_upper(hashstr_t *hs)
{
	gsize l;
	gchar *s;

	for (s=hs->s0; *s ;s++)
		*s = g_ascii_toupper(*s);

	l = hs->len;
	hs->h = _str_hash(hs->s0, &l);
	HASHSTR_ASSERT(l == hs->len);
}

void
hashstr_lower(hashstr_t *hs)
{
	gsize l;
	gchar *s;

	for (s=hs->s0; *s ;s++)
		*s = g_ascii_tolower(*s);

	l = hs->len;
	hs->h = _str_hash(hs->s0, &l);
	HASHSTR_ASSERT(l == hs->len);
}

