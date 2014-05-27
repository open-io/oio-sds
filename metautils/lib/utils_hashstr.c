#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.utils.hashstr"
#endif

#include <string.h>
#include <stdarg.h>

#include "./metautils_strings.h"
#include "./metautils_bits.h"
#include "./metautils_hashstr.h"

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

const gchar *
hashstr_str(const hashstr_t *hs)
{
	return unlikely(NULL == hs) ? 0 : hs->s0;
}

guint
hashstr_ulen(const hashstr_t *hs)
{
	return unlikely(NULL == hs) ? 0 : hs->hl.l;
}

gsize
hashstr_len(const hashstr_t *hs)
{
	return unlikely(NULL == hs) ? 0 : hs->hl.l;
}

gsize
hashstr_struct_size(const struct hashstr_s *hs)
{
	return unlikely(NULL == hs) ? 0 : hs->hl.l + HASHSTR_PREFIX;
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
	register int rc = CMP(hs1->hl.h, hs2->hl.h);

	if (unlikely(rc != 0))
		return rc;
	return hashstr_cmp(hs1, hs2);
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
	if (unlikely(NULL == hs))
		return g_memdup("", 1);
	return g_strdup_printf("(h=%u;l=%u;s=%s)", hs->hl.h, hs->hl.l, hs->s0);
}

void
hashstr_upper(hashstr_t *hs)
{
	if (unlikely(NULL == hs))
		return;
	metautils_str_upper(hs->s0);
	hs->hl = djb_hash_str(hs->s0);
}

void
hashstr_lower(hashstr_t *hs)
{
	if (unlikely(NULL == hs))
		return;
	metautils_str_lower(hs->s0);
	hs->hl = djb_hash_str(hs->s0);
}

