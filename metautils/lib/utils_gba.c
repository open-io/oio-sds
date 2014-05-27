#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "metautils"
#endif

#include "metautils.h"

void
metautils_gba_randomize(GByteArray *gba)
{
	if (unlikely(NULL == gba))
		return ;
	metautils_randomize_buffer(gba->data, gba->len);
}

gsize
metautils_gba_len(const GByteArray *gba)
{
	if (unlikely(NULL == gba))
		return 0;
	return gba->len;
}

static inline int
metautils_buffer_cmp(const guint8 * const d0, const guint l0,
		const guint8 * const d1, const guint l1)
{
	EXTRA_ASSERT(d0 != NULL);
	EXTRA_ASSERT(d1 != NULL);
	register gint cmp_data = memcmp(d0, d1, MIN(l0, l1));
	return MACRO_COND(cmp_data, cmp_data, CMP(l0, l1));
}

int
metautils_gba_cmp(const GByteArray *a, const GByteArray *b)
{
	EXTRA_ASSERT(a != NULL);
	EXTRA_ASSERT(b != NULL);
	return metautils_buffer_cmp(a->data, a->len, b->data, b->len);
}

GByteArray*
metautils_gba_dup(const GByteArray *gba)
{
	GByteArray *gba_copy = g_byte_array_new();
	if (gba && gba->data && gba->len)
		g_byte_array_append(gba_copy, gba->data, gba->len);
	return gba_copy;
}

gsize
metautils_gba_data_to_string(const GByteArray *gba, gchar *dst,
		gsize dst_size)
{
	gsize i, imax, idst;

	if (unlikely(NULL == gba || NULL == dst || 0 == dst_size))
		return 0;
	if (!gba->data || !gba->len)
		return 0;

	bzero(dst, dst_size);
	imax = MIN(gba->len,dst_size);
	for (i=0,idst=0; i<imax && idst<dst_size-5 ;i++) {
		gchar c = (gchar)(gba->data[i]);
		if (g_ascii_isprint(c) && c != '\\')
			dst[ idst++ ] = c;
		else
			idst += g_snprintf(dst+idst, dst_size-idst, "\\x%02X", c);
	}

	return idst;
}

GByteArray*
metautils_gba_from_string(const gchar *str)
{
	size_t len;
	GByteArray *gba;

	if (!str || !*str)
		return g_byte_array_new();

	len = strlen(str);
	gba = g_byte_array_sized_new(len + 1);
	g_byte_array_append(gba, (guint8*)str, len+1);
	g_byte_array_set_size(gba, gba->len - 1);
	return gba;
}

void
metautils_gba_gunref(gpointer p0, gpointer p1)
{
	(void) p1;
	if (p0 != NULL)
		g_byte_array_unref((GByteArray*)p0);
}

void
metautils_gba_unref(gpointer p)
{
	if (p != NULL)
		g_byte_array_unref((GByteArray*)p);
}

void
metautils_gba_clean(gpointer p)
{
	if (p != NULL)
		g_byte_array_free((GByteArray*)p, TRUE);
}

void
meatutils_gba_gclean(gpointer p1, gpointer p2)
{
	(void) p2;
	metautils_gba_clean(p1);
}

GByteArray*
metautils_gba_from_cid(const container_id_t cid)
{
	EXTRA_ASSERT(cid != NULL);
	return g_byte_array_append(
			g_byte_array_sized_new(sizeof(container_id_t)),
			cid, sizeof(container_id_t));
}

GString*
metautils_gba_to_hexgstr(GString *gstr, GByteArray *gba)
{
	guint max, len;

	if (!gstr)
		gstr = g_string_new("");

	len = gstr->len;
	max = gba->len * 2;
	g_string_set_size(gstr, max + len);
	buffer2str(gba->data, gba->len, gstr->str + len, gstr->len - len + 1);

	return gstr;
}

