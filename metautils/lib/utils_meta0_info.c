#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "metautils.meta0_info"
#endif

#include <errno.h>

#include "metautils.h"

static gboolean
func_equal_prefix(gconstpointer a, gconstpointer b)
{
	register gsize sA, sB;

	if (!a || !b)
		return FALSE;

	sA = ((meta0_info_t *) a)->prefixes_size;
	sB = ((meta0_info_t *) b)->prefixes_size;

	if (sA != sB)
		return FALSE;

	return (0 == memcmp(((meta0_info_t *) a)->prefixes, ((meta0_info_t *) b)->prefixes, sA)) ? TRUE : FALSE;
}


static guint
func_hash_prefix(gconstpointer k)
{
	return djb_hash_buf(((meta0_info_t *) k)->prefixes,
			((meta0_info_t *) k)->prefixes_size);
}


static void
func_free_meta0(gpointer v)
{
	if (v) {
		if (((meta0_info_t *) v)->prefixes)
			g_free(((meta0_info_t *) v)->prefixes);
		g_free(v);
	}
}


/* ------------------------------------------------------------------------- */


gsize
meta0_info_to_string(const meta0_info_t * m0i, gchar * dst, gsize dstSize)
{
	gsize i = 0;
	gsize offset;

	offset = g_snprintf(dst, dstSize, "%"G_GSIZE_FORMAT":", m0i->prefixes_size);

	offset += addr_info_to_string(&(m0i->addr), dst + offset, dstSize - offset);

	offset += g_snprintf(dst + offset, dstSize - offset, ":");

	for (i = 0; i < m0i->prefixes_size; i++)
		offset += g_snprintf(dst + offset, dstSize - offset, "%02x", m0i->prefixes[i]);

	return offset;
}

void
meta0_info_clean(meta0_info_t *m0)
{
	if (!m0) {
		errno = EINVAL;
		return;
	}
	if (m0->prefixes) {
		g_free(m0->prefixes);
		m0->prefixes = NULL;
	}
	g_free(m0);
}

void
meta0_info_gclean(gpointer d, gpointer u)
{
	(void) u;
	meta0_info_clean(d);
}


static meta0_info_t *
meta0_info_copy(meta0_info_t * src)
{
	meta0_info_t *m0i;

	if (!src || !src->prefixes) {
		errno = EINVAL;
		return NULL;
	}

	m0i = g_try_malloc0(sizeof(meta0_info_t));
	if (!m0i) {
		errno = ENOMEM;
		return NULL;
	}

	m0i->prefixes_size = src->prefixes_size;
	m0i->prefixes = g_try_malloc0(m0i->prefixes_size);
	if (!m0i->prefixes) {
		g_free(m0i);
		errno = ENOMEM;
		return NULL;
	}

	g_memmove(&(m0i->addr), &(src->addr), sizeof(addr_info_t));
	g_memmove(m0i->prefixes, src->prefixes, src->prefixes_size);
	errno = 0;
	return m0i;
}


GHashTable *
meta0_info_list_map_by_addr(GSList * mL, GError ** err)
{
	GSList *l;
	GHashTable *mH;

	(void) err;

	mH = g_hash_table_new_full(addr_info_hash, addr_info_equal, NULL, func_free_meta0);
	if (!mH) {
		errno = ENOMEM;
		return NULL;
	}

	for (l = mL; l; l = l->next) {
		meta0_info_t *arg, *m0i;

		if (!(l->data))
			continue;

		arg = (meta0_info_t *) l->data;
		m0i = g_hash_table_lookup(mH, arg);
		if (m0i) {	/*appends the prefix */
			guint8 *b = g_try_realloc(m0i->prefixes, m0i->prefixes_size + arg->prefixes_size);

			if (b) {
				m0i->prefixes = b;
				g_memmove(m0i->prefixes + m0i->prefixes_size, arg->prefixes, arg->prefixes_size);
				m0i->prefixes_size += arg->prefixes_size;
			}
		}
		else {		/*insert a copy */
			m0i = meta0_info_copy(arg);
			g_hash_table_insert(mH, m0i, m0i);
		}
	}

	errno = 0;
	return mH;
}


GHashTable *
meta0_info_list_map_by_prefix(GSList * mL, GError ** err)
{
	GSList *l;
	GHashTable *mH;

	(void) err;

	mH = g_hash_table_new_full(func_hash_prefix, func_equal_prefix, NULL, func_free_meta0);
	for (l = mL; l; l = l->next) {
		register int i, max;
		meta0_info_t dummy, *arg, *m0i;

		if (!l->data)
			continue;
		arg = (meta0_info_t *) l->data;

		dummy.prefixes_size = 2;
		dummy.prefixes = g_try_malloc(dummy.prefixes_size);
		g_memmove(&(dummy.addr), &(arg->addr), sizeof(addr_info_t));

		for (i = 1, max = arg->prefixes_size - 1; i < max; i += 2) {
			g_memmove(dummy.prefixes, arg->prefixes + i - 1, 2);
			m0i = g_hash_table_lookup(mH, &dummy);
			if (m0i) {	/*prefix already present, we do nothing else a debug */
				if (DEBUG_ENABLED()) {
					char str_addr[128];

					addr_info_to_string(&(dummy.addr), str_addr, sizeof(str_addr));
					DEBUG("double prefix found %02X%02X -> %s", dummy.prefixes[0], dummy.prefixes[1], str_addr);
				}
			}
			else {	/*prefix absent */
				m0i = meta0_info_copy(&dummy);
				g_hash_table_insert(mH, m0i, m0i);
			}
		}
		g_free(dummy.prefixes);
	}
	return mH;
}


GSList *
meta0_info_compress_prefixes(GSList * mL, GError ** err)
{
	gpointer k, v;
	GHashTableIter iter;
	GHashTable *map_addr = NULL;
	GSList *list_result = NULL;

	if (!mL) {
		GSETERROR(err, "invalid parameter");
		return NULL;
	}

	map_addr = meta0_info_list_map_by_addr(mL, err);
	if (!map_addr) {
		GSETERROR(err, "cannot build the address-indexed hash-map");
		return NULL;
	}

	g_hash_table_iter_init(&iter, map_addr);
	while (g_hash_table_iter_next(&iter, &k, &v)) {
		list_result = g_slist_prepend(list_result, v);
		g_hash_table_iter_steal(&iter);
	}
	g_hash_table_destroy(map_addr);
	return list_result;
}


GSList *
meta0_info_uncompress_prefixes(GSList * mL, GError ** err)
{
	gpointer k, v;
	GHashTableIter iter;
	GHashTable *map_prefix = NULL;
	GSList *list_result = NULL;

	if (!mL) {
		GSETERROR(err, "invalid parameter");
		return NULL;
	}

	map_prefix = meta0_info_list_map_by_prefix(mL, err);
	if (!map_prefix) {
		GSETERROR(err, "cannot build the prefix-indexed hash-map");
		return NULL;
	}

	g_hash_table_iter_init(&iter, map_prefix);
	while (g_hash_table_iter_next(&iter, &k, &v)) {
		list_result = g_slist_prepend(list_result, v);
		g_hash_table_iter_steal(&iter);
	}
	g_hash_table_destroy(map_prefix);
	return list_result;
}
