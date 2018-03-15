/*
OpenIO SDS meta0v2
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

#include <metautils/lib/metautils.h>

#include "meta0_utils.h"

static void garray_free(void *a) { if (a) g_array_free(a, TRUE); }

/* ------------------------------------------------------------------------- */

static guint16 meta0_utils_bytes_to_prefix(const guint8 *bytes) {
	return *((guint16*)bytes);
}

static GArray * _tree_ensure (GTree *tree, const gchar *url) {
	GArray *prefixes = g_tree_lookup(tree, url);
	if (!prefixes) {
		prefixes = g_array_new(FALSE, FALSE, 2);
		g_tree_replace(tree, g_strdup(url), prefixes);
	}
	return prefixes;
}

void meta0_utils_tree_add_url(GTree *byurl, const guint8 *b, const gchar *url) {
	GArray *prefixes = _tree_ensure(byurl, url);
	g_array_append_vals(prefixes, b, 1);
}

GTree* meta0_utils_tree_create(void) {
	return g_tree_new_full(metautils_strcmp3, NULL, g_free, garray_free);
}

static GTree* meta0_utils_array_to_tree(const GPtrArray *byprefix) {
	EXTRA_ASSERT(byprefix != NULL);
	GTree *result = meta0_utils_tree_create();

	for (guint i = 0; i < byprefix->len ;i++) {
		guint16 prefix = i;
		gchar **v = byprefix->pdata[i];
		if (unlikely(!v))
			continue;
		for (; *v ;v++)
			meta0_utils_tree_add_url(result, (guint8*)(&prefix), *v);
	}

	return result;
}

void
meta0_utils_array_add(GPtrArray *byprefix,
		const guint8 *bytes, const gchar *s)
{
	const guint16 prefix = meta0_utils_bytes_to_prefix(bytes);
	g_assert(byprefix->len > prefix);
	if (!byprefix->pdata[prefix]) {
		// We will typically set 3 services + NULL
		byprefix->pdata[prefix] = g_ptr_array_sized_new(4);
	}
	g_ptr_array_add(byprefix->pdata[prefix], g_strdup(s));
}

void
meta0_utils_array_finalize(GPtrArray *array)
{
	for (guint i = 0; i < array->len; i++) {
		if (array->pdata[i] != NULL) {
			g_ptr_array_add(array->pdata[i], NULL);
			array->pdata[i] = g_ptr_array_free(array->pdata[i], FALSE);
		}
	}
}

GPtrArray* meta0_utils_list_to_array(GSList *list) {
	GPtrArray *result = meta0_utils_array_create();

	for (GSList *l = list; l; l = l->next) {
		const struct meta0_info_s *m0i = l->data;
		if (unlikely(!m0i))
			continue;

		gchar url[STRLEN_ADDRINFO];
		grid_addrinfo_to_string(&(m0i->addr), url, sizeof(url));

		const guint8 *max = m0i->prefixes + m0i->prefixes_size;
		for (guint8 *p = m0i->prefixes; p < max; p += 2)
			meta0_utils_array_add(result, p, url);
	}

	meta0_utils_array_finalize(result);
	return result;
}

static gboolean _tree2list_traverser(gpointer k, gpointer v, gpointer u) {
	const gchar *url = k;
	GArray *pfx = v;
	GSList **pl = u;

	struct meta0_info_s *m0i = g_malloc0(sizeof(*m0i));
	grid_string_to_addrinfo(url, &(m0i->addr));
	m0i->prefixes_size = 2 * pfx->len;
	m0i->prefixes = g_memdup(pfx->data, m0i->prefixes_size);
	*pl = g_slist_prepend(*pl, m0i);

	return FALSE;
}

GSList* meta0_utils_tree_to_list(GTree *byurl) {
	EXTRA_ASSERT(byurl != NULL);
	GSList *result = NULL;
	g_tree_foreach(byurl, _tree2list_traverser, &result);
	return result;
}

gchar ** meta0_utils_array_get_urlv(GPtrArray *byprefix, const guint8 *b) {
	EXTRA_ASSERT(byprefix != NULL);
	EXTRA_ASSERT(byprefix->len == CID_PREFIX_COUNT);
	guint16 prefix = meta0_utils_bytes_to_prefix(b);
	g_assert(byprefix->len > prefix);
	return g_strdupv(byprefix->pdata[prefix]);
}

void meta0_utils_list_clean(GSList *list) {
	g_slist_free_full(list, (GDestroyNotify)meta0_info_clean);
}

GPtrArray * meta0_utils_array_create(void) {
	GPtrArray *array = g_ptr_array_sized_new(CID_PREFIX_COUNT);
	g_ptr_array_set_size(array, CID_PREFIX_COUNT);
	return array;
}

void meta0_utils_array_clean(GPtrArray *array) {
	if (!array)
		return;
	for (guint i=0; i<array->len ;i++) {
		gchar **p = array->pdata[i];
		if (p) g_strfreev(p);
		array->pdata[i] = NULL;
	}
	g_ptr_array_free(array, TRUE);
}

GPtrArray* meta0_utils_array_dup(const GPtrArray *in) {
	EXTRA_ASSERT(in != NULL);
	GPtrArray *result = g_ptr_array_sized_new(in->len);
	for (guint i = 0; i < in->len; i++) {
		/* g_strdupv(NULL) returns NULL */
		g_ptr_array_add(result, g_strdupv(in->pdata[i]));
	}
	EXTRA_ASSERT(in->len == result->len);
	return result;
}

GSList* meta0_utils_array_to_list(GPtrArray *byprefix) {
	EXTRA_ASSERT(byprefix != NULL);
	GTree *byurl = meta0_utils_array_to_tree(byprefix);
	GSList *list = meta0_utils_tree_to_list(byurl);
	g_tree_destroy(byurl);
	return list;
}

/* ------------------------------------------------------------------------- */

/* The group is represented by the network order 16-bytes prefix,
 * a.k.a. a simple cast from <guint8*> to <guint16> */
static void
_foreach_pfx(const guint16 grp_h16, const guint16 end_h16,
		meta0_on_prefix on_prefix, gpointer u)
{
	const guint16 grp_n16 = g_htons(grp_h16);

	for (guint16 idx_h16 = 0 ;;) {
		const guint16 pfx_h16 = grp_h16 | idx_h16;
		const guint16 pfx_n16 = g_htons(pfx_h16);
		if (!on_prefix(u, (const guint8*)&grp_n16, (const guint8*)&pfx_n16))
			return;
		if (idx_h16++ == end_h16)
			return;
	}
}

static const guint16 masks_h16[] = { 0, 0xF000, 0xFF00, 0xFFF0, 0xFFFF };

void
meta0_utils_foreach_prefix_in_group(const guint8* bin, guint digits,
		meta0_on_prefix on_prefix, gpointer u)
{
	g_assert(NULL != bin);
	g_assert(digits <= 4);
	const guint16 msk_h16 = masks_h16[digits];
	const guint16 pfx_n16 = *(const guint16*)bin;
	return _foreach_pfx(g_ntohs(pfx_n16) & msk_h16, ~msk_h16, on_prefix, u);
}

void
meta0_utils_foreach_prefix(guint digits, meta0_on_prefix on_prefix,
		gpointer u)
{
	g_assert(digits <= 4);
	const guint16 msk_h16 = masks_h16[digits];
	guint16 pfx_h16 = 0;
	do {
		const guint16 grp_h16 = pfx_h16 & msk_h16;
		const guint16 grp_n16 = g_htons(grp_h16);
		const guint16 pfx_n16 = g_htons(pfx_h16);
		if (!on_prefix(u, (guint8*)&grp_n16, (guint8*)&pfx_n16))
			return;
	} while (++pfx_h16);
}
