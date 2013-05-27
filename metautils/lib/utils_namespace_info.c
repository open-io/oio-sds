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

#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif

#ifndef LOG_DOMAIN
#define LOG_DOMAIN "metautils"
#endif

#include <string.h>
#include <errno.h>

#include "metautils.h"

gboolean
namespace_info_copy(namespace_info_t* src, namespace_info_t* dst, GError **error)
{
	if (src == NULL || dst == NULL) {
		GSETCODE(error, 500+EINVAL, "Argument src or dst should not be NULL");
		errno = EINVAL;
		return FALSE;
	}

	memcpy(dst->name, src->name, sizeof(src->name));
	dst->chunk_size = src->chunk_size;
	memcpy(&(dst->addr), &(src->addr), sizeof(addr_info_t));
	memcpy(&(dst->versions), &(src->versions), sizeof(struct ns_versions_s));

	if (src->options != NULL) {
		GHashTable *old = dst->options;

		dst->options = g_hash_table_ref(src->options);
		if (old)
			g_hash_table_unref(old);
	}
	if (src->storage_policy != NULL) {
		GHashTable *old = dst->storage_policy;

		dst->storage_policy = g_hash_table_ref(src->storage_policy);
		if (old)
			g_hash_table_unref(old);
	}
	if (src->data_security != NULL) {
		GHashTable *old = dst->data_security;

		dst->data_security = g_hash_table_ref(src->data_security);
		if (old)
			g_hash_table_unref(old);
	}
	if (src->data_treatments != NULL) {
		GHashTable *old = dst->data_treatments;

		dst->data_treatments = g_hash_table_ref(src->data_treatments);
		if (old)
			g_hash_table_unref(old);
	}

	errno = 0;
	return TRUE;
}

namespace_info_t*
namespace_info_dup(namespace_info_t* src, GError **error)
{
	namespace_info_t *dst;

	dst = g_try_malloc0(sizeof(namespace_info_t));
	if (!dst) {
		GSETERROR(error, "Memory allocation failure");
		return NULL;
	}

	memcpy(dst->name, src->name, sizeof(src->name));
	dst->chunk_size = src->chunk_size;
	memcpy(&(dst->addr), &(src->addr), sizeof(addr_info_t));
	memcpy(&(dst->versions), &(src->versions), sizeof(struct ns_versions_s));

	dst->options = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, metautils_gba_unref);
	if (src->options) {
		GHashTableIter iter;
		gpointer k, v;
		
		g_hash_table_iter_init(&iter, src->options);
		while (g_hash_table_iter_next(&iter, &k, &v))
			g_hash_table_insert(dst->options, g_strdup((gchar*)k), metautils_gba_dup(v));
	}
	dst->storage_policy = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, metautils_gba_unref);
	if (src->storage_policy) {
		GHashTableIter iter;
		gpointer k, v;
		
		g_hash_table_iter_init(&iter, src->storage_policy);
		while (g_hash_table_iter_next(&iter, &k, &v))
			g_hash_table_insert(dst->storage_policy, g_strdup((gchar*)k), metautils_gba_dup(v));
	}
	dst->data_security = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, metautils_gba_unref);
	if (src->data_security) {
		GHashTableIter iter;
		gpointer k, v;
		
		g_hash_table_iter_init(&iter, src->data_security);
		while (g_hash_table_iter_next(&iter, &k, &v))
			g_hash_table_insert(dst->data_security, g_strdup((gchar*)k), metautils_gba_dup(v));
	}
	dst->data_treatments = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, metautils_gba_unref);
	if (src->data_treatments) {
		GHashTableIter iter;
		gpointer k, v;
		
		g_hash_table_iter_init(&iter, src->data_treatments);
		while (g_hash_table_iter_next(&iter, &k, &v))
			g_hash_table_insert(dst->data_treatments, g_strdup((gchar*)k), metautils_gba_dup(v));
	}

	return dst;
}

void
namespace_info_clear(namespace_info_t* ns_info)
{
	if (ns_info == NULL)
		return;
	if (ns_info->options != NULL)
		g_hash_table_unref(ns_info->options);
	if (ns_info->storage_policy != NULL)
		g_hash_table_unref(ns_info->storage_policy);
	if (ns_info->data_security != NULL)
		g_hash_table_unref(ns_info->data_security);
	if (ns_info->data_treatments != NULL)
		g_hash_table_unref(ns_info->data_treatments);

	memset(ns_info, 0, sizeof(namespace_info_t));
}

void
namespace_info_free(namespace_info_t* ns_info)
{
	if (ns_info == NULL)
		return;

	namespace_info_clear(ns_info);
	g_free(ns_info);
}

void
namespace_info_gclean(gpointer p1, gpointer p2)
{
	(void) p2;
	if (p1)
		namespace_info_free((struct namespace_info_s*)p1);
}

GHashTable*
namespace_info_list2map(GSList *list_nsinfo, gboolean auto_free)
{
	GSList *l;
	GHashTable *ht;

	ht = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, auto_free ? (GDestroyNotify)namespace_info_free : NULL);
	for (l=list_nsinfo; l ;l=l->next) {
		if (l->data)
			g_hash_table_insert(ht, ((struct namespace_info_s*)l->data)->name, l->data);
	}
	return ht;
}

GSList*
namespace_info_extract_name(GSList *list_nsinfo, gboolean copy)
{
	GSList *l, *result;

	result = NULL;
	for (l=list_nsinfo; l ;l=l->next) {
		if (l->data)
			result = g_slist_prepend(result, (copy ? g_strndup((gchar*)l->data, LIMIT_LENGTH_NSNAME) : l->data));
	}
	return result;
}

gchar *
namespace_info_get_data_security(namespace_info_t *ni, const gchar *data_sec_key)
{
	if(NULL != ni->data_security) {
		GByteArray *gba = NULL;
		gba = g_hash_table_lookup(ni->data_security, data_sec_key);
		if(NULL != gba) {
			return g_strndup((gchar*)gba->data, gba->len);
		}
	}

	return NULL;
}

gchar *
namespace_info_get_data_treatments(namespace_info_t *ni, const gchar *data_treat_key)
{
	if(NULL != ni->data_treatments) {
		GByteArray *gba = NULL;
		gba = g_hash_table_lookup(ni->data_treatments, data_treat_key);
		if(NULL != gba) {
			return g_strndup((gchar*)gba->data, gba->len);
		}
	}

	return NULL;
}
