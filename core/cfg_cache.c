/* OpenIO SDS core library
 * Copyright (C) 2016 OpenIO, original work as part of OpenIO SDS
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 *License along with this library.
 */

#include <string.h>

#include <glib.h>

#include <oioext.h>
#include <oiocfg.h>

#include "internals.h"

struct oio_cfg_cache_handle_s
{
	struct oio_cfg_handle_vtable_s *vtable;
	GHashTable *cfg;
	GRWLock lock;
	gint64 last_update;
	gint64 delay;
};

static GHashTable*
_cfg_cache_get_cfg_unlocked(gpointer self)
{
	struct oio_cfg_cache_handle_s *cache = self;
	gint64 now = oio_ext_monotonic_time();

	if (cache->cfg && now < cache->last_update + cache->delay)
		return cache->cfg;

	g_rw_lock_reader_unlock(&cache->lock);
	g_rw_lock_writer_lock(&cache->lock);
	/* Check again in case another thread did the update
	 * while we were waiting */
	now = oio_ext_monotonic_time();
	if (!cache->cfg || now >= cache->last_update + cache->delay) {
		GHashTable *new_cfg = oio_cfg_parse();
		if (new_cfg) {
			if (cache->cfg)
				g_hash_table_destroy(cache->cfg);
			cache->cfg = new_cfg;
			cache->last_update = now;
		} else {
			// Silent failure
		}
	}
	g_rw_lock_writer_unlock(&cache->lock);
	g_rw_lock_reader_lock(&cache->lock);

	return cache->cfg;
}

static void
_cfg_cache_clean(struct oio_cfg_handle_s *self)
{
	struct oio_cfg_cache_handle_s *cache = (gpointer)self;
	g_rw_lock_writer_lock(&cache->lock);
	if (cache->cfg)
		g_hash_table_destroy(cache->cfg);
	cache->cfg = NULL;
	cache->last_update = 0L;
	g_rw_lock_writer_unlock(&cache->lock);
	g_rw_lock_clear(&cache->lock);
	g_free(cache);
}

static gchar **
_cfg_cache_namespaces(struct oio_cfg_handle_s *self)
{
	struct oio_cfg_cache_handle_s *cache = (gpointer)self;
	GHashTableIter iter;
	gpointer k, v;
	GPtrArray *tmp = g_ptr_array_sized_new(4);

	g_rw_lock_reader_lock(&cache->lock);
	GHashTable *ht = _cfg_cache_get_cfg_unlocked(self);
	g_hash_table_iter_init(&iter, ht);
	while (g_hash_table_iter_next(&iter, &k, &v)) {
		const gchar *sk = (gchar*)k;
		if (g_str_has_prefix(sk, "default/"))
			continue;
		if (!g_str_has_suffix(sk, "/conscience"))
			continue;
		gchar *ns = g_strndup(sk, strrchr(sk, '/') - sk);
		g_ptr_array_add(tmp, ns);
	}
	g_rw_lock_reader_unlock(&cache->lock);

	g_ptr_array_add(tmp, NULL);
	return (gchar**) g_ptr_array_free(tmp, FALSE);
}

static gchar*
_cfg_cache_get(struct oio_cfg_handle_s *self, const char *ns, const char *what)
{
	struct oio_cfg_cache_handle_s *cache = (gpointer)self;

	if (!ns || !strcasecmp(ns, "default"))
		ns = "default";

	gchar *key = oio_cfg_build_key(ns, what);
	gchar *value = NULL;

	g_rw_lock_reader_lock(&cache->lock);
	GHashTable *ht = _cfg_cache_get_cfg_unlocked(self);
	value = g_strdup(g_hash_table_lookup(ht, key));
	g_rw_lock_reader_unlock(&cache->lock);

	g_free(key);
	return value;
}

static struct oio_cfg_handle_vtable_s VTABLE =
{
	.clean = _cfg_cache_clean,
	.namespaces = _cfg_cache_namespaces,
	.get = _cfg_cache_get,
};

struct oio_cfg_handle_s *
oio_cfg_cache_create(gint64 delay)
{
	struct oio_cfg_cache_handle_s *cache =
			g_malloc0(sizeof(struct oio_cfg_cache_handle_s));
	cache->vtable = &VTABLE;
	g_rw_lock_init(&cache->lock);
	cache->delay = delay;
	// cache->cfg will be initialized at first call
	return (struct oio_cfg_handle_s *) cache;
}
