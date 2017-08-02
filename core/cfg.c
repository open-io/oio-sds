/*
OpenIO SDS core library
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

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

#include <core/oiocfg.h>

#include <string.h>

#include <core/oiolog.h>
#include <core/oiostr.h>

#include "internals.h"

static struct oio_cfg_handle_s *oio_cfg_handle_DEFAULT = NULL;

gchar *
oio_cfg_build_key(const gchar *ns, const gchar *what)
{
	gchar *k, *result;

	result = g_strconcat(ns, "/", what, NULL);
	for (k=strchr(result,'/'); k && *k ;k++)
		*k = g_ascii_tolower(*k);
	return result;
}

static void
config_load_ns(GHashTable *h, GKeyFile *kf, const gchar *ns)
{
	gchar **keys = g_key_file_get_keys(kf, ns, 0, NULL);
	if (keys) {
		g_hash_table_insert(h, oio_cfg_build_key(ns, "known"), g_strdup("yes"));
		for (gchar **pk=keys; *pk ;pk++) {
			gchar *v = g_key_file_get_string(kf, ns, *pk, NULL);
			g_hash_table_insert(h, oio_cfg_build_key(ns, *pk), v);
		}
		g_strfreev(keys);
	}
}

static void
config_load_file(GHashTable *h, const gchar *source)
{
	GError *err = NULL;
	GKeyFile *kf = g_key_file_new();
	if (!g_key_file_load_from_file(kf, source, 0, &err)) {
		GRID_TRACE("Failed to load [%s] : (%d) %s", source, err->code, err->message);
		g_clear_error(&err);
	} else {
		gchar **pg, **groups = NULL;
		groups = g_key_file_get_groups(kf, NULL);
		if (groups) {
			for (pg=groups; *pg ;pg++)
				config_load_ns(h, kf, *pg);
			g_strfreev(groups);
		}
	}
	g_key_file_free(kf);
}

static void
config_load_dir(GHashTable *ht, const gchar *dirname, GDir *gdir)
{
	const char *bn = NULL;

	while (NULL != (bn = g_dir_read_name(gdir))) {
		gchar *fullpath;

		if (*bn == '.')
			continue;
		fullpath = g_strconcat(dirname, G_DIR_SEPARATOR_S, bn, NULL);
		if (fullpath) {
			config_load_file(ht, fullpath);
			g_free(fullpath);
		}
	}
}

gchar **
oio_cfg_list_ns(void)
{
	if (oio_cfg_handle_DEFAULT)
		return oio_cfg_handle_namespaces (oio_cfg_handle_DEFAULT);

	GHashTableIter iter;
	gpointer k, v;
	GHashTable *ht = oio_cfg_parse();
	GPtrArray *tmp = g_ptr_array_sized_new(4);

	g_hash_table_iter_init(&iter, ht);
	while (g_hash_table_iter_next(&iter, &k, &v)) {
		const gchar *sk = (gchar*)k;
		if (g_str_has_prefix(sk, "default/"))
			continue;
		if (!g_str_has_suffix(sk, "/known"))
			continue;
		gchar *ns = g_strndup(sk, strrchr(sk,'/')- sk);
		g_ptr_array_add(tmp, ns);
	}
	g_hash_table_destroy(ht);
	g_ptr_array_add (tmp, NULL);
	return (gchar**) g_ptr_array_free(tmp, FALSE);
}

GHashTable*
oio_cfg_parse_file(const char *path)
{
	GHashTable *ht = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, g_free);
	config_load_file(ht, path);
	return ht;
}

GHashTable*
oio_cfg_parse(void)
{
	GHashTable *ht = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, g_free);

	// Load the system configuration
	if (g_file_test(OIO_CONFIG_FILE_PATH, G_FILE_TEST_IS_REGULAR))
		config_load_file(ht, OIO_CONFIG_FILE_PATH);

	if (g_file_test(OIO_CONFIG_DIR_PATH,
			G_FILE_TEST_IS_DIR|G_FILE_TEST_EXISTS)) {
		GDir *gdir = g_dir_open(OIO_CONFIG_DIR_PATH, 0, NULL);
		if (gdir) {
			config_load_dir(ht, OIO_CONFIG_DIR_PATH, gdir);
			g_dir_close(gdir);
		}
	}

	// Overwrite with the user configuration (if any)
	if (g_get_home_dir() && OIO_CONFIG_LOCAL_PATH) {
		gchar *local = g_strdup_printf("%s/%s", g_get_home_dir(),
				OIO_CONFIG_LOCAL_PATH);
		config_load_file(ht, local);
		g_free(local);
	}

	return ht;
}

gchar *
oio_cfg_get_value(const gchar *ns, const gchar *what)
{
	if (oio_cfg_handle_DEFAULT)
		return oio_cfg_handle_get (oio_cfg_handle_DEFAULT, ns, what);

	if (!ns || !strcasecmp(ns, "default"))
		ns = "default";

	GHashTable *ht;
	gchar *key = oio_cfg_build_key(ns, what);
	gchar *value = NULL;
	if (NULL != (ht = oio_cfg_parse())) {
		value = g_hash_table_lookup(ht, key);
		if (value)
			value = g_strdup(value);
		g_hash_table_destroy(ht);
	}
	g_free(key);
	return value;
}

gboolean
oio_cfg_get_bool (const char *ns, const char *what, gboolean def)
{
	gchar *v = oio_cfg_get_value(ns, what);
	if (!v)
		return def;
	gboolean rc = oio_str_parse_bool(v, def);
	g_free(v);
	return rc;
}

gchar *
oio_cfg_get_proxy_conscience (const char *ns)
{
	gchar *v = oio_cfg_get_value(ns, OIO_CFG_PROXY_CONSCIENCE);
	return v ? v : oio_cfg_get_proxy(ns);
}

gchar *
oio_cfg_get_proxy_directory (const char *ns)
{
	gchar *v = oio_cfg_get_value(ns, OIO_CFG_PROXY_DIRECTORY);
	return v ? v : oio_cfg_get_proxy(ns);
}

gchar *
oio_cfg_get_proxy_containers (const char *ns)
{
	gchar *v = oio_cfg_get_value(ns, OIO_CFG_PROXY_CONTAINERS);
	return v ? v : oio_cfg_get_proxy(ns);
}

gchar *
oio_cfg_get_swift(const char *ns)
{
	return oio_cfg_get_value(ns, OIO_CFG_SWIFT);
}

/* -------------------------------------------------------------------------- */

#define CFG_CALL(self,F) VTABLE_CALL(self,struct oio_cfg_handle_abstract_s*,F)

void
oio_cfg_handle_clean (struct oio_cfg_handle_s *self)
{
	CFG_CALL(self,clean)(self);
}

gchar **
oio_cfg_handle_namespaces (struct oio_cfg_handle_s *self)
{
	CFG_CALL(self,namespaces)(self);
}

gchar *
oio_cfg_handle_get (struct oio_cfg_handle_s *self, const char *ns, const char *k)
{
	CFG_CALL(self,get)(self,ns,k);
}

void
oio_cfg_set_handle (struct oio_cfg_handle_s *self)
{
	if (oio_cfg_handle_DEFAULT)
		oio_cfg_handle_clean(oio_cfg_handle_DEFAULT);
	oio_cfg_handle_DEFAULT = self;
}

/* -------------------------------------------------------------------------- */

struct oio_cfg_cache_handle_s
{
	struct oio_cfg_handle_vtable_s *vtable;
	GHashTable *cfg;
	GRWLock lock;
};

static GHashTable*
_cfg_cache_get_cfg_unlocked(gpointer self)
{
	struct oio_cfg_cache_handle_s *cache = self;

	if (cache->cfg)
		return cache->cfg;

	g_rw_lock_reader_unlock(&cache->lock);
	g_rw_lock_writer_lock(&cache->lock);
	/* Check again in case another thread did the update
	 * while we were waiting */
	if (!cache->cfg) {
		GHashTable *new_cfg = oio_cfg_parse();
		if (new_cfg) {
			if (cache->cfg)
				g_hash_table_destroy(cache->cfg);
			cache->cfg = new_cfg;
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

static struct oio_cfg_handle_vtable_s VTABLE = {
		.clean = _cfg_cache_clean,
		.namespaces = _cfg_cache_namespaces,
		.get = _cfg_cache_get,
};

struct oio_cfg_handle_s *
oio_cfg_cache_create_fragment(const char *path)
{
	struct oio_cfg_cache_handle_s *cache =
			g_malloc0(sizeof(struct oio_cfg_cache_handle_s));
	cache->vtable = &VTABLE;
	g_rw_lock_init(&cache->lock);
	cache->cfg = oio_cfg_parse_file(path);
	return (struct oio_cfg_handle_s *) cache;
}

struct oio_cfg_handle_s *
oio_cfg_cache_create(void)
{
	struct oio_cfg_cache_handle_s *cache =
			g_malloc0(sizeof(struct oio_cfg_cache_handle_s));
	cache->vtable = &VTABLE;
	g_rw_lock_init(&cache->lock);
	// cache->cfg will be initialized at first call
	return (struct oio_cfg_handle_s *) cache;
}

gboolean
oio_cfg_handle_has_ns(struct oio_cfg_handle_s *self, const char *ns)
{
	gchar *v = oio_cfg_handle_get(self, ns, "known");
	gboolean rc = oio_str_parse_bool(v, FALSE);
	if (v) g_free(v);
	return rc;
}
