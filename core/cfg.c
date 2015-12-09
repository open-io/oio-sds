/*
OpenIO SDS core library
Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage

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
#include <stdlib.h>

#include <glib.h>

#include "oio_core.h"
#include "internals.h"

static struct oio_cfg_handle_s *oio_cfg_handle_DEFAULT = NULL;

static gchar *
_build_key(const gchar *ns, const gchar *what)
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
	gchar **pk, **keys, *v;

	keys = g_key_file_get_keys(kf, ns, 0, NULL);
	if (keys) {
		for (pk=keys; *pk ;pk++) {
			v = g_key_file_get_string(kf, ns, *pk, NULL);
			g_hash_table_insert(h, _build_key(ns, *pk), v);
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
		if (!g_str_has_suffix(sk, "/conscience"))
			continue;
		gchar *ns = g_strndup(sk, strrchr(sk,'/')- sk);
		g_ptr_array_add(tmp, ns);
	}
	g_hash_table_destroy(ht);
	g_ptr_array_add (tmp, NULL);
	return (gchar**) g_ptr_array_free(tmp, FALSE);
}

GHashTable*
oio_cfg_parse(void)
{
	GHashTable *ht = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	// Load the system configuration
	if (g_file_test(OIO_CONFIG_FILE_PATH, G_FILE_TEST_IS_REGULAR))
		config_load_file(ht, OIO_CONFIG_FILE_PATH);

	if (g_file_test(OIO_CONFIG_DIR_PATH, G_FILE_TEST_IS_DIR|G_FILE_TEST_EXISTS)) {
		GDir *gdir = g_dir_open(OIO_CONFIG_DIR_PATH, 0, NULL);
		if (gdir) {
			config_load_dir(ht, OIO_CONFIG_DIR_PATH, gdir);
			g_dir_close(gdir);
		}
	}

	// Overwrite with the user configuration (if any) 
	if (g_get_home_dir() && OIO_CONFIG_LOCAL_PATH) {
		gchar *local = g_strdup_printf("%s/%s", g_get_home_dir(), OIO_CONFIG_LOCAL_PATH);
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
	gchar *key = _build_key(ns, what);
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
	oio_cfg_handle_DEFAULT = self;
}

