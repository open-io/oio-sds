/*
OpenIO SDS cluster
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.lib"
#endif

#include <string.h>
#include <stdlib.h>

#include <metautils/lib/metautils.h>

#include "gridcluster.h"

static gchar *
_get_key(const gchar *ns, const gchar *what)
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
			g_hash_table_insert(h, _get_key(ns, *pk), v);
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

GHashTable*
gridcluster_parse_config(void)
{
	GHashTable *ht = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	// Load the system configuration
	if (g_file_test(GCLUSTER_CONFIG_FILE_PATH, G_FILE_TEST_IS_REGULAR))
		config_load_file(ht, GCLUSTER_CONFIG_FILE_PATH);

	if (g_file_test(GCLUSTER_CONFIG_DIR_PATH, G_FILE_TEST_IS_DIR|G_FILE_TEST_EXISTS)) {
		GDir *gdir = g_dir_open(GCLUSTER_CONFIG_DIR_PATH, 0, NULL);
		if (gdir) {
			config_load_dir(ht, GCLUSTER_CONFIG_DIR_PATH, gdir);
			g_dir_close(gdir);
		}
	}

	// Overwrite with the user configuration (if any) 
	if (g_get_home_dir() && GCLUSTER_CONFIG_LOCAL_PATH) {
		gchar *local = g_strdup_printf("%s/%s", g_get_home_dir(), GCLUSTER_CONFIG_LOCAL_PATH);
		config_load_file(ht, local);
		g_free(local);
	}

	return ht;
}

gchar *
gridcluster_get_config(const gchar *ns, const gchar *what)
{
	if (!ns || !strcasecmp(ns, "default"))
		ns = "default";

	GHashTable *ht;
	gchar *key = _get_key(ns, what);
	gchar *value = NULL;
	if (NULL != (ht = gridcluster_parse_config())) {
		value = g_hash_table_lookup(ht, key);
		if (value)
			value = g_strdup(value);
		g_hash_table_destroy(ht);
	}
	g_free(key);
	return value;
}

gchar **
gridcluster_list_ns(void)
{
	GHashTableIter iter;
	gpointer k, v;
	GHashTable *ht = gridcluster_parse_config();
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
	return (gchar**) metautils_gpa_to_array(tmp, TRUE);
}

