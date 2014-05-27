#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.lib"
#endif

#include <string.h>
#include <stdlib.h>

#include <metautils/lib/metautils.h>

#include "gridcluster.h"

#define CONSCIENCE_KEY "conscience"

static int
config_overwrite_with_file(GHashTable *ns_hash, const gchar *source, GError **error)
{
	GKeyFile *key_file = NULL;
	gchar **ns_names = NULL;
	gsize nb_ns = 0;

	/* Load config file */
	key_file = g_key_file_new();

	if (!g_key_file_load_from_file(key_file, source, 0, error)) {
		g_key_file_free(key_file);
		GSETERROR(error, "Failed to load key file [%s]", source);
		return (0);
	}

	ns_names = g_key_file_get_groups(key_file, &nb_ns);
	if (nb_ns > 0) {
		int i = 0;
		gchar *name = NULL;

		for (i = 1, name = *ns_names; name; name = *(ns_names + (i++))) {
			addr_info_t addr;
			gboolean rc;
			gchar *conscience, *conscience_ip, *str_port;

			conscience = conscience_ip = str_port = NULL;
			DEBUG("Found a namespace : %s", name);

			if (!g_key_file_has_key(key_file, name, CONSCIENCE_KEY, error)) {
				GSETERROR(error, "No conscience specified for namespace [%s]", name);
				continue;
			}
			conscience = g_key_file_get_value(key_file, name, CONSCIENCE_KEY, error);
			rc = l4_address_init_with_url(&addr,conscience,error);
			g_free(conscience);
			if (!rc) {
				GSETERROR(error, "Conscience [%s] specified for namespace [%s] has an invalid format",
				    conscience, name);
				continue;
			}
			g_hash_table_insert(ns_hash, g_strdup(name), g_memdup(&addr,sizeof(addr_info_t)));
		}
	}
	g_strfreev(ns_names);

	g_key_file_free(key_file);
	return 1;
}

int
parse_cluster_config(GHashTable * ns_hash, GError ** error)
{
	/* Check args */
	if (ns_hash == NULL) {
		GSETERROR(error, "Param ns_hash cannot be NULL");
		return (0);
	}

	/* Loads the mandatory CONFIG_FILE_PATH */
	if (!config_overwrite_with_file(ns_hash, CONFIG_FILE_PATH, error)) {
		GSETERROR(error, "GridStorage configuration error");
		return 0;
	}

	/* overwrite this with the content of GCLUSTER_CONFIG_DIR_PATH */
	if (g_file_test(GCLUSTER_CONFIG_DIR_PATH, G_FILE_TEST_IS_DIR|G_FILE_TEST_EXISTS)) {
		GError *error_local;
		gchar fullpath[512];
		const char *bn = NULL;
		GDir *gdir = NULL;

		error_local = NULL;
		gdir = g_dir_open(GCLUSTER_CONFIG_DIR_PATH, 0, &error_local);
		if (!gdir) {
			INFO("Failed to open config directory [%s] : %s", GCLUSTER_CONFIG_DIR_PATH,
				gerror_get_message(error_local));
			if (error_local)
				g_clear_error(&error_local);
			return 1;/* This is not so bad, in facts ...*/
		}

		while (NULL != (bn = g_dir_read_name(gdir))) {

			if (*bn == '.') /* Skip hidden files*/
				continue;

			bzero(fullpath, sizeof(fullpath));
			g_snprintf(fullpath, sizeof(fullpath)-1, "%s/%s", GCLUSTER_CONFIG_DIR_PATH, bn);
			if (!g_file_test(fullpath, G_FILE_TEST_IS_REGULAR))
				continue; /* Skip directories, allow symlinks */
			error_local = NULL;
			if (!config_overwrite_with_file(ns_hash, fullpath, &error_local))
				INFO("Could not load [%s] : %s", fullpath, gerror_get_message(error_local));
			if (error_local)
				g_clear_error(&error_local);
		}

		g_dir_close(gdir);
		if (error_local)
			g_clear_error(&error_local);
	}

	return (1);
}

/* ------------------------------------------------------------------------- */

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
	GKeyFile *kf = NULL;

	kf = g_key_file_new();
	if (g_key_file_load_from_file(kf, source, 0, NULL)) {
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
config_load_dir(GHashTable *ht_cfg, const gchar *dirname, GDir *gdir)
{
	const char *bn = NULL;

	while (NULL != (bn = g_dir_read_name(gdir))) {
		gchar *fullpath;

		if (*bn == '.')
			continue;
		fullpath = g_strconcat(dirname, G_DIR_SEPARATOR_S, bn, NULL);
		if (fullpath) {
			config_load_file(ht_cfg, fullpath);
			g_free(fullpath);
		}
	}
}

GHashTable*
gridcluster_parse_config(void)
{
	GHashTable *ht_cfg;

	ht_cfg = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	config_load_file(ht_cfg, CONFIG_FILE_PATH);

	if (g_file_test(GCLUSTER_CONFIG_DIR_PATH, G_FILE_TEST_IS_DIR|G_FILE_TEST_EXISTS)) {
		GDir *gdir = g_dir_open(GCLUSTER_CONFIG_DIR_PATH, 0, NULL);
		if (gdir) {
			config_load_dir(ht_cfg, GCLUSTER_CONFIG_DIR_PATH, gdir);
			g_dir_close(gdir);
		}
	}

	return ht_cfg;
}

gchar *
gridcluster_get_config(const gchar *ns, const gchar *what, gint how)
{
	gchar *value = NULL;

	if (how & GCLUSTER_CFG_LOCAL) {
		GHashTable *ht_cfg;
		gchar *key;

		key = _get_key(ns, what);
		if (NULL != (ht_cfg = gridcluster_parse_config())) {
			value = g_hash_table_lookup(ht_cfg, key);
			if (value)
				value = g_strdup(value);
			g_hash_table_destroy(ht_cfg);
		}
		g_free(key);
	}

	return value;
}

/* ------------------------------------------------------------------------- */

static void
config_list_file(GHashTable *ht_list, const gchar *source)
{
	GKeyFile *kf = NULL;

	kf = g_key_file_new();
	if (g_key_file_load_from_file(kf, source, 0, NULL)) {
		gchar **pg, **groups = NULL;
		groups = g_key_file_get_groups(kf, NULL);
		if (groups) {
			for (pg=groups; *pg ;pg++) {
				if (g_key_file_has_key(kf, *pg, "conscience", NULL)) {
					g_hash_table_insert(ht_list, g_strdup(*pg),
							GUINT_TO_POINTER(1));
				}
			}
			g_strfreev(groups);
		}
	}
	g_key_file_free(kf);
}

static void
config_list_dir(GHashTable *ht_list, const gchar *dirname, GDir *gdir)
{
	const char *bn = NULL;

	while (NULL != (bn = g_dir_read_name(gdir))) {
		gchar *fullpath;

		if (*bn == '.')
			continue;
		fullpath = g_strconcat(dirname, G_DIR_SEPARATOR_S, bn, NULL);
		if (fullpath) {
			config_list_file(ht_list, fullpath);
			g_free(fullpath);
		}
	}
}

gchar **
gridcluster_list_ns(void)
{
	GHashTable *ht_list = g_hash_table_new(g_str_hash, g_str_equal);

	config_list_file(ht_list, CONFIG_FILE_PATH);

	if (g_file_test(GCLUSTER_CONFIG_DIR_PATH, G_FILE_TEST_IS_DIR|G_FILE_TEST_EXISTS)) {
		GDir *gdir = g_dir_open(GCLUSTER_CONFIG_DIR_PATH, 0, NULL);
		if (gdir) {
			config_list_dir(ht_list, GCLUSTER_CONFIG_DIR_PATH, gdir);
			g_dir_close(gdir);
		}
	}

	int i;
	gchar **result;
	GHashTableIter iter;
	gpointer k, v;

	result = g_malloc0(sizeof(gchar*) * (g_hash_table_size(ht_list) + 1));
	g_hash_table_iter_init(&iter, ht_list);
	for (i=0; g_hash_table_iter_next(&iter, &k, &v); i++)
		result[i] = (gchar*)k;
	g_hash_table_destroy(ht_list);

	return result;
}

