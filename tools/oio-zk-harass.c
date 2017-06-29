/*
OpenIO SDS oio-zk-harass
Copyright (C) 2017 OpenIO, as part of OpenIO Software Defined Storage

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

#include <unistd.h>

#include <glib.h>

#include <core/oiolog.h>
#include <metautils/lib/metautils.h>
#include <sqliterepo/synchro.h>

static GString *ns_name = NULL;
static gchar zkurl[1024] = "";

static guint nb_items = 0;
static GString *salt = NULL;

static struct sqlx_sync_s *ssync = NULL;

struct item_s {
	gint64 when_start;
	gint64 when_created;
	gint64 when_monitored;
	gint64 when_listed;
	gchar path[];
};

static struct item_s **paths = NULL;

static void
_listed(int zrc, const struct String_vector *sv, const void *data)
{
	guint idx = GPOINTER_TO_UINT(data);
	struct item_s *item = paths[idx];

	if (zrc == ZOK) {
		item->when_listed = g_get_monotonic_time();
		GRID_TRACE("listed %" G_GINT64_FORMAT " %s rc=%d siblings=%u",
				item->when_listed - item->when_start,
				item->path, zrc, (guint)sv->count);

		static guint64 count_delta = 0;
		static guint64 total_delta = 0;
		const guint64 delta = item->when_listed - item->when_start;
		total_delta += delta;
		count_delta ++;
		if (count_delta >= 1024) {
			GRID_INFO("RTT %" G_GUINT64_FORMAT "ms",
					(total_delta / count_delta) / G_TIME_SPAN_MILLISECOND);
			count_delta = 0;
			total_delta = 0;
		}
	} else {
		GRID_WARN("not listed %s rc=%d", item->path, zrc);
	}
}

static void
_watching_completion(int zrc, const struct Stat *s UNUSED, const void *data)
{
	guint idx = GPOINTER_TO_UINT(data);
	struct item_s *item = paths[idx];

	if (zrc == ZOK) {
		item->when_monitored = g_get_monotonic_time();
		GRID_TRACE("watching %" G_GINT64_FORMAT " %s rc=%d",
				item->when_monitored - item->when_start,
				item->path, zrc);
		sqlx_sync_awget_siblings(ssync, item->path,
			NULL, NULL, _listed, GUINT_TO_POINTER(idx));
	} else {
		GRID_WARN("not watching %s rc=%d", item->path, zrc);
	}
}

static void
_watching_monitor(zhandle_t *h UNUSED, int type, int state,
		const char *path UNUSED, void *data)
{
	guint idx = GPOINTER_TO_UINT(data);
	struct item_s *item = paths[idx];
	GRID_DEBUG("LEFT %u/%s %d/%d", idx, item->path, type, state);
}

static void
_created(int rc, const char *_path, const void *data)
{
	guint idx = GPOINTER_TO_UINT(data);
	struct item_s *item = paths[idx];
	const char *path = _path ? strrchr(_path, '/')+1 : NULL;

	if (rc == ZOK) {
		item->when_created = g_get_monotonic_time();
		strcpy(item->path, path);
		GRID_TRACE("created %" G_GINT64_FORMAT " %s rc=%d",
				item->when_created - item->when_start,
				item->path, rc);
		sqlx_sync_awexists(ssync, item->path,
				_watching_monitor, GUINT_TO_POINTER(idx),
				_watching_completion, GUINT_TO_POINTER(idx));
	} else {
		GRID_WARN("not created %s rc=%d", item->path, rc);
	}
}

static void
_kickoff(void)
{
	const char *v = zkurl;
	const gsize vlen = strlen(zkurl);

	GChecksum *h = g_checksum_new(G_CHECKSUM_SHA256);
	for (guint i=0; i<nb_items && grid_main_is_running(); ++i) {
		g_checksum_reset(h);
		g_checksum_update(h, (guint8*)salt, sizeof(salt));
		g_checksum_update(h, (guint8*)&i, sizeof(i));

		struct item_s *item = g_malloc0(sizeof(struct item_s) + 64 + 1 + 10 + 1);
		paths[i] = item;
		item->when_start = g_get_monotonic_time();
		strcpy(item->path, g_checksum_get_string(h));
		for (gchar *p=item->path; *p ;++p)
			*p = g_ascii_toupper(*p);
		item->path[64] = '-';
		item->path[65] = '\0';

		sqlx_sync_acreate(ssync, item->path, v, vlen, ZOO_EPHEMERAL|ZOO_SEQUENCE,
				_created, GUINT_TO_POINTER(i));

		g_usleep(50 * G_TIME_SPAN_MILLISECOND);
	}
	g_checksum_free(h);
}

static void
cli_action (void)
{
	GRID_NOTICE("Starting");

	_kickoff();
	while (grid_main_is_running())
		g_usleep(G_TIME_SPAN_SECOND);

	GRID_NOTICE("Exiting");
}

static struct grid_main_option_s *
cli_get_options(void)
{
	static struct grid_main_option_s cli_options[] = {
		{"Ns", OT_STRING, {.str=&ns_name}, "oio-sds NS name (used for the config)"},
		{"NbItems", OT_UINT, {.u=&nb_items}, "number of elections per worker thread"},
		{"Salt", OT_STRING, {.str=&salt}, "change the salt to compute the election keys"},
		{NULL, 0, {.i=0}, NULL}
	};

	return cli_options;
}

static void
cli_set_defaults(void)
{
	if (!ns_name)
		ns_name = g_string_new("OPENIO");
	else
		g_string_assign(ns_name, "OPENIO");
	memset(zkurl, 0, sizeof(zkurl));
	nb_items = 32768;
	ssync = NULL;
	salt = g_string_new("default");
}

static void
cli_specific_fini(void)
{
	if (ssync) {
		sqlx_sync_close(ssync);
		sqlx_sync_clear(ssync);
		ssync = NULL;
	}
	if (paths) {
		for (guint i=0; i<nb_items ;++i)
			g_free0(paths[i]);
		g_free(paths);
		paths = NULL;
	}
}

static void cli_specific_stop(void) { /* no op */ }

static const gchar *
cli_usage(void)
{
	return "ZK_CNX_STRING\n";
}

static gboolean
cli_configure(int argc, char **argv)
{
	if (!oio_var_value_with_files(ns_name->str, TRUE, NULL)) {
		GRID_ERROR("NS [%s] unknown in the configuration", ns_name->str);
		return FALSE;
	}

	if (argc != 1) {
		GRID_ERROR("Expected ZK connection string");
		return FALSE;
	}

	g_strlcpy(zkurl, argv[0], sizeof(zkurl));
	ssync = sqlx_sync_create(zkurl);
	if (!ssync) {
		GRID_ERROR("ZK connector error (init)");
		return FALSE;
	}

	gchar prefix[64 + LIMIT_LENGTH_NSNAME];
	g_snprintf(prefix, sizeof(prefix), "/hc/ns/%s/el/meta2", ns_name->str);

	sqlx_sync_set_prefix(ssync, prefix);
	sqlx_sync_set_hash(ssync, 2, 2);

	GError *err = sqlx_sync_open(ssync);
	if (err) {
		GRID_ERROR("ZK connection error: (%d) %s", err->code, err->message);
		g_clear_error(&err);
		return FALSE;
	}

	paths = g_malloc0(sizeof(gchar*) * nb_items);
	return TRUE;
}

struct grid_main_callbacks cli_callbacks =
{
	.options = cli_get_options,
	.action = cli_action,
	.set_defaults = cli_set_defaults,
	.specific_fini = cli_specific_fini,
	.configure = cli_configure,
	.usage = cli_usage,
	.specific_stop = cli_specific_stop,
};

int
main(int argc, char **args)
{
	return grid_main_cli(argc, args, &cli_callbacks);
}

