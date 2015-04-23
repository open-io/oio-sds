/*
OpenIO SDS sqlx
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.sqlx.server"
#endif

#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>

#include <glib.h>

#include <metautils/lib/metautils.h>
#include <resolver/hc_resolver.h>
#include <server/grid_daemon.h>
#include <server/transport_gridd.h>
#include <sqliterepo/replication_dispatcher.h>
#include "sqlx_service.h"

#define SQLX_TYPE "sqlx"

#define SQLX_SCHEMA \
	"INSERT INTO admin(k,v) VALUES (\"schema_version\",\"1.7\");"\
	"INSERT INTO admin(k,v) VALUES (\"version:main.admin\",\"1:0\");"\
	"VACUUM"

static gchar **
filter_services(struct sqlx_service_s *ss, gchar **s, gint64 seq, const gchar *t)
{
	gboolean matched = FALSE;
	GPtrArray *tmp = g_ptr_array_new();
	for (; *s ;s++) {
		struct meta1_service_url_s *u = meta1_unpack_url(*s);
		if (seq == u->seq && 0 == strcmp(t, u->srvtype)) {
			if (!g_ascii_strcasecmp(u->host, ss->url->str))
				matched = TRUE;
			else
				g_ptr_array_add(tmp, g_strdup(u->host));
		}
		meta1_service_url_clean(u);
	}

	if (matched) {
		g_ptr_array_add(tmp, NULL);
		return (gchar**)g_ptr_array_free(tmp, FALSE);
	}
	else {
		g_ptr_array_add(tmp, NULL);
		g_strfreev((gchar**)g_ptr_array_free(tmp, FALSE));
		return NULL;
	}
}

static gchar **
filter_services_and_clean(struct sqlx_service_s *ss,
		gchar **src, gint64 seq, const gchar *type)
{
	if (!src)
		return NULL;
	gchar **result = filter_services(ss, src, seq, type);
	g_strfreev(src);
	return result;
}

static GError *
_get_peers(struct sqlx_service_s *ss, struct sqlx_name_s *n,
		gboolean nocache, gchar ***result)
{
	EXTRA_ASSERT(ss != NULL);
	EXTRA_ASSERT(result != NULL);
	SQLXNAME_CHECK(n);

	const gchar *sep = strchr(n->base, '@');
	if (!sep)
		return NEWERROR(CODE_BAD_REQUEST, "Invalid base name [%s]", n->base);

	gint64 seq = g_ascii_strtoll(n->base, NULL, 10);
	struct hc_url_s *u = hc_url_empty();
	hc_url_set(u, HCURL_NS, ss->ns_name);
	if (!hc_url_set(u, HCURL_HEXID, sep+1)) {
		hc_url_clean(u);
		return NEWERROR(CODE_BAD_REQUEST, "Invalid HEXID [%s]", sep+1);
	}

	if (nocache) {
		hc_decache_reference_service(ss->resolver, u, n->type);
	}

	gchar **peers = NULL;
	GError *err = hc_resolve_reference_service(ss->resolver, u, n->type, &peers);
	hc_url_clean(u);

	if (NULL != err) {
		g_prefix_error(&err, "Peer resolution error");
		return err;
	}

	if (!(*result = filter_services_and_clean(ss, peers, seq, n->type)))
		return NEWERROR(CODE_CONTAINER_NOTFOUND, "Base not managed");
	return NULL;
}

static gboolean
_post_config(struct sqlx_service_s *ss)
{
	transport_gridd_dispatcher_add_requests(ss->dispatcher,
			sqlx_sql_gridd_get_requests(), ss->repository);

	// TODO maybe enable notifications
	return TRUE;
}

static void
_set_defaults(struct sqlx_service_s *ss)
{
	ss->flag_cached_bases = FALSE;
}

int
main(int argc, char ** argv)
{
	static struct sqlx_service_config_s cfg = {
		NAME_SRVTYPE_SQLX, "sqlxv1", "el/sqlx", 1, 3, SQLX_SCHEMA,
		_get_peers, _post_config, _set_defaults
	};
	return sqlite_service_main(argc, argv, &cfg);
}

