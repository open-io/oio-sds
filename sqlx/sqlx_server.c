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

static inline gchar **
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
_get_peers(struct sqlx_service_s *ss, const gchar *n, const gchar *t,
		gboolean nocache, gchar ***result)
{
	if (!n || !t || !result)
		return NEWERROR(500, "BUG [%s:%s:%d]", __FUNCTION__, __FILE__, __LINE__);

	const gchar *sep = strchr(n, '@');
	if (!sep)
		return NEWERROR(400, "Invalid base name [%s]", n);

	gint64 seq = g_ascii_strtoll(n, NULL, 10);
	struct hc_url_s *u = hc_url_empty();
	hc_url_set(u, HCURL_NS, ss->ns_name);
	if (!hc_url_set(u, HCURL_HEXID, sep+1)) {
		hc_url_clean(u);
		return NEWERROR(400, "Invalid HEXID [%s]", sep+1);
	}

	if (nocache) {
		hc_decache_reference_service(ss->resolver, u, t);
	}

	gchar **peers = NULL;
	GError *err = hc_resolve_reference_service(ss->resolver, u, t, &peers);
	hc_url_clean(u);

	if (NULL != err) {
		g_prefix_error(&err, "Peer resolution error");
		return err;
	}

	if (!(*result = filter_services_and_clean(ss, peers, seq, t)))
		return NEWERROR(CODE_CONTAINER_NOTFOUND, "Base not managed");
	return NULL;
}

static gboolean
_post_config(struct sqlx_service_s *ss)
{
	transport_gridd_dispatcher_add_requests(ss->dispatcher,
			sqlx_sql_gridd_get_requests(), ss->repository);
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
		"sqlx", "sqlxv1", "el/sqlx", 2, 2, SQLX_SCHEMA,
		_get_peers, _post_config, _set_defaults
	};
	return sqlite_service_main(argc, argv, &cfg);
}

