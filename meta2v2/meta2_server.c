/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015-2016 OpenIO, as part of OpenIO Software Defined Storage

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

#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>
#include <server/network_server.h>
#include <server/transport_gridd.h>
#include <resolver/hc_resolver.h>
#include <sqliterepo/sqliterepo.h>
#include <sqliterepo/replication_dispatcher.h>
#include <sqliterepo/upgrade.h>
#include <meta2v2/meta2_gridd_dispatcher.h>
#include <meta2v2/meta2_backend.h>
#include <meta2v2/meta2_backend_internals.h>
#include <meta2v2/meta2_events.h>
#include <sqlx/sqlx_service.h>

static struct meta2_backend_s *m2 = NULL;

static void
_task_reconfigure_m2(gpointer p)
{
	if (!PSRV(p)->nsinfo)
		return;
	meta2_backend_configure_nsinfo(m2, PSRV(p)->nsinfo);
}

static void
_task_reload_m2_lb(gpointer p)
{
	ADAPTIVE_PERIOD_DECLARE();
	if (!PSRV(p)->nsinfo)
		return;

	if (ADAPTIVE_PERIOD_SKIP())
		return;

	oio_lb_world__reload_pools(PSRV(p)->lb_world, PSRV(p)->lb,
			PSRV(p)->nsinfo);

	/* In meta2, we are only interrested in rawx and kinetic services */
	GSList *svctypes = NULL;
	svctypes = g_slist_prepend(svctypes, NAME_SRVTYPE_RAWX);
	svctypes = g_slist_prepend(svctypes, NAME_SRVTYPE_KINE);
	GError *err = sqlx_reload_lb_service_types(PSRV(p)->lb_world, PSRV(p)->lb,
			svctypes);
	if (err) {
		GRID_WARN("Failed to reload "NAME_SRVTYPE_RAWX" services: %s",
				err->message);
		g_clear_error(&err);
	} else {
		ADAPTIVE_PERIOD_ONSUCCESS(10);
	}
	g_slist_free(svctypes);

	oio_lb_world__reload_storage_policies(PSRV(p)->lb_world,
			PSRV(p)->lb, PSRV(p)->nsinfo);
	oio_lb_world__debug(PSRV(p)->lb_world);
}

static gchar **
filter_services(struct sqlx_service_s *ss,
		gchar **s, gint64 seq, const gchar *type)
{
	gboolean matched = FALSE;
	GPtrArray *tmp = g_ptr_array_new();
	(void) seq;
	for (; *s ;s++) {
		struct meta1_service_url_s *u = meta1_unpack_url(*s);
		if (0 == strcmp(type, u->srvtype)) {
			if (!g_ascii_strcasecmp(u->host, ss->url->str))
				matched = TRUE;
			else
				g_ptr_array_add(tmp, g_strdup(u->host));
		}
		meta1_service_url_clean(u);
	}

	gchar **out = (gchar**)metautils_gpa_to_array (tmp, TRUE);
	if (matched)
		return out;
	g_strfreev (out);
	return NULL;
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
_get_peers(struct sqlx_service_s *ss, const struct sqlx_name_s *n,
		gboolean nocache, gchar ***result)
{
	EXTRA_ASSERT(ss != NULL);
	EXTRA_ASSERT(result != NULL);

	gint retries = 1;
	gchar **peers = NULL;
	GError *err = NULL;

	gint64 seq = 1;
	struct oio_url_s *u = oio_url_empty ();
	oio_url_set(u, OIOURL_NS, ss->ns_name);
	if (!sqlx_name_extract (n, u, NAME_SRVTYPE_META2, &seq)) {
		oio_url_pclean (&u);
		return BADREQ("Invalid type name: '%s'", n->type);
	}

retry:
	if (nocache) {
		hc_decache_reference_service(ss->resolver, u, n->type);
		if (!result) {
			oio_url_pclean (&u);
			return NULL;
		}
	}

	peers = NULL;
	err = hc_resolve_reference_service(ss->resolver, u, n->type, &peers);

	if (NULL != err) {
		g_prefix_error(&err, "Peer resolution error: ");
		oio_url_clean(u);
		return err;
	}

	gchar **out = filter_services_and_clean(ss, peers, seq, n->type);

	if (!out) {
		if (retries-- > 0) {
			nocache = TRUE;
			goto retry;
		}
		err = NEWERROR(CODE_CONTAINER_NOTFOUND, "Base not managed");
	}

	if (err) {
		if (out)
			g_strfreev (out);
		*result = NULL;
	} else {
		*result = out;
	}

	oio_url_clean(u);
	return err;
}

static void
meta2_on_close(struct sqlx_sqlite3_s *sq3, gboolean deleted, gpointer cb_data)
{
	gint64 seq = 1;
	EXTRA_ASSERT(sq3 != NULL);

	if (!deleted)
		return;

	struct oio_url_s *u = oio_url_empty ();
	oio_url_set (u, OIOURL_NS, PSRV(cb_data)->ns_name);
	if (!sqlx_name_extract ((struct sqlx_name_s*)&sq3->name, u, NAME_SRVTYPE_META2, &seq)) {
		GRID_WARN("Invalid base name [%s]", sq3->name.base);
		return;
	}
	hc_decache_reference_service(PSRV(cb_data)->resolver, u, NAME_SRVTYPE_META2);
	oio_url_pclean(&u);
}

static gboolean
_post_config(struct sqlx_service_s *ss)
{
	GError *err = NULL;

	if (err != NULL) {
		GRID_WARN("%s", err->message);
		g_clear_error(&err);
		return FALSE;
	}

	// prepare a meta2 backend
	err = meta2_backend_init(&m2, ss->repository, ss->ns_name, ss->lb, ss->resolver);
	if (NULL != err) {
		GRID_WARN("META2 backend init failure: (%d) %s", err->code, err->message);
		g_clear_error(&err);
		return FALSE;
	}

	/* Make deleted bases exit the cache */
	sqlx_repository_configure_close_callback(ss->repository, meta2_on_close, ss);

	/* Make base replications update the cache */
	sqlx_repository_configure_change_callback(ss->repository,
			(sqlx_repo_change_hook)meta2_backend_change_callback, m2);

	/* Register meta2 requests handlers */
	transport_gridd_dispatcher_add_requests(ss->dispatcher,
			meta2_gridd_get_v2_requests(), m2);

	/* Register few meta2 tasks */
	grid_task_queue_register(ss->gtq_reload, 5,
			_task_reconfigure_m2, NULL, ss);
	grid_task_queue_register(ss->gtq_reload, 1,
			(GDestroyNotify)_task_reload_m2_lb, NULL, ss);

	m2->notifier = ss->events_queue;
	return TRUE;
}

int
main(int argc, char **argv)
{
	struct sqlx_service_config_s cfg = {
		NAME_SRVTYPE_META2, "m2v2",
		"el/" NAME_SRVTYPE_META2, 2, 2,
		schema, 1, 3,
		_get_peers, _post_config, NULL
	};

	int rc = sqlite_service_main (argc, argv, &cfg);
	if (m2)
		meta2_backend_clean (m2);
	return rc;
}

