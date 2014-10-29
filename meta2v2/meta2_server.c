#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.meta2.server"
#endif

#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <glib.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>
#include <server/network_server.h>
#include <server/transport_gridd.h>
#include <server/grid_daemon.h>
#include <resolver/hc_resolver.h>
#include <sqliterepo/sqliterepo.h>
#include <sqliterepo/replication_dispatcher.h>
#include <sqliterepo/upgrade.h>
#include <meta2v2/meta2_gridd_dispatcher.h>
#include <meta2v2/meta2_backend.h>
#include <meta2v2/meta2_backend_dbconvert.h>
#include <meta2v2/meta2_events.h>
#include <sqlx/sqlx_service.h>
#include <sqlx/sqlx_service_extras.h>

static struct meta2_backend_s *m2 = NULL;
static struct sqlx_upgrader_s *upgrader = NULL;


static void
_task_reconfigure_m2(gpointer p)
{
	meta2_backend_configure_nsinfo(m2, &(PSRV(p)->nsinfo));
}

static void
_task_notify_modified_containers(gpointer p)
{
	(void) p;
	GRID_DEBUG("Notifying modified containers");
	meta2_backend_notify_modified_containers(m2);
	GRID_DEBUG("Notification done");
}

static inline gchar **
filter_services(struct sqlx_service_s *ss,
		gchar **s, gint64 seq, const gchar *t)
{
	gboolean matched = FALSE;
	GPtrArray *tmp = g_ptr_array_new();
	(void) seq;
	for (; *s ;s++) {
		struct meta1_service_url_s *u = meta1_unpack_url(*s);
		if (0 == strcmp(t, u->srvtype)) {
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
		if (GRID_DEBUG_ENABLED()) {
			gchar *peers = g_strjoinv(", ", (gchar**)tmp->pdata);
			GRID_DEBUG("Peers: %s", peers);
			g_free(peers);
		}
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

static struct hc_url_s *
_init_hc_url(struct sqlx_service_s *ss, const gchar *n, gint64 *pseq)
{
	struct hc_url_s *u = hc_url_empty();

	hc_url_set(u, HCURL_NS, ss->ns_name);
	const gchar *sep = strchr(n, '@');
	gint64 seq = 1;

	if (!sep)
		sep = n;
	else {
		seq = g_ascii_strtoll(n, NULL, 10);
		++ sep;
	}
	if (!hc_url_set(u, HCURL_HEXID, sep)) {
		hc_url_clean(u);
		return NULL;
	}
	if (pseq)
		*pseq = seq;
	return u;
}

static GError *
_get_peers(struct sqlx_service_s *ss, const gchar *n, const gchar *t,
		gboolean nocache, gchar ***result)
{
	if (!n || !t || !result)
		return NEWERROR(500, "BUG [%s:%s:%d]", __FUNCTION__, __FILE__, __LINE__);
	if (!g_str_has_prefix(t, META2_TYPE_NAME))
		return NEWERROR(400, "Invalid type name: '%s'", t);

	gint retries = 1;
	gint64 seq = 1;
	struct hc_url_s *u = NULL;
	gchar **peers = NULL;
	GError *err = NULL;

	u = _init_hc_url(ss, n, &seq);
	if (!u)
		return NEWERROR(400, "Invalid base name [%s]", n);

retry:
	if (nocache) {
		hc_decache_reference_service(ss->resolver, u, t);
	}
	err = hc_resolve_reference_service(ss->resolver, u, t, &peers);

	if (NULL != err) {
		g_prefix_error(&err, "Peer resolution error: ");
		hc_url_clean(u);
		return err;
	}

	if (!(*result = filter_services_and_clean(ss, peers, seq, t))) {
		if (retries-- > 0) {
			peers = NULL;
			nocache = TRUE;
			goto retry;
		}
		err = NEWERROR(CODE_CONTAINER_NOTFOUND, "Base not managed");
	}

	hc_url_clean(u);
	return err;
}

static GError*
_upgrade_to_18(struct sqlx_sqlite3_s *sq3, gpointer cb_data)
{
	(void) cb_data;
	g_assert(sq3->db != NULL);
	return m2_convert_db(sq3->db);
}

static GError*
meta2_on_open(struct sqlx_sqlite3_s *sq3, gpointer cb_data)
{
	return sqlx_upgrade_do((struct sqlx_upgrader_s *)cb_data, sq3);
}

static void
meta2_on_close(struct sqlx_sqlite3_s *sq3, gboolean deleted, gpointer cb_data)
{
	EXTRA_ASSERT(sq3 != NULL);

	if (!deleted)
		return;

	struct hc_url_s *u = _init_hc_url(PSRV(cb_data), sq3->logical_name, NULL);
	if (!u) {
		GRID_WARN("Invalid base name [%s]", sq3->logical_name);
		return;
	}
	hc_decache_reference_service(PSRV(cb_data)->resolver, u, META2_TYPE_NAME);
	hc_url_clean(u);
	u = NULL;
}

static gboolean
_post_config(struct sqlx_service_s *ss)
{
	GError *err = NULL;

	upgrader = sqlx_upgrader_create();
	sqlx_upgrader_register(upgrader, "!1.8", "1.8", _upgrade_to_18, NULL);
	sqlx_repository_configure_open_callback(ss->repository, meta2_on_open, upgrader);

	err = sqlx_service_extras_init(ss);
	if (err != NULL) {
		GRID_WARN("%s", err->message);
		g_clear_error(&err);
		return FALSE;
	}

	// prepare a meta2 backend
	err = meta2_backend_init(&m2, ss->repository, ss->ns_name, ss->extras->lb,
			ss->resolver, ss->extras->evt_repo);
	if (err) {
		GRID_WARN("META2 backend init failure: (%d) %s", err->code, err->message);
		g_clear_error(&err);
		return FALSE;
	}
	meta2_backend_build_meta0_prefix_mapping(m2);
	GRID_DEBUG("META0 mappings now ready");

	/* Make deleted bases exit the cache */
	sqlx_repository_configure_close_callback(ss->repository, meta2_on_close, ss);

	// Register meta2 requests handlers
	transport_gridd_dispatcher_add_requests(ss->dispatcher,
			meta2_gridd_get_v1_requests(), m2);
	transport_gridd_dispatcher_add_requests(ss->dispatcher,
			meta2_gridd_get_v2_requests(), m2);

	// Register few meta2 tasks
	grid_task_queue_register(ss->gtq_reload, 5,
			(GDestroyNotify)sqlx_task_reload_event_config, NULL, ss);
	grid_task_queue_register(ss->gtq_reload, 5,
			_task_reconfigure_m2, NULL, ss);
	grid_task_queue_register(ss->gtq_reload, 10,
			(GDestroyNotify)sqlx_task_reload_lb, NULL, ss);

	grid_task_queue_register(ss->gtq_admin, 30,
			_task_notify_modified_containers, NULL, NULL);

	return TRUE;
}

int
main(int argc, char **argv)
{
	struct sqlx_service_config_s cfg = {
		META2_TYPE_NAME, "m2v2", "el/meta2", 2, 2, schema,
		_get_peers, _post_config, NULL
	};
	int rc = sqlite_service_main(argc, argv, &cfg);
	if (m2)
		meta2_backend_clean(m2);
	if (upgrader)
		sqlx_upgrader_destroy(upgrader);
	m2v2_clean_db();
	return rc;
}

