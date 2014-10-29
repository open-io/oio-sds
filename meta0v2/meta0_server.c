#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.meta0.server"
#endif

#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>

#include <sqliterepo/sqliterepo.h>
#include <sqliterepo/replication_dispatcher.h>
#include <sqliterepo/zk_manager.h>

#include <server/network_server.h>
#include <server/grid_daemon.h>
#include <server/stats_holder.h>
#include <server/transport_gridd.h>
#include <sqlx/sqlx_service.h>

#include "./internals.h"
#include "./meta0_backend.h"
#include "./meta0_gridd_dispatcher.h"

static struct zk_manager_s *m0zkmanager = NULL;
static gboolean zk_registered = FALSE;
static struct meta0_backend_s *m0 = NULL;
static struct meta0_disp_s *m0disp = NULL;

static gboolean
_register_to_zookeeper(struct sqlx_service_s *ss)
{
	if (ss->url && ss->zk_url && m0zkmanager) {
		GError *err = create_zk_node(m0zkmanager, NULL, ss->url->str, ss->url->str);
		if (err) {
			GRID_WARN("Failed to register meta0 [%s] to zookeeper", ss->url->str);
			g_clear_error(&err);
			return FALSE;
		}
	}
	return TRUE;
}

static void
_task_zk_registration(gpointer p)
{
	EXTRA_ASSERT(p != NULL);
	if (!zk_registered)
		zk_registered = _register_to_zookeeper(PSRV(p));
}

/* -------------------------------------------------------------------------- */

static gchar **
strv_filter(struct sqlx_service_s *ss, GSList *l)
{
	GPtrArray *tmp = g_ptr_array_new();
	for (; l!=NULL ;l=l->next) {
		struct zk_node_s *zknode = l->data;
		if (!zknode->content)
			continue;
		if (!g_ascii_strcasecmp(ss->url->str, zknode->content))
			continue;
		addr_info_t addr;
		if (!l4_address_init_with_url(&addr, zknode->content, NULL))
			continue;
		g_ptr_array_add(tmp, zknode->content);
		zknode->content = NULL;
	}

	g_ptr_array_add(tmp, NULL);
	return (gchar**)g_ptr_array_free(tmp, FALSE);
}

static GError *
_get_peers(struct sqlx_service_s *ss, const gchar *n, const gchar *t,
		gboolean nocache, gchar ***result)
{
	GSList *peers;
	GError *err;

	if (!n || !t || !result)
		return NEWERROR(500, "BUG [%s:%s:%d]", __FUNCTION__, __FILE__, __LINE__);
	if (g_ascii_strcasecmp(t, META0_TYPE_NAME))
		return NEWERROR(400, "Invalid type name");
	if (g_ascii_strcasecmp(n, ss->ns_name))
		return NEWERROR(400, "Invalid base name, expected [%s]", ss->ns_name);

	err = list_zk_children_node(m0zkmanager, NULL, &peers);
	if (err) {
		g_slist_free_full(peers, g_free);
		*result = NULL;
		g_prefix_error(&err, "ZooKeeper error: ");
		return err;
	}

	if (!(*result = strv_filter(ss, peers)))
		return NEWERROR(CODE_CONTAINER_NOTFOUND, "Base not managed");
	return NULL;
}


static void
_callback_change(struct sqlx_sqlite3_s *sq3, gpointer u)
{
	(void) sq3, (void) u;
	meta0_gridd_requested_reload(m0disp);
}

static gboolean
_post_config(struct sqlx_service_s *ss)
{
	GError *err;

	// Create the backend
	m0 = meta0_backend_init(ss->ns_name, ss->url->str, ss->repository);
	if (!m0) {
		GRID_WARN("META0 backend init failure");
		return FALSE;
	}

	// Create the zookeeper poller
	if (ss->zk_url) {
		err = zk_srv_manager_create(ss->ns_name, ss->zk_url,
				META0_TYPE_NAME, &m0zkmanager);
		if (err) {
			GRID_WARN("Zk manager init failed : (%d) %s",err->code, err->message);
			g_clear_error(&err);
			return FALSE;
		}
		for (;;) {
			err = create_zk_node(m0zkmanager, NULL, ss->url->str, ss->url->str);
			if (!err)
				break;
			GRID_DEBUG("Meta0's zookeeper node creation failure : (%d) %s",
				err->code, err->message);
			g_clear_error(&err);
			sleep(1);
		}
	}

	m0disp = meta0_gridd_get_dispatcher(m0, m0zkmanager, ss->ns_name);

	transport_gridd_dispatcher_add_requests(ss->dispatcher,
			meta0_gridd_get_requests(), m0disp);

	meta0_backend_migrate(m0);

	meta0_gridd_requested_reload(m0disp);

	sqlx_repository_configure_change_callback(ss->repository,
			_callback_change, NULL);

	grid_task_queue_register(ss->gtq_register, 3,
			_task_zk_registration, NULL, ss);

	return TRUE;
}

int
main(int argc, char ** argv)
{
	const struct sqlx_service_config_s cfg = {
		"meta0", "m0v2", "el/meta0", 0, 0, META0_SCHEMA,
		_get_peers, _post_config, NULL
	};
	int rc = sqlite_service_main(argc, argv, &cfg);
	if (m0zkmanager)
		zk_manager_clean(m0zkmanager);
	if (m0disp)
		meta0_gridd_free_dispatcher(m0disp);
	if (m0)
		meta0_backend_clean(m0);
	return rc;
}

