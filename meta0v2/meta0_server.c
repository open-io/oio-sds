/*
OpenIO SDS meta0v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS

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

#include <glib.h>

#include <metautils/lib/metautils.h>

#include <sqliterepo/sqliterepo.h>

#include <server/transport_gridd.h>
#include <sqlx/sqlx_service.h>

#include "meta0_backend.h"
#include "meta0_gridd_dispatcher.h"
#include "zk_manager.h"

static struct zk_manager_s *m0zkmanager = NULL;
static struct meta0_backend_s *m0 = NULL;
static struct meta0_disp_s *m0disp = NULL;

static gboolean
_register_to_zookeeper(struct sqlx_service_s *ss)
{
	if (ss->url && ss->zk_url && m0zkmanager) {
		GError *err = create_zk_node(m0zkmanager, NULL, ss->url->str, ss->url->str);
		if (err) {
			GRID_WARN("Failed to register meta0 [%s] to zookeeper: %s",
					ss->url->str, err->message);
			g_clear_error(&err);
			return FALSE;
		}
	}
	return TRUE;
}

/* -------------------------------------------------------------------------- */

static gchar **
strv_filter(struct sqlx_service_s *ss, GSList *l)
{
	(void) ss;
	GPtrArray *tmp = g_ptr_array_new();
	for (; l != NULL; l = l->next) {
		struct zk_node_s *zknode = l->data;
		if (!zknode->content)
			continue;
		addr_info_t addr;
		if (!grid_string_to_addrinfo(zknode->content, &addr))
			continue;
		g_ptr_array_add(tmp, zknode->content);
		zknode->content = NULL;
	}

	g_ptr_array_add(tmp, NULL);
	return (gchar**)g_ptr_array_free(tmp, FALSE);
}

static GError *
_get_peers(struct sqlx_service_s *ss, const struct sqlx_name_s *n,
		gboolean nocache UNUSED, gchar ***result)
{
	if (!n || !result)
		return SYSERR("BUG [%s:%s:%d]", __FUNCTION__, __FILE__, __LINE__);
	if (0 != strcmp(n->type, NAME_SRVTYPE_META0))
		return BADREQ("Invalid type name");
	if (0 != strcmp(n->base, ss->ns_name))
		return BADREQ("Invalid base name, expected [%s]", ss->ns_name);

	GSList *peers = NULL;
	GError *err = list_zk_children_node(m0zkmanager, NULL, &peers);
	if (err) {
		g_slist_free_full(peers, (GDestroyNotify)free_zknode);
		*result = NULL;
		g_prefix_error(&err, "ZooKeeper error: ");
		return err;
	}

	*result = strv_filter(ss, peers);
	g_slist_free_full(peers, (GDestroyNotify)free_zknode);
	if (likely(*result != NULL))
		return NULL;

	return NEWERROR(CODE_CONTAINER_NOTFOUND, "Base not managed");
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
				NAME_SRVTYPE_META0, &m0zkmanager);
		if (err) {
			GRID_WARN("Zk manager init failed: (%d) %s",
					err->code, err->message);
			g_clear_error(&err);
			return FALSE;
		}

		gboolean done = FALSE;
		for (guint i=0; i < 10 && !done && grid_main_is_running(); ++i) {
			done = _register_to_zookeeper(ss);
			if (!done)
				g_usleep(1 * G_TIME_SPAN_SECOND);
		}
		if (!done) {
			GRID_ERROR("Too many errors while registering in Zookeeper");
			return FALSE;
		}
	}

	m0disp = meta0_gridd_get_dispatcher(m0, ss->ns_name);

	transport_gridd_dispatcher_add_requests(ss->dispatcher,
			meta0_gridd_get_requests(), m0disp);

	meta0_gridd_requested_reload(m0disp);

	sqlx_repository_configure_change_callback(ss->repository,
			_callback_change, NULL);

	return TRUE;
}

static void
_set_defaults (struct sqlx_service_s *ss __attribute((unused)))
{
}

int
main(int argc, char ** argv)
{
	const struct sqlx_service_config_s cfg = {
		NAME_SRVTYPE_META0,
		"el/"NAME_SRVTYPE_META0, 0, 0,
		META0_SCHEMA, 0, 0,
		_get_peers, _post_config, _set_defaults
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

