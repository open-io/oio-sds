/*
OpenIO SDS meta1v2
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
#include <sys/resource.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>
#include <server/network_server.h>
#include <server/stats_holder.h>
#include <server/transport_gridd.h>
#include <sqliterepo/sqliterepo.h>
#include <sqliterepo/election.h>
#include <sqliterepo/replication_dispatcher.h>
#include <sqlx/sqlx_service.h>

#include "./internals.h"
#include "./meta1_backend.h"
#include "./meta1_backend_internals.h"
#include "./meta1_prefixes.h"
#include "./meta1_gridd_dispatcher.h"

static struct meta1_backend_s *m1 = NULL;
static volatile gboolean already_succeeded = FALSE;

static GError*
_reload_prefixes(struct sqlx_service_s *ss, gboolean init)
{
	gboolean meta0_ok = FALSE;
	GArray *updated_prefixes=NULL;
	struct meta1_prefixes_set_s *m1ps = meta1_backend_get_prefixes(m1);
	GError *err = meta1_prefixes_load(m1ps, ss->ns_name, ss->url->str,
			&updated_prefixes, &meta0_ok);
	if (err) {
		g_prefix_error(&err, "Reload error: ");
		if (updated_prefixes)
			g_array_free(updated_prefixes, TRUE);
		return err;
	}
	if (meta0_ok)
		already_succeeded = TRUE;

	if (updated_prefixes && !init) {
		if (updated_prefixes->len)
			GRID_INFO("RELOAD prefix, nb updated prefixes %d",updated_prefixes->len);
		guint i , max;
		guint16 prefix;
		gchar name[5];
		max = updated_prefixes->len;

		for ( i=0; i < max ; i++) {
			prefix = g_array_index(updated_prefixes,guint16 , i);
			g_snprintf(name, sizeof(name), "%02X%02X", ((guint8*)&prefix)[0], ((guint8*)&prefix)[1]);
			if (meta1_prefixes_is_managed(m1ps,(guint8*)&prefix)) {
				if (err) {
					GRID_WARN("SQLX error : (%d) %s", err->code, err->message);
					g_clear_error(&err);
				}
			}
			else { // Lost prefix managed
				struct sqlx_name_s n = {.base=name, .type=NAME_SRVTYPE_META1, .ns=ss->ns_name};
				err = election_exit(ss->election_manager, &n);
				if (err) {
					GRID_WARN("SQLX error : (%d) %s", err->code, err->message);
					g_clear_error(&err);
				}
			}
		}
	}

	if (updated_prefixes)
		g_array_free(updated_prefixes, TRUE);

	return NULL;
}

static void
_task_reload_prefixes(gpointer p)
{
	static volatile guint tick_reload = 0;

	if (already_succeeded && 0 != (tick_reload++ % 32))
		return;

	GError *err = _reload_prefixes(PSRV(p), FALSE);
	if (err) {
		GRID_WARN("Failed to reload the meta1 prefixes : (%d) %s",
				err->code, err->message);
		g_clear_error(&err);
	}
}

static void
_task_reload_policies(gpointer p)
{
	GError *err = NULL;
	gchar *cfg = gridcluster_get_service_update_policy (PSRV(p)->nsinfo);
	if (!cfg)
		err = NEWERROR(EINVAL, "Invalid parameter");
	else {
		err = service_update_reconfigure(meta1_backend_get_svcupdate(m1), cfg);
		g_free(cfg);
	}

	if (!err)
		GRID_TRACE("Service update policies reloaded");
	else {
		GRID_WARN("Service update policy reload error [%s] : (%d) %s",
				PSRV(p)->ns_name, err->code, err->message);
		g_clear_error(&err);
	}
}

static gchar **
filter_urls(gchar **src, const gchar *avoid)
{
	gboolean matched = FALSE;
	GPtrArray *tmp = g_ptr_array_new();
	for (; *src ;++src) {
		if (!g_ascii_strcasecmp(avoid, *src))
			matched = TRUE;
		else
			g_ptr_array_add(tmp, g_strdup(*src));
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
filter_urls_and_clean(gchar **src, const gchar *avoid)
{
	if (!src)
		return NULL;
	gchar **peers = filter_urls(src, avoid);
	g_strfreev(src);
	return peers;
}

static GError *
_get_peers(struct sqlx_service_s *ss, const struct sqlx_name_s *n,
		gboolean nocache, gchar ***result)
{
	container_id_t cid;
	guchar s[3]= {0,0,0};

	if (!n || !result)
		return NEWERROR(CODE_INTERNAL_ERROR, "BUG [%s:%s:%d]", __FUNCTION__, __FILE__, __LINE__);
	if (!g_str_has_prefix(n->type, NAME_SRVTYPE_META1))
		return NEWERROR(CODE_BAD_REQUEST, "Invalid type name");
	if (!oio_str_ishexa(n->base,4))
		return NEWERROR(CODE_BAD_REQUEST, "Invalid base name");

	memset(cid, 0, sizeof(container_id_t));
	s[0] = n->base[0];
	s[1] = n->base[1];
	((guint8*)cid)[0] = g_ascii_strtoull((gchar*)s, NULL, 16);
	s[0] = n->base[2];
	s[1] = n->base[3];
	((guint8*)cid)[1] = g_ascii_strtoull((gchar*)s, NULL, 16);

	if (nocache) {
		_reload_prefixes(ss, FALSE);
		if (!result)
			return NULL;
	}

	gchar **peers = meta1_prefixes_get_peers(
			meta1_backend_get_prefixes(m1), cid);
	if (!(*result = filter_urls_and_clean(peers, ss->url->str)))
		return NEWERROR(CODE_CONTAINER_NOTFOUND, "Base not managed");
	return NULL;
}

static gboolean
_post_config(struct sqlx_service_s *ss)
{
	GError *err = meta1_backend_init(&m1, ss->ns_name, ss->repository, ss->lb);
	if (NULL != err) {
		GRID_WARN("META1 backend init failure: (%d) %s", err->code, err->message);
		g_clear_error (&err);
		return FALSE;
	}

	transport_gridd_dispatcher_add_requests(ss->dispatcher,
			meta1_gridd_get_requests(), m1);

	gboolean done = FALSE;
	while (!done && grid_main_is_running ()) {
		/* Preloads the prefixes locally managed: It happens often that
		 * meta1 starts before gridagent, and _reload_prefixes() fails
		 * for this reason. */
		if (!(err = _reload_prefixes(ss, TRUE))) {
			done = TRUE;
		} else {
			GRID_WARN("PREFIXES reload failure : (%d) %s", err->code, err->message);
			g_clear_error(&err);
			g_usleep(1 * G_TIME_SPAN_SECOND);
		}
	}
	if (!done) {
		GRID_INFO("Stopped while loading M0 prefixes");
		return FALSE;
	}

	grid_task_queue_register(ss->gtq_reload, 5,
			_task_reload_policies, NULL, ss);
	grid_task_queue_register(ss->gtq_reload, 1,
			(GDestroyNotify)sqlx_task_reload_lb, NULL, ss);
	grid_task_queue_register(ss->gtq_reload, 1,
			_task_reload_prefixes, NULL, ss);

	m1->notifier = ss->events_queue;
	return TRUE;
}

int
main(int argc, char ** argv)
{
	static struct sqlx_service_config_s cfg = {
		NAME_SRVTYPE_META1, "m1v2",
		"el/" NAME_SRVTYPE_META1, 1, 3,
		META1_SCHEMA, 1, 2,
		_get_peers, _post_config, NULL
	};
	int rc = sqlite_service_main(argc, argv, &cfg);
	if (m1)
		meta1_backend_clean(m1);
	return rc;
}

