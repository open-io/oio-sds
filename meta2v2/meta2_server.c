/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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
#include <meta2v2/meta2_variables.h>
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
meta2_on_close(struct sqlx_sqlite3_s *sq3, gboolean deleted, gpointer cb_data)
{
	gint64 seq = 1;
	EXTRA_ASSERT(sq3 != NULL);

	if (!deleted)
		return;

	struct oio_url_s *u = oio_url_empty ();
	oio_url_set (u, OIOURL_NS, PSRV(cb_data)->ns_name);
	NAME2CONST(n, sq3->name);
	if (!sqlx_name_extract (&n, u, NAME_SRVTYPE_META2, &seq)) {
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

	/* Tell the meta2 is interested only by RAWX services */
	g_strlcpy(ss->srvtypes, NAME_SRVTYPE_RAWX, sizeof(ss->srvtypes));

	/* prepare a meta2 backend */
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

	hc_resolver_configure(ss->resolver, HC_RESOLVER_DECACHEM0);

	/* Register meta2 requests handlers */
	transport_gridd_dispatcher_add_requests(ss->dispatcher,
			meta2_gridd_get_v2_requests(), m2);

	/* Register few meta2 tasks */
	grid_task_queue_register(ss->gtq_reload, meta2_reload_nsinfo_period,
			_task_reconfigure_m2, NULL, ss);
	grid_task_queue_register(ss->gtq_reload, 1,
			(GDestroyNotify)sqlx_task_reload_lb, NULL, ss);

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
		sqlx_service_resolve_peers, _post_config, NULL
	};

	int rc = sqlite_service_main (argc, argv, &cfg);
	if (m2)
		meta2_backend_clean (m2);
	return rc;
}

