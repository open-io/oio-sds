/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS

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

static gboolean
_post_config(struct sqlx_service_s *ss)
{
	GError *err = NULL;

	if (err != NULL) {
		GRID_WARN("%s", err->message);
		g_clear_error(&err);
		return FALSE;
	}

	/* Tell the meta2 is interested only by rawx services,
	 * and also meta2 services (to resolve service IDs) */
	g_snprintf(ss->srvtypes, sizeof(ss->srvtypes), "%s,%s",
			NAME_SRVTYPE_RAWX, NAME_SRVTYPE_META2);

	/* prepare a meta2 backend */
	err = meta2_backend_init(&m2, ss->repository, ss->ns_name, ss->lb, ss->resolver);
	if (err) {
		GRID_WARN("meta2 backend init failure: (%d) %s", err->code, err->message);
		g_clear_error(&err);
		return FALSE;
	}

	/* Check the base just after opening */
	sqlx_repository_configure_open_callback(ss->repository,
			(sqlx_repo_open_hook)meta2_backend_open_callback,
			m2);

	/* Make deleted bases exit the cache */
	sqlx_repository_configure_close_callback(ss->repository,
			(sqlx_repo_close_hook)meta2_backend_close_callback, m2);

	/* Make base replications update the cache */
	sqlx_repository_configure_change_callback(ss->repository,
			(sqlx_repo_change_hook)meta2_backend_change_callback, m2);

	/* Send event */
	sqlx_repository_configure_db_properties_change_callback(ss->repository,
			(sqlx_repo_db_properties_change_hook)meta2_backend_db_properties_change_callback,
			m2);

	hc_resolver_configure(ss->resolver, HC_RESOLVER_DECACHEM0);

	/* Register meta2 requests handlers */
	transport_gridd_dispatcher_add_requests(ss->dispatcher,
			meta2_gridd_get_v2_requests(), m2);

	/* Register few meta2 tasks */
	grid_task_queue_register(ss->gtq_reload, meta2_reload_nsinfo_period,
			_task_reconfigure_m2, NULL, ss);
	grid_task_queue_register(ss->gtq_reload, 1,
			(GDestroyNotify)sqlx_task_reload_lb, NULL, ss);

	return TRUE;
}

int
main(int argc, char **argv)
{
	struct sqlx_service_config_s cfg = {
		NAME_SRVTYPE_META2, "m2v2",
		"el/" NAME_SRVTYPE_META2, 2, 2,
		schema, 1, 3,
		// FIXME(FVE): create a parameter to allow or deny peer requests.
		//sqlx_service_reply_no_peers,
		sqlx_service_resolve_peers,
		_post_config, NULL
	};

	int rc = sqlite_service_main (argc, argv, &cfg);
	if (m2)
		meta2_backend_clean (m2);
	return rc;
}

