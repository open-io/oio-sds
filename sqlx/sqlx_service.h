/*
OpenIO SDS sqlx
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

#ifndef OIO_SDS__sqlx__sqlx_service_h
# define OIO_SDS__sqlx__sqlx_service_h 1

#define PSRV(P) ((struct sqlx_service_s*)(P))

#include <glib.h>
#include <metautils/lib/metautils.h>
#include <sqliterepo/sqliterepo.h>
#include <sqliterepo/sqlx_remote.h>
#include <resolver/hc_resolver.h>
#include <server/transport_gridd.h>
#include <server/network_server.h>

struct sqlx_service_config_s;
struct sqlx_service_s;

struct sqlx_service_config_s
{
	const gchar *srvtype;
	const gchar *srvtag;

	const gchar *zk_prefix;
	const guint zk_hash_depth;
	const guint zk_hash_width;

	const gchar *schema;
	const guint repo_hash_depth;
	const guint repo_hash_width;

	/* if <nocache> is FALSE and <result> is NULL, then only decache */
	GError* (*get_peers) (struct sqlx_service_s *ss,
			const struct sqlx_name_s *n, gboolean nocache,
			gchar ***result);

	// Called at the end of the configure step. Destined to initiating
	// servces backends, plugging message handers, etc.
	gboolean (*post_config) (struct sqlx_service_s *ss);

	// Available to override
	void (*set_defaults) (struct sqlx_service_s *ss);
};

/* Elements common to any gridd+sqliterepo services */
struct sqlx_service_s
{
	gchar volume[1024];
	gchar ns_name[LIMIT_LENGTH_NSNAME];

	/* if left empty, all the services from the conscience will be reloaded.
	 * If filled, only the specified service types (coma-separated) will be
	 * considered */
	gchar srvtypes[128];

	struct replication_config_s *replication_config;
	const struct sqlx_service_config_s *service_config;

	GString *url;
	GString *announce;
	gchar *zk_url;

	GString *service_id;

	/* Should the service load an additional list of configuration files to
	 * supersede the values in place in the central configuration facility */
	GSList *config_paths;

	/* Should the service load the system configuration and feed the central
	 * configuration facility. */
	gboolean config_system;

	GPtrArray *sync_tab;

	struct sqlx_repository_s *repository;
	struct sqlx_peering_s *peering;
	struct election_manager_s *election_manager;
	struct network_server_s *server;
	struct gridd_request_dispatcher_s *dispatcher;
	struct hc_resolver_s *resolver;
	struct oio_lb_s *lb;
	struct oio_lb_world_s *lb_world;

	/* The tasks under this queue always follow a reload of the nsinfo field,
	   and can safely play with it. This is the place for LB reloading,
	   reconfiguration, etc. */
	struct namespace_info_s *nsinfo;
	struct grid_task_queue_s *gtq_reload;
	GThread *thread_reload;

	/* Queue dedicated to expirations elections, caches, etc. */
	struct grid_task_queue_s *gtq_admin;
	GThread *thread_admin;

	struct gridd_client_pool_s *clients_pool;
	GThread *thread_client;

	GThread *thread_timers;

	//-------------------------------------------------------------------
	// Variables used during the startup time of the server, but not used
	// anymore after that.
	//-------------------------------------------------------------------

	// Must the cache be set
	gboolean flag_cached_bases;

	// Are DB deletions allowed ?
	gboolean flag_delete_on;

	// Turn to TRUE to avoid locking the repository volume
	gboolean flag_nolock;

	// Allows the service to avoid initiating an event_queue. To be set by
	// services that know they won't evr generate events (meta0)
	gboolean flag_no_event;

	// Controls the election mode:
	// TRUE :  ELECTION_MODE_QUORUM
	// FALSE : ELECTION_MODE_NONE
	gboolean flag_replicable;
};

/* -------------------------------------------------------------------------- */

extern int sqlite_service_main(int argc, char **argv,
		const struct sqlx_service_config_s *cfg);

// FIXME: this is only used in meta1
/** Reloads the optional (oio_lb_s*). Exposed to let the
 * server enable it in its post-config hook. This is destined to
 * be registered in a task queue. */
void sqlx_task_reload_lb(struct sqlx_service_s *ss);

#endif /*OIO_SDS__sqlx__sqlx_service_h*/
