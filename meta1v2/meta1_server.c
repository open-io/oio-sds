/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.meta1.server"
#endif

#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <glib.h>

#include "../metautils/lib/metautils.h"
#include "../metautils/lib/common_main.h"
#include "../metautils/lib/resolv.h"
#include "../metautils/lib/lb.h"
#include "../metautils/lib/svc_policy.h"
#include "../cluster/lib/gridcluster.h"
#include "../server/network_server.h"
#include "../server/grid_daemon.h"
#include "../server/stats_holder.h"
#include "../server/transport_gridd.h"
#include "../sqliterepo/sqliterepo.h"
#include "../sqliterepo/replication_dispatcher.h"

#include "./internals.h"
#include "./meta1_backend.h"
#include "./meta1_prefixes.h"
#include "./meta1_gridd_dispatcher.h"

typedef guint (*cleanup_action_f) (void *, guint, GTimeVal*, GTimeVal*);

struct periodic_cleanup_s {
	time_t period;
	time_t delay;
	time_t duration;
	guint max; 
	cleanup_action_f action;
	void *data;
};

struct lb_slot_s {
	gchar *name;
	struct grid_lb_s *lb;
	struct grid_lb_iterator_s *iter;
};

struct replication_config_s replication_config;

static GQuark gquark_log = 0;

static gchar volume[1024];
static gchar ns_name[1024];

static GString *url = NULL;

static gchar *zk_url = NULL;
static struct meta1_backend_s *m1 = NULL;
static struct network_server_s *server = NULL;
static struct gridd_request_dispatcher_s *dispatcher = NULL;

static GThread *admin_thread = NULL;
static GThread *register_thread = NULL;

static GHashTable *lb_ht = NULL;

static guint period_refresh_services = 11;
static guint period_refresh_prefixes = 31;
static guint period_register = 1;

static struct grid_single_rrd_s *gsr_reqcounter = NULL;
static struct grid_single_rrd_s *gsr_reqtime = NULL;

static struct periodic_cleanup_s expire_bases = {
	.period = 1,
	.delay = 300,
	.duration = 1,
	.max = 50,
	.action = NULL,
	.data = NULL
};

static struct periodic_cleanup_s retry_elections = {
	.period = 2,
	.delay = 5,
	.duration = 1,
	.max = 100,
	.action = NULL,
	.data = NULL
};

static guint max_bases = 0;
static guint max_connections = 0;

/* ------------------------------------------------------------------------- */

static void
_meta1_warmup(struct meta1_backend_s *backend)
{
	int i, done;
	union {
		guint16 prefix;
		guint8 b[2];
	} u;
	struct sqlx_repository_s *repo;
	struct meta1_prefixes_set_s *m1ps;
	gchar name[8], type[] = META1_TYPE_NAME;

	u.prefix = 0;
	repo = meta1_backend_get_repository(backend);
	m1ps = meta1_backend_get_prefixes(backend);

	if (!sqlx_repository_replication_configured(repo)) {
		GRID_DEBUG("Replication disabled, no election warmup necessary");
		return;
	}

	for (i=done=0; i<65536 ;i++,u.prefix++) {
		if (meta1_prefixes_is_managed(m1ps, u.b)) {
			GError *err;
			g_snprintf(name, sizeof(name), "%02X%02X", u.b[0], u.b[1]);
			err = sqlx_repository_prepare_election(repo, type, name);
			if (!err)
				++ done;
			else {
				GRID_WARN("SQLX error : (%d) %s", err->code, err->message);
				g_clear_error(&err);
			}
		}
	}

	GRID_INFO("%d SQLX elections preallocated!", done);
}

static GError*
_reload_prefixes(gboolean init)
{
	GError *err;
	GArray *updated_prefixes=NULL;
	struct sqlx_repository_s *repo;
	struct meta1_prefixes_set_s *m1ps;

	m1ps = meta1_backend_get_prefixes(m1);
	repo = meta1_backend_get_repository(m1);
	err = meta1_prefixes_load(m1ps,
			ns_name, url->str, &updated_prefixes);

	if ( !err) {
		if ( updated_prefixes && !init ) {
			if (updated_prefixes->len)
				GRID_INFO("RELOAD prefix, nb updated prefixes %d",updated_prefixes->len);
			guint i , max;
			guint16 prefix;
			gchar name[8], type[] = META1_TYPE_NAME;
			max = updated_prefixes->len;

			for ( i=0; i < max ; i++)
			{
				prefix = g_array_index(updated_prefixes,guint16 , i);
				g_snprintf(name, sizeof(name), "%02X%02X", ((guint8*)&prefix)[0], ((guint8*)&prefix)[1]);
				if (meta1_prefixes_is_managed(m1ps,(guint8*)&prefix)) {
					err=sqlx_repository_prepare_election(repo, type, name);
					//err=sqlx_repository_use_base(repo, type, name);
					if ( err ) {
						GRID_WARN("SQLX error : (%d) %s", err->code, err->message);
						g_clear_error(&err);
					}
				} else {  //Lost prefix  managed
					err=sqlx_repository_exit_election(repo, type, name);
					if (err) {
						GRID_WARN("SQLX error : (%d) %s", err->code, err->message);
						g_clear_error(&err);
					}
				}
				if ( i % 10 == 0 ) {
					usleep(20000L);
				}

			}
			g_array_free(updated_prefixes, TRUE);
		}
	}

	return err;
}

/* ------------------------------------------------------------------------- */

static const char *
meta1_usage(void)
{
	return "NS VOLUME";
}

static struct grid_main_option_s *
meta1_get_options(void)
{
	static struct grid_main_option_s meta1_options[] =
	{
		{"Endpoint", OT_STRING, {.str=&url},
			"Bind to this IP:PORT couple instead of 0.0.0.0 and a random port"},
		{NULL, 0, {.i=0}, NULL}
	};

	return meta1_options;
}

static void
lb_slot_free(gpointer p)
{
	struct lb_slot_s *slot;
	if (!(slot = p))
		return;
	grid_lb_iterator_clean(slot->iter);
	grid_lb_clean(slot->lb);
	g_free(slot->name);
	g_free(slot);
}

static void
meta1_specific_fini(void)
{
	if (server) {
		network_server_close_servers(server);
		network_server_stop(server);
	}
	if (register_thread)
		g_thread_join(register_thread);

	if (m1) {
		struct sqlx_repository_s *repo = meta1_backend_get_repository(m1);
		sqlx_repository_exit_elections(repo, NULL);
	}

	if (admin_thread)
		g_thread_join(admin_thread);
	if (server)
		network_server_clean(server);
	if (dispatcher)
		gridd_request_dispatcher_clean(dispatcher);
	if (m1)
		meta1_backend_clean(m1);
	if (url)
		g_string_free(url, TRUE);

	if (lb_ht)
		g_hash_table_destroy(lb_ht);

	memset(volume, 0, sizeof(volume));
	memset(ns_name, 0, sizeof(ns_name));

	if (gsr_reqtime)
		grid_single_rrd_destroy(gsr_reqtime);
	if (gsr_reqcounter)
		grid_single_rrd_destroy(gsr_reqcounter);
}

static void
configure_max_descriptors(void)
{
	struct rlimit limit;

	if (0 != getrlimit(RLIMIT_NOFILE, &limit)) {
		GRID_ERROR("Max file descriptor unknown : getrlimit erorr (errno=%d) %s", errno, strerror(errno));
		abort();
	}
	else {
		guint cur100, cur95;
		cur100 = limit.rlim_cur;
		if (cur100 < 64) {
			GRID_ERROR("Not enough file descriptors allowed [%u], minimum 64 required", cur100);
			abort();
		}
		cur95 = cur100 - 50;
		max_bases = cur95 / 2;
		max_connections = cur95 / 2;
		GRID_INFO("MAXFD[%u/%u] CNX[%u] BASES[%u]", cur95, cur100, max_connections, max_bases);
	}
}

static void
meta1_set_defaults(void)
{
	gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);

	memset(&replication_config, 0, sizeof(replication_config));
	memset(volume, 0, sizeof(volume));
	memset(ns_name, 0, sizeof(ns_name));
	url = NULL;

	lb_ht = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, lb_slot_free);

	gsr_reqtime = grid_single_rrd_create(8);
	gsr_reqcounter = grid_single_rrd_create(8);
}

static gboolean
meta1_configure(int argc, char **argv)
{
	gsize s;

	if (!url) {
		GRID_WARN("No URL provided");
		return FALSE;
	}

	if (argc < 2) {
		GRID_WARN("Not enough options, see usage.");
		return FALSE;
	}

	s = g_strlcpy(ns_name, argv[0], sizeof(ns_name)-1);
	if (s >= sizeof(ns_name)) {
		GRID_WARN("Namespace name too long (given=%"G_GSIZE_FORMAT" max=%lu)",
				s, sizeof(ns_name));
		return FALSE;
	}

	s = g_strlcpy(volume, argv[1], sizeof(volume)-1);
	if (s >= sizeof(volume)) {
		GRID_WARN("Volume name too long (given=%"G_GSIZE_FORMAT" max=%lu)",
				s, sizeof(volume));
		return FALSE;
	}

	zk_url = gridcluster_get_config(ns_name, "zookeeper",
			GCLUSTER_CFG_NS|GCLUSTER_CFG_LOCAL);

	if (!zk_url) {
		GRID_INFO("No replication : no ZooKeeper URL configured");
	} else {
		GRID_INFO("Got zookeeper URL [%s]", zk_url);
	}

	GRID_DEBUG("META1 NS configured to [%s]", ns_name);
	GRID_DEBUG("META1 Volume configured to [%s]", volume);

	configure_max_descriptors();
	return TRUE;
}

static void
meta1_specific_stop(void)
{
	GRID_TRACE("STOP!");
	if (server)
		network_server_stop(server);
}

/* -------------------------------------------------------------------------- */

/*
static gboolean
lb_reload_srvtype(const gchar *srvtype)
{
	GError *err = NULL;
	GSList *list_srv = NULL;
	gchar* srvtype2 = NULL;
	gchar* srvtag_name = NULL;
	gchar* srvtag_value = NULL;

	unsigned int i = 0;
	gchar** srvtype_tok = g_strsplit(srvtype, "|", -1);
	while (srvtype_tok[i] != NULL) {
		i++;
	}
	if (i == 2) {
		g_strlcpy(srvtype2, srvtype_tok[0], strlen(srvtype_tok[0]));

		i = 0;
		gchar** temp_tok = g_strsplit(srvtype_tok[1], "=", -1);
        	while (temp_tok[i] != NULL) {
                	i++;
        	}
		if (i == 2) {
			g_strlcpy(srvtag_name, temp_tok[0], strlen(srvtype_tok[0]));
			g_strlcpy(srvtag_value, temp_tok[1], strlen(srvtype_tok[1]));
		}
	}
	else {
		g_strlcpy(srvtype2, srvtype, strlen(srvtype));
	}
	g_strfreev(srvtype_tok);

	list_srv = list_namespace_services(ns_name, srvtype2, &err);

	if (err) {
               	GRID_WARN("Gridagent error : Failed to list the services "
				"of type [%s] : code=%d %s", srvtype2, err->code,
                        	err->message);
                g_clear_error(&err);
		if (srvtype2) {
			g_free(srvtype2);
		}
		if (srvtag_name) {
			g_free(srvtag_name);
		}
		if (srvtag_value) {
                        g_free(srvtag_value);
                }
               	return FALSE;
        }
	
	struct lb_slot_s *slot = g_hash_table_lookup(lb_ht, srvtype2);

	if (!slot) {
		slot = g_malloc0(sizeof(*slot));
		slot->lb = grid_lb_init(ns_name, srvtype2);
		slot->iter = grid_lb_iterator_scored_round_robin(slot->lb);
		g_hash_table_insert(lb_ht, g_strdup(srvtype2), slot);
	}

	if (NULL != list_srv) {
		GSList *l;
		gboolean provide(struct service_info_s **p_si) {
			if (!l) {
				return FALSE;
			}
			*p_si = l->data;
			l->data = NULL;
			l = l->next;
		
			if (srvtag_name != NULL && srvtag_value != NULL) {
				for (i = 0; i < (*p_si)->tags->len; i++) {
					service_tag_t* current_tag = (service_tag_t*)g_ptr_array_index((*p_si)->tags, i);
					
					if (current_tag->type != STVT_STR) {
						continue;
					}
					else {
						if ((!g_strcmp0(current_tag->name, srvtag_name)) && (!g_strcmp0(current_tag->value.s, srvtag_value))) {
                                                	return TRUE;
                                        	}
					}
				}

				return FALSE;
			}

			return TRUE;
		}

		GRID_TRACE("Reloading srvtype=[%s] with %u services", srvtype2,
				g_slist_length(list_srv));

		l = list_srv;
		grid_lb_reload(slot->lb, provide);

		g_slist_foreach(list_srv, service_info_gclean, NULL);
		g_slist_free(list_srv);
	}

	meta1_configure_type(m1, srvtype2, slot->iter);
	if (srvtype2) {
        	g_free(srvtype2);
        }
        if (srvtag_name) {
        	g_free(srvtag_name);
        }
	if (srvtag_value) {
                g_free(srvtag_value);
        }
	return TRUE;
}
*/

static gboolean
lb_reload_srvtype(const gchar *srvtype)
{
	GError *err = NULL;
	GSList *list_srv = NULL;

	list_srv = list_namespace_services(ns_name, srvtype, &err);
	if (err) {
		GRID_WARN("Gridagent error : Failed to list the services "
				"of type [%s] : code=%d %s", srvtype, err->code,
				err->message);
		g_clear_error(&err);
		return FALSE;
	}

	struct lb_slot_s *slot = g_hash_table_lookup(lb_ht, srvtype);

	if (!slot) {
		slot = g_malloc0(sizeof(*slot));
		slot->lb = grid_lb_init(ns_name, srvtype);
		slot->iter = grid_lb_iterator_scored_round_robin(slot->lb);
		g_hash_table_insert(lb_ht, g_strdup(srvtype), slot);
	}

	if (NULL != list_srv) {
		GSList *l;
		gboolean provide(struct service_info_s **p_si) {
			if (!l)
				return FALSE;
			*p_si = l->data;
			l->data = NULL;
			l = l->next;
			return TRUE;
		}

		GRID_TRACE("Reloading srvtype=[%s] with %u services", srvtype,
				g_slist_length(list_srv));

		l = list_srv;
		grid_lb_reload(slot->lb, provide);

		g_slist_foreach(list_srv, service_info_gclean, NULL);
		g_slist_free(list_srv);
	}

	meta1_configure_type(m1, srvtype, slot->iter);
	return TRUE;
}

static gboolean
_reload_policies(void)
{
	GError *err;
	struct namespace_info_s *nsinfo;

	err = NULL;
	nsinfo = get_namespace_info(ns_name, &err);
	if (!nsinfo) {
		META1_ASSERT(err != NULL);
		GRID_WARN("Service update policy reload error [%s] : (%d) %s",
				ns_name, err->code, err->message);
		g_clear_error(&err);
		return FALSE;
	}

	META1_ASSERT(err == NULL);

	gchar *cfg = gridcluster_get_service_update_policy(nsinfo, "meta1");
	if (!cfg)
		err = g_error_new(gquark_log, EINVAL, "Invalid parameter");
	else {
		err = service_update_reconfigure(meta1_backend_get_svcupdate(m1), cfg);
		g_free(cfg);
	}
	namespace_info_free(nsinfo);

	if (!err) {
		GRID_TRACE("Service update policies reloaded");
		return TRUE;
	}

	GRID_WARN("Service update policy reload error [%s] : (%d) %s",
			ns_name, err->code, err->message);
	g_clear_error(&err);
	return FALSE;
}

static gboolean
_reload_lb(void)
{
	guint errors = 0;
	GError *err = NULL;
	GSList *l, *list_srvtypes = NULL;

	list_srvtypes = list_namespace_service_types(ns_name, &err);
	if (err) {
		GRID_WARN("Gridagent error : Failed to list the service types : "
				"code=%d\n\t%s", err->code, err->message);
		g_clear_error(&err);
		return FALSE;
	}

	for (l=list_srvtypes; l ;l=l->next) {
		if (!lb_reload_srvtype(l->data))
			++ errors;
	}

	if (errors) {
		GRID_TRACE("Reloaded %u service types, with %u errors",
				g_slist_length(list_srvtypes), errors);
		
	}
	if (list_srvtypes) {
		g_slist_foreach(list_srvtypes, g_free1, NULL);
		g_slist_free(list_srvtypes);
	}

	return errors == 0;
}

static void
cleanup_work(guint jiffies, struct periodic_cleanup_s *cleanup)
{
	guint count;
	GTimeVal end, pivot;
	struct sqlx_repository_s *repo;

	if (!cleanup->action)
		return;
	if (!m1)
		return;
	if (!(repo = meta1_backend_get_repository(m1)))
		return;
	if (!(jiffies % cleanup->period))
		return;

	g_get_current_time(&end);
	g_get_current_time(&pivot);
	g_time_val_add(&end, cleanup->duration * 1000000L);
	g_time_val_add(&pivot, cleanup->delay * -1000000L);

	count = cleanup->action(cleanup->data, cleanup->max, &pivot, &end);
	if (count) {
		GRID_TRACE2("%u object cleaned up", count);
	}
}

static gpointer
admin_worker(gpointer p)
{
	GError *err;
	guint jiffies = 0;

	metautils_ignore_signals();
	expire_bases.action = (cleanup_action_f) sqlx_repository_expire_bases;
	expire_bases.data = meta1_backend_get_repository(m1);
	retry_elections.action = (cleanup_action_f) sqlx_repository_retry_elections;
	retry_elections.data = meta1_backend_get_repository(m1);

	for (; grid_main_is_running(); jiffies++) {

		cleanup_work(jiffies, &expire_bases);
		cleanup_work(jiffies, &retry_elections);

		if (!(jiffies % period_refresh_services)) {
			_reload_lb();
			_reload_policies();
		}

		if (!(jiffies % period_refresh_prefixes)) {
			err = _reload_prefixes(FALSE);
			if (err) {
				GRID_WARN("Failed to reload the meta1 prefixes : (%d) %s", err->code, err->message);
				g_clear_error(&err);
			}
		}

		sleep(1);
	}

	return p;
}

static gpointer
register_worker(gpointer p)
{
	guint lastreg = 0, jiffies = 0;
	time_t now, last = 0;

	gchar *straddr = p;
	GError *err = NULL;
	struct service_info_s *si;

	metautils_ignore_signals();

	si = g_malloc0(sizeof(*si));
	si->tags = g_ptr_array_new();
	g_strlcpy(si->ns_name, ns_name, sizeof(si->ns_name)-1);
	g_strlcpy(si->type, "meta1", sizeof(si->type)-1);
	if (!grid_string_to_addrinfo(straddr, straddr+strlen(straddr), &(si->addr))) {
		GRID_WARN("Invalid URL [%s] : (%d) %s",
				straddr, errno, strerror(errno));
		grid_main_stop();
		return p;
	}

	service_tag_set_value_string(
			service_info_ensure_tag(si->tags, "tag.type"),
			"m1v2");

	service_tag_set_value_string(
			service_info_ensure_tag(si->tags, "tag.vol"),
			volume);
	service_tag_set_value_float(
			service_info_ensure_tag(si->tags, "stat.req_idle"),
			1.234);

	service_tag_set_value_macro(
			service_info_ensure_tag(si->tags, "stat.cpu"),
			"cpu", NULL);
	service_tag_set_value_macro(
			service_info_ensure_tag(si->tags, "stat.space"),
			"space", volume);
	service_tag_set_value_macro(
			service_info_ensure_tag(si->tags, "stat.io"),
			"io", volume);

	while (grid_main_is_running()) {

		if (!(jiffies % period_register) && (lastreg != jiffies)) {
			guint64 avg_counter, avg_time;

			/* Computes the avg requests rate/time */
			grid_single_rrd_feed(network_server_get_stats(server),
					INNER_STAT_NAME_REQ_COUNTER, gsr_reqcounter,
					INNER_STAT_NAME_REQ_TIME, gsr_reqtime,
					NULL);
			avg_counter = grid_single_rrd_get_delta(gsr_reqcounter, 4);
			avg_time = grid_single_rrd_get_delta(gsr_reqtime, 4);

			service_tag_set_value_i64(service_info_ensure_tag(si->tags, "stat.total_reqpersec"), avg_counter / 4);
			service_tag_set_value_i64(service_info_ensure_tag(si->tags, "stat.total_avreqtime"), (avg_time+1)/(avg_counter+1));

			/* send the registration now */
			err = NULL;
			if (!register_namespace_service(si, &err))
				g_message("Service registration failed: (%d) %s", err->code, err->message);
			if (err)
				g_clear_error(&err);

			/* save the registration jiffie */
			lastreg = jiffies;
		}

		if (!sqlx_repository_replication_configured(meta1_backend_get_repository(m1)))
			sleep(1);
		else {
			err = sqlx_repository_clients_round(meta1_backend_get_repository(m1), 1);
			if (err != NULL) {
				GRID_ERROR("Clients error : (%d) %s", err->code, err->message);
				g_clear_error(&err);
				grid_main_stop();
			}
		}

		if ((now = time(0)) != last) {
			++ jiffies;
			last = now;
		}
	}

	service_info_clean(si);
	return p;
}

static gchar **
strv_filter(gchar **src, const gchar *avoid)
{
	gchar **p, **result;
	guint max;

	if (!src)
		return NULL;

	max = 0;
	result = g_malloc0(sizeof(gchar*) * (max+1));

	for (p=src; *p ;p++) {
		if (0 != g_ascii_strcasecmp(avoid, *p)) {
			max ++;
			result = g_realloc(result, sizeof(gchar*) * (max+1));
			result[max-1] = g_strdup(*p);
			result[max] = NULL;
		}
	}

	g_strfreev(src);
	return result;
}

static gchar **
_get_peers(gpointer ctx, const gchar *n, const gchar *t)
{
	gchar **peers;
	container_id_t cid;
	gchar s[3];

	(void) ctx;
	if (g_ascii_strcasecmp(t, "meta1"))
		return NULL;

	memset(cid, 0, sizeof(container_id_t));
	s[2] = 0;
	s[0] = n[0];
	s[1] = n[1];
	((guint8*)cid)[0] = g_ascii_strtoull(s, NULL, 16);
	s[0] = n[2];
	s[1] = n[3];
	((guint8*)cid)[1] = g_ascii_strtoull(s, NULL, 16);

	peers = meta1_prefixes_get_peers(meta1_backend_get_prefixes(m1), cid);
	if (!peers || !*peers)
		return NULL;

	return strv_filter(peers, url->str);
}

static const gchar *
_get_zk(gpointer ctx)
{
	(void) ctx;
	return zk_url;
}

static const gchar *
_get_url(gpointer ctx)
{
	(void) ctx;
	return url->str;
}

static const gchar *
_get_ns(gpointer ctx)
{
	(void) ctx;
	return ns_name;
}

/**
 * @warning This function will block until gridagent is available
 */
static void
meta1_action(void)
{
	GError *err;

	/* Configures the backend part */
	err = meta1_backend_init(&m1, ns_name, url->str, volume);
	if (err) {
		GRID_WARN("META1 backend init failure : (%d) %s", err->code, err->message);
		g_clear_error(&err);
		return;
	}
	if (max_bases) {
		sqlx_repository_configure_maxbases(meta1_backend_get_repository(m1),
				max_bases);
	}
	GRID_TRACE("META1 backend initiated!");

	if (!_reload_lb() || !_reload_policies())
		GRID_WARN("Failed to perform an initial load of LB config");

	/* Configures the replication */
	if (zk_url) {
		replication_config.mode = ELECTION_MODE_QUORUM;
		replication_config.ctx = m1;
		replication_config.get_peers = _get_peers;
		replication_config.get_manager_url = _get_zk;
		replication_config.get_ns_name = _get_ns;
		replication_config.get_local_url = _get_url;
		replication_config.subpath = "el";
		replication_config.hash_width = 3;
		replication_config.hash_depth = 1;

		err = sqlx_repository_configure_replication(
				meta1_backend_get_repository(m1), &replication_config);
		if (err != NULL) {
			GRID_WARN("SQLX replication init failure : (%d) %s",
					err->code, err->message);
			g_clear_error(&err);
			return;
		}
	}

	/* Configures the network part */
	if (!(server = network_server_init())) {
		GRID_WARN("SERVER init failure : (%d) %s", errno, strerror(errno));
		return;
	}
	if (max_connections)
		network_server_set_maxcnx(server, max_connections);

	dispatcher = transport_gridd_build_empty_dispatcher();
	transport_gridd_dispatcher_add_requests(dispatcher, meta1_gridd_get_requests(), m1);
	transport_gridd_dispatcher_add_requests(dispatcher, sqlx_repli_gridd_get_requests(), meta1_backend_get_repository(m1));
	grid_daemon_bind_host(server, url->str, dispatcher);

	if (NULL != (err = network_server_open_servers(server))) {
		GRID_WARN("Failed to start some server sockets : (%d) %s",
				err->code, err->message);
		g_clear_error(&err);
		return;
	}

	/* Preloads the prefixes locally managed */
	err = _reload_prefixes(TRUE);
	while (NULL != err) {
		GRID_WARN("META1 init failure : (%d) %s",
				err->code, err->message);
		g_clear_error(&err);
		/* It happens often that meta1 starts before gridagent,
		 * and _reload_prefixes() fails for this reason. */
		GRID_WARN("Retrying in %d seconds...", CONNECT_RETRY_DELAY);
		sleep(CONNECT_RETRY_DELAY);
		err = _reload_prefixes(TRUE);
	}

	/* Start the administrative threads */
	admin_thread = g_thread_create(admin_worker, NULL, TRUE, &err);
	if (!admin_thread) {
		GRID_WARN("Failed to start the ADMIN thread : (%d) %s", err->code, err->message);
		g_clear_error(&err);
		return;
	}

	register_thread = g_thread_create(register_worker, url->str, TRUE, &err);
	if (!register_thread) {
		GRID_WARN("Failed to start the REGISTER thread : (%d) %s",
				err->code, err->message);
		g_clear_error(&err);
		return;
	}

	_meta1_warmup(m1);

	/* SERVER/GRIDD main run loop */
	if (NULL != (err = network_server_run(server))) {
		GRID_WARN("GRIDD run failure : (%d) %s", err->code, err->message);
		g_clear_error(&err);
		return;
	}

	GRID_INFO("Normally exiting.");
}

static struct grid_main_callbacks meta1_callbacks =
{
	.options = meta1_get_options,
	.action = meta1_action,
	.set_defaults = meta1_set_defaults,
	.specific_fini = meta1_specific_fini,
	.configure = meta1_configure,
	.usage = meta1_usage,
	.specific_stop = meta1_specific_stop,
};

int
main(int argc, char ** argv)
{
	return grid_main(argc, argv, &meta1_callbacks);
}

