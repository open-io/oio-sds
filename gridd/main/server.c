/*
OpenIO SDS gridd
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#ifndef DOMAIN_THREADS
# define DOMAIN_THREADS "threads.monitoring"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fnmatch.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <cluster/lib/gridcluster.h>

#include <gmodule.h>

#include "./server_internals.h"
#include "./internal_alerts.h"
#include "./sock.h"
#include "./plugin.h"
#include "./plugin_holder.h"
#include "./message_handler.h"
#include "./srvtimer.h"
#include "./srvstats.h"
#include "./srvalert.h"

#define PERIOD_DEBUG 60LLU
#define PERIOD_STATS 1LLU

#define PERIOD_REGISTER          1LLU
#define PERIOD_REFRESH_NS_INFO   5LLU

#define GET_INT(S,K,R) do {\
	if (g_key_file_has_key(cfgFile,S,K,NULL)) {\
		R = g_key_file_get_integer (cfgFile,S,K,err);\
		if (err && *err) return 0;\
	}\
} while (0)

/*extern variables*/

char *config_file=NULL;

guint32 gridd_flags = GRIDD_FLAG_NOLINGER | GRIDD_FLAG_SHUTDOWN
		| GRIDD_FLAG_QUICKACK | GRIDD_FLAG_KEEPALIVE;

/* NEW WAY INFORMATIONS ----------------------------------------------------- */

gboolean old_style = FALSE;
gchar* service_type = NULL;
gboolean rec_service = FALSE;
gboolean load_ns_info = FALSE;
namespace_info_t *ns_info = NULL;
addr_info_t *serv_addr = NULL;
GPtrArray *serv_tags = NULL;
gboolean first = TRUE;
gchar* ns_name = NULL;

/* -------------------------------------------------------------------------- */

volatile gboolean may_continue = TRUE;

struct alert_cfg_s default_alert_cfg = { 0, 30 };

gsize default_to_operation = DAEMON_DEFAULT_TIMEOUT_READ; /*ms*/
gsize default_to_connection = DAEMON_DEFAULT_TIMEOUT_ACCEPT; /*ms*/
gsize default_max_workers = 10;
gsize default_max_spare_workers = 10;
gsize default_min_spare_workers = 2;
gsize default_min_workers = 2;
struct message_handler_s BEACON_MSGHANDLER;
struct server_s BEACON_SRV;

/* INTERNAL STATISTICS MANAGEMENT ------------------------------------------- */

static GMutex stats_mutex;
static struct server_stats_s stats_interval = {0,0,0};
static struct server_stats_s stats_total = {0,0,0};
static GRWLock ns_info_lock;

#define STATS_LOCK()   g_mutex_lock   (&stats_mutex)
#define STATS_UNLOCK() g_mutex_unlock (&stats_mutex)
#define STATS_CNX_UP()   do { STATS_LOCK(); stats_total.total++; stats_total.created++; STATS_UNLOCK(); } while (0)
#define STATS_CNX_DOWN() do { STATS_LOCK(); stats_total.total--; stats_total.stopped++; STATS_UNLOCK(); } while (0)

static gboolean
GET_FLAG(GKeyFile *gkf, const gchar *section, const gchar *k, gboolean def)
{
	gchar buf[256];
	memset(buf, 0, sizeof(buf));
	g_snprintf(buf, sizeof(buf), "flag.%s", k);
	if (!g_key_file_has_key(gkf, section, buf, NULL))
		return def;
	gchar *v = g_key_file_get_value(gkf, section, buf, NULL);
	gboolean flag = oio_str_parse_bool(v, def);
	g_free(v);
	return flag;
}

void
gridd_set_flag(enum gridd_flag_e flag, int onoff)
{
	guint32 old_flags = gridd_flags;

	if (onoff)
		gridd_flags = gridd_flags | flag;
	else
		gridd_flags = gridd_flags & ~flag;

	if (old_flags != gridd_flags) {
		NOTICE("GRIDD flags changed (%08X) : [%08X] -> [%08X]",
				flag, old_flags, gridd_flags);
	}
	else {
		DEBUG("GRIDD flags unchanged (%08X) : [%08X]", flag, gridd_flags);
	}
}

static void
srv_inner_gauges_update (gpointer d)
{
	struct server_stats_s tmpTotalStats;
	(void) d;

	STATS_LOCK();
	memcpy (&tmpTotalStats, &stats_total, sizeof(stats_total));
	STATS_UNLOCK();

	srvstat_set_u64("gauge cnx.client", tmpTotalStats.total);
}

static gboolean
self_register_in_cluster(GError **err)
{
	/* Init the service header */
	service_info_t *si = g_malloc0(sizeof(service_info_t));
	memcpy(&(si->addr), serv_addr, sizeof(addr_info_t));
	g_strlcpy(si->ns_name, ns_info->name, sizeof(si->ns_name));
	g_strlcpy(si->type, service_type, sizeof(si->type));
	si->tags = g_ptr_array_new();

	if (first)
		service_tag_set_value_boolean(service_info_ensure_tag(si->tags, NAME_TAGNAME_RAWX_FIRST), first);

	/* Copy the service tags */
	if (!serv_tags)
		DEBUG("No tag found in gridd to set in service info");
	else {
		gsize i;
		for (i=0; i<serv_tags->len ;i++) {
			struct service_tag_s *tag = g_ptr_array_index(serv_tags, i);
			g_ptr_array_add(si->tags, service_tag_dup(tag));
		}
	}

	/* Register nw in the conscience */
	GError *e = register_namespace_service(si);
	if (NULL != e) {
		ERROR("Failed to register service in cluster : %s", gerror_get_message(*err));
		g_clear_error(&e);
	}

	service_info_clean(si);
	first = FALSE;
	return TRUE;
}

static void
srv_periodic_register (gpointer d)
{
	(void)d;
	GError *err = NULL;
	if(!self_register_in_cluster(&err))
		NOTICE("Failed to register service in cluster : %s", gerror_get_message(err));
	if(err)
		g_clear_error(&err);
}

static void
srv_periodic_refresh_ns_info (gpointer d)
{
	/* free current ns_info and load newer */
	namespace_info_t *nsinfo = NULL;
	namespace_info_t *tmp = NULL;
	GError *error = NULL;

	(void) d;

	if (!(error = conscience_get_namespace(ns_name, &ns_info))) {
		NOTICE("Failed to refresh the Namespace info from the gridagent");
		if(error)
			g_clear_error(&error);
		return;
	}
	g_rw_lock_writer_lock (&ns_info_lock);
	tmp = ns_info;
	ns_info = nsinfo;
	namespace_info_free(tmp);
	g_rw_lock_writer_unlock(&ns_info_lock);
	nsinfo = NULL;
}

static gpointer main_thread (gpointer arg);

/* SERVER ALERTS MANAGEMENT ------------------------------------------------ */

static void
server_notify_alert( struct server_s *srv )
{
	register time_t now;

	if (!srv) return;

	now = time(0);

	g_rec_mutex_lock (&(srv->recMutex));
	srv->alert_cfg.last_sent = now;
	g_rec_mutex_unlock (&(srv->recMutex));
}

static gboolean
server_alert_possible( struct server_s *srv )
{
	register time_t last, now, freq;

	if (!srv)
		return FALSE;

	g_rec_mutex_lock (&(srv->recMutex));
	last = srv->alert_cfg.last_sent;
	freq = srv->alert_cfg.frequency;
	g_rec_mutex_unlock (&(srv->recMutex));

	now = time(0);

	return (last<=0 || now-last>freq);
}

/* WORKER THREAD FUNCTIONS ------------------------------------------------- */

#define threads_debug(srv) g_strdup_printf("SRV=%s %d used=%d/%d idle=%d total[%d,%d] spare[%d,%d]", \
		srv->name, __LINE__, \
		srv->mon.used_workers, srv->mon.nb_workers, srv->mon.nb_workers - srv->mon.used_workers, \
		srv->mon.min_workers, srv->mon.max_workers, \
		srv->mon.min_spare_workers, srv->mon.max_spare_workers)

static void
thread_monitoring_add (struct server_s *srv, gboolean locked)
{
	if (!locked)
		g_rec_mutex_lock (&(srv->recMutex));

	srv->mon.creation ++;
	srv->mon.nb_workers ++;

	if (!locked)
		g_rec_mutex_unlock (&(srv->recMutex));
}

static void
thread_monitoring_remove (struct server_s *srv, gboolean locked)
{
	if (!locked)
		g_rec_mutex_lock (&(srv->recMutex));

	srv->mon.destruction ++;
	srv->mon.nb_workers --;

	if (!locked)
		g_rec_mutex_unlock (&(srv->recMutex));
}

static gboolean
thread_start(struct server_s *srv)
{
	GError *gErr = NULL;
	GThread *th;

	if (NULL != (th = g_thread_try_new("main", main_thread, srv, &gErr)))
		return TRUE;

	ERROR("Cannot start a worker thread : %s", gErr?gErr->message:"?");
	if (gErr)
		g_error_free(gErr);

	return FALSE;
}

static void
thread_monitoring_reserve (struct server_s *srv)
{
	gboolean defer_creation = FALSE;
	gchar *str_dbg = NULL;
	gint64 spare_workers;
	gboolean too_many_spare_workers, too_many_workers, too_few_spare_workers, too_few_workers;

	/* XXX start of locked section */
	g_rec_mutex_lock (&(srv->recMutex));

	srv->mon.used_workers ++;
	srv->mon.wake ++;

	spare_workers = srv->mon.nb_workers - srv->mon.used_workers;
	too_few_workers = srv->mon.nb_workers < srv->mon.min_workers;
	too_many_workers = srv->mon.nb_workers >= srv->mon.max_workers;
	too_few_spare_workers = spare_workers < srv->mon.min_spare_workers;
	too_many_spare_workers = spare_workers >= srv->mon.max_spare_workers;

	if (srv->mon.used_workers >= srv->mon.max_workers)
		srv->mon.max_reached ++;

	if (too_few_workers || too_few_spare_workers) {
		if (!too_many_spare_workers && !too_many_workers) {
			thread_monitoring_add(srv, TRUE);
			defer_creation = TRUE;
			str_dbg = threads_debug(srv);
		}
	}

	g_rec_mutex_unlock (&(srv->recMutex));
	/* XXX end of locked section */

	/* Deferred actions */
	if (str_dbg) {
		TRACE_DOMAIN(DOMAIN_THREADS, "%s TOO FEW", str_dbg);
		g_free(str_dbg);
	}
	if (defer_creation) {
		if (!thread_start(srv))
			thread_monitoring_remove(srv, FALSE);
	}
}

/**
 * @return FALSE if the thread is to be stopped, something else if it might continue
 */
static gboolean
thread_monitoring_release (struct server_s *srv)
{
	gboolean rc = TRUE;
	gchar *str_dbg = NULL;

	/* XXX start of locked section */
	g_rec_mutex_lock (&(srv->recMutex));

	srv->mon.used_workers --;

	gint spare_workers = srv->mon.nb_workers - srv->mon.used_workers;
	gboolean too_few_workers = srv->mon.nb_workers < srv->mon.min_workers;
	gboolean too_many_workers = srv->mon.nb_workers > srv->mon.max_workers;
	gboolean too_few_spare_workers = spare_workers < srv->mon.min_spare_workers;
	gboolean too_many_spare_workers = spare_workers > srv->mon.max_spare_workers;

	if ((srv->mon.nb_workers>1)) {
		if (too_many_workers || too_many_spare_workers) {
			if (!too_few_spare_workers && !too_few_workers) {
				str_dbg = threads_debug(srv);
				thread_monitoring_remove (srv, TRUE);
				rc = FALSE;
			}
		}
	}

	g_rec_mutex_unlock (&(srv->recMutex));
	/* XXX end of locked section */

	if (str_dbg) {
		TRACE_DOMAIN(DOMAIN_THREADS, "%s TOO MANY", str_dbg);
		g_free(str_dbg);
	}
	return rc;
}

static void
thread_monitoring_periodic_debug (struct server_s *srv)
{
	gchar *str_dbg = NULL;
	struct thread_monitoring_s mon, mon0;
	gchar str_pool[512];
	gsize str_pool_size;

	/* XXX locked section */
	g_rec_mutex_lock (&(srv->recMutex));
	memcpy(&mon, &(srv->mon), sizeof(struct thread_monitoring_s));
	memcpy(&mon0, &(srv->mon0), sizeof(struct thread_monitoring_s));
	memcpy(&(srv->mon0), &(srv->mon), sizeof(struct thread_monitoring_s));
	str_dbg = threads_debug(srv);
	g_rec_mutex_unlock (&(srv->recMutex));
	/* XXX end of locked section */

	gboolean too_many_workers = (mon.used_workers >= mon.max_workers);
	gboolean max_reached = (mon.max_reached != mon0.max_reached);

	/*and then print all*/
	DEBUG_DOMAIN (DOMAIN_THREADS, "%s wake=%"G_GUINT64_FORMAT" variation=+%"G_GUINT64_FORMAT"-%"G_GUINT64_FORMAT,
			str_dbg,
			(mon.wake - mon0.wake),
			(mon.creation - mon0.creation),
			(mon.destruction - mon0.destruction));
	g_free(str_dbg);

	if (too_many_workers) {
		WARN_DOMAIN (DOMAIN_THREADS, "%s ALL THREADS are currently used!", srv->name);
		if (server_alert_possible(srv)) {
			str_pool_size = accept_pool_to_string(srv->ap, str_pool, sizeof(str_pool));
			SRV_SEND_ERROR(ALERTID_SRV_THREADS,"Server [%s] on [%.*s] currently uses all its threads",
				srv->name, str_pool_size, str_pool);
			server_notify_alert(srv);
		}
	}
	else if (max_reached) {
		WARN_DOMAIN (DOMAIN_THREADS, "%s ALL THREADS have been used!", srv->name);
		if (server_alert_possible(srv)) {
			str_pool_size = accept_pool_to_string(srv->ap, str_pool, sizeof(str_pool));
			SRV_SEND_WARNING(ALERTID_SRV_THREADS,"Server [%s] on [%.*s] used all its threads",
				srv->name, str_pool_size, str_pool);
			server_notify_alert(srv);
		}
	}
}

static void
thread_monitoring_periodic_stats (struct server_s *srv)
{
	struct thread_monitoring_s mon;

	/* XXX end od locked section */
	g_rec_mutex_lock (&(srv->recMutex));
	memcpy(&mon, &(srv->mon), sizeof( struct thread_monitoring_s));
	g_rec_mutex_unlock (&(srv->recMutex));
	/* XXX end of locked section */

	srvstat_set_u64("gauge thread.active", mon.used_workers);
	srvstat_set_u64("gauge thread.total", mon.nb_workers);
}

/* ------------------------------------------------------------------------- */

gint
get_network_socket (message_handler_f h, char **addr, int *port, GError **error)
{
	SERVER s = NULL;
	ACCEPT_POOL ap = NULL;
	int id = 0, i = 0;
	struct sockaddr_storage sock_name;
	socklen_t sock_len = sizeof(struct sockaddr_storage);
	char host[48], str_port[6];

	for (s=BEACON_SRV.next; s && s!=&BEACON_SRV ;s=s->next) {
		ap = s->ap;

		for (i = 0; i < s->nbHandlers; i++) {
			if (s->handlers[i]->handler == h) {
				for (id = 0; id < ap->count; id++) {
					memset(&sock_name, 0, sizeof(struct sockaddr));
					if (!getsockname(ap->srv[id], (struct sockaddr*)&sock_name, &sock_len) &&
					   (sock_name.ss_family == PF_INET || sock_name.ss_family == PF_INET6)) {
						if (format_addr((struct sockaddr*)&sock_name, host, sizeof(host), str_port, sizeof(str_port), error)) {
							*addr = strdup(host);
							*port = atoi(str_port);
							return(1);
						}
					}
				}
			}
		}
	}

	GSETERROR(error, "No notwork socket found for this handler");
	return(0);
}

static gint
manage_message (SERVER srv, GByteArray *gba, struct request_context_s* ctx, GError **err)
{
	gint found=0;
	gint i=0;

	MESSAGE m = message_unmarshall(gba->data, gba->len, err);
	if (!m) {
		GSETERROR(err, "Cannot unmarshal the message");
		goto errorLabel;
	}

	gettimeofday(&(ctx->tv_start), NULL);
	ctx->request = m;

	int rc = GO_ON;

	/*find an appropriated message handler*/
	for (found=0,i=0; rc != DONE && i<srv->nbHandlers ; i++) {
		struct message_handler_s *h = srv->handlers[i];
		int match_rc = h->matcher(m, h->udata, err);

		if (match_rc < 0) {
			GSETERROR(err, "match error");
			goto errorLabel;
		}

		if (match_rc > 0) {
			found=1;
			if (h->handler_v2)
				rc = h->handler_v2 (ctx, err);
			else
				rc = h->handler (m, ctx->fd, ctx, err);

			/* Test rc: if go_on => continue; if done => end; if fail => stop, error */
			if (rc == FAIL) {
				GSETERROR(err, "Failed to execute a message handler");
				goto errorLabel;
			}
		}
	}

	/*if the message was not found, it is an error*/
	if (!found) {
		GSETERROR (err, "Command not found");
		goto errorLabel;
	}

	metautils_message_destroy (m);
	ctx->request = NULL;
	return 1;

errorLabel:
	metautils_message_destroy(m);
	ctx->request = NULL;
	return 0;
}

static gpointer
main_thread (gpointer arg)
{
	gchar str_addr_src[STRLEN_ADDRINFO];
	struct server_s *srv;

	/*init variables*/
	if (!(srv = arg))
		return NULL;

	/*about to block unwanted signals in the worker threads*/
	metautils_ignore_signals();

	/*loop on connections*/
	while (may_continue) {

		GError *gErr=NULL;
		gint clt;
		addr_info_t clt_addr;
		struct request_context_s* ctx;

		/*accept a new connection*/
		if (0 > (clt = accept_do(srv->ap, &clt_addr, &gErr))) {
			if (gErr) {
				ERROR("Cannot accept a new connection : %s", gErr->message);
				g_clear_error(&gErr);
			}
			continue;
		}

		/*notify that one more thread is running*/
		STATS_CNX_UP();

		thread_monitoring_reserve (srv);

		ctx = request_context_create(clt, &clt_addr);

		memset(str_addr_src, 0, sizeof(str_addr_src));
		grid_addrinfo_to_string(ctx->remote_addr, str_addr_src, sizeof(str_addr_src));
		TRACE ("Connection NEW fd=%d [%s]", clt, str_addr_src);

		while (may_continue) {

			if (!wait_for_socket(clt, 3000)) {
				if (srv->to_connection > 0) {
					gint64 now = time(0);
					if (now < ctx->tv_start.tv_sec ||
							(now - ctx->tv_start.tv_sec) > srv->to_connection) {
						GSETCODE(&gErr, ERRCODE_CONN_TIMEOUT, "Idle for too long");
						break;
					}
				}
				continue;
			}

			GByteArray *gba = l4v_read_2to(clt, srv->to_operation, srv->to_operation, &gErr);
			if (!gba) {
				GSETERROR(&gErr,"Read error");
				break;
			}

			gint rc = manage_message (srv, gba, ctx, &gErr);
			g_byte_array_free (gba,TRUE);
			if (!rc) {
				GSETERROR(&gErr,"Cannot manage the message");
				break;
			}

			gettimeofday(&(ctx->tv_start), NULL);
		}

		request_context_free(ctx);

		if (gErr) {
			switch (gErr->code) {
				case ERRCODE_CONN_RESET:
				case ERRCODE_CONN_CLOSED:
					TRACE ("Connection CLOSED/RESET fd=%i [%s]", clt, str_addr_src);
					break;
				case ERRCODE_CONN_TIMEOUT:
					DEBUG ("Connection TIMEOUT fd=%i [%s]", clt, str_addr_src);
					break;
				default:
					DEBUG ("Connection ERROR fd=%i [%s]", clt, str_addr_src);
					if (gErr->message)
						DEBUG ("cause:\n\t%s", gErr->message);
					break;
			}
			g_clear_error (&gErr);
		}

		TRACE ("Connection CLOSING fd=%i [%s]", clt, str_addr_src);
		if (gridd_flags & GRIDD_FLAG_SHUTDOWN)
			shutdown (clt, SHUT_RDWR);
		metautils_pclose (&clt);
		STATS_CNX_DOWN();

		if (!thread_monitoring_release(srv)) /* in excess */
			return 0;
	}

	thread_monitoring_remove(srv,FALSE);
	return 0;
}

static GHashTable*
extract_parameters (GKeyFile *kf, const char *s, const char *p, GError **err)
{
	gchar **all_keys=NULL, **current_key=NULL;
	gsize size=0;
	GHashTable *ht=NULL;
	size_t pref_len = p? strlen(p) : 0;

	ht = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	all_keys = g_key_file_get_keys (kf, s, &size, err);
	if (!all_keys)
	{
		GSETERROR(err, "cannot get the keys of the section '%s'", s);
	}
	for (current_key = all_keys; all_keys && *current_key; current_key++)
	{
		if (g_str_has_prefix(*current_key, p))
		{
			gchar *value = NULL;
			value = g_key_file_get_value (kf, s, *current_key, err);
			if (!value)
			{
				GSETERROR (err, "Cannot get the value");
				goto error;
			}
			g_hash_table_insert(ht, g_strdup(*current_key + pref_len), value);
		}
	}

	g_strfreev(all_keys);
	return ht;
error:
	if (ht)
		g_hash_table_destroy(ht);
	if (all_keys)
		g_strfreev(all_keys);
	return NULL;
}

#if 0
static int
prepare_plugins_reload (GKeyFile *cfgFile, GError **err)
{
	GHashTable *params=NULL;
	gchar **groups=NULL;
	gsize nbgroups=0, i;
	gchar *fileName=NULL;

	if (!cfgFile)
	{
		GSETERROR(err,"Invalid Parameter");
		goto errorLabel;
	}

	DEBUG ("Start loading all the plugins found in the configuration");

	/*run the key's list and keep those mathing Plugin~*/
	groups = g_key_file_get_groups (cfgFile, &nbgroups);
	if (!groups || nbgroups<=0)
	{
		GSETERROR(err,"Cannot retrieve the list of the configuration groups");
		goto errorLabel;
	}

	for (i=0; i<nbgroups ;i++)
	{
		gchar *group;
		group = groups[i];

		if (!group)
		{
			GSETERROR (err, "Invalid group name");
			goto errorLabel;
		}

		if (0 == fnmatch("Plugin.*", group, 0))
		{
			GModule *mod = NULL;

			/*get the filename of the plugin*/
			if (    !g_key_file_has_key (cfgFile, group, NAME_PATH, err)
				||	!(fileName = g_key_file_get_string (cfgFile, group, NAME_PATH, err)))
			{
				GSETERROR(err, "The group %s must contain the path of the plugin in the key %s", group, NAME_PATH);
				goto errorLabel;
			}

			/*get the parameter string*/
			params = extract_parameters (cfgFile, group, NAME_PARAM"_", err);
			if (!params)
			{
				GSETERROR(err,"Cannot load the parameters hash for the plugin (group %s in the configuration file)", group);
				goto errorLabel;
			}

			/*load the path*/
			mod = g_module_open (fileName, 0);
			if (!mod)
			{
				GSETERROR(err, "Cannot load the plug-in from file %s (%s)", fileName, g_module_error());
				goto errorLabel;
			}

			/*load the main exported symbol*/
			if (plugin_holder_update_config (mod, params, err))
				DEBUG ("updated %s", fileName);
			else {
				GSETERROR(err, "cannot update %s", fileName);
				goto errorLabel;
			}

			if (fileName) {
				g_free(fileName);
				fileName=NULL;
			}

			/*the hash table has not been copied, just its pointers*/
			params=NULL;
		}
	}

	g_strfreev(groups);

	return 1;

errorLabel:

	if (groups)
		g_strfreev (groups);

	if (fileName)
		g_free (fileName);

	if (params)
		g_hash_table_destroy (params);
	return 0;
}
#endif

static int
preload_plugins (GKeyFile *cfgFile, GError **err)
{
	GHashTable *params=NULL;
	gchar **groups=NULL;
	gsize nbgroups=0, i;
	gchar *fileName=NULL;

	if (!cfgFile)
	{
		GSETERROR(err,"Invalid Parameter");
		goto errorLabel;
	}

	DEBUG ("Start loading all the plugins found in the configuration");

	/*run the key's list and keep those mathing Plugin~*/
	groups = g_key_file_get_groups (cfgFile, &nbgroups);
	if (!groups || nbgroups<=0)
	{
		GSETERROR(err,"Cannot retrieve the list of the configuration groups");
		goto errorLabel;
	}

	for (i=0; i<nbgroups ;i++)
	{
		gchar *group;
		group = groups[i];

		if (!group)
		{
			GSETERROR (err, "Invalid group name");
			goto errorLabel;
		}

		if (0 == fnmatch("Plugin.*", group, 0))
		{
			GModule *mod = NULL;

			/*get the filename of the plugin*/
			if (    !g_key_file_has_key (cfgFile, group, NAME_PATH, err)
				||	!(fileName = g_key_file_get_string (cfgFile, group, NAME_PATH, err)))
			{
				GSETERROR(err, "The group %s must contain the path of the plugin in the key %s", group, NAME_PATH);
				goto errorLabel;
			}

			/*get the parameter string*/
			params = extract_parameters (cfgFile, group, NAME_PARAM"_", err);
			if (!params)
			{
				GSETERROR(err,"Cannot load the parameters hash for the plugin (group %s in the configuration file)", group);
				goto errorLabel;
			}

			/*load the path*/
			mod = g_module_open (fileName, 0);
			if (!mod)
			{
				GSETERROR(err, "Cannot load the plug-in from file %s (%s)", fileName, g_module_error());
				goto errorLabel;
			}

			/*load the main exported symbol*/
			if (plugin_holder_keep(mod, params, err))
			{
				DEBUG ("loaded %s", fileName);
			}
			else
			{
				GSETERROR(err, "cannot load %s", fileName);
				goto errorLabel;
			}

			if (fileName) {
				g_free(fileName);
				fileName=NULL;
			}

			/*the hash table has not been copied, just its pointers*/
			params=NULL;
		}
	}

	g_strfreev(groups);

	return 1;

errorLabel:

	if (groups)
		g_strfreev (groups);

	if (fileName)
		g_free (fileName);

	if (params)
		g_hash_table_destroy (params);
	return 0;
}

static void
set_srv_addr(const gchar* url)
{
	gchar str_addr[STRLEN_ADDRINFO];
	GError *local_error = NULL;
	addr_info_t *newaddr;

	EXTRA_ASSERT(url != NULL);

	newaddr = g_malloc0(sizeof(addr_info_t));
	if (!grid_string_to_addrinfo(url, newaddr))
		ERROR("Failed to init the server address to [%s] : %s", url, gerror_get_message(local_error));
	if (local_error)
		g_clear_error(&local_error);

	grid_addrinfo_to_string(newaddr, str_addr, sizeof(str_addr));
	NOTICE("Saving [%s] as main server address", str_addr);

	if (serv_addr != NULL) {
		grid_addrinfo_to_string(serv_addr, str_addr, sizeof(str_addr));
		WARN("Disarding anoter server address [%s], this won't be registered in the conscience", str_addr);
		addr_info_gclean(serv_addr, NULL);
	}

	serv_addr = newaddr;
}

static int
load_servers (GKeyFile *cfgFile, GError **err)
{
	gchar **srvList=NULL, **pluginList=NULL;
	gchar **groups=NULL;
	gsize nbgroups=0, i;

	if (!cfgFile)
	{
		GSETERROR(err,"Invalid Parameter");
		goto errorLabel;
	}

	DEBUG ("Start loading all the servers found in the configuration");

	/*run the key's list and keep those mathing Plugin~*/
	groups = g_key_file_get_groups (cfgFile, &nbgroups);
	if (!groups || nbgroups<=0)
	{
		GSETERROR(err,"Cannot retrieve the list of the configuration groups");
		return 0;
	}

	for (i=0; i<nbgroups ;i++)
	{
		gchar *group;
		group = groups[i];

		if (!group)
		{
			GSETERROR (err, "Invalid group name");
			return 0;
		}

		if (0 == fnmatch("Server.*", group, 0))
		{
			gsize nbPlugins=0;
			gchar *section=NULL, **url;
			struct server_s *srv = NULL;

			/*a plugin has been detected*/
			section = strchr(group,'.') + 1;

			/*check the presence of mandatory keys*/
			if (!g_key_file_has_key (cfgFile, group, NAME_PLUGINS, err))
			{
				GSETERROR(err,"the key '%s' was not found the section %s (1)", NAME_PLUGINS, section);
				goto errorLabel;
			}

			if (!g_key_file_has_key (cfgFile, group, NAME_LISTEN, err))
			{
				GSETERROR(err,"the key '%s' was not found the section %s (1)", NAME_LISTEN, section);
				goto errorLabel;
			}

			/* prepare a new server structure, unshift it in the list */
			if (!(srv = g_try_malloc0(sizeof(struct server_s))))
			{
				GSETERROR(err, "Memory allocation error");
				goto errorLabel;
			}

			srv->ap = NULL;
			srv->to_connection = default_to_connection;
			srv->to_operation = default_to_operation;
			srv->mon.nb_workers = 0;
			srv->mon.max_workers = default_max_workers;
			srv->mon.max_spare_workers = default_max_spare_workers;
			srv->mon.min_spare_workers = default_min_spare_workers;
			srv->mon.min_workers = default_min_workers;
			memcpy( &(srv->alert_cfg), &default_alert_cfg, sizeof(struct alert_cfg_s));
			g_strlcpy (srv->name, section, SIZE_SRVNAME-1);
			srv->next = BEACON_SRV.next;
			BEACON_SRV.next = srv;

			GET_INT(group,NAME_TIMEOUT_CNX,srv->to_connection);
			GET_INT(group,NAME_TIMEOUT_OP,srv->to_operation);
			GET_INT(group,NAME_WORKERS,srv->mon.max_workers);
			GET_INT(group,NAME_MAX_WORKERS,srv->mon.max_workers);
			GET_INT(group,NAME_MAX_SPARE_WORKERS,srv->mon.max_spare_workers);
			GET_INT(group,NAME_MIN_SPARE_WORKERS,srv->mon.min_spare_workers);
			GET_INT(group,NAME_MIN_WORKERS,srv->mon.min_workers);
			GET_INT(group,NAME_ALERT_PERIOD,srv->alert_cfg.frequency);

			// XXX For compatibility purposes, we still receive timeouts in
			// milliseconds, but we always compare them to timestamps in
			// seconds.
			srv->to_connection = srv->to_connection / 1000;

			CHECK_WORKER_COUNTERS(srv->mon.min_workers, srv->mon.max_workers,
					srv->mon.min_spare_workers, srv->mon.max_spare_workers);

			/*load the server list*/
			srvList = g_key_file_get_string_list (cfgFile, group, NAME_LISTEN, 0, err);
			if (!srvList)
			{
				GSETERROR(err,"the key '%s' was not found the section %s (2)", NAME_LISTEN, group);
				goto errorLabel;
			}

			if (!accept_make (&(srv->ap), err))
			{
				GSETERROR(err,"Cannot init a new connection pool");
				goto errorLabel;
			}

			for (url = srvList; srvList && *url && *(*url); url++)
			{
				set_srv_addr(*url);
				if (!accept_add(srv->ap, *url, err))
					goto errorLabel;
			}

			/*load the message handlers for this server structure*/

			pluginList = g_key_file_get_string_list (cfgFile, group, NAME_PLUGINS, &nbPlugins, err);
			if (!pluginList || nbPlugins<=0)
			{
				GSETERROR(err,"the key '%s' was not found the section %s, or it is empty", NAME_PLUGINS, section);
				goto errorLabel;
			}

			srv->handlers = g_try_malloc0 (nbPlugins * sizeof(struct message_handler_s*));
			if (!BEACON_SRV.next->handlers)
			{
				GSETERROR(err,"Memory allocation error");
				goto errorLabel;
			}
			srv->nbHandlers = nbPlugins;

			for (; nbPlugins>0 ; nbPlugins--)
			{
				struct message_handler_s *h;

				for (h=BEACON_MSGHANDLER.next; h ;h=h->next)
				{
					if (0 == strcmp (h->name, pluginList [nbPlugins-1]))
					{
						BEACON_SRV.next->handlers[nbPlugins-1] = h;
						DEBUG ("The message handler '%s' has been prepended to the server '%s'", pluginList [nbPlugins-1], BEACON_SRV.next->name);
						break;
					}
				}

				if (!BEACON_SRV.next->handlers[nbPlugins-1])
				{
					GSETERROR (err, "The server '%s' requires the message handler '%s'", BEACON_SRV.next->name, pluginList [nbPlugins-1]);
					return 0;
				}
			}

			/*debug the server structure*/
			DEBUG ("New server created SRV=%s POOL=%p WORKER={min:%d max:%d min_spare:%d max_spare:%d} TO_CNX=%i TO_OP=%i",
				srv->name, (void*)srv->ap,
				srv->mon.min_workers, srv->mon.max_workers,
				srv->mon.min_spare_workers, srv->mon.max_spare_workers,
				srv->to_connection, srv->to_operation);

			/**/
			if (srvList) {
				g_strfreev(srvList);
				srvList=NULL;
			}
			if (pluginList) {
				g_strfreev(pluginList);
				pluginList=NULL;
			}
		}
	}

	g_strfreev(groups);

	return 1;

errorLabel:

	if (groups)
		g_strfreev(groups);

	if (srvList)
		g_strfreev(srvList);

	if (pluginList)
		g_strfreev(pluginList);

	return 0;
}

static int
reload_defaults (GKeyFile *cfgFile, GError **err)
{
	if (!g_key_file_has_group (cfgFile, NAME_GENERAL)) {
		GSETERROR(err, "No '%s' group in configuration", NAME_GENERAL);
		return 0;
	}

	GET_INT(NAME_GENERAL,NAME_WORKERS,default_max_workers);
	GET_INT(NAME_GENERAL,NAME_MAX_WORKERS,default_max_workers);
	GET_INT(NAME_GENERAL,NAME_MAX_SPARE_WORKERS,default_max_spare_workers);
	GET_INT(NAME_GENERAL,NAME_MIN_SPARE_WORKERS,default_min_spare_workers);
	GET_INT(NAME_GENERAL,NAME_MIN_WORKERS,default_min_workers);
	GET_INT(NAME_GENERAL,NAME_TIMEOUT_CNX,default_to_connection);
	GET_INT(NAME_GENERAL,NAME_TIMEOUT_OP,default_to_operation);

	gridd_set_flag(GRIDD_FLAG_NOLINGER,
			GET_FLAG(cfgFile, NAME_GENERAL, "NOLINGER", TRUE));

	gridd_set_flag(GRIDD_FLAG_KEEPALIVE,
			GET_FLAG(cfgFile, NAME_GENERAL, "KEEPALIVE", TRUE));

	gridd_set_flag(GRIDD_FLAG_QUICKACK,
			GET_FLAG(cfgFile, NAME_GENERAL, "QUICKACK", TRUE));

	gridd_set_flag(GRIDD_FLAG_SHUTDOWN,
			GET_FLAG(cfgFile, NAME_GENERAL, "SHUTDOWN", TRUE));

	CHECK_WORKER_COUNTERS(default_min_workers, default_max_workers,
			default_min_spare_workers, default_max_spare_workers);

	return 1;
}

static int
load_defaults (GKeyFile *cfgFile, GError **err)
{
	if (!reload_defaults(cfgFile, err))
		return 0;

	return 1;
}

static void
load_service_tags(GKeyFile *cfgFile, GError **err)
{
	gchar **tags, **cur_tag;
	gchar *tag_name, *tag_value;
	gsize number_of_tags;
	struct service_tag_s tag_s;

	if (NULL == serv_tags)
		serv_tags = g_ptr_array_new();

	if (g_key_file_has_group (cfgFile, NAME_SERVICETAGS)) {
		tags = g_key_file_get_keys(cfgFile, NAME_SERVICETAGS, &number_of_tags, err);
		for (cur_tag = tags; *cur_tag; cur_tag++) {
			tag_name = g_strconcat("tag.", *cur_tag, NULL);
			tag_value = g_key_file_get_value(cfgFile, NAME_SERVICETAGS, *cur_tag, err);
			g_strlcpy(tag_s.name, tag_name, sizeof(tag_s.name));
			service_tag_set_value_string(&tag_s, tag_value);
			g_ptr_array_add(serv_tags, service_tag_dup(&tag_s));
			g_free(tag_name);
		}
		g_strfreev(tags);
	}
}

/**
 * @warning This function will block until gridagent is available
 */
static int
load_service_info (GKeyFile *cfgFile, GError **err)
{
	if (!g_key_file_has_group (cfgFile, NAME_SERVICE)) {
		DEBUG("No '%s' group in configuration, Old style service declaration", NAME_SERVICE);
		old_style = TRUE;
		return 1;
	}


	ns_name = g_key_file_get_string (cfgFile, NAME_SERVICE, NAME_NAMESPACE, err);

	service_type = g_key_file_get_string (cfgFile, NAME_SERVICE, NAME_SRV_TYPE, err);
	/* TODO: service type ok */

	rec_service = g_key_file_get_boolean (cfgFile, NAME_SERVICE, NAME_REGISTER, err);
	if (!rec_service)
		load_ns_info = g_key_file_get_boolean (cfgFile, NAME_SERVICE, NAME_LOAD_NS_INFO, err);
	else
		load_ns_info = TRUE;

	if(load_ns_info) {
		GError *e = conscience_get_namespace (ns_name, &ns_info);
		/* We really want these informations, so loop until we get them. */
		while (e) {
			g_clear_error(&e);
			WARN("Failed to get namespace info (Retrying in %d seconds): %s",
					GET_NS_INFO_RETRY_DELAY, (*err)->message);
			sleep(GET_NS_INFO_RETRY_DELAY);
			e = conscience_get_namespace (ns_name, &ns_info);
		}
	}

	load_service_tags(cfgFile, err);

	return 1;
}

static int
load_configuration (const char *cfg_path, GError **err)
{
	GKeyFile *cfgFile = NULL;

	INFO("Logging facility configured!");

	/*Parse the configuration*/
	cfgFile = g_key_file_new ();
	g_key_file_set_list_separator (cfgFile, ',');

	if (!g_key_file_load_from_file (cfgFile, cfg_path, G_KEY_FILE_NONE, err)) {
		GSETERROR(err, "Cannot parse the configuration");
		goto errorLabel;
	}

	/*loads the default values*/
	if (!load_defaults (cfgFile,err)) {
		GSETERROR(err, "Cannot set the default values from the configuration");
		goto errorLabel;
	}

	/* load info about service we are and our namespace */
	if (!load_service_info(cfgFile,err)) {
		GSETERROR (err, "Failed to get all informations about the service");
		goto errorLabel;
	}

	/*preloads the plugins*/
	if (!preload_plugins (cfgFile,err)) {
		GSETERROR (err, "Cannot preload the plugins from the configuration");
		goto errorLabel;
	}

	/*init all the loaded plugins*/
	if (!plugin_holder_init_all (err)) {
		GSETERROR (err, "an error occured during the plugins initialization");
		goto errorLabel;
	}

	INFO ("Plug-in's loaded!");

	/*then load the servers from the configuration file*/
	if (!load_servers (cfgFile, err)) {
		GSETERROR(err, "Cannot load servers");
		goto errorLabel;
	}

	INFO ("Server threads loaded!");

	g_key_file_free (cfgFile);
	return 1;
errorLabel:
	if (cfgFile)
		g_key_file_free (cfgFile);
	return 0;
}

static gint64
server_has_thread(struct server_s *srv)
{
	gint64 rc;

	g_rec_mutex_lock (&(srv->recMutex));
	rc = srv->mon.nb_workers;
	g_rec_mutex_unlock (&(srv->recMutex));
	return rc;
}

static void
wait_for_workers(void)
{
	struct server_s *srv;
	gboolean rc;
	gint64 i64;

	do {
		rc = FALSE;
		for (srv=BEACON_SRV.next; !rc && srv ;srv=srv->next) {
			if (0 < (i64 = server_has_thread(srv))) {
				rc = TRUE;
				INFO("Waiting for workers : still %"G_GINT64_FORMAT, i64);
			}
		}
		if (rc)
			sleep(1);
	} while (rc);

	NOTICE("No more workers detected");
}

static gboolean
start_server_threads(struct server_s *srv)
{
	gint i, max, nb;

	memset(&(srv->recMutex), 0, sizeof(srv->recMutex));
	g_rec_mutex_init (&(srv->recMutex));

	/* XXX start of locked section */
	g_rec_mutex_lock (&(srv->recMutex));
	max = MAX(srv->mon.min_workers,srv->mon.min_spare_workers);
	for (i=0; i<max ;i++)
		thread_monitoring_add(srv, TRUE);
	g_rec_mutex_unlock (&(srv->recMutex));
	/* XXX end of locked section */

	/* Deferred thread creations */
	nb = 0;
	while ((i--) > 0) {
		if (thread_start(srv)) {
			nb++;
		} else {
			ERROR("Cannot start a worker thread for %s", srv->name);
			thread_monitoring_remove(srv, FALSE);
		}
	}

	return nb > 0;
}

static gboolean
start_threads (void)
{
	gboolean all_done = TRUE;
	struct server_s *srv;

	for (srv=BEACON_SRV.next ; srv ; srv=srv->next) {
		if (start_server_threads(srv))
			NOTICE("Some threads started for %s",srv->name);
		else {
			ERROR("No threads started for %s",srv->name);
			all_done = FALSE;
		}
	}

	return all_done;
}

/* ------------------------------------------------------------------------- */

static void
main_action (void)
{
	srvtimer_register_regular ("server core statistics", srv_inner_gauges_update, NULL, NULL, 1);

	/*start the threads*/
	if (!start_threads()) {
		ERROR("Cannot start threads for all the servers");
		grid_main_stop();
		return;
	}

	/* Register service if needed */
	if (rec_service) {
		GError *err = NULL;
		if (!self_register_in_cluster(&err)) {
			ERROR("Failed to register service in cluster : (%d) %s", err->code, err->message);
			g_clear_error(&err);
		}
		/* Periodic register in cluster */
		srvtimer_register_regular(service_type, srv_periodic_register, NULL, NULL, PERIOD_REGISTER);
	}
	if(load_ns_info)
		srvtimer_register_regular(service_type, srv_periodic_refresh_ns_info, NULL, NULL, PERIOD_REFRESH_NS_INFO);
	/*Threads started, we start monitoring them*/

	struct server_s *s = NULL;

	for (s=BEACON_SRV.next; s && s!=&BEACON_SRV ;s=s->next) {
		srvtimer_register_regular(s->name, (srvtimer_f)thread_monitoring_periodic_debug, NULL, s, PERIOD_DEBUG);
		srvtimer_register_regular(s->name, (srvtimer_f)thread_monitoring_periodic_stats, NULL, s, PERIOD_STATS);
	}

	/*wait forever and fire the registered timers*/
	for (guint64 ticks=1; may_continue ;ticks++) {
		srvtimer_fire (ticks);
		g_usleep (1000000UL);
	}
}

static void
main_set_defaults (void)
{
	memset(&stats_interval, 0x00, sizeof(stats_interval));
	memset(&stats_total, 0x00, sizeof(stats_total));
	memset(&stats_mutex, 0, sizeof(stats_mutex));
	g_mutex_init(&stats_mutex);
	memset(&ns_info_lock, 0, sizeof(ns_info_lock));
	g_rw_lock_init(&ns_info_lock);
	memset(&BEACON_SRV, 0x00, sizeof(BEACON_SRV));
	memset(&BEACON_MSGHANDLER, 0x00, sizeof(BEACON_MSGHANDLER));
}

static gboolean
main_configure(int argc, char **argv)
{
	if (argc > 0) {
		config_file = g_strdup(argv[0]);
	} else {
		ERROR("Missing argument\n");
		return FALSE;
	}

	GError *err = NULL;
	if (!load_configuration (config_file, &err)) {
		ERROR("Failed to load the configuration : (%d) %s", err->code, err->message);
		return FALSE;
	}

	return TRUE;
}

static void
main_specific_fini (void)
{
	may_continue = FALSE;
	wait_for_workers();

	DEBUG("Closing the servers");
	for (SERVER srv=BEACON_SRV.next; srv ;srv=srv->next) {
		if (srv->ap) {
			GError *error = NULL;
			int nb = accept_close_servers( srv->ap, &error);
			if (nb>0)
				ERROR("%d server sockets could not be stopped : %s", nb, error?error->message:"?");
			if (error)
				g_clear_error( &error);
		}
	}

	DEBUG("Stopping the servers");
	for (SERVER srv=BEACON_SRV.next; srv ;srv=srv->next) {
		if (srv->ap) {
			g_free(srv->ap);
			srv->ap = NULL;
		}
	}

	plugin_holder_close_all();

	DEBUG("Unlinking the servers");
	for (struct server_s *s=BEACON_SRV.next; s ;s=s->next) {
		DEBUG("Stopping %p", s);
		if (s->handlers) {
			g_free(s->handlers);
			s->handlers = NULL;
		}
		g_rec_mutex_clear(&(s->recMutex));
	}

	DEBUG("Cleaning the servers");
	for (struct server_s *s=BEACON_SRV.next; s ;) {
		struct server_s *sTmp;
		DEBUG("Cleaning %p", s);
		sTmp = s->next;
		g_free(s);
		s = sTmp;
	}

	DEBUG("Cleaning the message handlers");
	for (struct message_handler_s *m=BEACON_MSGHANDLER.next; m ;) {
		struct message_handler_s *mTmp;
		DEBUG("Cleaning %p", m);
		mTmp = m->next;
		g_free(m);
		m = mTmp;
	}

	srvtimer_fini();
	srvstat_fini();
}

static void
main_specific_stop (void)
{
	may_continue = FALSE;
}

static const char *
main_usage (void)
{
	return "INIFILE";
}

static struct grid_main_option_s *
main_get_options(void)
{
	static struct grid_main_option_s options[] = {
		{NULL, 0, {.i=0}, NULL}
	};
	return options;
}

int
main (int argc, char **argv)
{
	static struct grid_main_callbacks callbacks = {
		.options = main_get_options,
		.action = main_action,
		.set_defaults = main_set_defaults,
		.specific_fini = main_specific_fini,
		.configure = main_configure,
		.usage = main_usage,
		.specific_stop = main_specific_stop,
	};
	if (!g_module_supported()) {
		g_error("GLib MODULES are not supported on this platform!");
		return 1;
	}

	return grid_main(argc, argv, &callbacks);
}

