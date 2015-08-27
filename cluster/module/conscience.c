/*
OpenIO SDS conscience
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

#include <glib.h>

#include <metautils/lib/metautils.h>
#include <server/transport_gridd.h>
#include <server/network_server.h>
#include <cluster/module/module.h>

static struct network_server_s *server = NULL;
static struct gridd_request_dispatcher_s *dispatcher = NULL;

static struct grid_task_queue_s *gtq_admin = NULL;
static GThread *th_admin = NULL;

static GRWLock services_lock;
static GTree *services = NULL;
static GTree *locks = NULL;

static GRWLock nsinfo_lock;
static struct namespace_info_s *nsinfo = NULL;
static GByteArray *nsinfo_cache = NULL;

static gboolean lock_has (const char *k) { return NULL != g_tree_lookup (locks, k); }
static void lock_set (const char *k) { g_tree_replace(locks, g_strdup(k), GINT_TO_POINTER(1)); }
static void lock_del (const char *k) { g_tree_remove (locks, k); }

static void srv_merge (struct service_info_s *si0, struct service_info_s *si)
{
	for (guint i=0; i<si->tags->len ;i++) {
		struct service_tag_s *t = si->tags->pdata[i];
		struct service_tag_s *t0 = service_info_ensure_tag (si0->tags, t->name);
		service_tag_copy (t0, t);
	}
}

/* -------------------------------------------------------------------------- */

static void
_task_expire (gpointer p)
{
	(void) p;
	gint64 pivot = network_server_bogonow (server) - 300;
	GSList *suspects = NULL;

	gboolean _identify (gchar *k, struct service_info_s *si, gpointer i) {
		(void) i;
		if (si->score.timestamp < pivot)
			suspects = g_slist_prepend (suspects, g_strdup(k));
		return FALSE;
	}
	g_rw_lock_reader_lock (&services_lock);
	g_tree_foreach (services, (GTraverseFunc)_identify, NULL);
	g_rw_lock_reader_unlock (&services_lock);

	if (suspects) {
		g_rw_lock_writer_lock (&services_lock);
		for (GSList *l=suspects; l ;l=l->next) {
			gchar *k = l->data;
			if (lock_has(k)) continue;
			g_tree_remove (services, k);
		}
		g_rw_lock_writer_unlock (&services_lock);
		g_slist_free_full (suspects, g_free);
	}
}

static void
_task_reweight (gpointer p)
{
	(void) p;
	gint64 sum = 0;
	guint count = 0;

	gboolean _agregate (gchar *k, struct service_info_s *si, gpointer i) {
		(void) i, (void) k, sum += si->score.value, count ++;
		return FALSE;
	}
	g_rw_lock_reader_lock (&services_lock);
	g_tree_foreach (services, (GTraverseFunc)_agregate, NULL);
	g_rw_lock_reader_unlock (&services_lock);

	gint32 average = count ? sum / count : 50;

	gboolean _reweight (gchar *k, struct service_info_s *si, gpointer i) {
		(void) k, (void) i;
		if (si->score.value > average)
			si->score.value ++;
		else if (si->score.value > 0)
			si->score.value --;
		return FALSE;
	}
	g_rw_lock_writer_lock (&services_lock);
	g_tree_foreach (services, (GTraverseFunc)_reweight, NULL);
	g_rw_lock_writer_unlock (&services_lock);
}

/* -------------------------------------------------------------------------- */

static gboolean
_cs_dispatch_NSINFO(struct gridd_reply_ctx_s *reply, gpointer g, gpointer h)
{
	(void) g, (void) h;
	if (!nsinfo_cache) {
		reply->send_error(0, NEWERROR(CODE_INTERNAL_ERROR, "NS not ready"));
		return TRUE;
	}

	GByteArray *body = g_byte_array_ref(nsinfo_cache);
	g_rw_lock_reader_lock (&nsinfo_lock);
	reply->add_body (body);
	g_rw_lock_reader_unlock (&nsinfo_lock);

	reply->send_reply (CODE_FINAL_OK, "OK");
	return TRUE;
}

static gboolean
_strv_has (gchar **types, const char *type)
{
	for (gchar **pt=types ; *pt ;pt++)
		if (!strcmp(*pt, type)) return TRUE;
	return FALSE;
}

static gboolean
_cs_dispatch_SRV(struct gridd_reply_ctx_s *reply, gpointer g, gpointer h)
{
	(void) g, (void) h;

	gboolean full = metautils_message_extract_flag (reply->request, NAME_MSGKEY_FULL, FALSE);
	gsize size = 0;
	void *data = metautils_message_get_field (reply->request, NAME_MSGKEY_TYPENAME, &size);
	gchar **types = data && size ? buffer_split(data, size, ",", 0) : g_malloc0 (sizeof(void*));

	GByteArray *packed = g_byte_array_new ();
	g_byte_array_append (packed, (guint8*)"\x30\x80", 2);

	gboolean _pack (gchar *k, struct service_info_s *si, gpointer i) {
		(void) k, (void) i;
		if (!_strv_has(types, si->type)) return FALSE;
		struct service_info_s tmp;
		memcpy (&tmp, si, sizeof(struct service_info_s));
		if (!full) tmp.tags = NULL;
		GByteArray *gba = NULL;
		if (NULL != (gba = service_info_marshall_1 (&tmp, NULL))) {
			g_byte_array_append (packed, gba->data, gba->len);
			g_byte_array_free (gba, TRUE);
		}
		return FALSE;
	}
	g_rw_lock_reader_lock (&services_lock);
	g_tree_foreach (services, (GTraverseFunc)_pack, packed);
	g_rw_lock_reader_unlock (&services_lock);

	g_byte_array_append (packed, (guint8*)"\x00\x00", 2);
	reply->add_body (packed);
	reply->send_reply (CODE_FINAL_OK, "OK");
	g_strfreev (types);
	return TRUE;
}

static gboolean
_cs_dispatch_TYPES(struct gridd_reply_ctx_s *reply, gpointer g, gpointer h)
{
	(void) g, (void) h;
	GTree *types = g_tree_new_full(metautils_strcmp3, NULL, g_free, NULL);

	gboolean _run_services (gpointer k, gpointer v, gpointer i) {
		(void) i, (void) k;
		struct service_info_s *si = v;
		g_tree_replace (types, g_strdup(si->type), GINT_TO_POINTER(1));
		return FALSE;
	}
	g_rw_lock_reader_lock (&services_lock);
	g_tree_foreach (services, _run_services, NULL);
	g_rw_lock_reader_unlock (&services_lock);

	GSList *l = NULL;
	gboolean _run_types(gpointer k, gpointer v, gpointer i) {	
		(void) v, (void) i; l = g_slist_prepend (l, k); return TRUE;
	}
	g_tree_foreach (types, _run_types, NULL);
	GByteArray *body = strings_marshall_gba (l, NULL);
	g_slist_free (l);
	g_tree_destroy (types);

	reply->add_body (body);
	reply->send_reply (CODE_FINAL_OK, "OK");
	return TRUE;
}

static gboolean
_cs_dispatch_PUSH(struct gridd_reply_ctx_s *reply, gpointer g, gpointer h)
{
	(void) g, (void) h;
	gint64 now = network_server_bogonow (server);
	GSList *list = NULL;
	GError *err = metautils_message_extract_body_encoded(reply->request, TRUE,
			&list, service_info_unmarshall);
	if (err) {
		g_slist_free_full (list, (GDestroyNotify)service_info_clean);
		reply->send_error(0,err);
		return TRUE;
	}

	g_rw_lock_writer_lock (&services_lock);
	for (GSList *l=list; l ;l=l->next) {
		struct service_info_s *si = l->data;
		if (!si) continue;
		gchar *k = service_info_key (si);
		struct service_info_s *si0 = g_tree_lookup(services, k);
		if (!si0) {
			si->score.value = 1;
			si->score.timestamp = now;
			g_tree_replace(services, k, si);
			l->data = si = NULL;
		} else {
			memcpy(&si0->addr, &si->addr, sizeof(addr_info_t));
			if (si->score.value == SCORE_UNSET) {
				if (si->tags && !lock_has(k)) {
					si->score.value = si0->score.value;
					si->score.timestamp = now;
					srv_merge (si0, si);
				}
			} else if (si->score.value == SCORE_UNLOCK) {
				lock_del (k);
			} else { /* lock */
				srv_merge (si0, si);
				lock_set (k);
			}
			g_free(k);
		}
	}
	g_rw_lock_writer_unlock (&services_lock);

	g_slist_free_full (list, (GDestroyNotify)service_info_clean);
	reply->send_reply (CODE_FINAL_OK, "OK");
	return TRUE;
}

static gboolean
_cs_dispatch_RM(struct gridd_reply_ctx_s *reply, gpointer g, gpointer h)
{
	(void) g, (void) h;
	reply->send_reply(CODE_NOT_IMPLEMENTED, "NYI");
	return TRUE;
}

/* -------------------------------------------------------------------------- */

static void
_cs_action(void)
{
	GError *err = network_server_open_servers (server);
	if (err) {
		GRID_ERROR("Failed to open the server sockets: (%d) %s", err->code, err->message);
		grid_main_set_status (1);
		return;
	}
	grid_task_queue_fire (gtq_admin);

	if (!(th_admin = grid_task_queue_run (gtq_admin, &err))) {
		GRID_ERROR("Failed to start the admin tasks: (%d) %s", err->code, err->message);
		grid_main_set_status (1);
		return;
	}

	network_server_run (server);
}

static void
_cs_specific_stop(void)
{
	grid_task_queue_stop (gtq_admin);
	network_server_stop (server);
}

static gboolean
_cs_configure(int argc, char **argv)
{
	(void) argc, (void) argv;
	struct gridd_request_descr_s descr[] = {
		{NAME_MSGNAME_CS_GET_NSINFO,   _cs_dispatch_NSINFO, NULL},
		{NAME_MSGNAME_CS_GET_SRV,      _cs_dispatch_SRV, NULL},
		{NAME_MSGNAME_CS_GET_SRVNAMES, _cs_dispatch_TYPES, NULL},
		{NAME_MSGNAME_CS_PUSH_SRV,     _cs_dispatch_PUSH, NULL},
		{NAME_MSGNAME_CS_RM_SRV,       _cs_dispatch_RM, NULL},
		{NULL, NULL, NULL}
	};

	nsinfo = g_malloc0 (sizeof(struct namespace_info_s));
	namespace_info_init (nsinfo);

	const char *cfg = "/home/jfs/.oio/sds/conf/NS-conscience.json";
	GError *err = NULL;
	gchar *data = NULL;
	gsize len = 0;
	g_file_get_contents (cfg, &data, &len, &err);
	if (!err)
		err = namespace_info_init_json (data, nsinfo);
	g_free0 (data);

	if (err) {
		GRID_ERROR ("Failed to load the configuration [%s]: (%d) %s",
				cfg, err->code, err->message);
		return FALSE;
	}

	nsinfo_cache = namespace_info_marshall (nsinfo, &err);
	if (err) {
		GRID_ERROR ("NSInfo encoding error: (%d) %s", err->code, err->message);
		return FALSE;
	}

	gtq_admin = grid_task_queue_create ("admin");
	locks = g_tree_new_full (metautils_strcmp3, NULL, g_free, NULL);
	services = g_tree_new_full (metautils_strcmp3, NULL, g_free, (GDestroyNotify)service_info_clean);
	server = network_server_init();
	dispatcher = transport_gridd_build_empty_dispatcher ();
	transport_gridd_dispatcher_add_requests (dispatcher, descr, NULL);
	network_server_bind_host(server, "127.0.0.1:6000", dispatcher,
			transport_gridd_factory);
	grid_task_queue_register (gtq_admin, 1, _task_expire, NULL, NULL);
	grid_task_queue_register (gtq_admin, 1, _task_reweight, NULL, NULL);
	return TRUE;
}

static void
_cs_set_defaults(void)
{
	g_rw_lock_init (&services_lock);
	g_rw_lock_init (&nsinfo_lock);
}

static void
_cs_specific_fini(void)
{
	// stop phase
	if (server) {
		network_server_stop (server);
		network_server_close_servers (server);
	}
	if (gtq_admin)
		grid_task_queue_stop (gtq_admin);
	if (th_admin) {
		g_thread_join (th_admin);
		th_admin = NULL;
	}
	// Close phase
	if (server) {
		network_server_clean (server);
		server = NULL;
	}
	if (dispatcher) {
		gridd_request_dispatcher_clean (dispatcher);
		dispatcher = NULL;
	}
	if (gtq_admin) {
		grid_task_queue_destroy (gtq_admin);
		gtq_admin = NULL;
	}
	if (services) {
		g_tree_destroy (services);
		services = NULL;
	}
	if (locks) {
		g_tree_destroy (locks);
		locks = NULL;
	}

	metautils_gba_unref (nsinfo_cache);
	namespace_info_free (nsinfo);
	g_rw_lock_clear (&services_lock);
	g_rw_lock_clear (&nsinfo_lock);
}

static struct grid_main_option_s *
_cs_get_options(void)
{
	static struct grid_main_option_s sqlx_options[] = {
		{NULL, 0, {.i=0}, NULL}
	};

	return sqlx_options;
}

static const char *
_cs_usage(void)
{
	return "";
}

int
main(int argc, char ** argv)
{
	struct grid_main_callbacks callbacks = {
		.options = _cs_get_options,
		.action = _cs_action,
		.set_defaults = _cs_set_defaults,
		.specific_fini = _cs_specific_fini,
		.configure = _cs_configure,
		.usage = _cs_usage,
		.specific_stop = _cs_specific_stop,
	};
	return grid_main(argc, argv, &callbacks);
}

