/*
OpenIO SDS conscience
Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage

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
#include <lua.h>
#include <lualib.h>
#include "lauxlib.h"

#include <metautils/metautils.h>
#include <server/transport_gridd.h>
#include <server/network_server.h>

#include "remote.h"
#include "srvset.h"

static GSList *urls = NULL;

static GRWLock scorers_lock;
static GTree *scorers = NULL;

static struct network_server_s *server = NULL;
static struct gridd_request_dispatcher_s *dispatcher = NULL;

static struct grid_task_queue_s *gtq_admin = NULL;
static GThread *th_admin = NULL;

static GRWLock services_lock;
static srvset_t *services = NULL;

static GRWLock nsinfo_lock;
static struct namespace_info_s *nsinfo = NULL;
static GByteArray *nsinfo_cache = NULL;

static void*
_allocator (gpointer i, gpointer p, size_t osize, size_t nsize)
{
	(void) i, (void) osize;
	return g_realloc (p, nsize);
}

static GError *
_load_scorer_from_file (const char *path, const char *type)
{
	GRID_DEBUG ("Loading the scoring script for [%s] from [%s]", type, path);

	lua_State *L = lua_newstate (_allocator, NULL);
	if (!L)
		return NEWERROR (CODE_INTERNAL_ERROR, "LUA env allocation error");

	GError *err = NULL;
	luaopen_math (L);
	int rc = luaL_dofile (L, path);
	if (rc != LUA_OK)
		err = NEWERROR(CODE_INTERNAL_ERROR, "Invalid configuration for [%s]"
				" in [%s]: %s", type, path, "bad LUA file");

	if (!err) { // check cumpute exists and is a function
		lua_pop (L, 1);
		lua_gc (L, LUA_GCCOLLECT, 0);
		lua_getglobal (L, "compute");
		if (lua_isnil (L, -1))
			err = NEWERROR(CODE_INTERNAL_ERROR, "Invalid configuration for [%s] in [%s]: no 'compute' function", type, path);
		lua_pop (L, 1);
	}

	if (err) {
		lua_close (L);
		return err;
	} else {
		g_rw_lock_writer_lock (&scorers_lock);
		g_tree_replace (scorers, g_strdup (type), L);
		g_rw_lock_writer_unlock (&scorers_lock);
		return NULL;
	}
}

static GError *
_load_scorers_from_dir (const char *base)
{
	GRID_DEBUG ("Loading the scoring scripts from [%s]", base);
	GError *err = NULL;
	GDir *gdir = g_dir_open(base, 0, &err);
	if (!gdir)
		return err;
	const char *sub;
	while (!err && NULL != (sub = g_dir_read_name (gdir))) {
		// only keep non-hidden lua files
		if (*sub == '.') continue;
		if (!g_str_has_suffix (sub, ".lua")) continue;
		gchar *full = g_strconcat (base, G_DIR_SEPARATOR_S, sub, NULL);
		gchar *type = g_strdup (sub);
		*(strchr(type, '.')) = '\0';
		err = _load_scorer_from_file (full, type);
		g_free (full);
		g_free (type);
	}
	g_dir_close (gdir);
	return err;
}

static void
_scorer_clean (gpointer p)
{
	if (!p) return;
	lua_close ((lua_State*)p);
}

static void
_task_expire (gpointer p)
{
	(void) p;
	gint64 pivot = network_server_bogonow (server) - 300;
	g_rw_lock_writer_lock (&services_lock);
	srvset_purge (services, pivot);
	g_rw_lock_writer_unlock (&services_lock);
}

static void
_set_score (struct service_info_s *si)
{
	if (si->score.timestamp == 0)
		return;
	lua_State *L = g_tree_lookup (scorers, si->type);
	if (!L) {
		si->score.value = SCORE_UNSET;
	} else { // score = compute(ns, type, oldscore, tags)
		lua_getglobal (L, "compute");
		lua_pushstring (L, "ns");
		lua_pushstring (L, si->type);
		lua_pushinteger (L, si->score.value);

		lua_newtable (L);
		if (si->tags) {
			for (guint i=0; i<si->tags->len ;i++) {
				struct service_tag_s *t = si->tags->pdata[i];
				lua_pushstring (L, t->name);
				switch (t->type) {
					case STVT_I64:  lua_pushinteger (L, t->value.i); break;
					case STVT_REAL: lua_pushnumber (L, t->value.r); break;
					case STVT_BOOL: lua_pushboolean (L, t->value.b); break;
					case STVT_STR:  lua_pushstring (L, t->value.s); break;
					case STVT_BUF:  lua_pushstring (L, t->value.buf); break;
					default: lua_pushnil (L); break;
				}
				lua_rawset (L, -3);
			}
		}

		lua_pcall (L, 4, 1, 0);
		if (lua_isnil (L, -1))
			si->score.value = SCORE_UNSET;
		else
			si->score.value = lua_tointeger (L, -1);
		lua_pop (L, 1);
	}
}

static void
_task_score (gpointer p)
{
	(void) p;
	struct timespec pre, post;

	// TODO reload the scorers

	clock_gettime (CLOCK_MONOTONIC, &pre);
	g_rw_lock_writer_lock (&services_lock);
	g_rw_lock_reader_lock (&scorers_lock);
	srvset_run (services, NULL, _set_score);
	g_rw_lock_reader_unlock (&scorers_lock);
	g_rw_lock_writer_unlock (&services_lock);
	clock_gettime (CLOCK_MONOTONIC, &post);

	post.tv_sec -= pre.tv_sec;
	post.tv_nsec -= pre.tv_nsec;
	if (post.tv_sec > 1 || post.tv_nsec > 100000000) // > 100ms
		GRID_WARN("Spent %ld.%06ld to set the scores", post.tv_sec, post.tv_nsec/1000);
	else
		GRID_DEBUG("Spent %ld.%06ld to set the scores", post.tv_sec, post.tv_nsec/1000);
}

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
_cs_dispatch_SRV(struct gridd_reply_ctx_s *reply, gpointer g, gpointer h)
{
	(void) g, (void) h;

	gboolean full = metautils_message_extract_flag (reply->request, NAME_MSGKEY_FULL, FALSE);
	gchar *types = metautils_message_extract_string_copy (reply->request, NAME_MSGKEY_TYPENAME);

	guint count = 0;
	GByteArray *packed = g_byte_array_new ();
	g_byte_array_append (packed, (guint8*)"\x30\x80", 2);

	void _pack (struct service_info_s *si) {
		GPtrArray *tags = si->tags;
		if (!full) si->tags = NULL;
		GByteArray *gba = service_info_marshall_1 (si, NULL);
		si->tags = tags;
		++ count;
		if (NULL != gba) {
			g_byte_array_append (packed, gba->data, gba->len);
			g_byte_array_free (gba, TRUE);
		}
	}
	g_rw_lock_reader_lock (&services_lock);
	srvset_run (services, types, _pack);
	g_rw_lock_reader_unlock (&services_lock);

	g_byte_array_append (packed, (guint8*)"\x00\x00", 2);
	reply->subject ("%s=%u", types, count);
	reply->add_body (packed);
	reply->send_reply (CODE_FINAL_OK, "OK");
	g_free0 (types);
	return TRUE;
}

static gboolean
_cs_dispatch_TYPES(struct gridd_reply_ctx_s *reply, gpointer g, gpointer h)
{
	(void) g, (void) h;

	// XXX TODO this can be cached (the list nearly never changes) !
	GSList *list = NULL;
	gboolean _run (gchar *t, gpointer i0, gpointer i1) {
		(void) i0, (void) i1;
		list = g_slist_prepend (list, g_strdup(t));
		return FALSE;
	}

	g_rw_lock_reader_lock (&services_lock);
	g_tree_foreach (scorers, (GTraverseFunc)_run, NULL);
	g_rw_lock_reader_unlock (&services_lock);

	GByteArray *body = strings_marshall_gba (list, NULL);
	g_slist_free (list);

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

	for (GSList *l=list; l ;l=l->next) {
		struct service_info_s *si = l->data;
		gint32 score = si->score.value;
		g_rw_lock_writer_lock (&services_lock);
		si = srvset_push_and_clean (services, si);
		/* the tags have already been merged */
		if (score == SCORE_UNLOCK) {
			si->score.value = 1;
			si->score.timestamp = now;
		} else if (score == SCORE_UNSET) {
			if (si->score.timestamp != 0) { /* not locked */
				if (si->score.value < 0)
					si->score.value = 1;
				si->score.timestamp = now;
			}
		} else { /* lock */
			si->score.value = score;
			si->score.timestamp = 0;
		}
		g_rw_lock_writer_unlock (&services_lock);
		l->data = NULL;
	}

	guint total = 0;
	g_rw_lock_reader_lock (&services_lock);
	total = srvset_count (services);
	g_rw_lock_reader_unlock (&services_lock);
	reply->subject("%u+%u", total, g_slist_length (list));

	g_slist_free_full (list, (GDestroyNotify)service_info_clean);
	reply->send_reply (CODE_FINAL_OK, "OK");
	return TRUE;
}

static gboolean
_cs_dispatch_RM(struct gridd_reply_ctx_s *reply, gpointer g, gpointer h)
{
	(void) g, (void) h;

	gchar *type = metautils_message_extract_string_copy (reply->request, NAME_MSGKEY_TYPENAME);
	GSList *list = NULL;
	GError *err = metautils_message_extract_body_encoded(reply->request, FALSE,
			&list, service_info_unmarshall);
	if (err) {
		reply->send_error(0,err);
		return TRUE;
	}

	if (list) { // Explicit services provded
		for (GSList *l=list; l ;l=l->next) {
			g_rw_lock_writer_lock (&services_lock);
			srvset_delete_iso (services, l->data);
			g_rw_lock_writer_unlock (&services_lock);
		}
	} else if (type) { // Flush all the services of a given type
		g_rw_lock_writer_lock (&services_lock);
		srvset_purge_type (services, type);
		g_rw_lock_writer_unlock (&services_lock);
	} else { // No service, no service type ... dunno ...
		err = NEWERROR(CODE_BAD_REQUEST, "No removal criterion");
	}

	g_free0 (type);
	g_slist_free_full (list, (GDestroyNotify)service_info_clean);
	if (err)
		reply->send_error (0, err);
	else
		reply->send_reply (CODE_FINAL_OK, "OK");
	return TRUE;
}

static void
_cs_action(void)
{
	GError *err = network_server_open_servers (server);
	if (err) {
		GRID_ERROR ("Failed to open the server sockets: (%d) %s", err->code, err->message);
		g_clear_error (&err);
		grid_main_set_status (1);
		return;
	}

	grid_task_queue_fire (gtq_admin);

	if (!(th_admin = grid_task_queue_run (gtq_admin, &err))) {
		GRID_ERROR ("Failed to start the admin tasks: (%d) %s", err->code, err->message);
		g_clear_error (&err);
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

static GError *
_load_nsinfo (const char *base, const char *sub)
{
	GError *err = NULL;
	gchar *data = NULL;
	gsize len = 0;
	gchar *path = g_strconcat (base, G_DIR_SEPARATOR_S, sub, NULL);
	g_file_get_contents (path, &data, &len, &err);
	g_free (path);
	if (err)
		return err;
	err = namespace_info_init_json (data, nsinfo);
	g_free0 (data);
	return err;
}

static gboolean
_cs_configure(int argc, char **argv)
{
	struct gridd_request_descr_s descr[] = {
		{NAME_MSGNAME_CS_GET_NSINFO,   _cs_dispatch_NSINFO, NULL},
		{NAME_MSGNAME_CS_GET_SRV,      _cs_dispatch_SRV, NULL},
		{NAME_MSGNAME_CS_GET_SRVNAMES, _cs_dispatch_TYPES, NULL},
		{NAME_MSGNAME_CS_PUSH_SRV,     _cs_dispatch_PUSH, NULL},
		{NAME_MSGNAME_CS_RM_SRV,       _cs_dispatch_RM, NULL},
		{NULL, NULL, NULL}
	};

	if (!urls) {
		GRID_ERROR("No URL configured. See the 'Endpoint' parameter");
		return FALSE;
	}
	if (argc < 1) {
		GRID_ERROR("Missing mandatory parameter");
		return FALSE;
	}

	GError *err;

	if (NULL != (err = _load_nsinfo (argv[0], "nsinfo.json"))) {
		GRID_ERROR ("Failed to load the namespace info: (%d) %s", err->code, err->message);
		return FALSE;
	}

	if (NULL != (err = _load_scorers_from_dir (argv[0]))) {
		GRID_ERROR ("Failed to load the scorers: (%d) %s", err->code, err->message);
		return FALSE;
	}

	nsinfo_cache = namespace_info_marshall (nsinfo, &err);
	if (err) {
		GRID_ERROR ("NSInfo encoding error: (%d) %s", err->code, err->message);
		return FALSE;
	}

	transport_gridd_dispatcher_add_requests (dispatcher, gridd_get_common_requests(), NULL);
	transport_gridd_dispatcher_add_requests (dispatcher, descr, NULL);

	for (GSList *l=urls; l ;l=l->next) {
		GRID_NOTICE("Binding to [%s]", (gchar*) l->data);
		network_server_bind_host(server, (gchar*) l->data,
				dispatcher, transport_gridd_factory);
	}
	grid_task_queue_register (gtq_admin, 1, _task_expire, NULL, NULL);
	grid_task_queue_register (gtq_admin, 1, _task_score, NULL, NULL);

	return TRUE;
}

static void
_cs_set_defaults(void)
{
	g_rw_lock_init (&services_lock);
	g_rw_lock_init (&nsinfo_lock);
	gtq_admin = grid_task_queue_create ("admin");
	services = srvset_new ();
	server = network_server_init();
	nsinfo = g_malloc0 (sizeof(struct namespace_info_s));
	namespace_info_init (nsinfo);
	dispatcher = transport_gridd_build_empty_dispatcher ();
	scorers = g_tree_new_full (metautils_strcmp3, NULL, g_free, _scorer_clean);
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
	// Close phase
	if (th_admin)
		g_thread_join (th_admin);
	if (server)
		network_server_clean (server);
	if (dispatcher)
		gridd_request_dispatcher_clean (dispatcher);
	if (gtq_admin)
		grid_task_queue_destroy (gtq_admin);
	if (services)
		srvset_clean (services);

	metautils_gba_unref (nsinfo_cache);
	namespace_info_free (nsinfo);
	g_rw_lock_clear (&services_lock);
	g_rw_lock_clear (&nsinfo_lock);
	g_slist_free_full (urls, g_free);
}

static struct grid_main_option_s *
_cs_get_options(void)
{
	static struct grid_main_option_s sqlx_options[] = {
		{"Endpoint", OT_LIST, {.lst = &urls}, "Bind to this IP:PORT"},
		{NULL, 0, {.i=0}, NULL}
	};

	return sqlx_options;
}

static const char *
_cs_usage(void)
{
	return "PATH_TO_JSON";
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

