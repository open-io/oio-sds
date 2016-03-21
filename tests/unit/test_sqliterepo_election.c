/*
OpenIO SDS sqliterepo
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#include <glib.h>

#undef GQ
#define GQ() g_quark_from_static_string("oio.sqlite")

#include <metautils/lib/metautils.h>
#include <sqliterepo/election.h>
#include <sqliterepo/version.h>
#include <sqliterepo/sqlx_remote.h>

#include "../../sqliterepo/election.c"

static volatile gint64 CLOCK_START = 0;
static volatile gint64 CLOCK = 0;

static gint64 _get_monotonic (void) { return CLOCK; }
static gint64 _get_real (void) { return CLOCK; }

/* -------------------------------------------------------------------------- */

static const char * _get_id (gpointer ctx) { (void) ctx; return "ID0"; }

static GError*
_get_peers (gpointer ctx, const struct sqlx_name_s *n, gboolean nocache,
		gchar ***result)
{
	(void) ctx, (void) n, (void) nocache;
	static char *tab[] = { "ID1", NULL };
	*result = g_strdupv (tab);
	return NULL;
}

static GError*
_get_peers_none (gpointer ctx, const struct sqlx_name_s *n, gboolean nocache,
		gchar ***result)
{
	(void) ctx, (void) n, (void) nocache;
	*result = g_malloc0(sizeof(gchar*));
	return NULL;
}

static GError*
_get_vers (gpointer ctx, const struct sqlx_name_s *n, GTree **result)
{
	(void) ctx, (void) n;
	*result = version_empty();
	return NULL;
}

/* Dummy Peering ------------------------------------------------------------ */

static void _peering_destroy (struct sqlx_peering_s *self);

static void _peering_use (struct sqlx_peering_s *self,
			const char *url,
			const struct sqlx_name_s *n);

static void _peering_getvers (struct sqlx_peering_s *self,
			const char *url,
			const struct sqlx_name_s *n,
			/* for the return */
			struct election_manager_s *manager,
			guint reqid,
			sqlx_peering_getvers_end_f result);

static void _peering_pipefrom (struct sqlx_peering_s *self,
			const char *url,
			const struct sqlx_name_s *n,
			const char *src,
			/* for the return */
			struct election_manager_s *manager,
			guint reqid,
			sqlx_peering_pipefrom_end_f result);

struct sqlx_peering_vtable_s vtable_peering_NOOP =
{
	_peering_destroy, _peering_use, _peering_getvers, _peering_pipefrom
};

static void _peering_destroy (struct sqlx_peering_s *self) { g_free (self); }

static void
_peering_use (struct sqlx_peering_s *self,
			const char *url,
			const struct sqlx_name_s *n)
{
	(void) self, (void) url, (void) n;
	GRID_DEBUG (">>> %s (%s)", __FUNCTION__, url);
}

static void
_peering_getvers (struct sqlx_peering_s *self,
			const char *url,
			const struct sqlx_name_s *n,
			/* for the return */
			struct election_manager_s *manager,
			guint reqid,
			sqlx_peering_getvers_end_f result)
{
	(void) self, (void) url, (void) n;
	(void) manager, (void) reqid, (void) result;
	GRID_DEBUG (">>> %s (%s)", __FUNCTION__, url);
}

static void
_peering_pipefrom (struct sqlx_peering_s *self,
			const char *url,
			const struct sqlx_name_s *n,
			const char *src,
			/* for the return */
			struct election_manager_s *manager,
			guint reqid,
			sqlx_peering_pipefrom_end_f result)
{
	(void) self, (void) url, (void) n, (void) src;
	(void) manager, (void) reqid, (void) result;
	GRID_DEBUG (">>> %s (%s)", __FUNCTION__, url);
}

static struct sqlx_peering_s *
_peering_noop (void)
{
	struct sqlx_peering_abstract_s *out = g_malloc0 (sizeof (*out));
	out->vtable = &vtable_peering_NOOP;
	return (struct sqlx_peering_s*) out;
}

/* Dummy Syncing ------------------------------------------------------------ */

enum hook_type_e
{
	CREATE = 1,
	DELETE,
	EXISTS_DONE,
	GET_DONE,
	CHILDREN_DONE,
	SIBLINGS_DONE,
};

static const char *
_pending_2str (enum hook_type_e t)
{
	switch (t) {
		ON_ENUM(,CREATE);
		ON_ENUM(,DELETE);
		ON_ENUM(,EXISTS_DONE);
		ON_ENUM(,GET_DONE);
		ON_ENUM(,CHILDREN_DONE);
		ON_ENUM(,SIBLINGS_DONE);
	}

	g_assert_not_reached ();
	return NULL;
}

struct sqlx_sync_s
{
	struct sqlx_sync_vtable_s *vtable;
	GArray *pending;
};

static void _sync_clear (struct sqlx_sync_s *ss);

static GError* _sync_open (struct sqlx_sync_s *ss);

static void _sync_close (struct sqlx_sync_s *ss);

static int _sync_acreate (struct sqlx_sync_s *ss, const char *path, const char *v,
		int vlen, int flags, string_completion_t completion, const void *data);

static int _sync_adelete (struct sqlx_sync_s *ss, const char *path, int version,
		void_completion_t completion, const void *data);

static int _sync_awexists (struct sqlx_sync_s *ss, const char *path,
		watcher_fn watcher, void* watcherCtx,
		stat_completion_t completion, const void *data);

static int _sync_awget (struct sqlx_sync_s *ss, const char *path,
		watcher_fn watcher, void* watcherCtx,
		data_completion_t completion, const void *data);

static int _sync_awget_children (struct sqlx_sync_s *ss, const char *path,
		watcher_fn watcher, void* watcherCtx,
		strings_completion_t completion, const void *data);

static int _sync_awget_siblings (struct sqlx_sync_s *ss, const char *path,
		watcher_fn watcher, void* watcherCtx,
		strings_completion_t completion, const void *data);

static void _sync_set_exit_hook (struct sqlx_sync_s *ss,
		void (*on_exit) (void*), void *on_exit_ctx);

struct sqlx_sync_vtable_s vtable_sync_NOOP =
{
	_sync_clear, _sync_open, _sync_close,
	_sync_acreate, _sync_adelete, _sync_awexists,
	_sync_awget, _sync_awget_children, _sync_awget_siblings,
	_sync_set_exit_hook
};

static void
_sync_clear (struct sqlx_sync_s *ss)
{
	GRID_DEBUG ("%s", __FUNCTION__);
	EXTRA_ASSERT (ss->vtable == &vtable_sync_NOOP);
	g_array_free (ss->pending, TRUE);
	g_free (ss);
}

static GError *
_sync_open (struct sqlx_sync_s *ss)
{
	(void) ss;
	GRID_DEBUG ("%s", __FUNCTION__);
	return NULL;
}

static void
_sync_close (struct sqlx_sync_s *ss)
{
	(void) ss;
	GRID_DEBUG ("%s", __FUNCTION__);
}

static int
_sync_acreate (struct sqlx_sync_s *ss, const char *path, const char *v,
		int vlen, int flags, string_completion_t completion, const void *data)
{
	(void) ss;
	(void) path, (void) v, (void) vlen, (void) flags;
	(void) completion, (void) data;
	GRID_DEBUG (".oO %s %s", __FUNCTION__, path);
	enum hook_type_e val = CREATE;
	g_array_append_vals (ss->pending, &val, 1);
	return ZOK;
}

static int
_sync_adelete (struct sqlx_sync_s *ss, const char *path, int version,
		void_completion_t completion, const void *data)
{
	(void) ss, (void) path, (void) version;
	(void) completion, (void) data;
	GRID_DEBUG (".oO %s %s", __FUNCTION__, path);
	enum hook_type_e val = DELETE;
	g_array_append_vals (ss->pending, &val, 1);
	return ZOK;
}

static int
_sync_awexists (struct sqlx_sync_s *ss, const char *path,
		watcher_fn watcher, void* watcherCtx,
		stat_completion_t completion, const void *data)
{
	(void) ss, (void) path;
	(void) watcher, (void) watcherCtx;
	(void) completion, (void) data;
	GRID_DEBUG (".oO %s %s", __FUNCTION__, path);
	if (completion) {
		enum hook_type_e val = EXISTS_DONE;
		g_array_append_vals (ss->pending, &val, 1);
	}
	return ZOK;
}

static int _sync_awget (struct sqlx_sync_s *ss, const char *path,
		watcher_fn watcher, void* watcherCtx,
		data_completion_t completion, const void *data)
{
	(void) ss, (void) path;
	(void) watcher, (void) watcherCtx;
	(void) completion, (void) data;
	GRID_DEBUG (".oO %s %s", __FUNCTION__, path);
	if (completion) {
		enum hook_type_e val = GET_DONE;
		g_array_append_vals (ss->pending, &val, 1);
	}
	return ZOK;
}

static int
_sync_awget_children (struct sqlx_sync_s *ss, const char *path,
		watcher_fn watcher, void* watcherCtx,
		strings_completion_t completion, const void *data)
{
	(void) ss, (void) path;
	(void) watcher, (void) watcherCtx;
	(void) completion, (void) data;
	GRID_DEBUG (".oO %s %s", __FUNCTION__, path);
	if (completion) {
		enum hook_type_e val = CHILDREN_DONE;
		g_array_append_vals (ss->pending, &val, 1);
	}
	return ZOK;
}

static int
_sync_awget_siblings (struct sqlx_sync_s *ss, const char *path,
		watcher_fn watcher, void* watcherCtx,
		strings_completion_t completion, const void *data)
{
	(void) ss, (void) path;
	(void) watcher, (void) watcherCtx;
	(void) completion, (void) data;
	GRID_DEBUG (".oO %s %s", __FUNCTION__, path);
	if (completion) {
		enum hook_type_e val = SIBLINGS_DONE;
		g_array_append_vals (ss->pending, &val, 1);
	}
	return ZOK;
}

static void
_sync_set_exit_hook (struct sqlx_sync_s *ss,
		void (*on_exit) (void*), void *on_exit_ctx)
{
	(void) ss, (void) on_exit, (void) on_exit_ctx;
}

static struct sqlx_sync_s *
_sync_factory__noop (void)
{
	struct sqlx_sync_s *out = g_malloc0 (sizeof (*out));
	out->vtable = &vtable_sync_NOOP;
	out->pending = g_array_new (TRUE, TRUE, sizeof(enum hook_type_e));
	return out;
}

/* -------------------------------------------------------------------------- */

static void
_pending_debug (GString *gs, const GArray *t)
{
	for (guint i=0; i<t->len ;++i) {
		const char *s = _pending_2str (g_array_index(t, enum hook_type_e, i));
		if (i) g_string_append_c (gs, ',');
		g_string_append (gs, s);
	}
}

static gboolean
_pending_check (const GArray *src, ...)
{
	gboolean rc = FALSE;
	/* Build a temporary array of expected values */
	GArray *tmp = g_array_new (TRUE, TRUE, sizeof(enum hook_type_e));
	va_list args;
	va_start(args, src);
	for (;;) {
		enum hook_type_e next = va_arg (args, enum hook_type_e);
		if (next <= 0) break;
		g_array_append_vals (tmp, &next, 1);
	}
	va_end(args);

	if (tmp->len != src->len) {
		GString *gs = g_string_new("");
		g_string_append (gs, "expected=");
		_pending_debug (gs, tmp);
		g_string_append (gs, " got=");
		_pending_debug (gs, src);
		GRID_WARN("Pending elements %s", gs->str);
		g_string_free (gs, TRUE);
		goto exit;
	}

	/* check the elements of <src> are in <tmp> */
	for (guint i=0; i < src->len ;++i) {
		if (g_array_index(src,enum hook_type_e,i)
				!= g_array_index(tmp,enum hook_type_e,i)) {
			const char *s = _pending_2str (g_array_index (src, enum hook_type_e, i));
			GRID_WARN ("%s not expected at %u", s, i);
			goto exit;
		}
	}

	rc = TRUE;
exit:
	g_array_free (tmp, TRUE);
	return rc;
}

static guint
_member_refcount (struct election_manager_s *manager, struct sqlx_name_s *n)
{
	hashstr_t *_k = sqliterepo_hash_name (n);
	struct election_member_s *m = manager_get_member (manager, _k);
	g_free (_k);
	g_assert_nonnull (m);
	guint count = m->refcount;
	member_unref (m);
	return count - 1;
}

#define _test_notfound() do \
{ \
	hashstr_t *_k = sqliterepo_hash_name (&name); \
	struct election_member_s *m = manager_get_member (manager, _k); \
	g_free (_k); \
	g_assert_null (m); \
} while (0)


#define _test_found(action) do \
{ \
	hashstr_t *_k = sqliterepo_hash_name (&name); \
	struct election_member_s *m = manager_get_member (manager, _k); \
	g_free (_k); \
	g_assert_nonnull (m); \
	action; \
	member_unref (m);\
} while (0)

#define _test_unref() _test_found( \
	member_unref(m); \
)

#define _test_transition(evt,arg,post) _test_found( \
	transition (m, evt, arg); \
	g_assert_cmpint (m->step, ==, post); \
)

#define _test_nochange(evt,arg) _test_found( \
	enum election_step_e before_##evt = m->step; \
	transition (m, evt, arg); \
	g_assert_cmpint (m->step, ==, before_##evt); \
)

#define _pending(...) g_assert_true (_pending_check(sync->pending, __VA_ARGS__))

#define _refcount() _member_refcount(manager, &name)

#define _trace() do \
{ \
	hashstr_t *_k = sqliterepo_hash_name (&name); \
	struct election_member_s *m = manager_get_member (manager, _k); \
	g_free (_k); \
	member_trace (__FUNCTION__, "test", m); \
	member_unref(m); \
} while (0)

static void
test_single (void)
{
	struct sqlx_name_s name = {
		.base = "base", .type = "type", .ns = "NS",
	};
	struct replication_config_s config = {
		_get_id, _get_peers, _get_vers, NULL, ELECTION_MODE_GROUP
	};
	struct sqlx_sync_s *sync = NULL;
	struct sqlx_peering_s *peering = NULL;
	struct election_manager_s *manager = NULL;
	GArray *iv = g_array_new (0,0,sizeof(gint64));
	gint64 i64 = 0;
	guint u = 0;

	CLOCK_START = CLOCK = g_random_int ();

	sync = _sync_factory__noop ();
	g_assert_nonnull (sync);
	peering = _peering_noop ();
	g_assert_nonnull (peering);

	g_assert_no_error (election_manager_create (&config, &manager));
	g_assert_nonnull (manager);
	election_manager_set_sync (manager, sync);
	election_manager_set_peering (manager, peering);

	_test_notfound ();

	g_assert_no_error (_election_init (manager, &name));

	_test_nochange (EVT_LIST_OK, NULL);
	_pending (0);
	_test_nochange (EVT_LIST_KO, NULL);
	_pending (0);
	_test_nochange (EVT_RESYNC_DONE, &u);
	_pending (0);
	_test_nochange (EVT_MASTER_KO, NULL);
	_pending (0);
	_test_nochange (EVT_MASTER_EMPTY, NULL);
	_pending (0);
	_test_nochange (EVT_MASTER_OK, NULL);
	_pending (0);
	_test_nochange (EVT_MASTER_CHANGE, NULL);
	_pending (0);

	_test_transition (EVT_NONE, NULL, STEP_CANDREQ);
	_pending (CREATE, 0);
	_test_nochange (EVT_NONE, NULL);
	_pending (CREATE, 0);
	_test_nochange (EVT_MASTER_KO, NULL);
	_pending (CREATE, 0);
	_test_nochange (EVT_MASTER_EMPTY, NULL);
	_pending (CREATE, 0);
	_test_nochange (EVT_MASTER_OK, NULL);
	_pending (CREATE, 0);
	_test_nochange (EVT_MASTER_CHANGE, NULL);
	_pending (CREATE, 0);

#if 0
	_test_transition (EVT_DISCONNECTED, NULL, STEP_FAILED);
	_test_nochange (EVT_DISCONNECTED, NULL);
	_test_nochange (EVT_NONE, NULL);

	CLOCK += manager->delay_retry_failed + 1;

	_test_transition (EVT_NONE, NULL, STEP_CANDREQ);
#endif

	g_assert_cmpuint (0, ==, election_manager_play_timers (manager, 0));

	g_array_remove_index_fast (sync->pending, 0);
	_pending (0);
	do {
		hashstr_t *key = sqliterepo_hash_name (&name);
		gchar *s = g_strdup_printf("XYZ-1");
		struct election_member_s *m = manager_get_member(manager, key);
		step_StartElection_completion (ZOK, s, m);
		member_unref (m);
		g_free (s);
		g_free (key);
	} while (0);
	_pending (EXISTS_DONE, SIBLINGS_DONE, 0);

	g_array_set_size (iv,0); /* there 2 nodes: 1,2 (MUST be sorted) */
	i64 = 1; g_array_append_vals (iv, &i64, 1);
	i64 = 2; g_array_append_vals (iv, &i64, 1);
	_test_transition (EVT_LIST_OK, iv, STEP_PRELEAD);
	g_array_remove_index (sync->pending, 1);
	_pending (EXISTS_DONE, 0);
	_test_unref();
	g_assert_cmpuint (_refcount(), ==, 2);

	CLOCK += manager->delay_fail_pending + 1;
	g_assert_cmpuint (_refcount(), ==, 2);
	g_assert_cmpuint (1, ==, election_manager_play_timers (manager, 0));
	g_assert_cmpuint (0, ==, election_manager_play_timers (manager, 0));
	CLOCK += manager->delay_expire_failed + 1;
	g_assert_cmpuint (1, ==, election_manager_play_timers (manager, 0));

	_pending (EXISTS_DONE, DELETE, 0);
	g_assert_cmpuint (_refcount(), ==, 3);

	g_assert_cmpuint (0, ==, election_manager_play_timers (manager, 0));

	election_manager_clean (manager);
	sqlx_peering__destroy (peering);
	sqlx_sync_close (sync);
	sqlx_sync_clear (sync);
	g_array_free (iv, TRUE);
}

static void
test_sets (void)
{
	struct replication_config_s config = {
		_get_id, _get_peers, _get_vers, NULL, ELECTION_MODE_GROUP
	};
	struct sqlx_sync_s *sync = NULL;
	struct sqlx_peering_s *peering = NULL;
	struct election_manager_s *manager = NULL;

	CLOCK_START = CLOCK = g_random_int ();

	sync = _sync_factory__noop ();
	g_assert_nonnull (sync);
	peering = _peering_noop ();
	g_assert_nonnull (peering);

	g_assert_no_error (election_manager_create (&config, &manager));
	g_assert_nonnull (manager);
	election_manager_set_sync (manager, sync);
	election_manager_set_peering (manager, peering);

	/* Init several bases */
	CLOCK ++;
#define NB 16
	for (int i=0; i<NB ;++i) {
		gchar tmp[128];
		g_snprintf (tmp, sizeof(tmp), "base-%d", i);
		struct sqlx_name_s name = { .base = tmp, .type = "type", .ns = "NS", };
		g_assert_no_error (_election_init (manager, &name));

		hashstr_t *_k = sqliterepo_hash_name (&name);
		struct election_member_s *m = manager_get_member (manager, _k);
		g_free (_k);

		member_set_status (m, STEP_PRELEAD);
		m->last_USE = CLOCK;
		m->last_atime = CLOCK;
		m->myid = 1;
		m->master_id = 1;
	}
	g_assert_cmpuint(NB, ==, manager->members_by_state[STEP_PRELEAD].count);
	CLOCK += manager->delay_fail_pending + 1;
	g_assert_cmpuint (1, ==, election_manager_play_timers (manager, 1));
	g_assert_cmpuint(1, ==, manager->members_by_state[STEP_FAILED].count);
	g_assert_cmpuint(NB-1, ==, manager->members_by_state[STEP_PRELEAD].count);
	g_assert_cmpuint (2, ==, election_manager_play_timers (manager, 2));
	g_assert_cmpuint(3, ==, manager->members_by_state[STEP_FAILED].count);
	g_assert_cmpuint(NB-3, ==, manager->members_by_state[STEP_PRELEAD].count);

	election_manager_clean (manager);
	sqlx_peering__destroy (peering);
	sqlx_sync_close (sync);
	sqlx_sync_clear (sync);
}

static void
test_create_bad_config(void)
{
	struct election_manager_s *m = NULL;
	GError *err;

	struct replication_config_s cfg0 = {
		NULL, _get_peers_none, _get_vers, NULL, ELECTION_MODE_NONE};
	err = election_manager_create(&cfg0, &m);
	g_assert_error(err, GQ(), ERRCODE_PARAM);
	g_clear_error(&err);

	struct replication_config_s cfg1 = {
		_get_id, NULL, _get_vers, NULL, ELECTION_MODE_NONE};
	err = election_manager_create(&cfg1, &m);
	g_assert_error(err, GQ(), ERRCODE_PARAM);
	g_clear_error(&err);

	struct replication_config_s cfg2 = {
		_get_id, _get_peers_none, NULL, NULL, ELECTION_MODE_NONE};
	err = election_manager_create(&cfg2, &m);
	g_assert_error(err, GQ(), ERRCODE_PARAM);
	g_clear_error(&err);

	struct replication_config_s cfg3 = {
		_get_id, _get_peers_none, _get_vers, NULL, ELECTION_MODE_NONE+3};
	err = election_manager_create(&cfg3, &m);
	g_assert_error(err, GQ(), ERRCODE_PARAM);
	g_clear_error(&err);
}

static void
test_election_init(void)
{
	struct replication_config_s cfg = {
		_get_id, _get_peers_none, _get_vers, NULL, ELECTION_MODE_NONE};
	struct sqlx_sync_s *sync = NULL;
	struct sqlx_peering_s *peering = NULL;
	struct election_manager_s *m = NULL;
	GError *err = NULL;

	sync = _sync_factory__noop ();
	g_assert_nonnull (sync);
	peering = _peering_noop ();
	g_assert_nonnull (peering);
	err = election_manager_create(&cfg, &m);
	g_assert_no_error(err);
	g_assert_nonnull (m);
	election_manager_set_sync (m, sync);
	election_manager_set_peering (m, peering);

	for (int i=0; i<8 ;++i) {
		struct sqlx_name_mutable_s n = {.ns="NS", .base=NULL, .type="type"};
		n.base = g_strdup_printf("base-%"G_GUINT32_FORMAT, g_random_int());
		err = election_init(m, sqlx_name_mutable_to_const(&n));
		g_assert_no_error(err);
		err = election_exit(m, sqlx_name_mutable_to_const(&n));
		g_assert_no_error(err);
		g_free (n.base);
	}

	election_manager_clean (m);
	sqlx_peering__destroy (peering);
	sqlx_sync_close (sync);
	sqlx_sync_clear (sync);
}

static void
test_create_ok(void)
{
	struct replication_config_s cfg = { _get_id, _get_peers_none, _get_vers,
		NULL, ELECTION_MODE_NONE};
	for (int i=0; i<8 ;++i) {
		struct election_manager_s *m = NULL;
		GError *err = election_manager_create(&cfg, &m);
		g_assert_no_error(err);
		election_manager_clean(m);
	}
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	oio_time_monotonic = _get_monotonic;
	oio_time_real = _get_real;
	g_test_add_func("/sqlx/election/create_bad_config", test_create_bad_config);
	g_test_add_func("/sqlx/election/create_ok", test_create_ok);
	g_test_add_func("/sqlx/election/election_init", test_election_init);
	g_test_add_func ("/sqliterepo/election/single", test_single);
	g_test_add_func ("/sqliterepo/election/sets", test_sets);
	return g_test_run();
}
