/*
OpenIO SDS unit tests
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS

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

#ifndef HAVE_EXTRA_ASSERT
#define HAVE_EXTRA_ASSERT 1
#endif

#undef GQ
#define GQ() g_quark_from_static_string("oio.sqlite")

#include <metautils/lib/metautils.h>
#include <sqliterepo/election.h>
#include <sqliterepo/version.h>
#include <sqliterepo/sqlx_remote.h>
#define FAKE_GETPEERS
#include "../../sqliterepo/election.c"

static volatile gint64 CLOCK_START = 0;
static volatile gint64 CLOCK = 0;

static gint64 _get_monotonic (void) { return CLOCK; }
static gint64 _get_real (void) { return CLOCK; }

static struct election_member_s *
manager_get_member (struct election_manager_s *m, const char *k)
{
	_manager_lock(m);
	struct election_member_s *member = _LOCKED_get_member (m, k);
	_manager_unlock(m);
	return member;
}

static void
member_reset_requests(struct election_member_s *m)
{
	m->requested_LEAVE = 0;
	m->requested_USE = 0;
	m->requested_PIPEFROM = 0;
	m->requested_LEFT_MASTER = 0;
	m->requested_LEFT_SELF = 0;
}

static gboolean
member_has_request (struct election_member_s *m)
{
	return m->requested_LEAVE != 0
		|| m->requested_USE != 0
		|| m->requested_PIPEFROM != 0
		|| m->requested_LEFT_MASTER != 0
		|| m->requested_LEFT_SELF != 0;
}

/* -------------------------------------------------------------------------- */

static const char * _get_id (gpointer ctx) { (void) ctx; return "ID0"; }

static char *PEERS[] = { "ID1", "ID0", NULL };

static GError*
_get_peers (gpointer ctx UNUSED, const struct sqlx_name_s *n UNUSED,
		gboolean nocache UNUSED, gchar ***result)
{
	if (result) {
		*result = g_strdupv (PEERS);
	}
	return NULL;
}

static GError*
_get_peers_none (gpointer ctx UNUSED, const struct sqlx_name_s *n UNUSED,
		gboolean nocache UNUSED, gchar ***result)
{
	if (result)
		*result = g_malloc0(sizeof(gchar*));
	return NULL;
}

static GError*
_get_vers (gpointer ctx UNUSED, const struct sqlx_name_s *n UNUSED,
		GTree **result)
{
	if (result)
		*result = version_empty();
	return NULL;
}

/* Dummy Peering ------------------------------------------------------------ */

static void _peering_destroy (struct sqlx_peering_s *self);

static void _peering_notify (struct sqlx_peering_s *self UNUSED) {}

static gboolean _peering_use (struct sqlx_peering_s *self,
			const char *url,
			const struct sqlx_name_inline_s *n,
		const char *peers UNUSED,
			const gboolean master);

static gboolean _peering_getvers (struct sqlx_peering_s *self,
		/* in */
		const char *url,
		const struct sqlx_name_inline_s *n,
		const char *peers UNUSED,
		/* out */
		struct election_member_s *m,
		const char *reqid,
		sqlx_peering_getvers_end_f result);

static gboolean _peering_pipefrom (struct sqlx_peering_s *self,
		/* in */
		const char *url,
		const struct sqlx_name_inline_s *n,
		const char *src,
		const gint check_type,
		/* out */
		struct election_member_s *m,
		guint reqid,
		sqlx_peering_pipefrom_end_f result);

struct sqlx_peering_vtable_s vtable_peering_NOOP =
{
	_peering_destroy, _peering_notify,
	_peering_use, _peering_getvers, _peering_pipefrom
};

static void _peering_destroy (struct sqlx_peering_s *self) { g_free (self); }

static gboolean
_peering_use (struct sqlx_peering_s *self,
		const char *url,
		const struct sqlx_name_inline_s *n,
		const char *peers UNUSED,
		const gboolean master)
{
	(void) self, (void) url, (void) n, (void) master;
	GRID_DEBUG (">>> %s (%s%s)", __FUNCTION__, url, master ? ", MASTER" : "");
	return FALSE;
}

static gboolean
_peering_getvers (struct sqlx_peering_s *self,
		/* in */
		const char *url,
		const struct sqlx_name_inline_s *n,
		const char *peers UNUSED,
		/* out */
		struct election_member_s *m,
		const char *reqid,
		sqlx_peering_getvers_end_f result)
{
	(void) self, (void) url, (void) n;
	(void) m, (void) reqid, (void) result;
	return FALSE;
}

static gboolean
_peering_pipefrom (struct sqlx_peering_s *self,
		/* in */
		const char *url,
		const struct sqlx_name_inline_s *n,
		const char *src,
		const gint check_type,
		/* out */
		struct election_member_s *m,
		guint reqid,
		sqlx_peering_pipefrom_end_f result)
{
	(void) self, (void) url, (void) n, (void) src, (void) check_type;
	(void) m, (void) reqid, (void) result;
	return FALSE;
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
	CMD_CREATE = 1,
	CMD_DELETE,
	CMD_EXIST,
	CMD_GET,
	CMD_LIST,
	CMD_DEL_WATCH,
};

static const char *
_pending_2str (enum hook_type_e t)
{
	switch (t) {
		ON_ENUM(,CMD_CREATE);
		ON_ENUM(,CMD_DELETE);
		ON_ENUM(,CMD_EXIST);
		ON_ENUM(,CMD_GET);
		ON_ENUM(,CMD_LIST);
		ON_ENUM(,CMD_DEL_WATCH);
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

static int _sync_aremove_all_watches(struct sqlx_sync_s *ss, const char *path,
		void_completion_t completion, const void *data);

struct sqlx_sync_vtable_s vtable_sync_NOOP =
{
	_sync_clear, _sync_open, _sync_close,
	_sync_acreate, _sync_adelete, _sync_awexists,
	_sync_awget, _sync_awget_children, _sync_awget_siblings,
	_sync_aremove_all_watches,
};

static void
_sync_clear (struct sqlx_sync_s *ss)
{
	EXTRA_ASSERT (ss->vtable == &vtable_sync_NOOP);
	g_array_free (ss->pending, TRUE);
	g_free (ss);
}

static GError *
_sync_open (struct sqlx_sync_s *ss UNUSED)
{
	EXTRA_ASSERT (ss->vtable == &vtable_sync_NOOP);
	GRID_DEBUG ("%s", __FUNCTION__);
	return NULL;
}

static void
_sync_close (struct sqlx_sync_s *ss UNUSED)
{
	EXTRA_ASSERT (ss->vtable == &vtable_sync_NOOP);
	GRID_DEBUG ("%s", __FUNCTION__);
}

static int
_sync_acreate (struct sqlx_sync_s *ss, const char *path UNUSED,
		const char *v UNUSED, int vlen UNUSED, int flags UNUSED,
		string_completion_t completion UNUSED, const void *data UNUSED)
{
	EXTRA_ASSERT (ss->vtable == &vtable_sync_NOOP);
	enum hook_type_e val = CMD_CREATE;
	g_array_append_vals (ss->pending, &val, 1);
	return ZOK;
}

static int
_sync_adelete (struct sqlx_sync_s *ss,
		const char *path UNUSED, int version UNUSED,
		void_completion_t completion UNUSED, const void *data UNUSED)
{
	EXTRA_ASSERT (ss->vtable == &vtable_sync_NOOP);
	enum hook_type_e val = CMD_DELETE;
	g_array_append_vals (ss->pending, &val, 1);
	return ZOK;
}

static int
_sync_awexists (struct sqlx_sync_s *ss, const char *path UNUSED,
		watcher_fn watcher UNUSED, void* watcherCtx UNUSED,
		stat_completion_t completion UNUSED, const void *data UNUSED)
{
	EXTRA_ASSERT (ss->vtable == &vtable_sync_NOOP);
	if (completion) {
		enum hook_type_e val = CMD_EXIST;
		g_array_append_vals (ss->pending, &val, 1);
	}
	return ZOK;
}

static int _sync_awget (struct sqlx_sync_s *ss, const char *path UNUSED,
		watcher_fn watcher UNUSED, void* watcherCtx UNUSED,
		data_completion_t completion UNUSED, const void *data UNUSED)
{
	EXTRA_ASSERT (ss->vtable == &vtable_sync_NOOP);
	if (completion) {
		enum hook_type_e val = CMD_GET;
		g_array_append_vals (ss->pending, &val, 1);
	}
	return ZOK;
}

static int
_sync_awget_children (struct sqlx_sync_s *ss, const char *path UNUSED,
		watcher_fn watcher UNUSED, void* watcherCtx UNUSED,
		strings_completion_t completion UNUSED, const void *data UNUSED)
{
	EXTRA_ASSERT (ss->vtable == &vtable_sync_NOOP);
	if (completion) {
		enum hook_type_e val = CMD_LIST;
		g_array_append_vals (ss->pending, &val, 1);
	}
	return ZOK;
}

static int
_sync_awget_siblings (struct sqlx_sync_s *ss, const char *path UNUSED,
		watcher_fn watcher UNUSED, void* watcherCtx UNUSED,
		strings_completion_t completion UNUSED, const void *data UNUSED)
{
	EXTRA_ASSERT (ss->vtable == &vtable_sync_NOOP);
	if (completion) {
		enum hook_type_e val = CMD_LIST;
		g_array_append_vals (ss->pending, &val, 1);
	}
	return ZOK;
}

static int
_sync_aremove_all_watches(struct sqlx_sync_s *ss, const char *path UNUSED,
		void_completion_t completion UNUSED, const void *data UNUSED)
{
	EXTRA_ASSERT (ss->vtable == &vtable_sync_NOOP);
	enum hook_type_e val = CMD_DEL_WATCH;
	g_array_append_vals (ss->pending, &val, 1);
	return ZOK;
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
		g_string_append_static (gs, "expected=");
		_pending_debug (gs, tmp);
		g_string_append_static (gs, " got=");
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

#define _test_nochange(evt,arg) do { \
	const enum election_step_e _pre = m->step; \
	transition (m, evt, arg); \
	const enum election_step_e _post = m->step; \
	GRID_INFO("%d/%s -(%d/%s)-> %d/%s", \
			(int) _pre, _step2str(_pre), \
			(int) evt, _evt2str(evt), \
			(int) _post, _step2str(_post)); \
	g_assert_cmpint (_pre, ==, _post); \
} while (0)

#define _pending(...) g_assert_true (_pending_check(sync->pending, __VA_ARGS__))

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
	election_manager_add_sync(m, sync);
	election_manager_set_peering (m, peering);

	for (int i=0; i<8 ;++i) {
		struct sqlx_name_inline_s n0 = {.ns="NS", .base="", .type="type"};
		g_snprintf(n0.base, sizeof(n0.base),
				"base-%"G_GUINT32_FORMAT, oio_ext_rand_int());
		NAME2CONST(n, n0);
		err = election_init(m, &n, NULL, NULL, NULL);
		g_assert_no_error(err);
		err = election_exit(m, &n);
		g_assert_no_error(err);
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

#define TEST_HEAD() \
	struct sqlx_name_s name = { .base = "base", .type = "type", .ns = "NS", }; \
	struct replication_config_s config = { \
		_get_id, _get_peers, _get_vers, NULL, ELECTION_MODE_GROUP \
	}; \
	struct sqlx_sync_s *sync = NULL; \
	struct sqlx_peering_s *peering = NULL; \
	struct election_manager_s *manager = NULL; \
	CLOCK_START = CLOCK = oio_ext_rand_int (); \
	sync = _sync_factory__noop (); \
	g_assert_nonnull (sync); \
	peering = _peering_noop (); \
	g_assert_nonnull (peering); \
	g_assert_no_error (election_manager_create (&config, &manager)); \
	g_assert_nonnull (manager); \
	election_manager_add_sync (manager, sync); \
	election_manager_set_peering (manager, peering); \
	gchar _k[OIO_ELECTION_KEY_LIMIT_LENGTH]; \
	sqliterepo_hash_name(&name, _k, sizeof(_k)); \
	struct election_member_s *m = manager_get_member (manager, _k); \
	g_assert_null(m); \
	g_assert_no_error (_election_init (manager, &name, NULL, NULL, NULL)); \
	m = manager_get_member (manager, _k); \
	g_assert_nonnull(m); \

#define TEST_TAIL() \
	election_manager_clean(manager); manager = NULL; \
	sqlx_sync_clear(sync); sync = NULL; \
	sqlx_peering__destroy(peering); peering = NULL;

static void test_STEP_NONE (void) {
	TEST_HEAD();

	void RESET() {
		g_array_set_size(sync->pending, 0);
		member_set_status(m, STEP_NONE);
		member_reset(m);
		member_reset_requests(m);
		m->when_unstable = 0;
		_member_assert_NONE(m);
	}

	/* Test No-Op transitions */
	static const int ABNORMAL[] = {
		EVT_DISCONNECTED, EVT_LEAVE_REQ, EVT_LEFT_SELF, EVT_LEFT_MASTER,
		EVT_GETPEERS_DONE, EVT_GETVERS_OK, EVT_GETVERS_KO,
		EVT_GETVERS_OLD, EVT_GETVERS_RACE,
		EVT_MASTER_OK, EVT_MASTER_KO, EVT_MASTER_BAD,
		EVT_CREATE_OK, EVT_CREATE_KO,
		EVT_EXISTS_OK, EVT_EXISTS_KO,
		EVT_LIST_OK, EVT_LIST_KO,
		EVT_LEAVE_OK, EVT_LEAVE_KO,
		EVT_SYNC_OK, EVT_SYNC_KO,
		-1 /* end beacon */
	};
	for (const int *pevt=ABNORMAL; *pevt >= 0 ;++pevt) {
		RESET();
		_test_nochange(*pevt, NULL);
		_member_assert_NONE(m);
		_pending(0);
		g_assert_false(member_has_request(m));
	}

	/* Legit transitions */
	RESET();
	transition(m, EVT_NONE, NULL);
	_member_assert_PEERING(m);
	_pending(0);

	RESET();
	transition(m, EVT_SYNC_REQ, NULL);
	_member_assert_PEERING(m);
	_pending(0);

	TEST_TAIL();
}

static void test_STEP_PEERING (void) {
	TEST_HEAD();

	void RESET() {
		g_array_set_size(sync->pending, 0);
		member_set_status(m, STEP_PEERING);
		member_reset(m);
		member_reset_requests(m);
		_member_assert_PEERING(m);
	}

	/* Test No-Op transitions */
	static const int ABNORMAL[] = {
		EVT_LEAVE_REQ, EVT_LEFT_SELF, EVT_LEFT_MASTER,
		EVT_GETVERS_OK, EVT_GETVERS_KO,
		EVT_GETVERS_OLD, EVT_GETVERS_RACE,
		EVT_MASTER_OK, EVT_MASTER_KO, EVT_MASTER_BAD,
		EVT_CREATE_OK, EVT_CREATE_KO,
		EVT_EXISTS_OK, EVT_EXISTS_KO,
		EVT_LIST_OK, EVT_LIST_KO,
		EVT_LEAVE_OK, EVT_LEAVE_KO,
		EVT_SYNC_OK, EVT_SYNC_KO,
		-1 /* end beacon */
	};
	for (const int *pevt=ABNORMAL; *pevt >= 0 ;++pevt) {
		RESET();
		_test_nochange(*pevt, NULL);
		_member_assert_PEERING(m);
		_pending(0);
		g_assert_false(member_has_request(m));
	}

	/* Legit transitions */
	RESET();
	transition(m, EVT_NONE, NULL);
	_member_assert_PEERING(m);
	_pending(0);

	RESET();
	transition(m, EVT_GETPEERS_DONE, NULL);
	_member_assert_FAILED(m);
	_pending(0);

	RESET();
	transition(m, EVT_GETPEERS_DONE, PEERS);
	_member_assert_CREATING(m);
	_pending(CMD_CREATE, 0);

	TEST_TAIL();
}

static void test_STEP_CREATING(void) {
	TEST_HEAD();

	void RESET() {
		g_array_set_size(sync->pending, 0);
		member_set_status(m, STEP_CREATING);
		member_reset(m);
		member_reset_requests(m);
		m->pending_ZK_CREATE = 1;
		m->when_unstable = oio_ext_monotonic_time();
		m->peers = g_strdupv(PEERS);
		_member_assert_CREATING(m);
	}

	/* Test No-Op transitions */
	static const int ABNORMAL[] = {
		EVT_NONE, EVT_LEFT_MASTER, EVT_LEFT_SELF,
		EVT_GETVERS_OK, EVT_GETVERS_KO, EVT_GETVERS_OLD, EVT_GETVERS_RACE,
		EVT_MASTER_OK, EVT_MASTER_KO, EVT_MASTER_BAD,
		EVT_EXISTS_OK, EVT_EXISTS_KO,
		EVT_LIST_OK, EVT_LIST_KO,
		EVT_LEAVE_OK, EVT_LEAVE_KO,
		EVT_SYNC_OK, EVT_SYNC_KO,
		-1 /* end beacon */
	};
	for (const int *pevt=ABNORMAL; *pevt >= 0 ;++pevt) {
		RESET();
		_test_nochange(*pevt, NULL);
		_member_assert_CREATING(m);
		_pending(0);
		g_assert_false(member_has_request(m));
	}

	/* interruptions */
	RESET();
	transition(m, EVT_DISCONNECTED, NULL);
	_member_assert_NONE(m);
	_pending(0);

	RESET();
	transition(m, EVT_LEAVE_REQ, NULL);
	_member_assert_CREATING(m);
	_pending(0);
	g_assert_cmpint(m->requested_LEAVE, ==, 1);

	/* Legit transitions with no interruption */
	gint32 id = oio_ext_rand_int_range(G_MININT32, G_MAXINT32);

	RESET();
	transition(m, EVT_CREATE_OK, &id);
	_member_assert_WATCHING(m);
	_pending(CMD_EXIST, 0);
	g_assert_cmpint(m->local_id, ==, id);

	RESET();
	transition(m, EVT_CREATE_KO, NULL);
	_member_assert_FAILED(m);
	_pending(0);

	TEST_TAIL();
}

static void test_STEP_WATCHING(void) {
	TEST_HEAD();

	void RESET() {
		g_array_set_size(sync->pending, 0);
		member_set_status(m, STEP_WATCHING);
		member_reset(m);
		member_reset_requests(m);
		member_set_local_id(m, oio_ext_rand_int());
		m->pending_ZK_EXISTS = 1;
		m->when_unstable = oio_ext_monotonic_time();
		m->peers = g_strdupv(PEERS);
		_member_assert_WATCHING(m);
	}

	/* Test No-Op transitions */
	static const int ABNORMAL[] = {
		EVT_NONE, EVT_LEFT_MASTER,
		EVT_GETVERS_OK, EVT_GETVERS_KO, EVT_GETVERS_OLD, EVT_GETVERS_RACE,
		EVT_MASTER_OK, EVT_MASTER_KO, EVT_MASTER_BAD,
		EVT_CREATE_OK, EVT_CREATE_KO,
		EVT_LIST_OK, EVT_LIST_KO,
		EVT_LEAVE_OK, EVT_LEAVE_KO,
		EVT_SYNC_OK, EVT_SYNC_KO,
		-1 /* end beacon */
	};
	for (const int *pevt=ABNORMAL; *pevt >= 0 ;++pevt) {
		RESET();
		_test_nochange(*pevt, NULL);
		_member_assert_WATCHING(m);
		_pending(0);
		g_assert_false(member_has_request(m));
	}

	/* interruptions */
	RESET();
	transition(m, EVT_DISCONNECTED, NULL);
	_member_assert_NONE(m);
	_pending(0);

	RESET();
	transition(m, EVT_LEAVE_REQ, NULL);
	_member_assert_WATCHING(m);
	_pending(0);
	g_assert_cmpint(m->requested_LEAVE, ==, 1);

	RESET();
	transition(m, EVT_LEFT_SELF, NULL);
	_member_assert_WATCHING(m);
	_pending(0);
	g_assert_cmpint(m->requested_LEFT_SELF, ==, 1);

	/* Legit transitions with no interruption */
	RESET();
	transition(m, EVT_EXISTS_OK, NULL);
	_member_assert_LISTING(m);
	_pending(CMD_LIST, 0);

	RESET();
	transition(m, EVT_EXISTS_KO, NULL);
	_member_assert_LEAVING(m);
#if ZOO_35
	_pending(CMD_DEL_WATCH, CMD_DELETE, 0);
#else
	_pending(CMD_DELETE, 0);
#endif

	TEST_TAIL();
}

static void test_STEP_LISTING(void) {
	TEST_HEAD();

	void RESET() {
		g_array_set_size(sync->pending, 0);
		member_set_status(m, STEP_LISTING);
		member_reset(m);
		member_reset_requests(m);
		member_set_local_id(m, oio_ext_rand_int());
		m->pending_ZK_LIST = 1;
		m->when_unstable = oio_ext_monotonic_time();
		m->peers = g_strdupv(PEERS);
		_member_assert_LISTING(m);
	}

	/* Test No-Op transitions */
	static const int ABNORMAL[] = {
		EVT_NONE, EVT_LEFT_MASTER,
		EVT_GETVERS_OK, EVT_GETVERS_KO, EVT_GETVERS_OLD, EVT_GETVERS_RACE,
		EVT_MASTER_OK, EVT_MASTER_KO, EVT_MASTER_BAD,
		EVT_CREATE_OK, EVT_CREATE_KO,
		EVT_EXISTS_OK, EVT_EXISTS_KO,
		EVT_LEAVE_OK, EVT_LEAVE_KO,
		EVT_SYNC_OK, EVT_SYNC_KO,
		-1 /* end beacon */
	};
	for (const int *pevt=ABNORMAL; *pevt >= 0 ;++pevt) {
		RESET();
		_test_nochange(*pevt, NULL);
		_member_assert_LISTING(m);
		_pending(0);
		g_assert_false(member_has_request(m));
	}

	/* interruptions */
	RESET();
	transition(m, EVT_DISCONNECTED, NULL);
	_member_assert_NONE(m);
	_pending(0);

	RESET();
	transition(m, EVT_LEAVE_REQ, NULL);
	_member_assert_LISTING(m);
	_pending(0);
	g_assert_cmpint(m->requested_LEAVE, ==, 1);

	RESET();
	transition(m, EVT_LEFT_SELF, NULL);
	_member_assert_LISTING(m);
	_pending(0);
	g_assert_cmpint(m->requested_LEFT_SELF, ==, 1);

	/* Legit transitions with no interruption */
	RESET();
	transition(m, EVT_LIST_KO, NULL);
	_member_assert_LEAVING_FAILING(m);
#if ZOO_35
	_pending(CMD_DEL_WATCH, CMD_DELETE, 0);
#else
	_pending(CMD_DELETE, 0);
#endif

	gint64 i64;

	RESET();
	i64 = m->local_id; /* -> master */
	transition(m, EVT_LIST_OK, &i64);
	if (!sqliterepo_allow_master) {
		g_assert_cmpint(m->local_id, !=, m->master_id);
		_member_assert_LEAVING(m);
		_pending(CMD_DELETE, 0);
	} else {
		g_assert_cmpint(m->local_id, ==, m->master_id);
		_member_assert_CHECKING_SLAVES(m);
		_pending(0);
	}

	RESET();
	i64 = m->local_id + 1; /* -> slave */
	transition(m, EVT_LIST_OK, &i64);
	g_assert_cmpint(m->local_id, !=, m->master_id);
	_member_assert_ASKING(m);
	_pending(CMD_GET, 0);

	TEST_TAIL();
}

static void test_STEP_CHECKING_SLAVES(void) {
	TEST_HEAD();

	void RESET() {
		g_array_set_size(sync->pending, 0);
		member_set_status(m, STEP_CHECKING_SLAVES);
		member_reset(m);
		member_reset_requests(m);
		member_set_local_id(m, oio_ext_rand_int());
		member_set_master_id(m, m->local_id);
		m->pending_GETVERS = 3;
		m->when_unstable = oio_ext_monotonic_time();
		m->peers = g_strdupv(PEERS);
		_member_assert_CHECKING_SLAVES(m);
	}

	/* Test No-Op transitions */
	static const int ABNORMAL[] = {
		EVT_NONE, EVT_LEFT_MASTER,
		EVT_MASTER_OK, EVT_MASTER_KO, EVT_MASTER_BAD,
		EVT_CREATE_OK, EVT_CREATE_KO,
		EVT_EXISTS_OK, EVT_EXISTS_KO,
		EVT_LEAVE_OK, EVT_LEAVE_KO,
		EVT_LIST_OK, EVT_LIST_KO,
		EVT_SYNC_OK, EVT_SYNC_KO,
		-1 /* end beacon */
	};
	for (const int *pevt=ABNORMAL; *pevt >= 0 ;++pevt) {
		RESET();
		_test_nochange(*pevt, NULL);
		_member_assert_CHECKING_SLAVES(m);
		_pending(0);
		g_assert_false(member_has_request(m));
	}

	/* interruptions */
	RESET();
	transition(m, EVT_DISCONNECTED, NULL);
	_member_assert_NONE(m);
	_pending(0);

	RESET();
	transition(m, EVT_LEAVE_REQ, NULL);
	_member_assert_CHECKING_SLAVES(m);
	_pending(0);
	g_assert_cmpint(m->requested_LEAVE, ==, 1);

	RESET();
	transition(m, EVT_LEFT_SELF, NULL);
	_member_assert_CHECKING_SLAVES(m);
	_pending(0);
	g_assert_cmpint(m->requested_LEFT_SELF, ==, 1);

	/* Legit transitions with no interruption:
	 * 1/ Non-LAST getvers reply */
	RESET();
	m->count_GETVERS = 3;
	m->pending_GETVERS = 2;
	transition(m, EVT_GETVERS_OK, NULL);
	_member_assert_CHECKING_SLAVES(m);
	g_assert_cmpint(m->count_GETVERS, ==, 3);
	g_assert_cmpint(m->pending_GETVERS, ==, 1);
	g_assert_cmpint(m->errors_GETVERS, ==, 0);
	g_assert_cmpint(m->outdated_GETVERS, ==, 0);
	g_assert_cmpint(m->concurrent_GETVERS, ==, 0);
	_pending(0);

	RESET();
	m->count_GETVERS = 3;
	m->pending_GETVERS = 2;
	transition(m, EVT_GETVERS_KO, NULL);
	_member_assert_CHECKING_SLAVES(m);
	g_assert_cmpint(m->count_GETVERS, ==, 3);
	g_assert_cmpint(m->pending_GETVERS, ==, 1);
	g_assert_cmpint(m->errors_GETVERS, ==, 1);
	g_assert_cmpint(m->outdated_GETVERS, ==, 0);
	g_assert_cmpint(m->concurrent_GETVERS, ==, 0);
	_pending(0);

	RESET();
	m->count_GETVERS = 3;
	m->pending_GETVERS = 2;
	transition(m, EVT_GETVERS_OLD, NULL);
	_member_assert_CHECKING_SLAVES(m);
	g_assert_cmpint(m->count_GETVERS, ==, 3);
	g_assert_cmpint(m->pending_GETVERS, ==, 1);
	g_assert_cmpint(m->errors_GETVERS, ==, 0);
	g_assert_cmpint(m->outdated_GETVERS, ==, 1);
	g_assert_cmpint(m->concurrent_GETVERS, ==, 0);
	_pending(0);

	RESET();
	m->count_GETVERS = 3;
	m->pending_GETVERS = 2;
	transition(m, EVT_GETVERS_RACE, NULL);
	_member_assert_CHECKING_SLAVES(m);
	g_assert_cmpint(m->count_GETVERS, ==, 3);
	g_assert_cmpint(m->pending_GETVERS, ==, 1);
	g_assert_cmpint(m->errors_GETVERS, ==, 0);
	g_assert_cmpint(m->outdated_GETVERS, ==, 0);
	g_assert_cmpint(m->concurrent_GETVERS, ==, 1);
	_pending(0);

	/* Legit transitions with no interruption:
	 * 2/ LAST getvers reply, quorum present */
	RESET();
	m->count_GETVERS = 3;
	m->pending_GETVERS = 1;
	transition(m, EVT_GETVERS_OK, NULL);
	_member_assert_MASTER(m);
	g_assert_false(member_has_getvers(m));
	_pending(0);

	RESET();
	m->count_GETVERS = 3;
	m->pending_GETVERS = 1;
	transition(m, EVT_GETVERS_KO, NULL);
	_member_assert_MASTER(m);
	g_assert_false(member_has_getvers(m));
	_pending(0);

	RESET();
	m->count_GETVERS = 3;
	m->pending_GETVERS = 1;
	transition(m, EVT_GETVERS_OLD, NULL);
	_member_assert_LEAVING(m);
	g_assert_false(member_has_getvers(m));
#if ZOO_35
	_pending(CMD_DEL_WATCH, CMD_DEL_WATCH, CMD_DELETE, 0);
#else
	_pending(CMD_DELETE, 0);
#endif

	RESET();
	m->count_GETVERS = 3;
	m->pending_GETVERS = 1;
	m->outdated_GETVERS = 1;
	transition(m, EVT_GETVERS_RACE, NULL);
	_member_assert_LEAVING(m);
	g_assert_false(member_has_getvers(m));
#if ZOO_35
	_pending(CMD_DEL_WATCH, CMD_DEL_WATCH, CMD_DELETE, 0);
#else
	_pending(CMD_DELETE, 0);
#endif

	/* Legit transitions with no interruption:
	 * 3/ LAST getvers reply, quorum absent */
	RESET();
	m->count_GETVERS = 3;
	m->pending_GETVERS = 1;
	m->errors_GETVERS = 1;
	m->attempts_GETVERS = 1;
	transition(m, EVT_GETVERS_KO, NULL);
	_member_assert_DELAYED_CHECKING_SLAVES(m);  /* 1 attempt left */
	g_assert_false(member_has_getvers(m));
	_pending(0);

	RESET();
	m->count_GETVERS = 3;
	m->pending_GETVERS = 1;
	m->errors_GETVERS = 1;
	transition(m, EVT_GETVERS_KO, NULL);
	_member_assert_LEAVING_FAILING(m);  /* no more attempts left */
	g_assert_false(member_has_getvers(m));
#if ZOO_35
	_pending(CMD_DEL_WATCH, CMD_DEL_WATCH, CMD_DELETE, 0);
#else
	_pending(CMD_DELETE, 0);
#endif

	TEST_TAIL();
}

static void test_STEP_MASTER(void) {
	TEST_HEAD();

	void RESET() {
		g_array_set_size(sync->pending, 0);
		member_set_status(m, STEP_MASTER);
		member_reset(m);
		member_reset_requests(m);
		member_set_local_id(m, oio_ext_rand_int());
		member_set_master_id(m, m->local_id);
		m->when_unstable = 0;
		m->peers = g_strdupv(PEERS);
		_member_assert_MASTER(m);
	}

	/* Test No-Op transitions */
	static const int ABNORMAL[] = {
		EVT_NONE, EVT_LEFT_MASTER,
		EVT_GETVERS_OK, EVT_GETVERS_KO, EVT_GETVERS_OLD, EVT_GETVERS_RACE,
		EVT_MASTER_OK, EVT_MASTER_KO, EVT_MASTER_BAD,
		EVT_CREATE_OK, EVT_CREATE_KO,
		EVT_EXISTS_OK, EVT_EXISTS_KO,
		EVT_LEAVE_OK, EVT_LEAVE_KO,
		EVT_LIST_OK, EVT_LIST_KO,
		EVT_SYNC_OK, EVT_SYNC_KO,
		-1 /* end beacon */
	};
	for (const int *pevt=ABNORMAL; *pevt >= 0 ;++pevt) {
		RESET();
		_test_nochange(*pevt, NULL);
		_member_assert_MASTER(m);
		_pending(0);
		g_assert_false(member_has_request(m));
	}

	/* interruptions */
	RESET();
	transition(m, EVT_DISCONNECTED, NULL);
	_member_assert_NONE(m);
	_pending(0);

	RESET();
	transition(m, EVT_LEAVE_REQ, NULL);
	_member_assert_LEAVING(m);
#if ZOO_35
	_pending(CMD_DEL_WATCH, CMD_DEL_WATCH, CMD_DELETE, 0);
#else
	_pending(CMD_DELETE, 0);
#endif
	g_assert_false(member_has_request(m));

	RESET();
	transition(m, EVT_LEFT_SELF, NULL);
	_member_assert_PEERING(m);
	_pending(0);
	g_assert_false(member_has_request(m));

	TEST_TAIL();
}

static void test_STEP_ASKING(void) {
	TEST_HEAD();

	void RESET() {
		g_array_set_size(sync->pending, 0);
		member_set_status(m, STEP_ASKING);
		member_reset(m);
		member_reset_requests(m);
		member_set_local_id(m, oio_ext_rand_int());
		member_set_master_id(m, m->local_id + 1);
		m->pending_ZK_GET = 1;
		m->attempts_GETVERS = 0;
		m->when_unstable = oio_ext_monotonic_time();
		m->peers = g_strdupv(PEERS);
		_member_assert_ASKING(m);
	}

	/* Test No-Op transitions */
	static const int ABNORMAL[] = {
		EVT_NONE,
		EVT_GETVERS_OK, EVT_GETVERS_KO, EVT_GETVERS_OLD, EVT_GETVERS_RACE,
		EVT_CREATE_OK, EVT_CREATE_KO,
		EVT_EXISTS_OK, EVT_EXISTS_KO,
		EVT_LEAVE_OK, EVT_LEAVE_KO,
		EVT_LIST_OK, EVT_LIST_KO,
		EVT_SYNC_OK, EVT_SYNC_KO,
		-1 /* end beacon */
	};
	for (const int *pevt=ABNORMAL; *pevt >= 0 ;++pevt) {
		RESET();
		_test_nochange(*pevt, NULL);
		_member_assert_ASKING(m);
		_pending(0);
		g_assert_false(member_has_request(m));
	}

	/* interruptions */
	RESET();
	transition(m, EVT_DISCONNECTED, NULL);
	_member_assert_NONE(m);
	_pending(0);

	RESET();
	transition(m, EVT_LEAVE_REQ, NULL);
	_member_assert_ASKING(m);
	_pending(0);
	g_assert_cmpint(m->requested_LEAVE, ==, 1);

	RESET();
	transition(m, EVT_LEFT_SELF, NULL);
	_member_assert_ASKING(m);
	_pending(0);
	g_assert_cmpint(m->requested_LEFT_SELF, ==, 1);

	RESET();
	transition(m, EVT_LEFT_MASTER, NULL);
	_member_assert_ASKING(m);
	_pending(0);
	g_assert_cmpint(m->requested_LEFT_MASTER, ==, 1);

	/* Legit transitions
	 * 1/ No past interruption */
	char *url = "127.0.0.1:6000";

	RESET();
	transition(m, EVT_MASTER_OK, url);
	_member_assert_CHECKING_MASTER(m);
	_pending(0);
	/* only one GETVERS sent to the master */
	g_assert_cmpint(m->pending_GETVERS, ==, 1);

	RESET();
	transition(m, EVT_MASTER_BAD, NULL);
	_member_assert_LEAVING_FAILING(m);
#if ZOO_35
	_pending(CMD_DEL_WATCH, CMD_DEL_WATCH, CMD_DELETE, 0);
#else
	_pending(CMD_DELETE, 0);
#endif

	RESET();
	transition(m, EVT_MASTER_KO, NULL);
	_member_assert_LEAVING_FAILING(m);
#if ZOO_35
	_pending(CMD_DEL_WATCH, CMD_DEL_WATCH, CMD_DELETE, 0);
#else
	_pending(CMD_DELETE, 0);
#endif

	/* Legit transitions
	 * 2/ Pending past interruption */

	/* MASTER_OK */
	RESET();
	m->requested_LEAVE = 1; /* left_self takes over both the others */
	m->requested_LEFT_SELF = 1;
	m->requested_LEFT_MASTER = 1;
	transition(m, EVT_MASTER_OK, NULL);
	_member_assert_LEAVING(m);
	g_assert_false(m->requested_LEFT_MASTER);
	g_assert_false(m->requested_LEFT_SELF);
	g_assert_false(m->requested_LEAVE);
#if ZOO_35
	_pending(CMD_DEL_WATCH, CMD_DEL_WATCH, CMD_DELETE, 0);
#else
	_pending(CMD_DELETE, 0);
#endif

	RESET();
	m->requested_LEFT_SELF = 1; /* left_self takes over left_master */
	m->requested_LEFT_MASTER = 1;
	transition(m, EVT_MASTER_OK, url);
	_member_assert_PEERING(m);
	g_assert_false(m->requested_LEFT_MASTER);
	g_assert_false(m->requested_LEFT_SELF);
	g_assert_false(m->requested_LEAVE);
	_pending(0);

	RESET();
	m->requested_LEFT_SELF = 1;
	transition(m, EVT_MASTER_OK, url);
	_member_assert_PEERING(m);
	g_assert_false(m->requested_LEFT_MASTER);
	g_assert_false(m->requested_LEFT_SELF);
	g_assert_false(m->requested_LEAVE);
	_pending(0);

	RESET();
	m->requested_LEFT_MASTER = 1;
	transition(m, EVT_MASTER_OK, url);
	_member_assert_LISTING(m);
	g_assert_false(m->requested_LEFT_MASTER);
	g_assert_false(m->requested_LEFT_SELF);
	g_assert_false(m->requested_LEAVE);
	_pending(CMD_LIST, 0);


	/* MASTER_BAD */
	RESET();
	m->requested_LEFT_SELF = 1;
	transition(m, EVT_MASTER_BAD, NULL);
	_member_assert_LEAVING_FAILING(m);
	g_assert_false(m->requested_LEFT_MASTER);
	g_assert_false(m->requested_LEFT_SELF);
	g_assert_false(m->requested_LEAVE);
#if ZOO_35
	_pending(CMD_DEL_WATCH, CMD_DEL_WATCH, CMD_DELETE, 0);
#else
	_pending(CMD_DELETE, 0);
#endif

	RESET();
	m->requested_LEFT_MASTER = 1;
	transition(m, EVT_MASTER_BAD, NULL);
	_member_assert_LEAVING_FAILING(m);
	g_assert_false(m->requested_LEFT_MASTER);
	g_assert_false(m->requested_LEFT_SELF);
	g_assert_false(m->requested_LEAVE);
#if ZOO_35
	_pending(CMD_DEL_WATCH, CMD_DEL_WATCH, CMD_DELETE, 0);
#else
	_pending(CMD_DELETE, 0);
#endif

	RESET();
	m->requested_LEAVE = 1;
	transition(m, EVT_MASTER_BAD, NULL);
	_member_assert_LEAVING_FAILING(m);
	g_assert_false(m->requested_LEFT_MASTER);
	g_assert_false(m->requested_LEFT_SELF);
	g_assert_false(m->requested_LEAVE);
#if ZOO_35
	_pending(CMD_DEL_WATCH, CMD_DEL_WATCH, CMD_DELETE, 0);
#else
	_pending(CMD_DELETE, 0);
#endif


	/* MASTER_KO */
	RESET();
	m->requested_LEAVE = 1;
	m->requested_LEFT_MASTER = 1;
	m->requested_LEFT_SELF = 1;
	transition(m, EVT_MASTER_KO, NULL);
	_member_assert_LEAVING(m);
	g_assert_false(m->requested_LEFT_MASTER);
	g_assert_false(m->requested_LEFT_SELF);
	g_assert_false(m->requested_LEAVE);
#if ZOO_35
	_pending(CMD_DEL_WATCH, CMD_DEL_WATCH, CMD_DELETE, 0);
#else
	_pending(CMD_DELETE, 0);
#endif

	RESET();
	m->requested_LEFT_MASTER = 1;
	m->requested_LEFT_SELF = 1;
	transition(m, EVT_MASTER_KO, NULL);
	_member_assert_LEAVING(m);
	g_assert_false(m->requested_LEFT_MASTER);
	g_assert_false(m->requested_LEFT_SELF);
	g_assert_false(m->requested_LEAVE);
#if ZOO_35
	_pending(CMD_DEL_WATCH, CMD_DEL_WATCH, CMD_DELETE, 0);
#else
	_pending(CMD_DELETE, 0);
#endif

	RESET();
	m->requested_LEFT_SELF = 1;
	transition(m, EVT_MASTER_KO, NULL);
	_member_assert_LEAVING(m);
	g_assert_false(m->requested_LEFT_MASTER);
	g_assert_false(m->requested_LEFT_SELF);
	g_assert_false(m->requested_LEAVE);
#if ZOO_35
	_pending(CMD_DEL_WATCH, CMD_DEL_WATCH, CMD_DELETE, 0);
#else
	_pending(CMD_DELETE, 0);
#endif

	RESET();
	m->requested_LEFT_MASTER = 1;
	transition(m, EVT_MASTER_KO, NULL);
	_member_assert_LISTING(m);
	g_assert_false(m->requested_LEFT_MASTER);
	g_assert_false(m->requested_LEFT_SELF);
	g_assert_false(m->requested_LEAVE);
	_pending(CMD_LIST, 0);

	RESET();
	m->requested_LEAVE = 1;
	transition(m, EVT_MASTER_KO, NULL);
	_member_assert_LEAVING(m);
	g_assert_false(m->requested_LEFT_MASTER);
	g_assert_false(m->requested_LEFT_SELF);
	g_assert_false(m->requested_LEAVE);
#if ZOO_35
	_pending(CMD_DEL_WATCH, CMD_DEL_WATCH, CMD_DELETE, 0);
#else
	_pending(CMD_DELETE, 0);
#endif

	TEST_TAIL();
}

static void test_STEP_DELAYED_CHECKING_MASTER(void) {
	TEST_HEAD();

	void RESET() {
		g_array_set_size(sync->pending, 0);
		member_set_status(m, STEP_DELAYED_CHECKING_MASTER);
		member_reset(m);
		member_reset_requests(m);
		member_set_local_id(m, oio_ext_rand_int());
		member_set_master_id(m, m->local_id + 1);
		member_set_master_url(m, "ID1");
		m->count_GETVERS = 0;
		m->pending_GETVERS = 0;
		m->attempts_GETVERS = 0;
		m->when_unstable = oio_ext_monotonic_time();
		m->peers = g_strdupv(PEERS);
		_member_assert_DELAYED_CHECKING_MASTER(m);
	}

	/* Test No-Op transitions */
	static const int ABNORMAL[] = {
		EVT_MASTER_OK, EVT_MASTER_KO, EVT_MASTER_BAD,
		EVT_GETVERS_OK, EVT_GETVERS_RACE, EVT_GETVERS_OLD, EVT_GETVERS_KO,
		EVT_CREATE_OK, EVT_CREATE_KO,
		EVT_EXISTS_OK, EVT_EXISTS_KO,
		EVT_LEAVE_OK, EVT_LEAVE_KO,
		EVT_LIST_OK, EVT_LIST_KO,
		EVT_SYNC_OK, EVT_SYNC_KO,
		-1 /* end beacon */
	};
	for (const int *pevt=ABNORMAL; *pevt >= 0 ;++pevt) {
		RESET();
		_test_nochange(*pevt, NULL);
		_member_assert_DELAYED_CHECKING_MASTER(m);
		_pending(0);
		g_assert_false(member_has_request(m));
	}

	/* interruptions */
	RESET();
	transition(m, EVT_DISCONNECTED, NULL);
	_member_assert_NONE(m);
	_pending(0);

	RESET();
	transition(m, EVT_LEAVE_REQ, NULL);
	_member_assert_LEAVING(m);
#if ZOO_35
	_pending(CMD_DEL_WATCH, CMD_DEL_WATCH, CMD_DELETE, 0);
#else
	_pending(CMD_DELETE, 0);
#endif
	g_assert_cmpint(m->requested_LEAVE, ==, 0);

	RESET();
	transition(m, EVT_LEFT_SELF, NULL);
	_member_assert_CREATING(m);
	_pending(CMD_CREATE, 0);
	g_assert_cmpint(m->requested_LEFT_SELF, ==, 0);

	RESET();
	transition(m, EVT_LEFT_MASTER, NULL);
	_member_assert_LISTING(m);
	_pending(CMD_LIST, 0);
	g_assert_cmpint(m->requested_LEFT_MASTER, ==, 0);

	/* Timeout not raised (clock untouched) */
	RESET();
	transition(m, EVT_NONE, NULL);
	_member_assert_DELAYED_CHECKING_MASTER(m);
	g_assert_false(member_has_getvers(m));
	_pending(0);

	/* Timeout raised without reload */
	RESET();
	m->requested_peers_decache = 0;
	m->attempts_GETVERS = 1;
	CLOCK += sqliterepo_getvers_delay + 1;
	transition(m, EVT_NONE, NULL);
	_member_assert_CHECKING_MASTER(m);
	g_assert_true(member_has_getvers(m));
	_pending(0);

	/* Timeout raised with reload */
	RESET();
	m->requested_peers_decache = 1;
	m->attempts_GETVERS = 1;
	CLOCK += sqliterepo_getvers_delay + 1;
	transition(m, EVT_NONE, NULL);
	_member_assert_REFRESH_CHECKING_MASTER(m);
	_pending(0);

	/* Timeout raised with reload, no attempts left, decache */
	RESET();
	m->requested_peers_decache = 1;
	m->attempts_GETVERS = 0;
	CLOCK += sqliterepo_getvers_delay + 1;
	transition(m, EVT_NONE, NULL);
	_member_assert_LEAVING_FAILING(m);
#if ZOO_35
	_pending(CMD_DEL_WATCH, CMD_DEL_WATCH, CMD_DELETE, 0);
#else
	_pending(CMD_DELETE, 0);
#endif

	/* Timeout raised with reload, no attempts left, no decache */
	RESET();
	m->requested_peers_decache = 0;
	m->attempts_GETVERS = 0;
	CLOCK += sqliterepo_getvers_delay + 1;
	transition(m, EVT_NONE, NULL);
	_member_assert_LEAVING_FAILING(m);
#if ZOO_35
	_pending(CMD_DEL_WATCH, CMD_DEL_WATCH, CMD_DELETE, 0);
#else
	_pending(CMD_DELETE, 0);
#endif

	TEST_TAIL();
}

static void test_STEP_REFRESH_CHECKING_MASTER(void) {
	TEST_HEAD();

	void RESET() {
		g_array_set_size(sync->pending, 0);
		member_set_status(m, STEP_REFRESH_CHECKING_MASTER);
		member_reset(m);
		member_reset_requests(m);
		member_set_local_id(m, oio_ext_rand_int());
		member_set_master_id(m, oio_ext_rand_int());
		member_set_master_url(m, "ID1");
		m->count_GETVERS = 0;
		m->pending_GETVERS = 0;
		m->attempts_GETVERS = 0;
		m->when_unstable = oio_ext_monotonic_time();
		m->peers = g_strdupv(PEERS);
		_member_assert_REFRESH_CHECKING_MASTER(m);
	}

	/* Test No-Op transitions */
	static const int ABNORMAL[] = {
		EVT_NONE,
		EVT_GETVERS_OK, EVT_GETVERS_RACE, EVT_GETVERS_OLD, EVT_GETVERS_KO,
		EVT_MASTER_OK, EVT_MASTER_KO, EVT_MASTER_BAD,
		EVT_CREATE_OK, EVT_CREATE_KO,
		EVT_EXISTS_OK, EVT_EXISTS_KO,
		EVT_LIST_OK, EVT_LIST_KO,
		EVT_LEAVE_OK, EVT_LEAVE_KO,
		EVT_SYNC_OK, EVT_SYNC_KO,
		-1 /* end beacon */
	};
	for (const int *pevt=ABNORMAL; *pevt >= 0 ;++pevt) {
		RESET();
		_test_nochange(*pevt, NULL);
		_member_assert_REFRESH_CHECKING_MASTER(m);
		_pending(0);
		g_assert_false(member_has_request(m));
	}

	/* Test interruptions */
	RESET();
	transition(m, EVT_DISCONNECTED, NULL);
	_member_assert_NONE(m);
	_pending(0);

	RESET();
	transition(m, EVT_SYNC_REQ, NULL);
	_member_assert_REFRESH_CHECKING_MASTER(m);
	_pending(0);
	g_assert_cmpint(m->requested_PIPEFROM, ==, 1);

	RESET();
	transition(m, EVT_LEAVE_REQ, NULL);
	_member_assert_REFRESH_CHECKING_MASTER(m);
	_pending(0);
	g_assert_cmpint(m->requested_LEAVE, ==, 1);

	RESET();
	transition(m, EVT_LEFT_SELF, NULL);
	_member_assert_REFRESH_CHECKING_MASTER(m);
	_pending(0);
	g_assert_cmpint(m->requested_LEFT_SELF, ==, 1);

	RESET();
	transition(m, EVT_LEFT_MASTER, NULL);
	_member_assert_REFRESH_CHECKING_MASTER(m);
	_pending(0);
	g_assert_cmpint(m->requested_LEFT_MASTER, ==, 1);

	/* Legit transitions, no pending signal */
	RESET();
	transition(m, EVT_GETPEERS_DONE, NULL);
	_member_assert_LEAVING_FAILING(m);
#if ZOO_35
	_pending(CMD_DEL_WATCH, CMD_DEL_WATCH, CMD_DELETE, 0);
#else
	_pending(CMD_DELETE, 0);
#endif

	RESET();
	transition(m, EVT_GETPEERS_DONE, PEERS);
	_member_assert_CHECKING_MASTER(m);
	g_assert_true(member_has_getvers(m));
	_pending(0);

	/* Legit transitions, pending signal */
	RESET();
	m->requested_LEFT_MASTER = 1;
	transition(m, EVT_GETPEERS_DONE, PEERS);
	_member_assert_LISTING(m);
	g_assert_cmpint(m->requested_LEFT_MASTER, ==, 0);
	_pending(CMD_LIST, 0);

	RESET();
	m->requested_LEAVE = 1;
	transition(m, EVT_GETPEERS_DONE, PEERS);
	_member_assert_LEAVING(m);
	g_assert_cmpint(m->requested_LEAVE, ==, 0);
#if ZOO_35
	_pending(CMD_DEL_WATCH, CMD_DEL_WATCH, CMD_DELETE, 0);
#else
	_pending(CMD_DELETE, 0);
#endif

	RESET();
	m->requested_LEFT_SELF = 1;
	transition(m, EVT_GETPEERS_DONE, PEERS);
	_member_assert_PEERING(m);
	g_assert_cmpint(m->requested_LEFT_SELF, ==, 0);
	_pending(0);

	RESET();
	m->requested_PIPEFROM = 1;
	transition(m, EVT_GETPEERS_DONE, PEERS);
	_member_assert_CHECKING_MASTER(m);
	g_assert_cmpint(m->requested_PIPEFROM, ==, 1);
	_pending(0);

	TEST_TAIL();
}

static void test_STEP_DELAYED_CHECKING_SLAVES(void) {
	TEST_HEAD();

	void RESET() {
		g_array_set_size(sync->pending, 0);
		member_set_status(m, STEP_DELAYED_CHECKING_SLAVES);
		member_reset(m);
		member_reset_requests(m);
		member_set_local_id(m, oio_ext_rand_int());
		member_set_master_id(m, m->local_id);
		member_set_master_url(m, NULL);
		m->count_GETVERS = 0;
		m->pending_GETVERS = 0;
		m->attempts_GETVERS = 0;
		m->when_unstable = oio_ext_monotonic_time();
		m->peers = g_strdupv(PEERS);
		_member_assert_DELAYED_CHECKING_SLAVES(m);
	}

	/* Test No-Op transitions */
	static const int ABNORMAL[] = {
		EVT_MASTER_OK, EVT_MASTER_KO, EVT_MASTER_BAD,
		EVT_GETVERS_OK, EVT_GETVERS_RACE, EVT_GETVERS_OLD, EVT_GETVERS_KO,
		EVT_CREATE_OK, EVT_CREATE_KO,
		EVT_EXISTS_OK, EVT_EXISTS_KO,
		EVT_LEAVE_OK, EVT_LEAVE_KO,
		EVT_LIST_OK, EVT_LIST_KO,
		EVT_SYNC_OK, EVT_SYNC_KO,
		-1 /* end beacon */
	};
	for (const int *pevt=ABNORMAL; *pevt >= 0 ;++pevt) {
		RESET();
		_test_nochange(*pevt, NULL);
		_member_assert_DELAYED_CHECKING_SLAVES(m);
		_pending(0);
		g_assert_false(member_has_request(m));
	}

	/* interruptions */
	RESET();
	transition(m, EVT_DISCONNECTED, NULL);
	_member_assert_NONE(m);
	_pending(0);

	RESET();
	transition(m, EVT_LEAVE_REQ, NULL);
	_member_assert_LEAVING(m);
#if ZOO_35
	_pending(CMD_DEL_WATCH, CMD_DEL_WATCH, CMD_DELETE, 0);
#else
	_pending(CMD_DELETE, 0);
#endif
	g_assert_cmpint(m->requested_LEAVE, ==, 0);

	RESET();
	transition(m, EVT_LEFT_SELF, NULL);
	_member_assert_CREATING(m);
	_pending(CMD_CREATE, 0);
	g_assert_cmpint(m->requested_LEFT_SELF, ==, 0);

	RESET();
	transition(m, EVT_LEFT_MASTER, NULL);
	_member_assert_DELAYED_CHECKING_SLAVES(m);
	_pending(0);
	g_assert_cmpint(m->requested_LEFT_MASTER, ==, 0);

	RESET();
	transition(m, EVT_SYNC_REQ, NULL);
	_member_assert_DELAYED_CHECKING_SLAVES(m);
	_pending(0);
	g_assert_cmpint(m->requested_PIPEFROM, ==, 0);

	/* Timeout not raised (clock untouched) */
	RESET();
	transition(m, EVT_NONE, NULL);
	_member_assert_DELAYED_CHECKING_SLAVES(m);
	g_assert_false(member_has_getvers(m));
	_pending(0);

	/* Timeout raised without reload and no pending interruption */
	RESET();
	m->requested_peers_decache = 0;
	m->attempts_GETVERS = 1;
	CLOCK += sqliterepo_getvers_delay + 1;
	transition(m, EVT_NONE, NULL);
	_member_assert_CHECKING_SLAVES(m);
	g_assert_true(member_has_getvers(m));
	_pending(0);

	/* Timeout raised with reload but no pending signal */
	RESET();
	m->requested_peers_decache = 1;
	m->attempts_GETVERS = 1;
	CLOCK += sqliterepo_getvers_delay + 1;
	transition(m, EVT_NONE, NULL);
	_member_assert_REFRESH_CHECKING_SLAVES(m);
	_pending(0);

	/* Timeout raised without reload, no pending interruption, no attempt, no refresh */
	RESET();
	m->requested_peers_decache = 0;
	m->attempts_GETVERS = 0;
	CLOCK += sqliterepo_getvers_delay + 1;
	transition(m, EVT_NONE, NULL);
	_member_assert_LEAVING_FAILING(m);
#if ZOO_35
	_pending(CMD_DEL_WATCH, CMD_DEL_WATCH, CMD_DELETE, 0);
#else
	_pending(CMD_DELETE, 0);
#endif

	/* Timeout raised without reload, no pending interruption, no attempt, refresh */
	RESET();
	m->requested_peers_decache = 1;
	m->attempts_GETVERS = 0;
	CLOCK += sqliterepo_getvers_delay + 1;
	transition(m, EVT_NONE, NULL);
	_member_assert_LEAVING_FAILING(m);
#if ZOO_35
	_pending(CMD_DEL_WATCH, CMD_DEL_WATCH, CMD_DELETE, 0);
#else
	_pending(CMD_DELETE, 0);
#endif

	TEST_TAIL();
}

static void test_STEP_REFRESH_CHECKING_SLAVES(void) {
	TEST_HEAD();

	void RESET() {
		g_array_set_size(sync->pending, 0);
		member_set_status(m, STEP_REFRESH_CHECKING_SLAVES);
		member_reset(m);
		member_reset_requests(m);
		member_set_local_id(m, oio_ext_rand_int());
		member_set_master_id(m, m->local_id);
		member_set_master_url(m, NULL);
		m->count_GETVERS = 0;
		m->pending_GETVERS = 0;
		m->attempts_GETVERS = 0;
		m->when_unstable = oio_ext_monotonic_time();
		m->peers = g_strdupv(PEERS);
		_member_assert_REFRESH_CHECKING_SLAVES(m);
	}

	/* Test No-Op transitions */
	static const int ABNORMAL[] = {
		EVT_NONE,
		EVT_GETVERS_OK, EVT_GETVERS_RACE, EVT_GETVERS_OLD, EVT_GETVERS_KO,
		EVT_MASTER_OK, EVT_MASTER_KO, EVT_MASTER_BAD,
		EVT_CREATE_OK, EVT_CREATE_KO,
		EVT_EXISTS_OK, EVT_EXISTS_KO,
		EVT_LIST_OK, EVT_LIST_KO,
		EVT_LEAVE_OK, EVT_LEAVE_KO,
		EVT_SYNC_OK, EVT_SYNC_KO,
		EVT_SYNC_REQ, EVT_LEFT_MASTER,
		-1 /* end beacon */
	};
	for (const int *pevt=ABNORMAL; *pevt >= 0 ;++pevt) {
		RESET();
		_test_nochange(*pevt, NULL);
		_member_assert_REFRESH_CHECKING_SLAVES(m);
		_pending(0);
		g_assert_false(member_has_request(m));
	}

	/* Test interruptions */
	RESET();
	transition(m, EVT_DISCONNECTED, NULL);
	_member_assert_NONE(m);
	_pending(0);

	RESET();
	transition(m, EVT_LEAVE_REQ, NULL);
	_member_assert_REFRESH_CHECKING_SLAVES(m);
	_pending(0);
	g_assert_cmpint(m->requested_LEAVE, ==, 1);

	RESET();
	transition(m, EVT_LEFT_SELF, NULL);
	_member_assert_REFRESH_CHECKING_SLAVES(m);
	_pending(0);
	g_assert_cmpint(m->requested_LEFT_SELF, ==, 1);

	/* Legit transitions, no pending signal */
	RESET();
	transition(m, EVT_GETPEERS_DONE, NULL);
	_member_assert_LEAVING_FAILING(m);
#if ZOO_35
	_pending(CMD_DEL_WATCH, CMD_DEL_WATCH, CMD_DELETE, 0);
#else
	_pending(CMD_DELETE, 0);
#endif

	RESET();
	transition(m, EVT_GETPEERS_DONE, PEERS);
	_member_assert_CHECKING_SLAVES(m);
	g_assert_true(member_has_getvers(m));
	_pending(0);

	/* Legit transitions, pending signals */
	RESET();
	m->requested_LEFT_SELF = 1;
	transition(m, EVT_GETPEERS_DONE, PEERS);
	_member_assert_PEERING(m);
	g_assert_cmpint(m->requested_LEFT_SELF, ==, 0);
	_pending(0);

	RESET();
	m->requested_LEAVE = 1;
	transition(m, EVT_GETPEERS_DONE, PEERS);
	_member_assert_LEAVING(m);
	g_assert_cmpint(m->requested_LEAVE, ==, 0);
#if ZOO_35
	_pending(CMD_DEL_WATCH, CMD_DEL_WATCH, CMD_DELETE, 0);
#else
	_pending(CMD_DELETE, 0);
#endif

	RESET();
	m->requested_LEFT_MASTER = 1;
	transition(m, EVT_GETPEERS_DONE, PEERS);
	_member_assert_CHECKING_SLAVES(m);
	g_assert_cmpint(m->requested_LEFT_MASTER, ==, 1);
	_pending(0);

	RESET();
	m->requested_PIPEFROM = 1;
	transition(m, EVT_GETPEERS_DONE, PEERS);
	_member_assert_CHECKING_SLAVES(m);
	g_assert_cmpint(m->requested_PIPEFROM, ==, 1);
	_pending(0);

	TEST_TAIL();
}

static void test_STEP_CHECKING_MASTER(void) {
	TEST_HEAD();

	void RESET() {
		g_array_set_size(sync->pending, 0);
		member_set_status(m, STEP_CHECKING_MASTER);
		member_reset(m);
		member_reset_requests(m);
		member_set_local_id(m, oio_ext_rand_int());
		member_set_master_id(m, m->local_id + 1);
		member_set_master_url(m, "ID1");
		m->count_GETVERS = 1;
		m->pending_GETVERS = 1;
		m->attempts_GETVERS = 2;
		m->when_unstable = oio_ext_monotonic_time();
		m->peers = g_strdupv(PEERS);
		_member_assert_CHECKING_MASTER(m);
	}

	/* Test No-Op transitions */
	static const int ABNORMAL[] = {
		EVT_NONE,
		EVT_MASTER_OK, EVT_MASTER_KO, EVT_MASTER_BAD,
		EVT_CREATE_OK, EVT_CREATE_KO,
		EVT_EXISTS_OK, EVT_EXISTS_KO,
		EVT_LEAVE_OK, EVT_LEAVE_KO,
		EVT_LIST_OK, EVT_LIST_KO,
		EVT_SYNC_OK, EVT_SYNC_KO,
		-1 /* end beacon */
	};
	for (const int *pevt=ABNORMAL; *pevt >= 0 ;++pevt) {
		RESET();
		_test_nochange(*pevt, NULL);
		_member_assert_CHECKING_MASTER(m);
		_pending(0);
		g_assert_false(member_has_request(m));
	}

	/* interruptions */
	RESET();
	transition(m, EVT_DISCONNECTED, NULL);
	_member_assert_NONE(m);
	_pending(0);

	RESET();
	transition(m, EVT_LEAVE_REQ, NULL);
	_member_assert_CHECKING_MASTER(m);
	_pending(0);
	g_assert_cmpint(m->requested_LEAVE, ==, 1);

	RESET();
	transition(m, EVT_LEFT_SELF, NULL);
	_member_assert_CHECKING_MASTER(m);
	_pending(0);
	g_assert_cmpint(m->requested_LEFT_SELF, ==, 1);

	RESET();
	transition(m, EVT_LEFT_MASTER, NULL);
	_member_assert_CHECKING_MASTER(m);
	_pending(0);
	g_assert_cmpint(m->requested_LEFT_MASTER, ==, 1);

	/* Legit transitions with no interruption:
	 * LAST getvers reply (there is only one GETVERS sent, any reply is
	 * the last) */
	RESET();
	transition(m, EVT_GETVERS_OK, NULL);
	_member_assert_SLAVE(m);
	g_assert_false(member_has_getvers(m));
	_pending(0);

	RESET();
	m->attempts_GETVERS = 1;
	transition(m, EVT_GETVERS_KO, NULL);
	_member_assert_DELAYED_CHECKING_MASTER(m);
	g_assert_false(member_has_getvers(m));
	_pending(0);

	RESET();
	m->attempts_GETVERS = 0;
	transition(m, EVT_GETVERS_KO, NULL);
	_member_assert_LEAVING_FAILING(m);
	g_assert_false(member_has_getvers(m));
#if ZOO_35
	_pending(CMD_DEL_WATCH, CMD_DEL_WATCH, CMD_DELETE, 0);
#else
	_pending(CMD_DELETE, 0);
#endif

	RESET();
	m->attempts_GETVERS = 1;
	transition(m, EVT_GETVERS_OLD, NULL);
	_member_assert_SYNCING(m);
	g_assert_false(member_has_getvers(m));
	_pending(0);

	RESET();
	m->attempts_GETVERS = 0;
	transition(m, EVT_GETVERS_RACE, NULL);
	_member_assert_SYNCING(m);
	g_assert_false(member_has_getvers(m));
	_pending(0);

	TEST_TAIL();
}

static void test_STEP_SLAVE(void) {
	TEST_HEAD();

	void RESET() {
		g_array_set_size(sync->pending, 0);
		member_set_status(m, STEP_SLAVE);
		member_reset(m);
		member_reset_requests(m);
		member_set_local_id(m, oio_ext_rand_int());
		member_set_master_id(m, m->local_id + 1);
		member_set_master_url(m, "ID1");
		m->when_unstable = 0;
		m->peers = g_strdupv(PEERS);
		_member_assert_SLAVE(m);
	}

	/* Test No-Op transitions */
	static const int ABNORMAL[] = {
		EVT_NONE,
		EVT_GETVERS_OK, EVT_GETVERS_KO, EVT_GETVERS_OLD, EVT_GETVERS_RACE,
		EVT_MASTER_OK, EVT_MASTER_KO, EVT_MASTER_BAD,
		EVT_CREATE_OK, EVT_CREATE_KO,
		EVT_EXISTS_OK, EVT_EXISTS_KO,
		EVT_LEAVE_OK, EVT_LEAVE_KO,
		EVT_LIST_OK, EVT_LIST_KO,
		EVT_SYNC_OK, EVT_SYNC_KO,
		-1 /* end beacon */
	};
	for (const int *pevt=ABNORMAL; *pevt >= 0 ;++pevt) {
		RESET();
		_test_nochange(*pevt, NULL);
		_member_assert_SLAVE(m);
		_pending(0);
		g_assert_false(member_has_request(m));
	}

	/* interruptions */
	RESET();
	transition(m, EVT_DISCONNECTED, NULL);
	_member_assert_NONE(m);
	_pending(0);

	RESET();
	transition(m, EVT_LEAVE_REQ, NULL);
	_member_assert_LEAVING(m);
#if ZOO_35
	_pending(CMD_DEL_WATCH, CMD_DEL_WATCH, CMD_DELETE, 0);
#else
	_pending(CMD_DELETE, 0);
#endif

	RESET();
	transition(m, EVT_LEFT_SELF, NULL);
	_member_assert_PEERING(m);
	_pending(0);

	RESET();
	transition(m, EVT_LEFT_MASTER, NULL);
	_member_assert_LISTING(m);
	_pending(CMD_LIST, 0);

	TEST_TAIL();
}

static void test_STEP_SYNCING(void) {
	TEST_HEAD();

	void RESET() {
		g_array_set_size(sync->pending, 0);
		member_set_status(m, STEP_SYNCING);
		member_reset(m);
		member_reset_requests(m);
		member_set_local_id(m, oio_ext_rand_int());
		member_set_master_id(m, m->local_id + 1);
		member_set_master_url(m, "ID1");
		m->pending_PIPEFROM = 1;
		m->when_unstable = oio_ext_monotonic_time();
		m->peers = g_strdupv(PEERS);
		_member_assert_SYNCING(m);
	}

	/* Test No-Op transitions */
	static const int ABNORMAL[] = {
		EVT_NONE, EVT_LEAVE_REQ,
		EVT_GETVERS_OK, EVT_GETVERS_KO, EVT_GETVERS_OLD, EVT_GETVERS_RACE,
		EVT_MASTER_OK, EVT_MASTER_KO, EVT_MASTER_BAD,
		EVT_CREATE_OK, EVT_CREATE_KO,
		EVT_EXISTS_OK, EVT_EXISTS_KO,
		EVT_LEAVE_OK, EVT_LEAVE_KO,
		EVT_LIST_OK, EVT_LIST_KO,
		-1 /* end beacon */
	};
	for (const int *pevt=ABNORMAL; *pevt >= 0 ;++pevt) {
		RESET();
		_test_nochange(*pevt, NULL);
		_member_assert_SYNCING(m);
		_pending(0);
		guint _flag = m->pending_PIPEFROM;
		m->pending_PIPEFROM = 0;
		g_assert_false(member_has_action(m));
		m->pending_PIPEFROM = BOOL(_flag);
	}

	/* interruptions */
	RESET();
	transition(m, EVT_DISCONNECTED, NULL);
	_member_assert_NONE(m);
	_pending(0);

	RESET();
	transition(m, EVT_LEFT_SELF, NULL);
	_member_assert_SYNCING(m);
	_pending(0);

	RESET();
	transition(m, EVT_LEFT_MASTER, NULL);
	_member_assert_SYNCING(m);
	_pending(0);

	TEST_TAIL();
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
	g_test_add_func("/sqlx/election/step/NONE", test_STEP_NONE);
	g_test_add_func("/sqlx/election/step/PEERING", test_STEP_PEERING);
	g_test_add_func("/sqlx/election/step/CREATING", test_STEP_CREATING);
	g_test_add_func("/sqlx/election/step/WATCHING", test_STEP_WATCHING);
	g_test_add_func("/sqlx/election/step/LISTING", test_STEP_LISTING);
	g_test_add_func("/sqlx/election/step/CHECKING_SLAVES", test_STEP_CHECKING_SLAVES);
	g_test_add_func("/sqlx/election/step/MASTER", test_STEP_MASTER);
	g_test_add_func("/sqlx/election/step/ASKING", test_STEP_ASKING);
	g_test_add_func("/sqlx/election/step/CHECKING_MASTER", test_STEP_CHECKING_MASTER);
	g_test_add_func("/sqlx/election/step/DELAYED_CHECKING_MASTER", test_STEP_DELAYED_CHECKING_MASTER);
	g_test_add_func("/sqlx/election/step/DELAYED_CHECKING_SLAVES", test_STEP_DELAYED_CHECKING_SLAVES);
	g_test_add_func("/sqlx/election/step/SLAVE", test_STEP_SLAVE);
	g_test_add_func("/sqlx/election/step/SYNCING", test_STEP_SYNCING);
	g_test_add_func("/sqlx/election/step/REFRESH_CHECKING_SLAVES", test_STEP_REFRESH_CHECKING_SLAVES);
	g_test_add_func("/sqlx/election/step/REFRESH_CHECKING_MASTER", test_STEP_REFRESH_CHECKING_MASTER);
	return g_test_run();
}
