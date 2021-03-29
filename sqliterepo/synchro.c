/*
OpenIO SDS sqliterepo
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

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <zookeeper.h>

#include <metautils/lib/metautils.h>
#include <sqliterepo/sqliterepo_variables.h>
#include <sqliterepo/sqliterepo_remote_variables.h>

#include "version.h"
#include "synchro.h"
#include "sqlx_remote.h"
#include "gridd_client_pool.h"

/* Unfortunately, state2String() is not exported by Zookeeper. */
const char * zoo_state2str(int state) {
#define ON_STATE(N) do { if (state == ZOO_##N##_STATE) return #N; } while (0)
	ON_STATE(EXPIRED_SESSION);
	ON_STATE(AUTH_FAILED);
	ON_STATE(CONNECTING);
	ON_STATE(ASSOCIATING);
	ON_STATE(CONNECTED);
#if ZOO_35
	ON_STATE(READONLY);
	ON_STATE(NOTCONNECTED);
#endif
	return "INVALID_STATE";
}

static const char * zoo_zevt2str(int zevt) {
#define ON_ZEVT(N) do { if (zevt == ZOO_##N##_EVENT) return #N; } while (0)
	ON_ZEVT(CREATED);
	ON_ZEVT(DELETED);
	ON_ZEVT(CHANGED);
	ON_ZEVT(CHILD);
	ON_ZEVT(SESSION);
	ON_ZEVT(NOTWATCHING);
	return "EVENT?";
}

struct sqlx_sync_s
{
	struct sqlx_sync_vtable_s *vtable;

	gchar *zk_prefix;
	gchar *zk_url;
	zhandle_t *zh;
	clientid_t zk_id;

	guint hash_width;
	guint hash_depth;

	struct grid_single_rrd_s *conn_attempts;
};

static void _clear(struct sqlx_sync_s *ss);

static GError* _open(struct sqlx_sync_s *ss);

static void _close(struct sqlx_sync_s *ss);

static int _acreate (struct sqlx_sync_s *ss, const char *path, const char *v,
		int vlen, int flags, string_completion_t completion, const void *data);

static int _adelete (struct sqlx_sync_s *ss, const char *path, int version,
		void_completion_t completion, const void *data);

static int _awexists (struct sqlx_sync_s *ss, const char *path,
		watcher_fn watcher, void* watcherCtx,
		stat_completion_t completion, const void *data);

static int _awget (struct sqlx_sync_s *ss, const char *path,
		watcher_fn watcher, void* watcherCtx,
		data_completion_t completion, const void *data);

static int _awget_children (struct sqlx_sync_s *ss, const char *path,
		watcher_fn watcher, void* watcherCtx,
		strings_completion_t completion, const void *data);

static int _awget_siblings (struct sqlx_sync_s *ss, const char *path,
		watcher_fn watcher, void* watcherCtx,
		strings_completion_t completion, const void *data);

static int _aremove_all_watches(struct sqlx_sync_s *ss, const char *path,
		void_completion_t completion, const void *data);

static struct sqlx_sync_vtable_s VTABLE =
{
	_clear,
	_open,
	_close,
	_acreate,
	_adelete,
	_awexists,
	_awget,
	_awget_children,
	_awget_siblings,
	_aremove_all_watches,
};

static gchar *
_sanitize_and_shuffle_zk_url(const char *url)
{
	if (!oio_str_is_set(url)) {
		GRID_ERROR("Invalid ZK connection string: %s", "not set");
		return NULL;
	}

	gchar **tokens = g_strsplit(url, OIO_CSV_SEP, -1);
	if (!tokens) {
		GRID_ERROR("Invalid ZK connection string: %s", "not coma-separated");
		return NULL;
	}
	for (gchar **t=tokens; *t ;++t) {
		if (!oio_str_is_set(*t)) {
			GRID_ERROR("Invalid ZK connection string: %s", "empty tokens");
			g_strfreev(tokens);
			return NULL;
		}
	}
	if (sqliterepo_zk_shuffle)
		oio_ext_array_shuffle((void**)tokens, g_strv_length(tokens));

	gchar *shuffled = g_strjoinv(OIO_CSV_SEP, tokens);
	g_strfreev(tokens);
	return shuffled;
}

struct sqlx_sync_s*
sqlx_sync_create(const char *url)
{
	gchar *shuffled = _sanitize_and_shuffle_zk_url(url);
	if (!shuffled)
		return NULL;

	struct sqlx_sync_s *ss = g_malloc0(sizeof(struct sqlx_sync_s));
	ss->vtable = &VTABLE;
	ss->zk_prefix = NULL;
	ss->zk_url = shuffled;
	ss->conn_attempts = grid_single_rrd_create(
			oio_ext_monotonic_seconds(), disconnection_rrd_window + 1);
	return ss;
}

void
sqlx_sync_set_prefix(struct sqlx_sync_s *ss, const gchar *prefix)
{
	EXTRA_ASSERT(ss != NULL);
	EXTRA_ASSERT(ss->vtable == &VTABLE);
	oio_str_replace(&ss->zk_prefix, prefix);
	GRID_DEBUG("SYNC prefix set to [%s]", prefix);
}

void
sqlx_sync_set_hash(struct sqlx_sync_s *ss, guint w, guint d)
{
	EXTRA_ASSERT(ss != NULL);
	EXTRA_ASSERT(ss->vtable == &VTABLE);
	ss->hash_width = CLAMP(w,1,3);
	ss->hash_depth = MIN(d,2);
	GRID_DEBUG("SYNC hash set to [%ux%u]", w, d);
}

//------------------------------------------------------------------------------

static gchar *
_realpath(const struct sqlx_sync_s *ss, const char *path,
		gchar *d, gsize dlen)
{
	EXTRA_ASSERT(ss->zk_prefix != NULL);

	guint w;
	switch (ss->hash_depth) {
		case 0:
			g_snprintf(d, dlen, "%s/%s", ss->zk_prefix, path);
			return d;
		case 1:
			w = CLAMP(ss->hash_width, 1, 3);
			g_snprintf(d, dlen, "%s/%.*s/%s", ss->zk_prefix, w, path, path);
			return d;
		default:
			w = CLAMP(ss->hash_width, 1, 2);
			g_snprintf(d, dlen, "%s/%.*s/%.*s/%s", ss->zk_prefix,
					w, path, w, path + w, path);
			return d;
	}
}

static gchar *
_realdirname(const struct sqlx_sync_s *ss, const char *path,
		gchar *d, gsize dlen)
{
	EXTRA_ASSERT(ss->zk_prefix != NULL);

	guint w;
	switch (ss->hash_depth) {
		case 0:
			g_strlcpy(d, ss->zk_prefix, dlen);
			return d;
		case 1:
			w = CLAMP(ss->hash_width, 1, 3);
			g_snprintf(d, dlen, "%s/%.*s", ss->zk_prefix, w, path);
			return d;
		default:
			w = CLAMP(ss->hash_width, 1, 2);
			g_snprintf(d, dlen, "%s/%.*s/%.*s", ss->zk_prefix,
					w, path, w, path + w);
			return d;
	}
}

static void __attribute__ ((constructor))
_zk_init_env (void)
{
	zoo_set_debug_level (ZOO_LOG_LEVEL_WARN);
}

//------------------------------------------------------------------------------

static void zk_main_watch(zhandle_t *zh UNUSED, int type, int state,
		const char *path UNUSED, void *watcherCtx);

static void
_reconnect(struct sqlx_sync_s *ss)
{
	if (ss->zh) {
		GRID_NOTICE("Zookeeper: disconnecting "
				"(expired session or too many soft reconnections)");
		zookeeper_close(ss->zh);
	}

	/* Forget the previous ID and reconnect */
	memset (&ss->zk_id, 0, sizeof(ss->zk_id));

	GRID_NOTICE("Zookeeper: starting connection to [%s]", ss->zk_url);
	ss->zh = zookeeper_init(ss->zk_url, zk_main_watch,
			sqliterepo_zk_timeout / G_TIME_SPAN_MILLISECOND, &ss->zk_id, ss, 0);
	if (!ss->zh) {
		GRID_ERROR("Zookeeper init failure: (%d) %s",
				errno, strerror(errno));
		grid_main_set_status (2);
		grid_main_stop ();
	}
}

static void
zk_main_watch(zhandle_t *zh, int type, int state, const char *path UNUSED,
		void *watcherCtx)
{
	EXTRA_ASSERT (watcherCtx != NULL);
	EXTRA_ASSERT (zh != NULL);

	/* The current call happens in the bg thread of the ZK handle. Let's
	 * ensure it ignores the signals we rely on. */
	metautils_ignore_signals();

	if (type != ZOO_SESSION_EVENT) {
		GRID_TRACE("Zookeeper: non-session event type=%d state=%d path=%s",
				type, state, path);
		return;
	}

	const gint64 now = oio_ext_monotonic_seconds();
	struct sqlx_sync_s *ss = watcherCtx;

	if (state == ZOO_EXPIRED_SESSION_STATE || state == ZOO_AUTH_FAILED_STATE) {
		GRID_WARN("Zookeeper: %s/%s to %s",
				zoo_zevt2str(type), zoo_state2str(state),
				ss->zk_url);
		return _reconnect(ss);
	} else if (state == ZOO_CONNECTING_STATE) {
		const guint64 delta = grid_single_rrd_get_delta(
				ss->conn_attempts, now, disconnection_rrd_window);
		if (delta > disconnection_threshold) {
			/* There were many connection attempts recently, sign of an
			 * underlying zookeeper problem. We will try to wipe everything
			 * and start from the beginning. */
			return _reconnect(ss);
		} else {
			GRID_NOTICE("Zookeeper: (re)connecting to [%s]", ss->zk_url);
		}
	} else if (state == ZOO_ASSOCIATING_STATE) {
		GRID_DEBUG("Zookeeper: associating to [%s]", ss->zk_url);
	} else if (state == ZOO_CONNECTED_STATE) {
		const clientid_t *p_cid = zh ? zoo_client_id(zh) : NULL;
		if (p_cid)
			memcpy(&ss->zk_id, p_cid, sizeof(clientid_t));
		GRID_INFO("Zookeeper: connected to [%s] id=%"G_GINT64_FORMAT,
				ss->zk_url, ss->zk_id.client_id);
		grid_single_rrd_add(ss->conn_attempts, now, 1);
	} else {
		GRID_WARN("Zookeeper: %s unmanaged %s/%s id=%"G_GINT64_FORMAT,
				ss->zk_url, zoo_zevt2str(type), zoo_state2str(state),
				ss->zk_id.client_id);
	}
}

static GError*
_open(struct sqlx_sync_s *ss)
{
	EXTRA_ASSERT(ss != NULL);
	EXTRA_ASSERT(ss->vtable == &VTABLE);

	if (NULL != ss->zh)
		return NEWERROR(CODE_INTERNAL_ERROR, "BUG: ZK connection already initiated");
	ss->zh = zookeeper_init(ss->zk_url, zk_main_watch,
			sqliterepo_zk_timeout / G_TIME_SPAN_MILLISECOND, NULL, ss, 0);
	if (NULL == ss->zh)
		return NEWERROR(CODE_INTERNAL_ERROR, "ZK connection failure");
	return NULL;
}

static void
_close(struct sqlx_sync_s *ss)
{
	EXTRA_ASSERT(ss != NULL);
	EXTRA_ASSERT(ss->vtable == &VTABLE);
	if (ss->zh) {
		zookeeper_close(ss->zh);
		ss->zh = NULL;
	}
}

static void
_clear(struct sqlx_sync_s *ss)
{
	EXTRA_ASSERT(ss != NULL);
	EXTRA_ASSERT(ss->vtable == &VTABLE);
	_close(ss);
	oio_str_clean (&ss->zk_prefix);
	oio_str_clean (&ss->zk_url);
	grid_single_rrd_destroy(ss->conn_attempts);
	memset(ss, 0, sizeof(*ss));
	g_free(ss);
}

static int
_acreate (struct sqlx_sync_s *ss, const char *path, const char *v,
		int vlen, int flags, string_completion_t completion, const void *data)
{
	EXTRA_ASSERT(ss != NULL);
	EXTRA_ASSERT(ss->vtable == &VTABLE);
#ifdef HAVE_ENBUG
	if (oio_sync_failure_threshold_action >= oio_ext_rand_int_range(1,100))
		return ZOPERATIONTIMEOUT;
#endif
	gchar p[PATH_MAXLEN];
	int rc = zoo_acreate(ss->zh, _realpath(ss, path, p, sizeof(p)),
			v, vlen, &ZOO_OPEN_ACL_UNSAFE,
			flags, completion, data);
	return rc;
}

static int
_adelete (struct sqlx_sync_s *ss, const char *path, int version,
		void_completion_t completion, const void *data)
{
	EXTRA_ASSERT(ss != NULL);
	EXTRA_ASSERT(ss->vtable == &VTABLE);
#ifdef HAVE_ENBUG
	if (oio_sync_failure_threshold_action >= oio_ext_rand_int_range(1,100))
		return ZOPERATIONTIMEOUT;
#endif
	gchar p[PATH_MAXLEN];
	int rc = zoo_adelete(ss->zh, _realpath(ss, path, p, sizeof(p)),
			version, completion, data);
	return rc;
}

static int
_awexists (struct sqlx_sync_s *ss, const char *path,
		watcher_fn watcher, void* watcherCtx,
		stat_completion_t completion, const void *data)
{
	EXTRA_ASSERT(ss != NULL);
	EXTRA_ASSERT(ss->vtable == &VTABLE);
#ifdef HAVE_ENBUG
	if (oio_sync_failure_threshold_action >= oio_ext_rand_int_range(1,100))
		return ZOPERATIONTIMEOUT;
#endif
	gchar p[PATH_MAXLEN];
	int rc = zoo_awexists(ss->zh, _realpath(ss, path, p, sizeof(p)),
			watcher, watcherCtx, completion, data);
	return rc;
}

static int
_awget (struct sqlx_sync_s *ss, const char *path,
		watcher_fn watcher, void* watcherCtx,
		data_completion_t completion, const void *data)
{
	EXTRA_ASSERT(ss != NULL);
	EXTRA_ASSERT(ss->vtable == &VTABLE);
#ifdef HAVE_ENBUG
	if (oio_sync_failure_threshold_action >= oio_ext_rand_int_range(1,100))
		return ZOPERATIONTIMEOUT;
#endif
	gchar p[PATH_MAXLEN];
	int rc = zoo_awget(ss->zh, _realpath(ss, path, p, sizeof(p)),
			watcher, watcherCtx, completion, data);
	return rc;
}

static int
_awget_children (struct sqlx_sync_s *ss, const char *path,
		watcher_fn watcher, void* watcherCtx,
		strings_completion_t completion, const void *data)
{
	EXTRA_ASSERT(ss != NULL);
	EXTRA_ASSERT(ss->vtable == &VTABLE);
#ifdef HAVE_ENBUG
	if (oio_sync_failure_threshold_action >= oio_ext_rand_int_range(1,100))
		return ZOPERATIONTIMEOUT;
#endif
	gchar p[PATH_MAXLEN];
	int rc = zoo_awget_children(ss->zh, _realpath(ss, path, p, sizeof(p)),
			watcher, watcherCtx, completion, data);
	return rc;
}

static int
_awget_siblings (struct sqlx_sync_s *ss, const char *path,
		watcher_fn watcher, void* watcherCtx,
		strings_completion_t completion, const void *data)
{
	EXTRA_ASSERT(ss != NULL);
	EXTRA_ASSERT(ss->vtable == &VTABLE);
#ifdef HAVE_ENBUG
	if (oio_sync_failure_threshold_action >= oio_ext_rand_int_range(1,100))
		return ZOPERATIONTIMEOUT;
#endif
	gchar p[PATH_MAXLEN];
	int rc = zoo_awget_children(ss->zh, _realdirname(ss, path, p, sizeof(p)),
			watcher, watcherCtx, completion, data);
	return rc;
}

static int
_aremove_all_watches(struct sqlx_sync_s *ss, const char *path,
		void_completion_t completion, const void *data)
{
	EXTRA_ASSERT(ss != NULL);
	EXTRA_ASSERT(ss->vtable == &VTABLE);
#ifdef HAVE_ENBUG
	if (oio_sync_failure_threshold_action >= oio_ext_rand_int_range(1,100))
		return ZOPERATIONTIMEOUT;
#endif
	int rc = ZOK;
#if ZOO_35
	gchar p[PATH_MAXLEN];
	_realpath(ss, path, p, sizeof(p));
	// XXX: the (void_completion_t *) cast is necessary because of a bogus API
	// XXX: we should set 'local' to TRUE, but it did not work with ZK 3.5.5
	rc = zoo_aremove_all_watches(ss->zh, p,
			ZWATCHTYPE_DATA, FALSE, (void_completion_t *)completion, data);
#else
	(void) ss;
	(void) path;
	(void) completion;
	(void) data;
#endif
	return rc;
}

/* -------------------------------------------------------------------------- */

#define SYNC_CALL(self,F) VTABLE_CALL(self,struct abstract_sqlx_sync_s*,F)

void
sqlx_sync_clear(struct sqlx_sync_s *self)
{
#ifdef HAVE_EXTRA_DEBUG
	SYNC_CALL(self,clear)(self);
#else
	return _clear(self);
#endif
}

GError *
sqlx_sync_open(struct sqlx_sync_s *self)
{
#ifdef HAVE_EXTRA_DEBUG
	SYNC_CALL(self,open)(self);
#else
	return _open(self);
#endif
}

void
sqlx_sync_close(struct sqlx_sync_s *self)
{
#ifdef HAVE_EXTRA_DEBUG
	SYNC_CALL(self,close)(self);
#else
	return _close(self);
#endif
}

int
sqlx_sync_acreate (struct sqlx_sync_s *ss, const char *path,
		const char *v, int vlen, int flags,
		string_completion_t completion, const void *d)
{
#ifdef HAVE_EXTRA_DEBUG
	SYNC_CALL(ss,acreate)(ss, path, v, vlen, flags, completion, d);
#else
	return _acreate(ss, path, v, vlen, flags, completion, d);
#endif
}

int
sqlx_sync_adelete (struct sqlx_sync_s *ss, const char *path, int version,
		void_completion_t completion, const void *d)
{
#ifdef HAVE_EXTRA_DEBUG
	SYNC_CALL(ss,adelete)(ss, path, version, completion, d);
#else
	return _adelete(ss, path, version, completion, d);
#endif
}

int
sqlx_sync_awexists(struct sqlx_sync_s *ss, const char *path,
		watcher_fn watch, void* watchCtx,
		stat_completion_t completion, const void *d)
{
#ifdef HAVE_EXTRA_DEBUG
	SYNC_CALL(ss,awexists)(ss, path, watch, watchCtx, completion, d);
#else
	return _awexists(ss, path, watch, watchCtx, completion, d);
#endif
}

int
sqlx_sync_awget (struct sqlx_sync_s *ss, const char *path,
		watcher_fn watch, void* watchCtx,
		data_completion_t completion, const void *d)
{
#ifdef HAVE_EXTRA_DEBUG
	SYNC_CALL(ss,awget)(ss, path, watch, watchCtx, completion, d);
#else
	return _awget(ss, path, watch, watchCtx, completion, d);
#endif
}

int
sqlx_sync_awget_children (struct sqlx_sync_s *ss, const char *path,
		watcher_fn watch, void* watchCtx,
		strings_completion_t completion, const void *d)
{
#ifdef HAVE_EXTRA_DEBUG
	SYNC_CALL(ss,awget_children)(ss, path, watch, watchCtx, completion, d);
#else
	return _awget_children(ss, path, watch, watchCtx, completion, d);
#endif
}

int
sqlx_sync_awget_siblings (struct sqlx_sync_s *ss, const char *path,
		watcher_fn watch, void* watchCtx,
		strings_completion_t completion, const void *d)
{
#ifdef HAVE_EXTRA_DEBUG
	SYNC_CALL(ss,awget_siblings)(ss, path, watch, watchCtx, completion, d);
#else
	return _awget_siblings(ss, path, watch, watchCtx, completion, d);
#endif
}

int
sqlx_sync_aremove_all_watches(struct sqlx_sync_s *ss, const char *path,
		void_completion_t completion, const void *d)
{
#ifdef HAVE_EXTRA_DEBUG
	SYNC_CALL(ss,aremove_all_watches)(ss, path, completion, d);
#else
	return _aremove_all_watches(ss, path, completion, d);
#endif
}

int
sqlx_sync_uses_handle(struct sqlx_sync_s *ss, zhandle_t *zh)
{
	return ss? ss->zh == zh: FALSE;
}

gchar*
sqlx_sync_zk_full_key_path(struct sqlx_sync_s *ss, const char *key)
{
	if (!ss || !key)
		return NULL;
	gchar p[PATH_MAXLEN];
	_realpath(ss, key, p, sizeof(p));
	return g_strdup(p);
}

const char*
sqlx_sync_zk_server(struct sqlx_sync_s *ss)
{
	if (!ss || !ss->zh)
		return NULL;
#if ZOO_MAJOR_VERSION > 3 || (ZOO_MAJOR_VERSION == 3 && ZOO_MINOR_VERSION >= 5)
	return zoo_get_current_server(ss->zh);
#else
	return "# requires zookeeper>=3.5 #";
#endif
}

/* -------------------------------------------------------------------------- */

static void _direct_destroy (struct sqlx_peering_s *self);

static void _direct_notify (struct sqlx_peering_s *self);

static gboolean _direct_use (struct sqlx_peering_s *self,
		/* in */
		const char *url,
		const struct sqlx_name_inline_s *n,
		const char *peers,
		const gboolean master);

static gboolean _direct_getvers (struct sqlx_peering_s *self,
		/* in */
		const char *url,
		const struct sqlx_name_inline_s *n,
		const char *peers,
		/* out */
		struct election_member_s *m,
		const char *reqid,
		sqlx_peering_getvers_end_f result);

static gboolean _direct_pipefrom (struct sqlx_peering_s *self,
		/* in */
		const char *url,
		const struct sqlx_name_inline_s *n,
		const char *src,
		const gint check_type,
		/* out */
		struct election_member_s *m,
		guint reqid,
		sqlx_peering_pipefrom_end_f result);

struct sqlx_peering_vtable_s vtable_peering_DIRECT =
{
	_direct_destroy, _direct_notify,
	_direct_use, _direct_getvers, _direct_pipefrom
};

struct sqlx_peering_direct_s
{
	struct sqlx_peering_vtable_s *vtable;

	/* poolifies the client sockets to avoid reserving to many file
	 * descriptors. */
	struct gridd_client_pool_s *pool;

	GThreadPool *pool_udp_use;

	/* Some requests may be sent over a UDP channel. We just need a file
	 * descriptor from the application */
	int fd_udp;
};

/* @private */
struct use_request_s {
	gint64 deadline;
	gsize addr_len;
	struct sockaddr_in6 addr;
	struct sqlx_name_inline_s name;
	gboolean master;
	gchar reqid[LIMIT_LENGTH_REQID];
	gchar peers[];
};

static void
_use_by_udp_no_free(struct use_request_s *req, struct sqlx_peering_direct_s *self)
{
	NAME2CONST(n, req->name);
	GByteArray *msg = sqlx_pack_USE(&n, req->peers, req->master, req->deadline);
	const ssize_t len = msg->len;
	const ssize_t sent = sendto(self->fd_udp, msg->data, msg->len,
			MSG_NOSIGNAL, (struct sockaddr*) &req->addr, req->addr_len);
	g_byte_array_unref(msg);
	if (sent != len) {
		int errsav = errno;
		GRID_DEBUG("USE(%s.%s) failed: (%d) %s",
				n.base, n.type, errsav, strerror(errsav));
	}
}

static void
_use_by_udp(struct use_request_s *req, struct sqlx_peering_direct_s *self)
{
	if (oio_str_is_set(req->reqid))
		oio_ext_set_reqid(req->reqid);
	else
		oio_ext_set_prefixed_random_reqid("udp-use-");
	_use_by_udp_no_free(req, self);
	g_free(req);
}

struct sqlx_peering_s *
sqlx_peering_factory__create_direct (struct gridd_client_pool_s *pool)
{
	struct sqlx_peering_direct_s *self = g_malloc0 (sizeof(*self));
	self->vtable = &vtable_peering_DIRECT;
	self->pool = pool;
	self->fd_udp = -1;
	self->pool_udp_use = g_thread_pool_new((GFunc)_use_by_udp, self, 8, FALSE, NULL);
	return (struct sqlx_peering_s*) self;
}

void
sqlx_peering_direct__set_udp (struct sqlx_peering_s *self, int fd)
{
	if (!self) return;
	struct sqlx_peering_direct_s *p = (struct sqlx_peering_direct_s*) self;
	g_assert(p->vtable == &vtable_peering_DIRECT);
	p->fd_udp = fd;
}

static void
_direct_destroy (struct sqlx_peering_s *self)
{
	if (!self) return;
	struct sqlx_peering_direct_s *p = (struct sqlx_peering_direct_s*) self;
	g_assert(p->vtable == &vtable_peering_DIRECT);
	if (p->pool_udp_use)
		g_thread_pool_free(p->pool_udp_use, FALSE, TRUE);
	g_free (p);
}

static void
_direct_notify (struct sqlx_peering_s *self)
{
	if (!self) return;
	struct sqlx_peering_direct_s *p = (struct sqlx_peering_direct_s*) self;
	EXTRA_ASSERT(p->vtable == &vtable_peering_DIRECT);
	gridd_client_pool_notify(p->pool);
}

static gboolean
_direct_use(struct sqlx_peering_s *self,
		/* in */
		const char *url,
		const struct sqlx_name_inline_s *ni,
		const char *peers,
		const gboolean master)
{
	struct sqlx_peering_direct_s *p = (struct sqlx_peering_direct_s*) self;
	EXTRA_ASSERT(p != NULL && p->vtable == &vtable_peering_DIRECT);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(ni != NULL);

	const gint64 now = oio_ext_monotonic_time();
	const gint64 deadline = now + (G_TIME_SPAN_SECOND * oio_election_use_timeout_req);

	if (p->fd_udp >= 0) {
		/* A UDP socket has been configured, so we skip the queue and the pool
		 * for TCP RPC */
		gsize struct_size =
				sizeof(struct use_request_s) + 1 + (peers? strlen(peers) : 0);
		struct use_request_s *req = g_alloca(struct_size);
		req->deadline = deadline;
		req->addr_len = sizeof(req->addr);
		memcpy(&(req->name), ni, sizeof(req->name));
		req->master = master;
		if (!grid_string_to_sockaddr(url,
					(struct sockaddr*)&(req->addr), &req->addr_len)) {
			GRID_WARN("Invalid peer addr [%s]", url);
		} else {
			g_strlcpy(req->reqid, oio_ext_ensure_reqid("sync-use-"),
					LIMIT_LENGTH_REQID);
			if (peers)
				strcpy(req->peers, peers);
			if (sqliterepo_udp_deferred) {
				metautils_gthreadpool_push("UDP", p->pool_udp_use,
						g_memdup(req, struct_size));
			} else {
				_use_by_udp_no_free(req, p);
			}
		}
		return FALSE;
	} else {
		/* No UDP socket was configured, thus we prepare a handle for a defered
		 * TCP RPC */
		struct event_client_s *mc =
			g_slice_alloc0(sizeof(struct event_client_s));
		mc->struct_size = sizeof(struct event_client_s);
		mc->client = gridd_client_create_empty ();

		gridd_client_set_timeout(mc->client, oio_election_use_timeout_req);
		gridd_client_set_timeout_cnx(mc->client, oio_election_use_timeout_cnx);

		GError *err = gridd_client_connect_url (mc->client, url);
		if (err) {
			GRID_WARN("USE error: (%d) %s", err->code, err->message);
			event_client_free(mc);
			g_error_free(err);
			return FALSE;
		} else {
			NAME2CONST(n, *ni);
			GByteArray *req = sqlx_pack_USE(&n, peers, master, deadline);
			err = gridd_client_request (mc->client, req, NULL, NULL);
			g_byte_array_unref(req);
			if (err) {
				GRID_WARN("USE error: (%d) %s", err->code, err->message);
				event_client_free(mc);
				g_error_free(err);
				return FALSE;
			} else {
				gridd_client_pool_defer(p->pool, mc);
				return TRUE;
			}
		}
	}
}

struct evtclient_PIPEFROM_s
{
	struct event_client_s ec;

	sqlx_peering_pipefrom_end_f hook;
	struct election_member_s *m;
	guint reqid;
};

static void
on_end_PIPEFROM (struct evtclient_PIPEFROM_s *mc)
{
	EXTRA_ASSERT(mc != NULL);
	EXTRA_ASSERT(mc->ec.client != NULL);
	GError *err = gridd_client_error(mc->ec.client);
	mc->hook (err, mc->m, mc->reqid);
	if (err)
		g_error_free(err);
}

static gboolean
_direct_pipefrom (struct sqlx_peering_s *self,
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
	struct sqlx_peering_direct_s *p = (struct sqlx_peering_direct_s*) self;
	EXTRA_ASSERT(p != NULL && p->vtable == &vtable_peering_DIRECT);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(m != NULL);

	struct evtclient_PIPEFROM_s *mc =
		g_slice_alloc0(sizeof(struct evtclient_PIPEFROM_s));
	mc->ec.struct_size = sizeof(struct evtclient_PIPEFROM_s);
	mc->ec.client = gridd_client_create_empty ();
	mc->ec.on_end = (gridd_client_end_f) on_end_PIPEFROM;
	mc->hook = result;
	mc->m = m;
	mc->reqid = reqid;

	const gint64 deadline = oio_ext_get_deadline();
	gridd_client_set_timeout_cnx(mc->ec.client,
			oio_clamp_timeout(oio_election_resync_timeout_cnx, deadline));
	gridd_client_set_timeout(mc->ec.client,
			oio_clamp_timeout(oio_election_resync_timeout_req, deadline));

	GError *err = gridd_client_connect_url (mc->ec.client, url);
	if (NULL != err) {
		gridd_client_fail(mc->ec.client, err);
		event_client_free(&mc->ec);
		return FALSE;
	} else {
		NAME2CONST(n0, *n);
		GByteArray *req = sqlx_pack_PIPEFROM(&n0, src, check_type,
				oio_clamp_deadline(oio_election_resync_timeout_req, deadline));
		err = gridd_client_request(mc->ec.client, req, NULL, NULL);
		g_byte_array_unref(req);
		if (NULL != err) {
			gridd_client_fail(mc->ec.client, err);
			event_client_free(&mc->ec);
			return FALSE;
		} else {
			gridd_client_pool_defer(p->pool, &mc->ec);
			return TRUE;
		}
	}
}

struct evtclient_GETVERS_s
{
	struct event_client_s ec;

	sqlx_peering_getvers_end_f hook;
	struct election_member_s *m;
	GTree *vremote;
	// FIXME(FVE): move reqid to event_client_s
	char reqid[LIMIT_LENGTH_REQID];
};

static void
on_end_GETVERS(struct evtclient_GETVERS_s *mc)
{
	EXTRA_ASSERT(mc != NULL);
	EXTRA_ASSERT(mc->ec.client != NULL);

	GError *err = gridd_client_error(mc->ec.client);
	if (!err && !mc->vremote)
		err = SYSERR("BUG: no version replied");
	if (likely(NULL != mc->hook)) {
		if (err)
			mc->hook (err, mc->m, mc->reqid, NULL);
		else
			mc->hook (NULL, mc->m, mc->reqid, mc->vremote);
	}

	if (mc->vremote)
		g_tree_destroy (mc->vremote);
	if (err)
		g_error_free (err);
}

static gboolean
on_reply_GETVERS (gpointer ctx, MESSAGE reply)
{
	EXTRA_ASSERT(reply != NULL);
	struct evtclient_GETVERS_s *ec = ctx;
	EXTRA_ASSERT(ec != NULL);

	gsize bsize = 0;
	void *b = metautils_message_get_BODY(reply, &bsize);
	if (!b || !bsize)
		return TRUE;

	GTree *version;
	if (!(version = version_decode(b, bsize))) {
		GRID_WARN("Invalid encoded version in reply");
		return FALSE;
	}

	if (ec->vremote)
		g_tree_destroy(ec->vremote);
	ec->vremote = version;
	return TRUE;
}

static gboolean
_direct_getvers (struct sqlx_peering_s *self,
		/* in */
		const char *url,
		const struct sqlx_name_inline_s *n,
		const char *peers,
		/* out */
		struct election_member_s *m,
		const char *reqid,
		sqlx_peering_getvers_end_f result)
{
	struct sqlx_peering_direct_s *p = (struct sqlx_peering_direct_s*) self;
	EXTRA_ASSERT(p != NULL && p->vtable == &vtable_peering_DIRECT);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(m != NULL);

	struct evtclient_GETVERS_s *mc =
		g_slice_alloc0(sizeof(struct evtclient_GETVERS_s));
	mc->ec.struct_size = sizeof(struct evtclient_GETVERS_s);
	mc->ec.client = gridd_client_create_empty ();
	mc->ec.on_end = (gridd_client_end_f) on_end_GETVERS;
	mc->hook = result;
	mc->m = m;
	if (!reqid)
		reqid = oio_ext_ensure_reqid("sync-vers-");
	g_strlcpy(mc->reqid, reqid, LIMIT_LENGTH_REQID);
	mc->vremote = NULL;

	const gint64 now = oio_ext_monotonic_time();
	const gint64 deadline = now + (G_TIME_SPAN_SECOND * oio_election_getvers_timeout_req);

	gridd_client_set_timeout(mc->ec.client, oio_election_getvers_timeout_req);
	gridd_client_set_timeout_cnx(mc->ec.client, oio_election_getvers_timeout_cnx);

	GError *err = gridd_client_connect_url (mc->ec.client, url);
	if (NULL != err) {
		gridd_client_fail(mc->ec.client, err);
		event_client_free(&mc->ec);
		return FALSE;
	} else {
		NAME2CONST(n0, *n);
		GByteArray *req = sqlx_pack_GETVERS(&n0, peers, deadline);
		err = gridd_client_request (mc->ec.client, req, mc, on_reply_GETVERS);
		g_byte_array_unref(req);
		if (NULL != err) {
			gridd_client_fail(mc->ec.client, err);
			event_client_free(&mc->ec);
			return FALSE;
		} else {
			gridd_client_pool_defer(p->pool, &mc->ec);
			return TRUE;
		}
	}
}

/* -------------------------------------------------------------------------- */

#define PEER_CALL(self,F) VTABLE_CALL(self,struct sqlx_peering_abstract_s*,F)

void
sqlx_peering__destroy (struct sqlx_peering_s *self)
{
#ifdef HAVE_EXTRA_DEBUG
	PEER_CALL(self,destroy)(self);
#else
	return _direct_destroy(self);
#endif
}

void
sqlx_peering__notify (struct sqlx_peering_s *self)
{
#ifdef HAVE_EXTRA_DEBUG
	PEER_CALL(self,notify)(self);
#else
	return _direct_notify(self);
#endif
}

gboolean
sqlx_peering__use (struct sqlx_peering_s *self,
		/* in */
		const char *url,
		const struct sqlx_name_inline_s *n,
		const char *peers,
		const gboolean master)
{
#ifdef HAVE_EXTRA_DEBUG
	PEER_CALL(self,use)(self, url, n, peers, master);
#else
	return _direct_use(self, url, n, peers, master);
#endif
}

gboolean
sqlx_peering__getvers (struct sqlx_peering_s *self,
		/* in */
		const char *url,
		const struct sqlx_name_inline_s *n,
		const char *peers,
		/* out */
		struct election_member_s *m,
		const char *reqid,
		sqlx_peering_getvers_end_f result)
{
#ifdef HAVE_EXTRA_DEBUG
	PEER_CALL(self,getvers)(self, url, n, peers, m, reqid, result);
#else
	return _direct_getvers(self, url, n, peers, m, reqid, result);
#endif
}

gboolean
sqlx_peering__pipefrom (struct sqlx_peering_s *self,
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
#ifdef HAVE_EXTRA_DEBUG
	PEER_CALL(self,pipefrom)(self, url, n, src, check_type, m, reqid, result);
#else
	return _direct_pipefrom(self, url, n, src, check_type, m, reqid, result);
#endif
}
