/*
OpenIO SDS sqliterepo
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

#include <zookeeper.h>
#include <zookeeper_log.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/common_variables.h>
#include <sqliterepo/sqliterepo_variables.h>
#include <sqliterepo/sqliterepo_remote_variables.h>

#include "version.h"
#include "synchro.h"
#include "sqlx_remote.h"
#include "gridd_client_pool.h"

static const char * zoo_state2str(int state) {
#define ON_STATE(N) do { if (state == ZOO_##N##_STATE) return #N; } while (0)
	ON_STATE(EXPIRED_SESSION);
	ON_STATE(AUTH_FAILED);
	ON_STATE(CONNECTING);
	ON_STATE(ASSOCIATING);
	ON_STATE(CONNECTED);
	return "STATE?";
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
zk_main_watch(zhandle_t *zh UNUSED, int type, int state, const char *path UNUSED,
		void *watcherCtx)
{
	metautils_ignore_signals();

	struct sqlx_sync_s *ss = watcherCtx;
	EXTRA_ASSERT (ss != NULL);

	if (type != ZOO_SESSION_EVENT) {
		GRID_TRACE("Zookeeper: non-session event type=%d state=%d path=%s",
				type, state, path);
		return;
	}

	gint64 now = oio_ext_monotonic_seconds();
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
		memcpy(&(ss->zk_id), zoo_client_id(ss->zh), sizeof(clientid_t));
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
	OUTGOING("ZK_CREATE %s %d", p, rc);
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
	OUTGOING("ZK_DEL %s %d", p, rc);
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
	GRID_TRACE2("ZK_EXISTS %s %d", p, rc);
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
	OUTGOING("ZK_GET %s %d", p, rc);
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
	OUTGOING("ZK_CHILDREN %s %d", p, rc);
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
	OUTGOING("ZK_CHILDREN %s %d", p, rc);
	return rc;
}

/* -------------------------------------------------------------------------- */

static void _direct_destroy (struct sqlx_peering_s *self);

static void _direct_use (struct sqlx_peering_s *self,
		const char *url,
		const struct sqlx_name_s *n);

static void _direct_getvers (struct sqlx_peering_s *self,
		const char *url,
		const struct sqlx_name_s *n,
		struct election_manager_s *manager,
		guint reqid,
		sqlx_peering_getvers_end_f result);

static void _direct_pipefrom (struct sqlx_peering_s *self,
		const char *url,
		const struct sqlx_name_s *n,
		const char *src,
		struct election_manager_s *manager,
		guint reqid,
		sqlx_peering_pipefrom_end_f result);

struct sqlx_peering_vtable_s vtable_peering_DIRECT =
{
	_direct_destroy, _direct_use, _direct_getvers, _direct_pipefrom
};

struct sqlx_peering_direct_s
{
	struct sqlx_peering_vtable_s *vtable;

	/* Instanciates client. Designed for testing purposes, to avoid requiring
	   any network during the tests. */
	struct gridd_client_factory_s *factory;

	/* pool'ifies the client sockets to avoid reserving to many file
	 * descriptors. */
	struct gridd_client_pool_s *pool;

	/* Some requests may be sent over a UDP channel. We just need a file
	 * descriptor from the application */
	int fd_udp;
};

struct sqlx_peering_s *
sqlx_peering_factory__create_direct (struct gridd_client_pool_s *pool,
		struct gridd_client_factory_s *factory)
{
	struct sqlx_peering_direct_s *self = g_malloc0 (sizeof(*self));
	self->vtable = &vtable_peering_DIRECT;
	self->pool = pool;
	self->factory = factory;
	self->fd_udp = -1;
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
	g_free (p);
}

static void
_direct_use (struct sqlx_peering_s *self,
		const char *url,
		const struct sqlx_name_s *n)
{
	struct sqlx_peering_direct_s *p = (struct sqlx_peering_direct_s*) self;
	EXTRA_ASSERT(p != NULL && p->vtable == &vtable_peering_DIRECT);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(n != NULL);

	const gint64 deadline = oio_ext_get_deadline();

	if (p->fd_udp >= 0) {
		struct sockaddr_storage ss;
		gsize ss_len = sizeof(ss);
		struct sockaddr *sa = (struct sockaddr*) &ss;
		if (grid_string_to_sockaddr(url, sa, &ss_len)) {
			GByteArray *req = sqlx_pack_USE(n,
					oio_clamp_deadline(oio_election_use_timeout_req, deadline));
			const ssize_t sent = sendto(p->fd_udp, req->data, req->len,
					MSG_NOSIGNAL, sa, ss_len);
			const ssize_t len = req->len;
			g_byte_array_unref(req);
			if (sent != len) {
				int errsav = errno;
				GRID_DEBUG("USE(%s,%s.%s) failed: (%d) %s",
						url, n->base, n->type, errsav, strerror(errsav));
			} else {
				OUTGOING("DB_USE udp %s %s.%s", url, n->base, n->type);
			}
		}
	} else {
		struct event_client_s *mc = g_malloc0 (sizeof(struct event_client_s));
		mc->client = gridd_client_factory_create_client (p->factory);

		gridd_client_set_timeout(mc->client,
				oio_clamp_timeout(oio_election_use_timeout_req, deadline));
		gridd_client_set_timeout_cnx(mc->client,
				oio_clamp_timeout(oio_election_use_timeout_cnx, deadline));

		GError *err = gridd_client_connect_url (mc->client, url);
		if (err) {
			GRID_DEBUG("USE error: (%d) %s", err->code, err->message);
			event_client_free(mc);
		} else {
			GByteArray *req = sqlx_pack_USE(n,
					oio_clamp_deadline(oio_election_use_timeout_req, deadline));
			err = gridd_client_request (mc->client, req, NULL, NULL);
			g_byte_array_unref(req);
			if (err) {
				GRID_DEBUG("USE error: (%d) %s", err->code, err->message);
				event_client_free(mc);
			} else {
				gridd_client_pool_defer(p->pool, mc);
				OUTGOING("DB_USE tcp %s %s.%s", url, n->base, n->type);
			}
		}
	}
}

struct evtclient_PIPEFROM_s
{
	struct event_client_s ec;

	sqlx_peering_pipefrom_end_f hook;
	struct election_manager_s *manager;
	guint reqid;
	struct sqlx_name_inline_s name;
};

static void
on_end_PIPEFROM (struct evtclient_PIPEFROM_s *mc)
{
	EXTRA_ASSERT(mc != NULL);
	EXTRA_ASSERT(mc->ec.client != NULL);
	GError *err = gridd_client_error(mc->ec.client);
	NAME2CONST(n, mc->name);
	mc->hook (err, mc->manager, &n, mc->reqid);
	if (err)
		g_error_free(err);
}

static void
_direct_pipefrom (struct sqlx_peering_s *self,
		const char *url,
		const struct sqlx_name_s *n,
		const char *src,
		/* for the output */
		struct election_manager_s *manager,
		guint reqid,
		sqlx_peering_pipefrom_end_f result)
{
	struct sqlx_peering_direct_s *p = (struct sqlx_peering_direct_s*) self;
	EXTRA_ASSERT(p != NULL && p->vtable == &vtable_peering_DIRECT);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(n != NULL);

	struct evtclient_PIPEFROM_s *mc =
		g_malloc0 (sizeof(struct evtclient_PIPEFROM_s));
	mc->ec.client = gridd_client_factory_create_client (p->factory);
	mc->ec.on_end = (gridd_client_end_f) on_end_PIPEFROM;
	mc->hook = result;
	mc->manager = manager;
	NAMEFILL(mc->name, *n);
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
	} else {
		GByteArray *req = sqlx_pack_PIPEFROM(n, src,
				oio_clamp_deadline(oio_election_resync_timeout_req, deadline));
		err = gridd_client_request(mc->ec.client, req, NULL, NULL);
		g_byte_array_unref(req);
		if (NULL != err) {
			gridd_client_fail(mc->ec.client, err);
			event_client_free(&mc->ec);
		} else {
			gridd_client_pool_defer(p->pool, &mc->ec);
			OUTGOING("DB_PIPEFROM tcp %s %s.%s", url, n->base, n->type);
		}
	}
}

struct evtclient_GETVERS_s
{
	struct event_client_s ec;

	sqlx_peering_getvers_end_f hook;
	struct sqlx_name_inline_s name;
	struct election_manager_s *manager;
	GTree *vremote;
	guint reqid;
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
		NAME2CONST(n, mc->name);
		if (err)
			mc->hook (err, mc->manager, &n, mc->reqid, NULL);
		else
			mc->hook (NULL, mc->manager, &n, mc->reqid, mc->vremote);
	}

	if (mc->vremote)
		g_tree_destroy (mc->vremote);
	if (err)
		g_error_free (err);
}

static gboolean
on_reply_GETVERS (gpointer ctx, MESSAGE reply)
{
	GRID_TRACE2("%s(%p,%p)", __FUNCTION__, ctx, reply);
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

static void
_direct_getvers (struct sqlx_peering_s *self,
		const char *url,
		const struct sqlx_name_s *n,
		struct election_manager_s *manager,
		guint reqid,
		sqlx_peering_getvers_end_f result)
{
	struct sqlx_peering_direct_s *p = (struct sqlx_peering_direct_s*) self;
	EXTRA_ASSERT(p != NULL && p->vtable == &vtable_peering_DIRECT);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(n != NULL);

	struct evtclient_GETVERS_s *mc =
		g_malloc0 (sizeof(struct evtclient_GETVERS_s));
	mc->ec.client = gridd_client_factory_create_client (p->factory);
	mc->ec.on_end = (gridd_client_end_f) on_end_GETVERS;
	mc->hook = result;
	mc->manager = manager;
	NAMEFILL(mc->name, *n);
	mc->reqid = reqid;
	mc->vremote = NULL;

	const gint64 deadline = oio_ext_get_deadline();
	gridd_client_set_timeout(mc->ec.client,
			oio_clamp_timeout(oio_election_getvers_timeout_req, deadline));
	gridd_client_set_timeout_cnx(mc->ec.client,
			oio_clamp_timeout(oio_election_getvers_timeout_cnx, deadline));

	GError *err = gridd_client_connect_url (mc->ec.client, url);
	if (NULL != err) {
		gridd_client_fail(mc->ec.client, err);
		event_client_free(&mc->ec);
	} else {
		GByteArray *req = sqlx_pack_GETVERS(n,
				oio_clamp_deadline(oio_election_getvers_timeout_req, deadline));
		err = gridd_client_request (mc->ec.client, req, mc, on_reply_GETVERS);
		g_byte_array_unref(req);
		if (NULL != err) {
			gridd_client_fail(mc->ec.client, err);
			event_client_free(&mc->ec);
		} else {
			gridd_client_pool_defer(p->pool, &mc->ec);
			OUTGOING("DB_GETVERS tcp %s %s.%s", url, n->base, n->type);
		}
	}
}

/* -------------------------------------------------------------------------- */

#define PEER_CALL(self,F) VTABLE_CALL(self,struct sqlx_peering_abstract_s*,F)

void
sqlx_peering__destroy (struct sqlx_peering_s *self)
{
	PEER_CALL(self,destroy)(self);
}

void
sqlx_peering__use (struct sqlx_peering_s *self, const char *url,
		const struct sqlx_name_s *n)
{
	PEER_CALL(self,use)(self,url,n);
}

void
sqlx_peering__getvers (struct sqlx_peering_s *self, const char *url,
		const struct sqlx_name_s *n, struct election_manager_s *manager,
		guint reqid, sqlx_peering_getvers_end_f result)
{
	PEER_CALL(self,getvers)(self,url,n, manager,reqid,result);
}

void
sqlx_peering__pipefrom (struct sqlx_peering_s *self, const char *url,
			const struct sqlx_name_s *n, const char *src,
			struct election_manager_s *manager, guint reqid,
			sqlx_peering_pipefrom_end_f result)
{
	PEER_CALL(self,pipefrom)(self,url,n,src, manager,reqid,result);
}
