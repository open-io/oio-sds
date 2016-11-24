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

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <metautils/lib/metautils.h>

#include <zookeeper.h>
#include <zookeeper_log.h>

#include "version.h"
#include "synchro.h"
#include "sqlx_remote.h"
#include "gridd_client_pool.h"

struct sqlx_sync_s
{
	struct sqlx_sync_vtable_s *vtable;

	void (*on_exit) (void *ctx);
	void *on_exit_ctx;

	gchar *zk_prefix;
	gchar *zk_url;
	zhandle_t *zh;
	clientid_t zk_id;

	guint hash_width;
	guint hash_depth;
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

static void _set_exit_hook(struct sqlx_sync_s *ss, void (*on_exit_hook) (void*),
		void *on_exit_ctx);

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
	_set_exit_hook
};

struct sqlx_sync_s*
sqlx_sync_create(const char *url, gboolean shuffle)
{
	gchar **tokens = g_strsplit(url, ",", -1);
	if (!tokens) {
		GRID_ERROR("Invalid ZK connection string");
		return NULL;
	}
	for (gchar **t=tokens; *t ;++t) {
		if (!oio_str_is_set(*t)) {
			GRID_ERROR("Invalid ZK connection string: empty tokens");
			g_strfreev(tokens);
			return NULL;
		}
	}

	struct sqlx_sync_s *ss = g_malloc0(sizeof(struct sqlx_sync_s));
	ss->vtable = &VTABLE;
	ss->zk_prefix = g_strdup("/NOTSET");

	if (shuffle)
		oio_ext_array_shuffle((void**)tokens, g_strv_length(tokens));
	ss->zk_url = g_strjoinv(",", tokens);
	g_strfreev(tokens);

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

static void
_set_exit_hook(struct sqlx_sync_s *ss, void (*on_exit_hook) (void*),
		void *on_exit_ctx)
{
	EXTRA_ASSERT(ss != NULL);
	EXTRA_ASSERT(ss->vtable == &VTABLE);
	ss->on_exit = on_exit_hook;
	ss->on_exit_ctx = on_exit_ctx;
}

//------------------------------------------------------------------------------

static gchar *
_realpath(const struct sqlx_sync_s *ss, const gchar *path)
{
	guint w;
	switch (ss->hash_depth) {
		case 0:
			return g_strdup_printf("%s/%s", ss->zk_prefix, path);
		case 1:
			w = CLAMP(ss->hash_width, 1, 3);
			return g_strdup_printf("%s/%.*s/%s", ss->zk_prefix, w, path, path);
		default:
			w = CLAMP(ss->hash_width, 1, 2);
			return g_strdup_printf("%s/%.*s/%.*s/%s", ss->zk_prefix,
					w, path, w, path + w, path);
	}
}

static gchar *
_realdirname(const struct sqlx_sync_s *ss, const gchar *path)
{
	guint w;
	switch (ss->hash_depth) {
		case 0:
			return g_strdup(ss->zk_prefix);
		case 1:
			w = CLAMP(ss->hash_width, 1, 3);
			return g_strdup_printf("%s/%.*s", ss->zk_prefix, w, path);
		default:
			w = CLAMP(ss->hash_width, 1, 2);
			return g_strdup_printf("%s/%.*s/%.*s", ss->zk_prefix,
					w, path, w, path + w);
	}
}

static void __attribute__ ((constructor))
_zk_init_env (void)
{
	zoo_set_debug_level (ZOO_LOG_LEVEL_WARN);
}

//------------------------------------------------------------------------------

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

	if (state == ZOO_EXPIRED_SESSION_STATE) {
		if (ss->zh) {
			GRID_NOTICE("Zookeeper: disconnecting (expired session)");
			zookeeper_close(ss->zh);
		}
		if (NULL != ss->on_exit)
			ss->on_exit(ss->on_exit_ctx);

		/* XXX(jfs): forget the previous ID and reconnect */
		memset (&ss->zk_id, 0, sizeof(ss->zk_id));
		GRID_NOTICE("Zookeeper: starting connection to [%s]", ss->zk_url);
		ss->zh = zookeeper_init(ss->zk_url, zk_main_watch,
				SQLX_SYNC_DEFAULT_ZK_TIMEOUT, &ss->zk_id, ss, 0);
		if (!ss->zh) {
			GRID_ERROR("Zookeeper init failure: (%d) %s",
					errno, strerror(errno));
			grid_main_set_status (2);
			grid_main_stop ();
		}
	} else if (state == ZOO_AUTH_FAILED_STATE) {
		GRID_WARN("Zookeeper: auth problem to [%s]", ss->zk_url);
	} else if (state == ZOO_CONNECTING_STATE) {
		GRID_NOTICE("Zookeeper: (re)connecting to [%s]", ss->zk_url);
	} else if (state == ZOO_ASSOCIATING_STATE) {
		GRID_DEBUG("Zookeeper: associating to [%s]", ss->zk_url);
	} else if (state == ZOO_CONNECTED_STATE) {
		memcpy(&(ss->zk_id), zoo_client_id(ss->zh), sizeof(clientid_t));
		GRID_INFO("Zookeeper: connected to [%s] id=%"G_GINT64_FORMAT,
				ss->zk_url, ss->zk_id.client_id);
	} else {
		GRID_WARN("Zookeeper: unmanaged event %d [%s] id=%"G_GINT64_FORMAT,
				state, ss->zk_url, ss->zk_id.client_id);
	}
}

static GError*
_open(struct sqlx_sync_s *ss)
{
	EXTRA_ASSERT(ss != NULL);
	EXTRA_ASSERT(ss->vtable == &VTABLE);
	if (NULL != ss->zh)
		return NEWERROR(CODE_INTERNAL_ERROR, "BUG : ZK connection already initiated");
	ss->zh = zookeeper_init(ss->zk_url, zk_main_watch,
			SQLX_SYNC_DEFAULT_ZK_TIMEOUT, NULL, ss, 0);
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
	memset(ss, 0, sizeof(*ss));
	g_free(ss);
}

static int
_acreate (struct sqlx_sync_s *ss, const char *path, const char *v,
		int vlen, int flags, string_completion_t completion, const void *data)
{
	EXTRA_ASSERT(ss != NULL);
	EXTRA_ASSERT(ss->vtable == &VTABLE);
	gchar *p = _realpath(ss, path);
	int rc = zoo_acreate(ss->zh, p, v, vlen, &ZOO_OPEN_ACL_UNSAFE,
			flags, completion, data);
	OUTGOING("ZK_CREATE %s %d", p, rc);
	g_free(p);
	return rc;
}

static int
_adelete (struct sqlx_sync_s *ss, const char *path, int version,
		void_completion_t completion, const void *data)
{
	EXTRA_ASSERT(ss != NULL);
	EXTRA_ASSERT(ss->vtable == &VTABLE);
	gchar *p = _realpath(ss, path);
	int rc = zoo_adelete(ss->zh, p, version, completion, data);
	OUTGOING("ZK_DEL %s %d", p, rc);
	g_free(p);
	return rc;
}

static int
_awexists (struct sqlx_sync_s *ss, const char *path,
		watcher_fn watcher, void* watcherCtx,
		stat_completion_t completion, const void *data)
{
	EXTRA_ASSERT(ss != NULL);
	EXTRA_ASSERT(ss->vtable == &VTABLE);
	gchar *p = _realpath(ss, path);
	int rc = zoo_awexists(ss->zh, p, watcher, watcherCtx, completion, data);
	GRID_TRACE2("ZK_EXISTS %s %d", p, rc);
	g_free(p);
	return rc;
}

static int
_awget (struct sqlx_sync_s *ss, const char *path,
		watcher_fn watcher, void* watcherCtx,
		data_completion_t completion, const void *data)
{
	EXTRA_ASSERT(ss != NULL);
	EXTRA_ASSERT(ss->vtable == &VTABLE);
	gchar *p = _realpath(ss, path);
	int rc = zoo_awget(ss->zh, p, watcher, watcherCtx, completion, data);
	OUTGOING("ZK_GET %s %d", p, rc);
	g_free(p);
	return rc;
}

static int
_awget_children (struct sqlx_sync_s *ss, const char *path,
		watcher_fn watcher, void* watcherCtx,
		strings_completion_t completion, const void *data)
{
	EXTRA_ASSERT(ss != NULL);
	EXTRA_ASSERT(ss->vtable == &VTABLE);
	gchar *p = _realpath(ss, path);
	int rc = zoo_awget_children(ss->zh, p, watcher, watcherCtx, completion,
			data);
	OUTGOING("ZK_CHILDREN %s %d", p, rc);
	g_free(p);
	return rc;
}

static int
_awget_siblings (struct sqlx_sync_s *ss, const char *path,
		watcher_fn watcher, void* watcherCtx,
		strings_completion_t completion, const void *data)
{
	EXTRA_ASSERT(ss != NULL);
	EXTRA_ASSERT(ss->vtable == &VTABLE);
	gchar *p = _realdirname(ss, path);
	int rc = zoo_awget_children(ss->zh, p, watcher, watcherCtx, completion, data);
	OUTGOING("ZK_CHILDREN %s %d", p, rc);
	g_free(p);
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

	if (p->fd_udp >= 0) {
		struct sockaddr_storage ss;
		gsize ss_len = sizeof(ss);
		struct sockaddr *sa = (struct sockaddr*) &ss;
		if (grid_string_to_sockaddr(url, sa, &ss_len)) {
			GByteArray *req = sqlx_pack_USE(n);
			const ssize_t sent =
				sendto(p->fd_udp, req->data, req->len, 0, sa, ss_len);
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
		gridd_client_set_timeout(mc->client, SQLX_SYNC_TIMEOUT);
		GError *err = gridd_client_connect_url (mc->client, url);
		if (err) {
			GRID_DEBUG("USE error: (%d) %s", err->code, err->message);
			event_client_free(mc);
		} else {
			GByteArray *req = sqlx_pack_USE(n);
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
	struct sqlx_name_mutable_s name;
	guint reqid;
};

static void
on_end_PIPEFROM (struct evtclient_PIPEFROM_s *mc)
{
	EXTRA_ASSERT(mc != NULL);
	EXTRA_ASSERT(mc->ec.client != NULL);
	GError *err = gridd_client_error(mc->ec.client);
	mc->hook (err, mc->manager, sqlx_name_mutable_to_const(&mc->name), mc->reqid);
	if (err)
		g_error_free(err);
	sqlx_name_clean(&mc->name);
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
	sqlx_name_dup (&mc->name, n);
	mc->reqid = reqid;

	gridd_client_set_timeout(mc->ec.client, SQLX_RESYNC_TIMEOUT);

	GError *err = gridd_client_connect_url (mc->ec.client, url);
	if (NULL != err) {
		gridd_client_fail(mc->ec.client, err);
		event_client_free(&mc->ec);
	} else {
		GByteArray *req = sqlx_pack_PIPEFROM(n, src);
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
	struct sqlx_name_mutable_s name;
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
		const struct sqlx_name_s *n = sqlx_name_mutable_to_const(&mc->name);
		if (err)
			mc->hook (err, mc->manager, n, mc->reqid, NULL);
		else
			mc->hook (NULL, mc->manager, n, mc->reqid, mc->vremote);
	}

	if (mc->vremote)
		g_tree_destroy (mc->vremote);
	if (err)
		g_error_free (err);
	sqlx_name_clean (&mc->name);
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
	sqlx_name_dup (&mc->name, n);
	mc->reqid = reqid;
	mc->vremote = NULL;

	gridd_client_set_timeout(mc->ec.client, SQLX_SYNC_TIMEOUT);

	GError *err = gridd_client_connect_url (mc->ec.client, url);
	if (NULL != err) {
		gridd_client_fail(mc->ec.client, err);
		event_client_free(&mc->ec);
	} else {
		GByteArray *req = sqlx_pack_GETVERS(n);
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
