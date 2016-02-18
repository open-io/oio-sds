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
sqlx_sync_create(const char *url)
{
	struct sqlx_sync_s *ss = g_malloc0(sizeof(struct sqlx_sync_s));
	ss->vtable = &VTABLE;
	ss->zk_url = g_strdup(url);
	ss->zk_prefix = g_strdup("/NOTSET");
	return ss;
}

void
sqlx_sync_set_prefix(struct sqlx_sync_s *ss, const gchar *prefix)
{
	EXTRA_ASSERT(ss != NULL);
	EXTRA_ASSERT(ss->vtable == &VTABLE);
	oio_str_replace(&ss->zk_prefix, prefix);
	GRID_NOTICE("SYNC prefix set to [%s]", prefix);
}

void
sqlx_sync_set_hash(struct sqlx_sync_s *ss, guint w, guint d)
{
	EXTRA_ASSERT(ss != NULL);
	EXTRA_ASSERT(ss->vtable == &VTABLE);
	ss->hash_width = CLAMP(w,1,3);
	ss->hash_depth = MIN(d,2);
	GRID_NOTICE("SYNC hash set to [%ux%u]", w, d);
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
zk_main_watch(zhandle_t *zh, int type, int state, const char *path,
		void *watcherCtx)
{
	metautils_ignore_signals();

	struct sqlx_sync_s *ss = watcherCtx;
	(void) zh;
	(void) path;

	if (type == ZOO_SESSION_EVENT) {
		if (state == ZOO_CONNECTING_STATE) {
			if (ss->zh)
				zookeeper_close(ss->zh);
			if (NULL != ss->on_exit)
				ss->on_exit(ss->on_exit_ctx);
			ss->zh = zookeeper_init(ss->zk_url, zk_main_watch,
				SQLX_SYNC_DEFAULT_ZK_TIMEOUT, &ss->zk_id, ss, 0);
		}
	}
	else {
		if (state == ZOO_EXPIRED_SESSION_STATE) {
			GRID_WARN("Zookeeper: expired session to [%s]", ss->zk_url);
		}
		else if (state == ZOO_AUTH_FAILED_STATE) {
			GRID_WARN("Zookeeper: auth problem to [%s]", ss->zk_url);
		}
		else if (state == ZOO_CONNECTING_STATE) {
			GRID_WARN("Zookeeper: (re)connecting to [%s]", ss->zk_url);
		}
		else if (state == ZOO_ASSOCIATING_STATE) {
			GRID_DEBUG("Zookeeper: associating to [%s]", ss->zk_url);
		}
		else if (state == ZOO_CONNECTED_STATE) {
			memcpy(&(ss->zk_id), zoo_client_id(ss->zh), sizeof(clientid_t));
			GRID_INFO("Zookeeper: connected to [%s] id=%"G_GINT64_FORMAT,
					ss->zk_url, ss->zk_id.client_id);
		}
	}
}

static GError*
_open(struct sqlx_sync_s *ss)
{
	EXTRA_ASSERT(ss != NULL);
	EXTRA_ASSERT(ss->vtable == &VTABLE);
	if (NULL != ss->zh)
		return NEWERROR(CODE_INTERNAL_ERROR, "BUG : ZK connection already initiated");
	ss->zh = zookeeper_init(ss->zk_url, zk_main_watch, 4000, NULL, ss, 0);
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
	GRID_TRACE2("SYNC create(%p) = %d", p, rc);
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
	GRID_TRACE2("SYNC delete(%s) = %d", p, rc);
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
	GRID_TRACE2("SYNC exists(%s) = %d", p, rc);
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
	GRID_TRACE2("SYNC get(%s) = %d", p, rc);
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
	GRID_TRACE2("SYNC children(%s) = %d", p, rc);
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
	GRID_TRACE("SYNC children(%s) = %d", p, rc);
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
};

struct sqlx_peering_s *
sqlx_peering_factory__create_direct (struct gridd_client_pool_s *pool,
		struct gridd_client_factory_s *factory)
{
	struct sqlx_peering_direct_s *self = g_malloc0 (sizeof(*self));
	self->vtable = &vtable_peering_DIRECT;
	self->pool = pool;
	self->factory = factory;
	return (struct sqlx_peering_s*) self;
}

static void
_direct_destroy (struct sqlx_peering_s *self)
{
	if (!self) return;
	struct sqlx_peering_direct_s *p = (struct sqlx_peering_direct_s*) self;
	EXTRA_ASSERT(p->vtable == &vtable_peering_DIRECT);
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

	GByteArray *req = sqlx_pack_USE(n);

	struct event_client_s *mc = g_malloc0 (sizeof(struct event_client_s));
	mc->client = gridd_client_factory_create_client (p->factory);
	gridd_client_connect_url (mc->client, url);
	gridd_client_request (mc->client, req, NULL, NULL);
	gridd_client_set_timeout(mc->client, 1.0);
	gridd_client_pool_defer(p->pool, mc);
	g_byte_array_unref(req);
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
	if (err) g_error_free(err);
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

	GByteArray *req = sqlx_pack_PIPEFROM(n, src);

	struct evtclient_PIPEFROM_s *mc =
		g_malloc0 (sizeof(struct evtclient_PIPEFROM_s));
	mc->ec.client = gridd_client_factory_create_client (p->factory);
	mc->ec.on_end = (gridd_client_end_f) on_end_PIPEFROM;
	mc->hook = result;
	mc->manager = manager;
	sqlx_name_dup (&mc->name, n);
	mc->reqid = reqid;

	gridd_client_connect_url (mc->ec.client, url);
	gridd_client_request(mc->ec.client, req, NULL, NULL);
	gridd_client_set_timeout(mc->ec.client, 30.0);
	gridd_client_pool_defer(p->pool, &mc->ec);

	g_byte_array_unref(req);
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
	if (err)
		mc->hook (err, mc->manager, sqlx_name_mutable_to_const(&mc->name), mc->reqid, NULL);
	else if (!mc->vremote) {
		err = SYSERR("BUG: no version replied");
		mc->hook (err, mc->manager, sqlx_name_mutable_to_const(&mc->name), mc->reqid, NULL);
	} else {
		mc->hook (NULL, mc->manager, sqlx_name_mutable_to_const(&mc->name), mc->reqid, mc->vremote);
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

	gridd_client_connect_url (mc->ec.client, url);

	GByteArray *req = sqlx_pack_GETVERS(n);
	gridd_client_request (mc->ec.client, req, mc, on_reply_GETVERS);
	g_byte_array_unref(req);

	gridd_client_set_timeout(mc->ec.client, 1.0);
	gridd_client_pool_defer(p->pool, &mc->ec);
}

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
