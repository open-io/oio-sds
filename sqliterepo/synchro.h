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

#ifndef OIO_SDS__sqliterepo__synchro_h
# define OIO_SDS__sqliterepo__synchro_h 1

/**
 * SYNCHRONICITY module :
 *
 * Helps the developper to make use of a ZooKeeper-like server.
 */
#include <zookeeper.h>

struct sqlx_sync_s;

struct sqlx_sync_vtable_s
{
	void (*clear) (struct sqlx_sync_s *ss);

	GError* (*open) (struct sqlx_sync_s *ss);

	void (*close) (struct sqlx_sync_s *ss);

	int (*acreate) (struct sqlx_sync_s *ss, const char *path, const char *v,
			int vlen, int flags, string_completion_t completion, const void *data);

	int (*adelete) (struct sqlx_sync_s *ss, const char *path, int version,
			void_completion_t completion, const void *data);

	int (*awexists) (struct sqlx_sync_s *ss, const char *path,
			watcher_fn watcher, void* watcherCtx,
			stat_completion_t completion, const void *data);

	int (*awget) (struct sqlx_sync_s *ss, const char *path,
			watcher_fn watcher, void* watcherCtx,
			data_completion_t completion, const void *data);

	int (*awget_children) (struct sqlx_sync_s *ss, const char *path,
			watcher_fn watcher, void* watcherCtx,
			strings_completion_t completion, const void *data);

	int (*awget_siblings) (struct sqlx_sync_s *ss, const char *path,
			watcher_fn watcher, void* watcherCtx,
			strings_completion_t completion, const void *data);

	/** Sets the exit callback. It only works with a sqlx synchronizer out of
	 * sqlx_sync_create() */
	void (*set_exit_hook) (struct sqlx_sync_s *ss,
			void (*on_exit) (void*), void *on_exit_ctx);
};

struct abstract_sqlx_sync_s
{
	struct sqlx_sync_vtable_s *vtable;
};

#define sqlx_sync_clear(ss) \
	((struct abstract_sqlx_sync_s*)(ss))->vtable->clear(ss)

#define sqlx_sync_open(ss) \
	((struct abstract_sqlx_sync_s*)(ss))->vtable->open(ss)

#define sqlx_sync_close(ss) \
	((struct abstract_sqlx_sync_s*)(ss))->vtable->close(ss)

#define sqlx_sync_acreate(ss, path, v, vlen, flags, completion, data) \
	((struct abstract_sqlx_sync_s*)(ss))->vtable->acreate(ss, path, v, vlen, flags, completion, data)

#define sqlx_sync_adelete(ss, path, ver, completion, data) \
	((struct abstract_sqlx_sync_s*)(ss))->vtable->adelete(ss, path, ver, completion, data)

#define sqlx_sync_awexists(ss, path, watch, watchctx, completion, data) \
	((struct abstract_sqlx_sync_s*)(ss))->vtable->awexists(ss, path, watch, watchctx, completion, data)

#define sqlx_sync_awget(ss, path, watch, watchctx, completion, data) \
	((struct abstract_sqlx_sync_s*)(ss))->vtable->awget(ss, path, watch, watchctx, completion, data)

#define sqlx_sync_awget_children(ss, path, watch, watchctx, completion, d) \
	((struct abstract_sqlx_sync_s*)(ss))->vtable->awget_children(ss, path, watch, watchctx, completion, d)

#define sqlx_sync_awget_siblings(ss, path, watch, watchctx, completion, d) \
	((struct abstract_sqlx_sync_s*)(ss))->vtable->awget_siblings(ss, path, watch, watchctx, completion, d)

#define sqlx_sync_set_exit_hook(ss,hook,data) \
	((struct abstract_sqlx_sync_s*)(ss))->vtable->set_exit_hook(ss, hook, data)

/** Initiates a sqlx synchronizer based on ZooKeeper.
 * @param url the Zookeeper connection string */
struct sqlx_sync_s * sqlx_sync_create(const char *url, gboolean shuffle);

void sqlx_sync_set_prefix(struct sqlx_sync_s *ss, const gchar *prefix);

void sqlx_sync_set_hash(struct sqlx_sync_s *ss, guint witdth, guint depth);

static inline const char * zoo_state2str(int state) {
#define ON_STATE(N) do { if (state == ZOO_##N##_STATE) return #N; } while (0)
	ON_STATE(EXPIRED_SESSION);
	ON_STATE(AUTH_FAILED);
	ON_STATE(CONNECTING);
	ON_STATE(ASSOCIATING);
	ON_STATE(CONNECTED);
	return "STATE?";
}

static inline const char * zoo_zevt2str(int zevt) {
#define ON_ZEVT(N) do { if (zevt == ZOO_##N##_EVENT) return #N; } while (0)
	ON_ZEVT(CREATED);
	ON_ZEVT(DELETED);
	ON_ZEVT(CHANGED);
	ON_ZEVT(CHILD);
	ON_ZEVT(SESSION);
	ON_ZEVT(NOTWATCHING);
	return "EVENT?";
}

/* -------------------------------------------------------------------------- */

struct sqlx_name_s;
struct election_manager_s;
struct gridd_client_factory_s;
struct gridd_client_pool_s;

struct sqlx_peering_s;

typedef void (*sqlx_peering_pipefrom_end_f) (GError *e,
		struct election_manager_s *m, const struct sqlx_name_s *n,
		guint reqid);

typedef void (*sqlx_peering_getvers_end_f) (GError *e,
		struct election_manager_s *m, const struct sqlx_name_s *n,
		guint reqid, GTree *vremote);

/* Represents what an election needs to communicate with its peers. */
struct sqlx_peering_vtable_s
{
	void (*destroy) (struct sqlx_peering_s *self);

	void (*use) (struct sqlx_peering_s *self,
			const char *url,
			const struct sqlx_name_s *n);

	void (*getvers) (struct sqlx_peering_s *self,
			const char *url,
			const struct sqlx_name_s *n,
			/* for the return */
			struct election_manager_s *manager,
			guint reqid,
			sqlx_peering_getvers_end_f result);

	void (*pipefrom) (struct sqlx_peering_s *self,
			const char *url,
			const struct sqlx_name_s *n,
			const char *src,
			/* for the return */
			struct election_manager_s *manager,
			guint reqid,
			sqlx_peering_pipefrom_end_f result);
};

struct sqlx_peering_abstract_s
{
	struct sqlx_peering_vtable_s *vtable;
};

void sqlx_peering__destroy (struct sqlx_peering_s *self);

void sqlx_peering__use (struct sqlx_peering_s *self, const char *url,
		const struct sqlx_name_s *n);

void sqlx_peering__getvers (struct sqlx_peering_s *self, const char *url,
		const struct sqlx_name_s *n, struct election_manager_s *manager,
		guint reqid, sqlx_peering_getvers_end_f result);

void sqlx_peering__pipefrom (struct sqlx_peering_s *self, const char *url,
			const struct sqlx_name_s *n, const char *src,
			struct election_manager_s *manager, guint reqid,
			sqlx_peering_pipefrom_end_f result);

struct sqlx_peering_s * sqlx_peering_factory__create_direct (
		struct gridd_client_pool_s *clipool,
		struct gridd_client_factory_s *clifac);

void sqlx_peering_direct__set_udp (struct sqlx_peering_s *self, int fd);

#endif /*OIO_SDS__sqliterepo__synchro_h*/
