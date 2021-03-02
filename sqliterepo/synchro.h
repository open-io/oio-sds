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

#ifndef OIO_SDS__sqliterepo__synchro_h
# define OIO_SDS__sqliterepo__synchro_h 1

/**
 * SYNCHRONICITY module :
 *
 * Helps the developper to make use of a ZooKeeper-like server.
 */
#include <glib.h>
#include <zookeeper.h>

#define PATH_MAXLEN 128 + LIMIT_LENGTH_NSNAME
#define ZOO_35 ZOO_MAJOR_VERSION > 3 || (ZOO_MAJOR_VERSION == 3 && ZOO_MINOR_VERSION >= 5)

struct sqlx_sync_s;

struct election_member_s;

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

	int (*aremove_all_watches) (struct sqlx_sync_s *ss, const char *path,
			void_completion_t completion, const void *data);
};

struct abstract_sqlx_sync_s
{
	struct sqlx_sync_vtable_s *vtable;
};

void sqlx_sync_clear(struct sqlx_sync_s *ss);

GError * sqlx_sync_open(struct sqlx_sync_s *ss);

void sqlx_sync_close(struct sqlx_sync_s *ss);

int sqlx_sync_acreate (struct sqlx_sync_s *ss, const char *path, const char *v,
		int vlen, int flags, string_completion_t completion, const void *data);

int sqlx_sync_adelete (struct sqlx_sync_s *ss, const char *path, int version,
		void_completion_t completion, const void *data);

int sqlx_sync_awexists(struct sqlx_sync_s *ss, const char *path,
		watcher_fn watcher, void* watcherCtx,
		stat_completion_t completion, const void *data);

int sqlx_sync_awget (struct sqlx_sync_s *ss, const char *path,
		watcher_fn watcher, void* watcherCtx,
		data_completion_t completion, const void *data);

int sqlx_sync_awget_children (struct sqlx_sync_s *ss, const char *path,
		watcher_fn watcher, void* watcherCtx,
		strings_completion_t completion, const void *data);

int sqlx_sync_awget_siblings (struct sqlx_sync_s *ss, const char *path,
		watcher_fn watcher, void* watcherCtx,
		strings_completion_t completion, const void *data);

int sqlx_sync_aremove_all_watches(struct sqlx_sync_s *ss, const char *path,
		  void_completion_t completion, const void *data);

/** Initiates a sqlx synchronizer based on ZooKeeper.
 * @param url the Zookeeper connection string */
struct sqlx_sync_s * sqlx_sync_create(const char *url);

void sqlx_sync_set_prefix(struct sqlx_sync_s *ss, const gchar *prefix);

void sqlx_sync_set_hash(struct sqlx_sync_s *ss, guint witdth, guint depth);

/** Tell if the current synchronizer handle is using the specified
 * Zookeeper handle. */
int sqlx_sync_uses_handle(struct sqlx_sync_s *ss, zhandle_t *zh);

/** Build to full ZK path to the key. Must be freed with g_free. */
gchar* sqlx_sync_zk_full_key_path(struct sqlx_sync_s *ss, const char *key);

/** Tell which server this handle is connected to. */
const char* sqlx_sync_zk_server(struct sqlx_sync_s *ss);

/** Get a string describing one of Zookeeper's state constants. */
const char * zoo_state2str(int state);

/* -------------------------------------------------------------------------- */

struct sqlx_name_s;
struct sqlx_name_inline_s;
struct election_manager_s;
struct gridd_client_pool_s;

struct sqlx_peering_s;

typedef void (*sqlx_peering_pipefrom_end_f) (GError *e,
		struct election_member_s *m,
		guint reqid);

typedef void (*sqlx_peering_getvers_end_f) (GError *e,
		struct election_member_s *m,
		const char *reqid,
		GTree *vremote);

/* Represents what an election needs to communicate with its peers. */
struct sqlx_peering_vtable_s
{
	void (*destroy) (struct sqlx_peering_s *self);

	void (*notify) (struct sqlx_peering_s *self);

	/** @return FALSE if no notify() is necessary (i.e. no command deferred) */
	gboolean (*use) (struct sqlx_peering_s *self,
			/* in */
			const char *url,
			const struct sqlx_name_inline_s *n,
			const gchar *peers,
			const gboolean master);

	/** @return FALSE if no notify() is necessary (i.e. no command deferred) */
	gboolean (*getvers) (struct sqlx_peering_s *self,
			/* in */
			const char *url,
			const struct sqlx_name_inline_s *n,
			const gchar *peers,
			/* out */
			struct election_member_s *m,
			const char *reqid,
			sqlx_peering_getvers_end_f result);

	/** @return FALSE if no notify() is necessary (i.e. no command deferred) */
	gboolean (*pipefrom) (struct sqlx_peering_s *self,
			/* in */
			const char *url,
			const struct sqlx_name_inline_s *n,
			const char *src,
			const gint check_type,
			/* out */
			struct election_member_s *m,
			guint reqid,
			sqlx_peering_pipefrom_end_f result);
};

struct sqlx_peering_abstract_s
{
	struct sqlx_peering_vtable_s *vtable;
};

void sqlx_peering__destroy (struct sqlx_peering_s *self);

void sqlx_peering__notify (struct sqlx_peering_s *self);

gboolean sqlx_peering__use (struct sqlx_peering_s *self,
		/* in */
		const char *url,
		const struct sqlx_name_inline_s *n,
		const char *peers,
		const gboolean master);

gboolean sqlx_peering__getvers (struct sqlx_peering_s *self,
		/* in */
		const char *url,
		const struct sqlx_name_inline_s *n,
		const char *peers,
		/* out */
		struct election_member_s *m,
		const char *reqid,
		sqlx_peering_getvers_end_f result);

gboolean sqlx_peering__pipefrom (struct sqlx_peering_s *self,
		/* in */
		const char *url,
		const struct sqlx_name_inline_s *n,
		const char *src,
		const gint check_type,
		/* out */
		struct election_member_s *m,
		guint reqid,
		sqlx_peering_pipefrom_end_f result);

struct sqlx_peering_s * sqlx_peering_factory__create_direct (
		struct gridd_client_pool_s *clipool);

void sqlx_peering_direct__set_udp (struct sqlx_peering_s *self, int fd);

#endif /*OIO_SDS__sqliterepo__synchro_h*/
