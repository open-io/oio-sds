#ifndef HC_sqliterepo_synchro__h
# define HC_sqliterepo_synchro__h 1

#ifndef SQLX_SYNC_DEFAULT_ZK_TIMEOUT
# define SQLX_SYNC_DEFAULT_ZK_TIMEOUT 4000
#endif

/**
 * SYNCHRONICITY module :
 *
 * Helps the developper to make use of a ZooKeeper-like server.
 */
#include <zookeeper/zookeeper.h>

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
struct sqlx_sync_s * sqlx_sync_create(const char *url);

void sqlx_sync_set_prefix(struct sqlx_sync_s *ss, const gchar *prefix);

void sqlx_sync_set_hash(struct sqlx_sync_s *ss, guint witdth, guint depth);

#endif // HC_sqliterepo_synchro__h
