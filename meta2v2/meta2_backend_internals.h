#ifndef META2V2_INTERNALS__H
# define META2V2_INTERNALS__H 1
# include <stdlib.h>
# include <unistd.h>
# include <errno.h>

# include <metautils/lib/metautils.h>
# include <metautils/lib/metacomm.h>
# include <sqliterepo/sqliterepo.h>
# include <sqliterepo/sqlite_utils.h>
# include <meta2v2/meta2_backend.h>
# include <meta2v2/meta2_events.h>

# ifndef M2V2_KEY_VERSION
#  define M2V2_KEY_VERSION "m2vers"
# endif

# ifndef M2V2_KEY_QUOTA
#  define M2V2_KEY_QUOTA "quota"
# endif

# ifndef M2V2_KEY_NAMESPACE
#  define M2V2_KEY_NAMESPACE "namespace"
# endif

# ifndef M2V2_KEY_SIZE
#  define M2V2_KEY_SIZE "container_size"
# endif

# ifndef M2V2_KEY_VERSIONING_POLICY
#  define M2V2_KEY_VERSIONING_POLICY "versioning_policy"
# endif

# ifndef M2V2_KEY_KEEP_DELETED_DELAY
#  define M2V2_KEY_KEEP_DELETED_DELAY "keep_deleted_delay"
# endif

# ifndef META2_INIT_FLAG
#  define META2_INIT_FLAG "m2v2:init"
# endif
# ifndef META2_EVTFIELD_M2ADDR
#  define META2_EVTFIELD_M2ADDR "M2ADDR"
# endif
# ifndef META2_EVTFIELD_CHUNKS
#  define META2_EVTFIELD_CHUNKS "CHUNKS"
# endif

# ifndef CONNECT_RETRY_DELAY
#  define CONNECT_RETRY_DELAY 10
# endif

# ifndef META2_URL_LOCAL_BASE
#  define META2_URL_LOCAL_BASE "__M2V2_LOCAL_BASE__"
# endif

struct transient_s
{
	GMutex *lock;
	GTree *tree;
};

struct meta2_backend_s
{
	gchar ns_name[LIMIT_LENGTH_NSNAME]; /* Read-only */

	struct sqlx_repository_s *repo;

	struct service_update_policies_s *policies;

	struct grid_lbpool_s *glp;

	GMutex *lock_ns_info;
	struct namespace_info_s ns_info;

	GMutex *lock_transient;
	GHashTable *transient;

	/* Must a BEANS generation request perform a pre-check on the ALIAS's
	 * existence. */
	gboolean flag_precheck_on_generate;

	/* Notification events */
	GStaticRWLock rwlock_evt_config;
	GHashTable *evt_config; /* <gchar*, struct event_config_s*> */

	// array of GSList* of addr_info_t*
	GPtrArray *m0_mapping;
	GMutex *modified_containers_lock;
	GHashTable *modified_containers;

	struct hc_resolver_s *resolver;
};

struct transient_element_s
{
	time_t expiration;
	GDestroyNotify cleanup;
	gpointer what;
};

void transient_put(GTree *t, const gchar *key, gpointer what, GDestroyNotify cleanup);

gpointer transient_get(GTree *t, const gchar *key);

void transient_del(GTree *t, const gchar *key);

void transient_tree_cleanup(GTree *t);

void transient_cleanup(struct transient_s *t);

/* ------------------------------------------------------------------------- */

GError* m2b_transient_put(struct meta2_backend_s *m2b, const gchar *key, const gchar *hexid,
		gpointer what, GDestroyNotify cleanup);

gpointer m2b_transient_get(struct meta2_backend_s *m2b, const gchar *key, const gchar *hexid , GError **err);

GError* m2b_transient_del(struct meta2_backend_s *m2b, const gchar *key, const gchar *hexid);

void m2b_transient_cleanup(struct meta2_backend_s *m2b);

#endif /* META2V2_INTERNALS__H */
