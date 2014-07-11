/**
 * @file meta_resolver_explicit.h
 * Explicit META resolver
 */

#ifndef __RESOLVER_DIRECT_H__
# define __RESOLVER_DIRECT_H__

/**
 * @defgroup meta_resolver META Resolver
 * @ingroup private
 * @defgroup resolver_explicit Explicit Resolver
 * @ingroup meta_resolver
 * @{
 */

# include <glib.h>
# include <metautils/lib/metatypes.h>

typedef struct prefix_info_s prefix_info_t;
typedef struct resolver_direct_s resolver_direct_t;

struct metacd_s;

#define COND_MAXWAIT_MS 2000

struct prefix_info_s
{
	GArray *addresses; 	/* Array of meta1 which manage this prefix (master & replicates) */	
	gint master_index; 	/* The position of the meta1_master in the array */
};

struct resolver_direct_s
{
	struct {
		struct {
			gint op;
			gint cnx;
		} conscience;
		struct {
			gint op;
			gint cnx;
		} m0;
		struct {
			gint op;
			gint cnx;
		} m1;
	} timeout;
	
	GCond *refresh_condition;
	GMutex *use_mutex;
	gboolean refresh_pending;

	addr_info_t meta0;
	GPtrArray *mappings;

	/* Maybe-NULL handle to a metacd (NULL -> metacd unavailable) */
	struct metacd_s *metacd;
};

#define M0CACHE_LOCK(R)      g_mutex_lock ((R).use_mutex)
#define M0CACHE_UNLOCK(R)    g_mutex_unlock ((R).use_mutex)
#define M0CACHE_INIT_LOCK(R) { (R).use_mutex = g_mutex_new (); }
#define M0CACHE_FINI_LOCK(R) g_mutex_free ((R).use_mutex)

resolver_direct_t* resolver_direct_create2 (const char * const config,
	gint to_cnx, gint to_req, GError **err);

resolver_direct_t* resolver_direct_create (const gchar * const url, GError **err);

resolver_direct_t* resolver_direct_create_with_metacd(const gchar * const url,
	struct metacd_s *metacd, gint to_cnx, gint to_req, GError **err);

void resolver_direct_free (resolver_direct_t *r);

void resolver_direct_clear (resolver_direct_t *r);

void resolver_direct_decache_all (resolver_direct_t *r);

int resolver_direct_reload (resolver_direct_t *r, GError **err);

addr_info_t* resolver_direct_get_meta1 (resolver_direct_t *r, const container_id_t cID, int read_only, GSList *exclude, GError **err);

int resolver_direct_set_meta1_master (resolver_direct_t *r, const container_id_t cid, const char *master, GError **e);

GSList* resolver_direct_get_meta2_once (resolver_direct_t *r, const char *ns, const container_id_t cID, GSList **exclude, GError **err);

GSList* resolver_direct_get_meta2 (resolver_direct_t *r, const char *ns, const container_id_t cID, GError **err, int max_attempts);

/** @} */

#endif /*__RESOLVER_DIRECT_H__*/
