/**
 * @file meta_resolver_metacd.h
 * Cached META resolver
 */
#ifndef __RESOLVER_METACD_H__
# define __RESOLVER_METACD_H__

/**
 * @defgroup resolver_metacd MetaCD Resolver
 * @ingroup meta_resolver
 * @{
 */

# include <glib.h>
# include <metautils/lib/metatypes.h>

struct metacd_s;


struct metacd_s* resolver_metacd_create (const char * const config, GError **err);


void resolver_metacd_free (struct metacd_s *d);


int resolver_metacd_is_up (struct metacd_s *m);


void resolver_metacd_decache (struct metacd_s *m, const container_id_t cID);


void resolver_metacd_decache_all (struct metacd_s *m);

addr_info_t* resolver_metacd_get_meta0 (struct metacd_s *m, GError **err);

addr_info_t* resolver_metacd_get_meta1 (struct metacd_s *m, const container_id_t cID, int ro, GSList *exclude,
		gboolean *p_ref_exists, GError **err);

int resolver_metacd_set_meta1_master(struct metacd_s *m, const container_id_t cid, const char *m1, GError **e);

GSList* resolver_metacd_get_meta2 (struct metacd_s *m, const container_id_t cID, GError **err);

struct meta2_raw_content_s* resolver_metacd_get_content (struct metacd_s *m, const container_id_t cID,
	const gchar *content, GError **err);

gboolean resolver_metacd_del_content(struct metacd_s *m, const container_id_t cID, const gchar *path, GError **err);

gboolean resolver_metacd_put_content (struct metacd_s *m, struct meta2_raw_content_s *raw_content, GError **err);

/** @} */

#endif /*__RESOLVER_METACD_H__*/
