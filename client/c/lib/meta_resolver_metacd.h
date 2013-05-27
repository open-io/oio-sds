/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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
# include <metatypes.h>

# include "./metacd_remote.h"

typedef struct metacd_s metacd_t;


metacd_t* resolver_metacd_create (const char * const config, GError **err);


void resolver_metacd_free (metacd_t *d);


int resolver_metacd_is_up (metacd_t *m);


void resolver_metacd_decache (metacd_t *m, const container_id_t cID);


void resolver_metacd_decache_all (metacd_t *m);

addr_info_t* resolver_metacd_get_meta0 (metacd_t *m, GError **err);

addr_info_t* resolver_metacd_get_meta1 (metacd_t *m, const container_id_t cID, int ro, GSList *exclude, GError **err);

int resolver_metacd_set_meta1_master(metacd_t *m, const container_id_t cid, const char *m1, GError **e);

GSList* resolver_metacd_get_meta2 (metacd_t *m, const container_id_t cID, GError **err);

struct meta2_raw_content_s* resolver_metacd_get_content (metacd_t *m, const container_id_t cID,
	const gchar *content, GError **err);

gboolean resolver_metacd_del_content(metacd_t *m, const container_id_t cID, const gchar *path, GError **err);

gboolean resolver_metacd_put_content (metacd_t *m, struct meta2_raw_content_s *raw_content, GError **err);

/** @} */

#endif /*__RESOLVER_METACD_H__*/
