/*
OpenIO SDS client
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

#ifndef OIO_SDS__client__c__lib__meta_resolver_metacd_h
# define OIO_SDS__client__c__lib__meta_resolver_metacd_h 1

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

#endif /*OIO_SDS__client__c__lib__meta_resolver_metacd_h*/