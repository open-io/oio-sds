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

#ifndef HC_RESOLVER__H
# define HC_RESOLVER__H 1

enum hc_resolver_flags_e
{
	HC_RESOLVER_NOCACHE = 0x01,
	HC_RESOLVER_NOATIME = 0x02,
	HC_RESOLVER_NOMAX =   0x04,
};

/* forward declarations */
struct meta1_service_url_s;
struct hc_url_s;

/* Hidden type */
struct hc_resolver_s;

/**
 * @return NULL in case of error, or a resolver ready to use
 */
struct hc_resolver_s* hc_resolver_create(void);

/**
 * @param r the resolver to be destroyed
 */
void hc_resolver_destroy(struct hc_resolver_s *r);

/**
 * @param r
 * @param url
 * @param srvtype
 * @param result
 * @return
 */
GError* hc_resolve_reference_service(struct hc_resolver_s *r,
		struct hc_url_s *url, const gchar *srvtype, gchar ***result);

/**
 * @param r
 * @param url
 * @param srvtype
 */
void hc_decache_reference_service(struct hc_resolver_s *r,
		struct hc_url_s *url, const gchar *srvtype);

#endif
